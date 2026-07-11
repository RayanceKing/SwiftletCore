//===----------------------------------------------------------------------===//
//
//  Socks5Handler.swift
//  SwiftletCore — SOCKS5 Inbound Connection Handler
//
//  This file implements the core SOCKS5 protocol state machine as a
//  `ChannelInboundHandler`.  It drives the two‑phase client handshake
//  (authentication → request), establishes the upstream TCP connection,
//  and transitions the channel pipeline into a lightweight bidirectional
//  relay for the remainder of the session.
//
//  State Machine
//  -------------
//  ```
//  awaitingGreeting ──[greeting received]──► awaitingRequest
//                                                    │
//                                    [CONNECT request received]
//                                                    │
//                                                    ▼
//                                               connecting
//                                               /        \
//                                   [outbound OK]      [outbound failed]
//                                     /                      \
//                                    ▼                        ▼
//                           setup relay +              send error reply
//                           success reply              + close channel
//  ```
//
//  After the relay is set up, the decoder, encoder, and this handler are
//  removed from the pipeline and replaced with `Socks5RelayHandler`
//  instances.  No further SOCKS5 framing is applied — raw TCP bytes flow
//  bidirectionally.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
@preconcurrency import NIOPosix

// MARK: - Handler

/// A `ChannelInboundHandler` that implements a complete SOCKS5 (RFC 1928)
/// CONNECT proxy with NO AUTHENTICATION REQUIRED.
///
/// - Important: This handler is **not** shareable — a fresh instance must be
///   created for each inbound client channel.
public final class Socks5InboundHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn  = Socks5InboundMessage
    public typealias OutboundOut = Socks5OutboundMessage

    // MARK: - Connection State

    /// Models the linear progression of a SOCKS5 connection.
    private enum State: Sendable {
        /// Waiting for the initial client greeting (method advertisement).
        case awaitingGreeting
        /// Authentication completed; waiting for the CONNECT / BIND / UDP request.
        case awaitingRequest
        /// An upstream connection is in flight — no further SOCKS5 messages
        /// are expected until it completes or fails.
        case connecting
        /// The handler is being removed from the pipeline; relay mode is active.
        case done
    }

    /// Current position in the SOCKS5 connection lifecycle.
    private var state: State = .awaitingGreeting

    // MARK: - ChannelInboundHandler

    /// Routes an inbound SOCKS5 message to the correct handler based on the
    /// current connection state.
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let message = unwrapInboundIn(data)

        switch (state, message) {
        case (.awaitingGreeting, .greeting(let greeting)):
            handleGreeting(context: context, greeting: greeting)

        case (.awaitingRequest, .request(let request)):
            handleRequest(context: context, request: request)

        case (.connecting, _):
            // The client sent data before we finished connecting — this is a
            // protocol violation.  Drop the data; the connection will be
            // resolved (success or failure) momentarily.
            break

        case (.done, _):
            // Handler is being removed; ignore stray reads.
            break

        default:
            // Unexpected message for the current state (e.g. a request before
            // a greeting, or a second greeting).  Tear down the connection.
            context.close(mode: .all, promise: nil)
        }
    }

    /// When the client disconnects mid‑handshake, clean up any in‑flight
    /// upstream connection attempt (the future callback will no‑op when it
    /// discovers the channel is inactive).
    public func channelInactive(context: ChannelHandlerContext) {
        state = .done
        context.fireChannelInactive()
    }

    /// If the decoder or any other pipeline component throws, close the
    /// channel immediately.  The error has already been logged by NIO.
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.close(mode: .all, promise: nil)
    }

    // MARK: - Greeting Handler

    /// Selects an authentication method from the client's offered list.
    ///
    /// Currently only `NO AUTHENTICATION REQUIRED` (0x00) is supported.
    /// If the client does not offer it, we send `NO ACCEPTABLE METHODS`
    /// (0xFF) and close the connection per RFC 1928 §3.
    private func handleGreeting(
        context: ChannelHandlerContext,
        greeting: Socks5Greeting
    ) {
        if greeting.methods.contains(.noAuthentication) {
            // Accept the connection with no authentication.
            let selection = Socks5OutboundMessage.methodSelection(.noAuthentication)
            context.writeAndFlush(wrapOutboundOut(selection), promise: nil)
            state = .awaitingRequest
        } else {
            // The client did not offer NO AUTH — reject.
            let rejection = Socks5OutboundMessage.methodSelection(.noAcceptable)
            let channel = context.channel
            context.writeAndFlush(wrapOutboundOut(rejection)).whenComplete { _ in
                channel.close(mode: .all, promise: nil)
            }
        }
    }

    // MARK: - Request Handler

    /// Validates the client's request and, for CONNECT commands, initiates
    /// an upstream TCP connection to the requested destination.
    private func handleRequest(
        context: ChannelHandlerContext,
        request: Socks5Request
    ) {
        // --- Command validation ------------------------------------------
        guard request.command == .connect else {
            // BIND and UDP ASSOCIATE are not yet implemented.
            // Write the error reply directly as raw bytes and close.
            var errorReply = context.channel.allocator.buffer(capacity: 10)
            errorReply.writeInteger(UInt8(0x05), as: UInt8.self)       // VER
            errorReply.writeInteger(
                Socks5Reply.commandNotSupported.rawValue,
                as: UInt8.self
            )                                                            // REP
            errorReply.writeInteger(UInt8(0x00), as: UInt8.self)       // RSV
            errorReply.writeInteger(UInt8(0x01), as: UInt8.self)       // ATYP = IPv4
            errorReply.writeBytes([0x00, 0x00, 0x00, 0x00])             // 0.0.0.0
            errorReply.writeInteger(UInt16(0), as: UInt16.self)         // port 0
            let channel = context.channel
            channel.writeAndFlush(errorReply).whenComplete { _ in
                channel.close(mode: .all, promise: nil)
            }
            return
        }

        // --- Initiate upstream connection --------------------------------
        state = .connecting
        connectToRemote(context: context, target: request.target)
    }

    // MARK: - Upstream Connection

    /// Launches a `ClientBootstrap` on the same event loop as the inbound
    /// channel to keep everything single‑threaded and allocation‑friendly.
    private func connectToRemote(
        context: ChannelHandlerContext,
        target: Socks5Target
    ) {
        let bootstrap = ClientBootstrap(group: context.eventLoop)
            .connectTimeout(.seconds(10))
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelInitializer { channel in
                // The remote channel starts with an empty pipeline — raw TCP.
                channel.eventLoop.makeSucceededVoidFuture()
            }

        let future: EventLoopFuture<Channel>

        switch target {
        case .ipv4(let address, let port):
            future = bootstrap.connect(host: address, port: port)
        case .domain(let name, let port):
            future = bootstrap.connect(host: name, port: port)
        case .ipv6(let address, let port):
            future = bootstrap.connect(host: address, port: port)
        }

        // Capture the client Channel for lifetime checks inside the
        // @Sendable closure without capturing the non-Sendable context.
        let clientChannel = context.channel

        future.whenComplete { [weak self] result in
            guard let self = self else { return }

            // If the client channel closed while we were connecting, there
            // is nothing left to do — discard the upstream channel (if any).
            guard clientChannel.isActive else {
                if case .success(let channel) = result {
                    channel.close(mode: .all, promise: nil)
                }
                return
            }

            switch result {
            case .success(let remoteChannel):
                self.handleOutboundSuccess(
                    clientChannel: clientChannel,
                    remoteChannel: remoteChannel
                )
            case .failure(let error):
                self.handleOutboundFailure(
                    clientChannel: clientChannel,
                    error: error
                )
            }
        }
    }

    // MARK: - Outbound Success

    /// The upstream connection was established.  Send a success reply to the
    /// client and reconfigure the pipeline for bidirectional relay.
    ///
    /// The reply is written as raw bytes directly to the client channel to
    /// avoid capturing the non‑Sendable `ChannelHandlerContext`.  Because
    /// both this write and the subsequent `removeHandler` calls are enqueued
    /// on the same event loop, the bytes are guaranteed to enter the
    /// channel's outbound buffer before the encoder is removed.
    private func handleOutboundSuccess(
        clientChannel: Channel,
        remoteChannel: Channel
    ) {
        // Encode a SUCCEEDED reply as raw bytes (10 bytes total).
        // Format: VER(0x05) | REP(0x00) | RSV(0x00) | ATYP(0x01) |
        //         BND.ADDR(0.0.0.0) | BND.PORT(0)
        var reply = clientChannel.allocator.buffer(capacity: 10)
        reply.writeInteger(UInt8(0x05), as: UInt8.self)      // VER
        reply.writeInteger(UInt8(0x00), as: UInt8.self)      // REP = succeeded
        reply.writeInteger(UInt8(0x00), as: UInt8.self)      // RSV
        reply.writeInteger(UInt8(0x01), as: UInt8.self)      // ATYP = IPv4
        reply.writeBytes([0x00, 0x00, 0x00, 0x00])            // 0.0.0.0
        reply.writeInteger(UInt16(0), as: UInt16.self)        // port 0

        clientChannel.writeAndFlush(reply, promise: nil)
        state = .done
        setupRelay(clientChannel: clientChannel, remoteChannel: remoteChannel)
    }

    // MARK: - Outbound Failure

    /// Maps the underlying connection error to a SOCKS5 reply code, sends
    /// a raw error reply to the client, and closes the channel.
    private func handleOutboundFailure(
        clientChannel: Channel,
        error: Error
    ) {
        let replyCode = mapToReply(error)

        // Encode the error reply as raw bytes (10 bytes total).
        var reply = clientChannel.allocator.buffer(capacity: 10)
        reply.writeInteger(UInt8(0x05), as: UInt8.self)       // VER
        reply.writeInteger(replyCode.rawValue, as: UInt8.self) // REP
        reply.writeInteger(UInt8(0x00), as: UInt8.self)       // RSV
        reply.writeInteger(UInt8(0x01), as: UInt8.self)       // ATYP = IPv4
        reply.writeBytes([0x00, 0x00, 0x00, 0x00])             // 0.0.0.0
        reply.writeInteger(UInt16(0), as: UInt16.self)         // port 0

        clientChannel.writeAndFlush(reply).whenComplete { _ in
            clientChannel.close(mode: .all, promise: nil)
        }
    }

    /// Maps a NIO or system connection error to the closest SOCKS5 reply code.
    private func mapToReply(_ error: Error) -> Socks5Reply {
        switch error {
        case let ioError as IOError:
            switch ioError.errnoCode {
            case ECONNREFUSED:
                return .connectionRefused
            case ENETUNREACH:
                return .networkUnreachable
            case EHOSTUNREACH, EHOSTDOWN:
                return .hostUnreachable
            case ETIMEDOUT:
                return .ttlExpired
            default:
                return .generalFailure
            }
        case is ChannelError:
            // Channel-level errors from NIO (e.g. connect timeout).
            return .hostUnreachable
        default:
            return .generalFailure
        }
    }

    // MARK: - Pipeline Reconfiguration (Relay Setup)

    /// Replaces the SOCKS5 codec and handshake handler with lightweight
    /// `Socks5RelayHandler` instances on both the client and upstream
    /// channels so raw TCP bytes flow bidirectionally.
    ///
    /// After this method returns the handler is eligible for deallocation —
    /// all captured state lives in the flat‑map chain, not in `self`.
    private func setupRelay(
        clientChannel: Channel,
        remoteChannel: Channel
    ) {

        let clientRelay = Socks5RelayHandler(peerChannel: remoteChannel)
        let remoteRelay = Socks5RelayHandler(peerChannel: clientChannel)

        // Remove the SOCKS5 codec and handshake handler from the client
        // pipeline, then install the relay handlers on both sides.
        //
        // Order matters: remove the handshake handler first so it cannot
        // receive any more `channelRead` events, then strip the codec.
        clientChannel.pipeline.removeHandler(
            name: Socks5PipelineName.handler
        ).flatMap {
            clientChannel.pipeline.removeHandler(
                name: Socks5PipelineName.encoder
            )
        }.flatMap {
            clientChannel.pipeline.removeHandler(
                name: Socks5PipelineName.decoder
            )
        }.flatMap {
            clientChannel.pipeline.addHandler(
                clientRelay,
                name: Socks5PipelineName.relay
            )
        }.flatMap {
            remoteChannel.pipeline.addHandler(
                remoteRelay,
                name: Socks5PipelineName.relay
            )
        }.whenComplete { result in
            switch result {
            case .success:
                // Kick off reads on both channels — everything is wired up.
                clientChannel.read()
                remoteChannel.read()

            case .failure:
                // Pipeline reconfiguration failed — tear both sides down.
                clientChannel.close(mode: .all, promise: nil)
                remoteChannel.close(mode: .all, promise: nil)
            }
        }
    }
}