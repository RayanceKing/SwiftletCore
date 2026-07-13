//===----------------------------------------------------------------------===//
//
//  gRPCTransportHandler.swift
//  SwiftletCore — HTTP/2 + gRPC Transport Handler
//
//  Performs an HTTP/2 connection handshake, opens a single streaming
//  gRPC‑over‑HTTP/2 stream, injects the `gRPCFrameCodec` into the stream
//  channel pipeline, and welds protocol‑specific handlers (VMess, VLESS,
//  Trojan) above the codec.
//
//  Pipeline Architecture
//  ---------------------
//  ```
//  [TCP Socket]
//    → NIOHTTP2Handler (multiplexer)
//    → HTTP2StreamChannel (created by multiplexer)
//        → gRPCFrameDecoder
//        → gRPCFrameEncoder
//        → Protocol Handler (VMess/VLESS/Trojan)
//  ```
//
//  Thread Safety
//  -------------
//  `gRPCTransportHandler` is a `ChannelInboundHandler` that holds
//  reference‑type state (the multiplexer and stream channel reference)
//  accessed only on the channel's event loop.  Marked `@unchecked Sendable`
//  following the same pattern as `ProxyChannelPoolBridgeHandler`.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
@preconcurrency import NIOHTTP2
@preconcurrency import NIOHPACK
import Foundation

// MARK: - gRPC Transport Configuration

/// Configuration for establishing a gRPC transport stream.
public struct gRPCTransportConfiguration: Sendable {
    /// The gRPC service name used to construct the `:path` pseudo‑header:
    /// `"/<serviceName>/Tun"`.
    public let serviceName: String

    /// The `:authority` pseudo‑header value.  If `nil`, the outbound
    /// connection's `host` is used.
    public let authority: String?

    /// Whether TLS is enabled for the underlying HTTP/2 connection.
    public let tlsEnabled: Bool

    /// TLS SNI override.  If `nil`, the host is used.
    public let sni: String?

    /// Creates a gRPC transport configuration.
    public init(
        serviceName: String,
        authority: String? = nil,
        tlsEnabled: Bool = true,
        sni: String? = nil
    ) {
        self.serviceName = serviceName
        self.authority = authority
        self.tlsEnabled = tlsEnabled
        self.sni = sni
    }
}

// MARK: - gRPC Stream Channel Key

/// Simple handler that completes a promise when its channel becomes active.
/// Used to asynchronously await the HTTP/2 stream channel creation.
internal final class gRPCStreamChannelPromiseHandler: ChannelInboundHandler,
                                                      @unchecked Sendable {
    public typealias InboundIn = Any

    private let promise: EventLoopPromise<Channel>

    init(promise: EventLoopPromise<Channel>) {
        self.promise = promise
    }

    public func channelActive(context: ChannelHandlerContext) {
        promise.succeed(context.channel)
        // Remove ourselves — we're only needed for the activation signal.
        _ = context.pipeline.syncOperations.removeHandler(context: context)
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        promise.fail(error)
    }
}

// MARK: - gRPC Transport Handler

/// A `ChannelInboundHandler` that performs an HTTP/2 connection handshake,
/// creates a gRPC stream, and returns the stream channel via a promise.
///
/// Usage:
/// ```swift
/// let bootstrap = ClientBootstrap(group: group)
///     .channelInitializer { channel in
///         channel.pipeline.addHandler(gRPCTransportHandler(config: config))
///     }
/// let channel = try await bootstrap.connect(host: host, port: port).get()
/// ```
public final class gRPCTransportHandler: ChannelInboundHandler,
                                          @unchecked Sendable {

    public typealias InboundIn = Any
    public typealias OutboundOut = Any

    // MARK: - Configuration

    /// The gRPC transport configuration.
    private let config: gRPCTransportConfiguration

    /// The destination host.
    private let host: String

    /// The destination port.
    private let port: Int

    /// A promise that resolves with the stream `Channel` once the HTTP/2
    /// stream has been opened and the gRPC codec has been installed.
    private let streamChannelPromise: EventLoopPromise<Channel>

    /// The multiplexer, retained for stream creation.
    private var multiplexer: HTTP2StreamMultiplexer?

    // MARK: - Initialisation

    /// - Parameters:
    ///   - config: gRPC transport configuration.
    ///   - host: Destination proxy host.
    ///   - port: Destination proxy port.
    ///   - streamChannelPromise: Fulfilled when the gRPC stream channel is
    ///     ready for protocol handler installation.
    public init(
        config: gRPCTransportConfiguration,
        host: String,
        port: Int,
        streamChannelPromise: EventLoopPromise<Channel>
    ) {
        self.config = config
        self.host = host
        self.port = port
        self.streamChannelPromise = streamChannelPromise
        self.multiplexer = nil
    }

    // MARK: - ChannelInboundHandler

    public func channelActive(context: ChannelHandlerContext) {
        let loop = context.eventLoop

        // ---- 1. Install the HTTP/2 multiplexer ----------------------------
        let multiplexer = HTTP2StreamMultiplexer(mode: .client, channel: context.channel) {
            // This closure is called for each new stream created by the
            // remote peer (server‑push).  We don't expect server‑push in
            // gRPC proxy usage, so we just set up a basic handler.
            streamChannel in
            streamChannel.pipeline.addHandler(NoOpHandler())
        }

        self.multiplexer = multiplexer

        // Extract non-Sendable refs before the @Sendable closure.
        let channel = context.channel

        context.channel.pipeline.addHandler(multiplexer).flatMap {
            // ---- 2. Create the gRPC stream --------------------------------
            self.createGRPCStream(channel: channel, loop: loop)
        }.flatMap { streamChannel in
            // ---- 3. Install gRPC codec on the stream channel ---------------
            streamChannel.pipeline.addGRPCFrameCodec().flatMap {
                // ---- 4. Install the activation promise handler -------------
                streamChannel.pipeline.addHandler(
                    gRPCStreamChannelPromiseHandler(promise: self.streamChannelPromise)
                )
            }
        }.whenFailure { error in
            self.streamChannelPromise.fail(error)
        }

        // Forward the active event up.
        context.fireChannelActive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        streamChannelPromise.fail(error)
        context.fireErrorCaught(error)
    }

    // MARK: - gRPC Stream Creation

    /// Creates a single HTTP/2 stream for gRPC communication using the
    /// configured service name and authority.
    private func createGRPCStream(
        channel: Channel,
        loop: EventLoop
    ) -> EventLoopFuture<Channel> {
        guard let multiplexer = self.multiplexer else {
            return loop.makeFailedFuture(gRPCTransportError.noMultiplexer)
        }

        let authority = config.authority ?? host
        let path = "/\(config.serviceName)/Tun"

        // Create the stream.  The multiplexer's inbound stream initializer
        // configures the pipeline; we just need to activate the stream by
        // sending the gRPC request headers.
        multiplexer.createStreamChannel(promise: streamChannelPromise) { [config] streamChannel in
            let headers = HPACKHeaders([
                (":method",     "POST"),
                (":scheme",     config.tlsEnabled ? "https" : "http"),
                (":path",       path),
                (":authority",  authority),
                ("content-type", "application/grpc"),
                ("te",          "trailers"),
            ])
            // Configure the stream to send headers on active.
            return streamChannel.pipeline.addHandler(
                gRPCStreamHeadersHandler(headers: headers)
            )
        }

        return streamChannelPromise.futureResult
    }
}

// MARK: - Stream Headers Handler

/// Sends the gRPC request HEADERS frame when the stream channel becomes
/// active, then removes itself from the pipeline.
internal final class gRPCStreamHeadersHandler: ChannelInboundHandler,
                                                @unchecked Sendable {
    public typealias InboundIn = Any

    private let headers: HPACKHeaders

    init(headers: HPACKHeaders) {
        self.headers = headers
    }

    public func channelActive(context: ChannelHandlerContext) {
        // Send the HEADERS frame on the stream channel.
        // The NIOHTTP2 layer automatically wraps this into the correct
        // HTTP2Frame for the stream.
        context.writeAndFlush(
            NIOAny(HTTP2Frame(streamID: 0, payload: .headers(.init(headers: headers)))),
            promise: nil
        )
        // Remove ourselves — headers only need to be sent once.
        _ = context.pipeline.syncOperations.removeHandler(context: context)
    }
}

// MARK: - No‑op Handler

/// A minimal handler that does nothing — used for unexpected server‑push
/// streams.
internal final class NoOpHandler: ChannelInboundHandler, @unchecked Sendable {
    public typealias InboundIn = Any
    public init() {}
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {}
}

// MARK: - Errors

public enum gRPCTransportError: Error, Sendable {
    /// The HTTP/2 multiplexer was not initialised before stream creation.
    case noMultiplexer
    /// The gRPC stream channel failed to become active.
    case streamNotActive
    /// The remote peer closed the gRPC stream unexpectedly.
    case streamClosed
}

extension gRPCTransportError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .noMultiplexer:
            return "HTTP/2 multiplexer not initialised"
        case .streamNotActive:
            return "gRPC stream channel did not become active"
        case .streamClosed:
            return "gRPC stream closed by remote peer"
        }
    }
}
