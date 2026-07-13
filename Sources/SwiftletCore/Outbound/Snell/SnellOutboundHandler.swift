//===----------------------------------------------------------------------===//
//
//  SnellOutboundHandler.swift
//  SwiftletCore — Snell v4 Outbound Protocol Handler
//
//  A `ChannelDuplexHandler` that implements the Snell v4 client‑side
//  protocol state machine.  On channel activation it synthesises the
//  Snell handshake frame (nonce + encrypted metadata), transitions
//  through a handshake‑verification phase, and then enters a streaming
//  encrypt/decrypt forwarding mode.
//
//  State Machine
//  -------------
//  ```
//          channelActive
//               │
//     ┌─────────▼─────────┐
//     │   .handshaking     │  → send nonce + encrypted metadata
//     └─────────┬─────────┘
//               │ server response received
//     ┌─────────▼─────────┐
//     │   .forwarding      │  → encrypt outbound, decrypt inbound
//     └─────────┬─────────┘
//               │ channel inactive
//     ┌─────────▼─────────┐
//     │   .closed          │
//     └───────────────────┘
//  ```
//
//  Pipeline Placement
//  ------------------
//  ```
//  [TCP Socket]
//    → ProxyChannelPoolBridgeHandler
//    → SnellOutboundHandler  ◄── this handler
//    → [Per‑Session Relay]
//  ```
//
//  Thread Safety
//  -------------
//  `SnellOutboundHandler` is a `ChannelDuplexHandler` marked
//  `@unchecked Sendable`.  All mutable state is accessed exclusively
//  on the channel's event loop.  No locks are required.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Connection State

/// Internal state machine for the Snell v4 client protocol.
private enum SnellConnectionState: Sendable {
    /// Awaiting the server's handshake verification.
    case handshaking
    /// Streaming session — all data is encrypted/decrypted.
    case forwarding
    /// Session terminated.
    case closed
}

// MARK: - Snell Outbound Handler

/// A `ChannelDuplexHandler` that drives the Snell v4 client protocol.
///
/// ## Usage
/// ```swift
/// let handler = SnellOutboundHandler(
///     host: "target.example.com",
///     port: 443,
///     psk: "my-shared-secret"
/// )
/// channel.pipeline.addHandler(handler, name: "snell")
/// ```
public final class SnellOutboundHandler: ChannelDuplexHandler,
                                          @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Configuration

    /// Target hostname or IP address to connect to through the proxy.
    private let host: String

    /// Target port.
    private let port: UInt16

    /// Pre‑shared key for session key derivation.
    private let psk: String

    // MARK: - State

    /// The current Snell session (nonce + derived key + counters).
    private var session: SnellSession?

    /// Internal connection state machine.
    private var state: SnellConnectionState = .handshaking

    /// Accumulator for inbound handshake response bytes.
    private var handshakeBuffer: ByteBuffer?

    // MARK: - Initialisation

    /// - Parameters:
    ///   - host: Target hostname or IP address.
    ///   - port: Target port.
    ///   - psk: Pre‑shared key string.
    public init(host: String, port: UInt16, psk: String) {
        self.host = host
        self.port = port
        self.psk = psk
    }

    // MARK: - ChannelInboundHandler

    public func channelActive(context: ChannelHandlerContext) {
        // ---- 1. Create the Snell session ---------------------------------
        let (nonce, newSession) = SnellCryptoEngine.newSession(psk: psk)
        self.session = newSession

        // ---- 2. Build and send the handshake frame -----------------------
        do {
            let handshakeFrame = try SnellCryptoEngine.buildEncryptedMetadata(
                host: host,
                port: port,
                command: snellCommandConnect,
                session: newSession
            )

            var outbound = context.channel.allocator.buffer(
                capacity: handshakeFrame.count
            )
            outbound.writeBytes(handshakeFrame)
            context.writeAndFlush(wrapOutboundOut(outbound), promise: nil)
        } catch {
            context.fireErrorCaught(error)
            context.close(mode: .all, promise: nil)
            return
        }

        // ---- 3. Enable inbound reads ------------------------------------
        context.read()
        context.fireChannelActive()
    }

    /// Processes inbound data.  During handshaking, accumulates bytes until
    /// the server response is complete, then verifies it.  During forwarding,
    /// decrypts and fires the plaintext up the pipeline.
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        switch state {
        case .handshaking:
            // Accumulate handshake response bytes.
            if var buf = handshakeBuffer {
                buf.writeBuffer(&incoming)
                handshakeBuffer = buf
            } else {
                handshakeBuffer = incoming
            }

            // Try to verify the handshake response.
            processHandshakeResponse(context: context)

        case .forwarding:
            // Decrypt and forward.
            do {
                guard let ses = session else {
                    context.close(mode: .all, promise: nil)
                    return
                }
                let cipherBytes = incoming.readBytes(length: incoming.readableBytes) ?? []
                let plaintext = try ses.decrypt(ciphertext: Data(cipherBytes))
                var out = context.channel.allocator.buffer(capacity: plaintext.count)
                out.writeBytes(plaintext)
                context.fireChannelRead(wrapInboundOut(out))
            } catch {
                context.fireErrorCaught(error)
            }

        case .closed:
            break
        }
    }

    /// Propagates writability changes only while forwarding.
    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        if case .forwarding = state {
            context.fireChannelWritabilityChanged()
        }
    }

    /// Cleans up session state on channel close.
    public func channelInactive(context: ChannelHandlerContext) {
        state = .closed
        session = nil
        handshakeBuffer = nil
        context.fireChannelInactive()
    }

    /// Propagates errors to the pipeline.
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .closed
        context.fireErrorCaught(error)
    }

    // MARK: - ChannelOutboundHandler

    /// Encrypts outbound payloads during the forwarding state.
    /// During handshaking, the initial frame has already been written
    /// by `channelActive`, so outbound writes are buffered or dropped.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        switch state {
        case .handshaking:
            // Buffer outbound writes until the handshake completes.
            // In practice, the TUN bridge won't write until the
            // connection is established upstream.  Drop with warning.
            promise?.fail(SnellHandlerError.notConnected)

        case .forwarding:
            var payload = unwrapOutboundIn(data)
            do {
                guard let ses = session else {
                    promise?.fail(SnellHandlerError.notConnected)
                    return
                }
                let encrypted = try ses.encrypt(
                    buffer: &payload,
                    allocator: context.channel.allocator
                )
                context.write(wrapOutboundOut(encrypted), promise: promise)
            } catch {
                promise?.fail(error)
            }

        case .closed:
            promise?.fail(SnellHandlerError.notConnected)
        }
    }

    // MARK: - Handshake Processing

    /// Attempts to verify the accumulated handshake response.
    ///
    /// The server response is: `ciphertext(8 bytes) || tag(16 bytes)` = 24 bytes.
    /// Once verified, transitions to `.forwarding` and fires any buffered
    /// inbound data.
    private func processHandshakeResponse(context: ChannelHandlerContext) {
        guard let buf = handshakeBuffer, let ses = session else { return }

        // The Snell v4 server response is 24 bytes (8 bytes ciphertext + 16 byte tag).
        let responseLength = 24
        guard buf.readableBytes >= responseLength else {
            // Still waiting for more bytes.
            return
        }

        var bufferCopy = buf
        guard let responseBytes = bufferCopy.readBytes(length: responseLength) else {
            return
        }

        do {
            let success = try SnellCryptoEngine.verifyHandshakeResponse(
                data: Data(responseBytes),
                session: ses
            )
            guard success else {
                context.fireErrorCaught(SnellHandlerError.handshakeRejected)
                context.close(mode: .all, promise: nil)
                return
            }

            // Handshake verified — transition to forwarding.
            state = .forwarding

            // If there are remaining bytes after the handshake response,
            // decrypt and forward them.
            if bufferCopy.readableBytes > 0 {
                handshakeBuffer = bufferCopy
                let remaining = bufferCopy.readBytes(length: bufferCopy.readableBytes) ?? []
                let plaintext = try ses.decrypt(ciphertext: Data(remaining))
                var out = context.channel.allocator.buffer(capacity: plaintext.count)
                out.writeBytes(plaintext)
                context.fireChannelRead(wrapInboundOut(out))
            }

            handshakeBuffer = nil

        } catch {
            context.fireErrorCaught(error)
            context.close(mode: .all, promise: nil)
        }
    }
}

// MARK: - Errors

public enum SnellHandlerError: Error, Sendable {
    /// Attempted to write before the handshake completed.
    case notConnected
    /// The server rejected the handshake.
    case handshakeRejected
    /// The session was nil when it should have been present.
    case noSession
}

extension SnellHandlerError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .notConnected:
            return "Snell: not connected (handshake not complete)"
        case .handshakeRejected:
            return "Snell: handshake rejected by server"
        case .noSession:
            return "Snell: session not initialised"
        }
    }
}
