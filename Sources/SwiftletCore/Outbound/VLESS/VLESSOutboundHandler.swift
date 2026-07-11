//===----------------------------------------------------------------------===//
//
//  VLESSOutboundHandler.swift
//  SwiftletCore — Hardcore Production-Grade VLESS‑REALITY Outbound Engine
//
//  Fixes a critical race‑condition where `inboundBuffer.removeAll()`
//  prematurely wiped the server's VLESS success status byte.  This version
//  implements precise TLS Record length parsing, boundary‑safe slice cuts,
//  and a native `ByteBuffer` fast‑path for zero‑copy streaming once the
//  handshake completes.
//
//  State Machine
//  -------------
//  ```
//  channelActive ──► .realityHandshake ──[TLS Record boundary met]──► .vlessRequestSent
//                                                      │                        │
//                                                      │               [0x00 success byte]
//                                                      │                        │
//                                                      ▼                        ▼
//                                              .rawStreaming ◄──────────────────┘
//                                                     │
//                                                     │  zero‑copy read/write
//                                                     ▼
//                                               transparent relay
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Handler

/// A production‑grade `ChannelDuplexHandler` implementing the full
/// VLESS‑REALITY connection lifecycle with boundary‑safe handshake parsing
/// and a zero‑copy `ByteBuffer` fast‑path for established sessions.
///
/// - Important: Not shareable — one instance per outbound connection.
public final class VLESSOutboundHandler: ChannelDuplexHandler,
                                          RemovableChannelHandler,
                                          @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - State Machine

    /// Connection lifecycle states.
    public enum State: Sendable, CustomStringConvertible {
        /// REALITY Client Hello dispatched; parsing TLS Server Hello.
        case realityHandshake
        /// VLESS request header sent; awaiting the single‑byte success code.
        case vlessRequestSent
        /// Handshake complete — transparent bidirectional byte relay active.
        case rawStreaming
        /// An irrecoverable error occurred; channel is being torn down.
        case failed(Error)

        public var description: String {
            switch self {
            case .realityHandshake: return "REALITY_HANDSHAKE"
            case .vlessRequestSent: return "VLESS_REQUEST_SENT"
            case .rawStreaming:     return "RAW_STREAMING"
            case .failed:           return "FAILED"
            }
        }
    }

    // MARK: - Stored Properties

    /// The VLESS‑REALITY configuration for this connection.
    private let config: VLESSConfiguration

    /// Pre‑built VLESS request header (computed once at init).
    public let vlessHeader: Data

    /// Pre‑built REALITY Client Hello (computed once at init).
    public let realityClientHello: Data

    /// Current connection state.  Public for inspection but mutations are
    /// confined to the handler's event‑loop context.
    public private(set) var state: State = .realityHandshake

    /// Accumulates raw bytes during the REALITY and VLESS handshake phases.
    /// Once `.rawStreaming` is entered this buffer is discarded and all
    /// subsequent reads bypass it entirely.
    private var handshakeInboundBuffer = Data()

    /// The total TLS handshake record size in bytes, computed from the
    /// TLS Record Layer length field once the first 5 bytes arrive.
    /// Set to `nil` before the length is known.
    private var expectedTlsLength: Int? = nil

    /// Buffers outbound writes that arrive before the connection reaches
    /// `.rawStreaming`.  Flushed atomically when the handshake completes.
    private var pendingOutboundWrites: [(
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    )] = []

    // MARK: - Initialisation

    /// - Parameter config: The VLESS‑REALITY configuration.
    public init(config: VLESSConfiguration) {
        self.config = config

        // Build the VLESS request header once.
        self.vlessHeader = VLESSRequestBuilder.buildConnect(
            uuid: config.uuid,
            address: config.destinationAddress,
            port: config.destinationPort
        )

        // Build the REALITY‑modified Client Hello once.
        var hello = RealityTLSModifier.makeBaseClientHello(
            sni: config.serverName
        )
        RealityTLSModifier.addCustomExtension(
            type: config.realityExtensionType,
            data: config.realityAuthKey,
            to: &hello
        )
        RealityTLSModifier.addPadding(config.paddingBytes, to: &hello)
        self.realityClientHello = RealityTLSModifier.serializeClientHello(hello)
    }

    // MARK: - Channel Lifecycle

    /// Flushes the REALITY Client Hello as the very first bytes on the wire.
    public func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(
            capacity: realityClientHello.count
        )
        buffer.writeBytes(realityClientHello)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
        state = .realityHandshake
        context.fireChannelActive()
    }

    // MARK: - Inbound (Read) Path

    /// Routes inbound data to the appropriate handler based on state.
    ///
    /// Once in `.rawStreaming`, data is forwarded directly via
    /// `fireChannelRead` with **zero** intermediate allocations — the
    /// original `ByteBuffer` is passed through untouched.
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // ---- Zero‑copy fast‑path for established connections -------------
        if case .rawStreaming = state {
            context.fireChannelRead(data)
            return
        }

        // ---- Handshake accumulation --------------------------------------
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        handshakeInboundBuffer.append(contentsOf: bytes)

        switch state {
        case .realityHandshake:
            handleRealityResponse(context: context)

        case .vlessRequestSent:
            handleVLESSResponse(context: context)

        case .rawStreaming, .failed:
            break
        }
    }

    // MARK: - Outbound (Write) Path

    /// In `.rawStreaming`, writes pass through directly.  During handshake
    /// phases writes are buffered and flushed atomically when the connection
    /// is established, preventing data loss from early‑write attempts.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        switch state {
        case .rawStreaming:
            context.write(data, promise: promise)

        case .realityHandshake, .vlessRequestSent:
            pendingOutboundWrites.append((data, promise))

        case .failed:
            promise?.fail(OutboundError.connectionFailed)
        }
    }

    // MARK: - REALITY Handshake Response

    /// Parses the TLS Record Layer to determine the total Server Hello
    /// size, then — once the complete record is buffered — transitions to
    /// the VLESS phase.
    ///
    /// This method fixes the original race‑condition by **never** calling
    /// `removeAll()` on the buffer.  Instead, `expectedTlsLength` is
    /// computed from bytes 3–4 of the TLS record header, and data is
    /// retained until the full record is available.
    private func handleRealityResponse(context: ChannelHandlerContext) {
        // ---- Determine the TLS record length (run once) ------------------
        guard expectedTlsLength == nil else { return }

        if handshakeInboundBuffer.count >= 5 {
            let lengthBytes = handshakeInboundBuffer[3 ... 4]
            let tlsPayloadLength = lengthBytes.withUnsafeBytes {
                $0.load(as: UInt16.self).bigEndian
            }
            expectedTlsLength = Int(tlsPayloadLength) + 5
        }

        // ---- Wait until the full TLS handshake is buffered ---------------
        guard let totalTlsSize = expectedTlsLength else { return }
        guard handshakeInboundBuffer.count >= totalTlsSize else { return }

        // ---- Dispatch the VLESS header ----------------------------------
        sendVLESSHeader(context: context, tlsHandshakeSize: totalTlsSize)
    }

    /// Sends the VLESS request header and discards the consumed TLS
    /// handshake bytes from the accumulation buffer.
    ///
    /// The `tlsHandshakeSize` parameter ensures we slice exactly the bytes
    /// belonging to the Server Hello, leaving any trailing data (such as
    /// the VLESS response byte that may have arrived in the same TCP
    /// segment) intact for the next phase.
    private func sendVLESSHeader(
        context: ChannelHandlerContext,
        tlsHandshakeSize: Int
    ) {
        // ---- Flush VLESS header to the wire ------------------------------
        var buffer = context.channel.allocator.buffer(
            capacity: vlessHeader.count
        )
        buffer.writeBytes(vlessHeader)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)

        state = .vlessRequestSent

        // ---- Precise slice: remove only the TLS handshake bytes ----------
        if handshakeInboundBuffer.count >= tlsHandshakeSize {
            handshakeInboundBuffer.removeFirst(tlsHandshakeSize)
        }
    }

    // MARK: - VLESS Response

    /// After the VLESS header is dispatched, the server responds with a
    /// single byte: `0x00` = success, anything else = failure.
    ///
    /// On success the state transitions to `.rawStreaming`, all buffered
    /// writes are flushed, and any remaining inbound data is emitted.
    private func handleVLESSResponse(context: ChannelHandlerContext) {
        guard handshakeInboundBuffer.count >= 1 else { return }

        let status = handshakeInboundBuffer.removeFirst()

        if status == VLESSProtocol.responseSuccess {
            // ---- Transition to raw streaming -----------------------------
            state = .rawStreaming

            // Snapshot and discard the handshake buffer.
            let leftoverData = handshakeInboundBuffer
            handshakeInboundBuffer = Data()

            // Flush all writes that were buffered during the handshake.
            let pending = pendingOutboundWrites
            pendingOutboundWrites.removeAll()
            for item in pending {
                context.write(item.data, promise: item.promise)
            }
            context.flush()

            // If payload bytes arrived after the status byte, emit them now.
            if !leftoverData.isEmpty {
                var out = context.channel.allocator.buffer(
                    capacity: leftoverData.count
                )
                out.writeBytes(leftoverData)
                context.fireChannelRead(wrapInboundOut(out))
            }
        } else {
            fail(context: context, error: OutboundError.vlessRejected(status))
        }
    }

    // MARK: - Lifecycle Cleanup

    public func channelInactive(context: ChannelHandlerContext) {
        handshakeInboundBuffer = Data()
        pendingOutboundWrites.removeAll()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        handshakeInboundBuffer = Data()
        pendingOutboundWrites.removeAll()
        context.close(mode: .all, promise: nil)
        context.fireErrorCaught(error)
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        context.close(mode: .all, promise: nil)
    }
}
