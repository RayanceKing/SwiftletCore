//===----------------------------------------------------------------------===//
//
//  TUICClientStreamHandler.swift
//  SwiftletCore — TUIC v5 Per‑Stream Channel Handler
//
//  A SwiftNIO `ChannelInboundHandler` bound to a single QUIC stream
//  channel.  It accumulates raw bytes arriving on the stream, decodes
//  them into TUIC v5 frames, and routes `.packet` payload upstream
//  while handling `.disconnect` for lifecycle teardown.
//
//  Pipeline placement
//  ------------------
//  ```
//  [QUIC Stream] → TUICClientStreamHandler → [TUN2SocksBridge / upper layer]
//  ```
//
//  The handler is **not** shareable — one instance per stream channel.
//
//  Zero‑copy contract
//  ------------------
//  The handler operates on `ByteBuffer` slices.  Accumulated data is
//  appended to an internal buffer; successful frame decodes advance
//  the reader index without copying the original buffer storage.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - TUIC Client Stream Handler

/// Decodes TUIC v5 frames from the byte stream of a single QUIC stream
/// channel and delivers extracted payload data to the upper pipeline.
///
/// ## Frame processing
///
/// | Frame Type | Action |
/// |---|---|
/// | `.authenticate` | Ignored (validated by the manager on the control stream). |
/// | `.connect` | Ignored (per‑stream handler only sees post‑connect data). |
/// | `.packet` | Payload extracted and fired upstream via `fireChannelRead`. |
/// | `.disconnect` | Stream marked as closing; `channelInactive` fired upstream. |
/// | `.heartbeat` | Ignored at stream level. |
///
/// ## Backpressure
///
/// The handler uses `TUICStreamDecoder`'s nil‑on‑incomplete semantics:
/// partial frames are retained in an internal accumulation buffer until
/// enough bytes arrive to complete the decode.  The reader index is
/// never advanced past a complete frame boundary, preventing memory
/// fragmentation in partial‑read scenarios.
public final class TUICClientStreamHandler: ChannelInboundHandler,
                                              RemovableChannelHandler,
                                              @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer

    // MARK: - Configuration

    /// The TUIC session / stream identifier for this stream.
    public let sessionID: UInt16

    // MARK: - Accumulation Buffer

    /// Buffers raw bytes arriving on this stream until a complete TUIC
    /// frame can be decoded.  `TUICStreamDecoder` peeks without consuming,
    /// so partial data is never lost across decode attempts.
    private var accumulationBuffer = ByteBuffer()

    // MARK: - Callbacks

    /// Invoked when a `.packet` frame is decoded and payload data is
    /// ready for the upper layer (e.g. TUN2SocksBridge).
    public var onData: (@Sendable (Data) -> Void)?

    /// Invoked when the stream is being torn down (`.disconnect` frame
    /// received or channel becomes inactive).
    public var onDisconnect: (@Sendable () -> Void)?

    /// Invoked when an error is encountered during frame decoding.
    public var onError: (@Sendable (Error) -> Void)?

    // MARK: - State

    /// Total bytes received on this stream.
    public private(set) var totalBytesReceived: Int = 0

    /// Whether the stream is still active (has not received `.disconnect`
    /// and the channel is still open).
    public private(set) var isActive: Bool = true

    // MARK: - Initialisation

    /// Creates a handler for a single TUIC stream.
    ///
    /// - Parameter sessionID: The TUIC session / stream identifier.
    public init(sessionID: UInt16) {
        self.sessionID = sessionID
    }

    // MARK: - ChannelInboundHandler

    /// Receives raw bytes from the QUIC stream channel.
    ///
    /// Bytes are appended to the internal accumulation buffer and then
    /// decoded frame‑by‑frame.  Any bytes belonging to an incomplete
    /// frame are retained for the next `channelRead` invocation.
    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        var incoming = unwrapInboundIn(data)
        guard incoming.readableBytes > 0 else { return }

        // Append to the accumulation buffer.
        accumulationBuffer.writeBuffer(&incoming)
        totalBytesReceived += accumulationBuffer.readableBytes

        // Drain complete frames.
        processAccumulatedData(context: context)
    }

    // MARK: - Channel Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        isActive = false
        onDisconnect?()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        onError?(error)
        context.fireErrorCaught(error)
    }

    // MARK: - Frame Decoding Loop

    /// Attempts to decode as many complete TUIC frames as possible from
    /// the internal accumulation buffer.  Partial frames are left in
    /// the buffer for the next invocation.
    private func processAccumulatedData(context: ChannelHandlerContext) {
        while accumulationBuffer.readableBytes > 0 {
            let frame: TUICFrame
            do {
                guard let decoded = try TUICStreamDecoder.decodeNextFrame(
                    from: &accumulationBuffer
                ) else {
                    // Incomplete frame — wait for more bytes.
                    return
                }
                frame = decoded
            } catch {
                onError?(error)
                context.fireErrorCaught(error)
                return
            }

            switch frame {
            case .packet(_, let payload):
                // Fire the payload upstream.
                var outBuffer = context.channel.allocator.buffer(
                    capacity: payload.count
                )
                outBuffer.writeBytes(payload)
                context.fireChannelRead(wrapInboundOut(outBuffer))

                // Also notify via callback.
                onData?(payload)

            case .disconnect:
                isActive = false
                onDisconnect?()
                context.fireChannelInactive()
                return

            case .authenticate, .connect, .heartbeat:
                // These frames are not expected on a per‑stream channel;
                // the manager handles them on the control stream.
                break
            }
        }
    }

    // MARK: - Injection (for testing)

    /// Simulates an incoming byte stream by injecting data directly into
    /// the accumulation buffer and decoding it synchronously.
    ///
    /// This bypasses the NIO pipeline for unit‑test convenience.
    ///
    /// - Parameter bytes: Raw TUIC‑framed bytes.
    /// - Returns: Array of decoded payload data from `.packet` frames.
    @discardableResult
    public func simulateIncomingBytes(_ bytes: Data) -> [Data] {
        var buffer = ByteBuffer(bytes: bytes)
        totalBytesReceived += buffer.readableBytes
        accumulationBuffer.writeBuffer(&buffer)

        var extractedPayloads: [Data] = []

        while accumulationBuffer.readableBytes > 0 {
            let frame: TUICFrame?
            do {
                frame = try TUICStreamDecoder.decodeNextFrame(
                    from: &accumulationBuffer
                )
            } catch {
                onError?(error)
                break
            }

            guard let decoded = frame else { break }

            switch decoded {
            case .packet(_, let payload):
                extractedPayloads.append(payload)
                onData?(payload)
            case .disconnect:
                isActive = false
                onDisconnect?()
                return extractedPayloads
            case .authenticate, .connect, .heartbeat:
                break
            }
        }

        return extractedPayloads
    }
}
