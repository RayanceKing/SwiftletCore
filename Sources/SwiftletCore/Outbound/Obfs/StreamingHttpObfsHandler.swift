//===----------------------------------------------------------------------===//
//
//  StreamingHttpObfsHandler.swift
//  SwiftletCore — Streaming HTTP Obfuscation Transport
//
//  A high‑performance, non‑blocking HTTP streaming encoder/decoder that
//  wraps every outbound proxy chunk into a valid simulated HTTP POST
//  request and de‑frames inbound HTTP responses back into pristine
//  byte streams.  Required for VMess+HTTP, VLESS+HTTP, and Trojan+HTTP
//  protocol combinations.
//
//  Pipeline placement
//  ------------------
//  ```
//  [Proxy Core] → StreamingHttpObfsHandler → [NIOSSLHandler?] → [TCP]
//  ```
//
//  Outbound (Write) — HTTP POST Wrapping
//  -------------------------------------
//  Every chunk is wrapped in its own HTTP request:
//  ```
//  POST /video/stream HTTP/1.1\r\n
//  Host: {fakeDomain}\r\n
//  Content-Type: application/octet-stream\r\n
//  Content-Length: {chunkLength}\r\n
//  Connection: keep-alive\r\n
//  \r\n
//  {raw proxy encrypted bytes}
//  ```
//
//  Inbound (Read) — HTTP Response De‑framing
//  -----------------------------------------
//  Sequential HTTP responses are parsed, the `Content‑Length` header
//  is extracted, and exactly that many body bytes are sliced out and
//  forwarded upstream.  The HTTP header overhead is discarded.
//
//  State Machine (Inbound)
//  -----------------------
//  ```
//  .scanningForHeader ──[\r\n\r\n found]──► .readingBody(N)
//        ▲                                      │
//        │         [N bytes consumed]            │
//        └──────────────────────────────────────┘
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Streaming HTTP Obfs Handler

/// A `ChannelDuplexHandler` that wraps every outbound data chunk into
/// a simulated HTTP POST request and de‑frames inbound HTTP responses
/// back into raw byte streams.
///
/// Unlike `SimpleObfsHandler` which only prepends a single masquerade
/// header at connection start, this handler continuously frames and
/// de‑frames the stream — each outbound write becomes its own HTTP
/// request, and each inbound response is parsed and stripped.
///
/// - Important: Not shareable — one instance per outbound connection.
public final class StreamingHttpObfsHandler: ChannelDuplexHandler,
                                               RemovableChannelHandler,
                                               @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Configuration

    /// The fake Host header domain (e.g. `"stream.video-cdn.com"`).
    public let host: String

    /// The HTTP request path (default `"/video/stream"`).
    public let path: String

    /// Optional custom User‑Agent header.
    public let userAgent: String?

    // MARK: - Inbound State

    private enum InboundState: Equatable {
        /// Scanning the accumulation buffer for the `\r\n\r\n` header
        /// terminator.
        case scanningForHeader

        /// Header has been parsed; waiting for `contentLength` body
        /// bytes to arrive.
        case readingBody(contentLength: Int)
    }

    private var inboundState: InboundState = .scanningForHeader
    private var inboundAccumulator = ByteBuffer()

    // MARK: - Counters

    /// Number of outbound HTTP chunks written.
    public private(set) var outboundChunksWritten: Int = 0

    /// Number of inbound HTTP responses fully de‑framed.
    public private(set) var inboundResponsesParsed: Int = 0

    /// Total bytes of proxy payload sent (after HTTP wrapping overhead).
    public private(set) var payloadBytesSent: Int = 0

    /// Total bytes of proxy payload received (after HTTP stripping).
    public private(set) var payloadBytesReceived: Int = 0

    // MARK: - Initialisation

    /// Creates a streaming HTTP obfuscation handler.
    ///
    /// - Parameters:
    ///   - host: The fake Host header domain.
    ///   - path: The HTTP request path (default `"/video/stream"`).
    ///   - userAgent: Optional custom User‑Agent (defaults to a
    ///     Chrome‑on‑Windows signature).
    public init(
        host: String,
        path: String = "/video/stream",
        userAgent: String? = nil
    ) {
        self.host = host
        self.path = path
        self.userAgent = userAgent
    }

    // MARK: - Outbound (Write) — HTTP POST Wrapping

    /// Wraps `buffer` in an HTTP POST request and writes it downstream.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var buffer = unwrapOutboundIn(data)
        guard buffer.readableBytes > 0 else {
            context.write(data, promise: promise)
            return
        }

        // Read the raw payload bytes.
        let payloadLen = buffer.readableBytes
        guard let payload = buffer.readBytes(length: payloadLen) else {
            promise?.succeed(())
            return
        }
        let payloadData = Data(payload)

        // Build the HTTP POST header.
        let header = Self.buildPostHeader(
            host: host,
            path: path,
            contentLength: payloadLen,
            userAgent: userAgent
        )

        // Write header + payload in one combined buffer.
        let totalSize = header.count + payloadLen
        var combined = context.channel.allocator.buffer(capacity: totalSize)
        combined.writeBytes(header)
        combined.writeBytes(payloadData)

        outboundChunksWritten += 1
        payloadBytesSent += payloadLen

        context.write(wrapOutboundOut(combined), promise: promise)
    }

    // MARK: - Inbound (Read) — HTTP Response De‑framing

    /// Accumulates inbound bytes and de‑frames complete HTTP responses.
    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        var buffer = unwrapInboundIn(data)
        guard buffer.readableBytes > 0 else { return }

        inboundAccumulator.writeBuffer(&buffer)
        processInboundAccumulator(context: context)
    }

    // MARK: - Inbound Processing Loop

    /// Drains complete HTTP responses from the accumulation buffer.
    /// Partial responses are left in the buffer for the next read.
    private func processInboundAccumulator(context: ChannelHandlerContext) {
        // Use a labelled loop so we can continue processing even when
        // readableBytes drops to 0 mid‑iteration (e.g. after scanning
        // a header with Content‑Length: 0).
        loop: while true {
            switch inboundState {
            case .scanningForHeader:
                guard let contentLength = scanForHeaderEnd() else {
                    return // Need more bytes.
                }
                inboundState = .readingBody(contentLength: contentLength)
                // Fall through to readingBody immediately.

            case .readingBody(let contentLength):
                guard inboundAccumulator.readableBytes >= contentLength else {
                    return // Need more body bytes.
                }

                // Extract exactly Content‑Length bytes of body.
                let body: [UInt8]
                if contentLength == 0 {
                    body = []
                } else {
                    guard let bytes = inboundAccumulator.readBytes(
                        length: contentLength
                    ) else { return }
                    body = bytes
                }

                payloadBytesReceived += contentLength
                inboundResponsesParsed += 1
                inboundState = .scanningForHeader

                // Forward the pristine body upstream (skip empty bodies).
                if contentLength > 0 {
                    var outBuffer = context.channel.allocator.buffer(
                        capacity: contentLength
                    )
                    outBuffer.writeBytes(body)
                    context.fireChannelRead(wrapInboundOut(outBuffer))
                }

                // If we've consumed all readable bytes, stop.
                if inboundAccumulator.readableBytes == 0 { return }
            }
        }
    }

    // MARK: - Header Scanning

    /// Scans the accumulation buffer for `\r\n\r\n` and extracts the
    /// `Content-Length` value from the HTTP response header.
    ///
    /// - Returns: The `Content‑Length` value if the header is complete
    ///   and parseable, or `nil` if more bytes are needed.
    private func scanForHeaderEnd() -> Int? {
        let readable = inboundAccumulator.readableBytes
        guard readable >= 4 else { return nil }

        guard let bytes = inboundAccumulator.getBytes(
            at: inboundAccumulator.readerIndex,
            length: readable
        ) else { return nil }

        // ---- Find \r\n\r\n terminator ---------------------------------
        var headerEnd: Int?
        for i in 0 ... (bytes.count - 4) {
            if bytes[i] == 0x0D, bytes[i+1] == 0x0A,
               bytes[i+2] == 0x0D, bytes[i+3] == 0x0A {
                headerEnd = i + 4
                break
            }
        }

        guard let end = headerEnd else {
            // Safety valve: if we've accumulated over 64 KB without
            // finding the terminator, the stream is malformed.
            if readable > 65536 {
                // Discard and reset to avoid memory exhaustion.
                inboundAccumulator.clear()
                inboundState = .scanningForHeader
            }
            return nil
        }

        // ---- Parse Content-Length from header text --------------------
        let headerBytes = bytes[0 ..< end]
        let headerText = String(decoding: headerBytes, as: UTF8.self)
        let contentLength = Self.parseContentLength(from: headerText)

        // ---- Discard the header block (advance reader) ----------------
        inboundAccumulator.moveReaderIndex(forwardBy: end)

        return contentLength
    }

    // MARK: - Channel Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        inboundAccumulator.clear()
        inboundState = .scanningForHeader
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        inboundAccumulator.clear()
        inboundState = .scanningForHeader
        context.fireErrorCaught(error)
    }

    // MARK: - Static Helpers

    /// Builds an HTTP POST request header for a chunk of `contentLength`
    /// bytes.
    public static func buildPostHeader(
        host: String,
        path: String = "/video/stream",
        contentLength: Int,
        userAgent: String? = nil
    ) -> Data {
        let ua = userAgent
            ?? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

        let header = """
            POST \(path) HTTP/1.1\r
            Host: \(host)\r
            Content-Type: application/octet-stream\r
            Content-Length: \(contentLength)\r
            Connection: keep-alive\r
            User-Agent: \(ua)\r
            \r

            """
        return Data(header.utf8)
    }

    /// Parses the `Content-Length` value from an HTTP response header
    /// string.  Returns 0 if the header is missing or unparseable.
    public static func parseContentLength(from headerText: String) -> Int {
        let lines = headerText.components(separatedBy: "\r\n")
        for line in lines {
            let lower = line.lowercased()
            if lower.hasPrefix("content-length:") {
                let value = line.dropFirst(15)
                    .trimmingCharacters(in: .whitespaces)
                return Int(value) ?? 0
            }
        }
        return 0
    }
}
