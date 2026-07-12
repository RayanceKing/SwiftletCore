//===----------------------------------------------------------------------===//
//
//  SimpleObfsHandler.swift
//  SwiftletCore — Simple‑Obfs (HTTP / TLS) Streaming Duplex Handler
//
//  Classic stream‑morphing obfuscation that prepends a convincing
//  HTTP request or TLS ClientHello signature onto raw proxy traffic
//  to defeat simple statistical‑pattern firewalls.  The remote
//  obfs server echoes a matching dummy response, which this handler
//  strips before forwarding the pristine inner proxy stream.
//
//  Pipeline placement
//  ------------------
//  ```
//  [Proxy Protocol] → SimpleObfsHandler → [TCP Socket]
//  ```
//
//  Modes
//  -----
//  **HTTP** — Prepends a standard `GET / HTTP/1.1` request with
//  configurable Host header.  Strips the `HTTP/1.1 200 OK` response
//  header block (delimited by `\r\n\r\n`).
//
//  **TLS** — Prepends a synthetic TLS 1.3 ClientHello with the given
//  SNI.  Strips the TLS handshake records from the inbound stream
//  until Application Data (0x17) is encountered, then passes
//  everything through.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Obfs Mode

/// The obfuscation strategy for Simple‑Obfs.
public enum ObfsMode: Sendable, Equatable {
    /// HTTP masquerade — prepend an HTTP request header and strip
    /// the HTTP response header block.
    ///
    /// - Parameter host: The Host header value (e.g. `"www.bing.com"`).
    case http(host: String)

    /// TLS masquerade — prepend a TLS 1.3 ClientHello and strip
    /// TLS handshake records until Application Data appears.
    ///
    /// - Parameter host: The SNI hostname embedded in the ClientHello
    ///   (e.g. `"www.microsoft.com"`).
    case tls(host: String)
}

// MARK: - Simple Obfs Handler

/// A `ChannelDuplexHandler` that implements the Simple‑Obfs
/// obfuscation protocol.
///
/// ## Outbound (Write) Path
/// On the **first** write, the handler synthesises a masquerade
/// header (HTTP request or TLS ClientHello) and writes it *before*
/// the actual payload.  Subsequent writes pass through directly.
///
/// ## Inbound (Read) Path
/// On the **first** read, the handler scans for and strips the
/// dummy response block:
/// - HTTP: finds `\r\n\r\n` and discards the header prefix.
/// - TLS: parses TLS record headers and discards handshake records
///   until Application Data (0x17) is encountered.
///
/// After both the outbound header has been sent and the inbound
/// response has been stripped, the handler enters a zero‑copy
/// passthrough mode for the remainder of the connection.
///
/// - Important: Not shareable — one instance per outbound connection.
public final class SimpleObfsHandler: ChannelDuplexHandler,
                                        RemovableChannelHandler,
                                        @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Configuration

    /// The active obfuscation mode.
    public let mode: ObfsMode

    // MARK: - State

    /// Whether the outbound masquerade header has been sent.
    public private(set) var isHeaderSent: Bool = false

    /// Whether the inbound dummy response has been stripped.
    public private(set) var isResponseStripped: Bool = false

    /// Accumulates inbound bytes until the response header can be
    /// fully stripped.  Discarded once stripping is complete.
    private var inboundAccumulator = ByteBuffer()

    // MARK: - Initialisation

    /// Creates a Simple‑Obfs handler.
    ///
    /// - Parameter mode: The obfuscation strategy (`.http` or `.tls`).
    public init(mode: ObfsMode) {
        self.mode = mode
    }

    // MARK: - Outbound (Write) Path

    /// On the first write, prepends the masquerade header.  Subsequent
    /// writes pass through directly.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var buffer = unwrapOutboundIn(data)

        if !isHeaderSent {
            isHeaderSent = true

            // Build the masquerade header.
            let headerBytes = Self.buildHeader(for: mode)
            let totalSize = headerBytes.count + buffer.readableBytes

            var combined = context.channel.allocator.buffer(capacity: totalSize)
            combined.writeBytes(headerBytes)
            combined.writeBuffer(&buffer)

            context.write(wrapOutboundOut(combined), promise: promise)
        } else {
            context.write(wrapOutboundOut(buffer), promise: promise)
        }
    }

    // MARK: - Inbound (Read) Path

    /// On the first read, strips the dummy response header.  After
    /// stripping is complete, bytes pass through directly.
    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        var buffer = unwrapInboundIn(data)

        if !isResponseStripped {
            inboundAccumulator.writeBuffer(&buffer)
            processInboundAccumulator(context: context)
        } else {
            // Streaming mode — direct passthrough.
            context.fireChannelRead(wrapInboundOut(buffer))
        }
    }

    // MARK: - Inbound Processing

    /// Attempts to strip the response header from the accumulation
    /// buffer.  Once the header boundary is found and removed, any
    /// remaining payload is forwarded upstream and the handler
    /// transitions to streaming mode.
    private func processInboundAccumulator(context: ChannelHandlerContext) {
        switch mode {
        case .http:
            stripHTTPResponse(context: context)

        case .tls:
            stripTLSHandshake(context: context)
        }
    }

    // MARK: - HTTP Response Stripping

    /// Scans for the HTTP header terminator `\r\n\r\n` and removes
    /// everything up to and including it.
    private func stripHTTPResponse(context: ChannelHandlerContext) {
        let readable = inboundAccumulator.readableBytes
        guard readable >= 4 else { return }

        // Search for \r\n\r\n (0x0D 0x0A 0x0D 0x0A).
        guard let bytes = inboundAccumulator.getBytes(
            at: inboundAccumulator.readerIndex,
            length: readable
        ) else { return }

        var headerEnd: Int?
        for i in 0 ... (bytes.count - 4) {
            if bytes[i] == 0x0D, bytes[i+1] == 0x0A,
               bytes[i+2] == 0x0D, bytes[i+3] == 0x0A {
                headerEnd = i + 4
                break
            }
        }

        guard let end = headerEnd else {
            // Edge case: partial response without \r\n\r\n terminator
            // but with enough bytes to be a valid header.  If the
            // buffer is unusually large without the terminator, pass
            // through to avoid deadlock (some servers omit the blank
            // line on error responses).
            if readable > 8192 {
                // Safety valve: after 8 KB without finding the
                // terminator, assume no header and pass through.
                let data = inboundAccumulator
                inboundAccumulator.clear()
                isResponseStripped = true
                if data.readableBytes > 0 {
                    context.fireChannelRead(wrapInboundOut(data))
                }
            }
            return
        }

        // Advance past the header block.
        inboundAccumulator.moveReaderIndex(forwardBy: end)
        isResponseStripped = true

        // Forward any remaining payload after the header.
        let remainingBytes = inboundAccumulator.readableBytes
        if remainingBytes > 0 {
            if let remaining = inboundAccumulator.readSlice(
                length: remainingBytes
            ) {
                inboundAccumulator.clear()
                context.fireChannelRead(wrapInboundOut(remaining))
            }
        }
    }

    // MARK: - TLS Handshake Stripping

    /// Parses TLS record headers from the accumulation buffer and
    /// discards handshake records until the first Application Data
    /// (0x17) record is found, then forwards everything from that
    /// point onward.
    private func stripTLSHandshake(context: ChannelHandlerContext) {
        while inboundAccumulator.readableBytes >= 5 {
            guard let contentType: UInt8 = inboundAccumulator.getInteger(
                at: inboundAccumulator.readerIndex
            ) else { return }

            guard let recordLength: UInt16 = inboundAccumulator.getInteger(
                at: inboundAccumulator.readerIndex + 3,
                endianness: .big,
                as: UInt16.self
            ) else { return }

            let totalRecord = 5 + Int(recordLength)
            guard inboundAccumulator.readableBytes >= totalRecord else {
                // Incomplete record — wait for more data.
                return
            }

            if contentType == TLSRecord.contentTypeApplicationData {
                // Found the first Application Data record.
                // Skip the 5‑byte record header and extract the
                // inner payload.  Everything after this record
                // (including any subsequent App Data or raw bytes)
                // is also real data.
                isResponseStripped = true

                // Advance past the 5‑byte TLS record header.
                inboundAccumulator.moveReaderIndex(forwardBy: 5)

                // Forward everything from here (App Data payload
                // plus any trailing data).
                let remaining = inboundAccumulator.readableBytes
                if remaining > 0 {
                    if let forward = inboundAccumulator.readSlice(
                        length: remaining
                    ) {
                        inboundAccumulator.clear()
                        context.fireChannelRead(wrapInboundOut(forward))
                    }
                }
                return
            }

            // Discard this handshake record and continue scanning.
            inboundAccumulator.moveReaderIndex(forwardBy: totalRecord)
        }
    }

    // MARK: - Channel Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        inboundAccumulator.clear()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        inboundAccumulator.clear()
        context.fireErrorCaught(error)
    }

    // MARK: - Header Builders

    /// Builds the masquerade header bytes for the configured mode.
    public static func buildHeader(for mode: ObfsMode) -> Data {
        switch mode {
        case .http(let host):
            return buildHTTPHeader(host: host)
        case .tls(let host):
            return buildTLSClientHello(host: host)
        }
    }

    /// Builds a synthetic HTTP/1.1 GET request header.
    private static func buildHTTPHeader(host: String) -> Data {
        let header = """
            GET / HTTP/1.1\r
            Host: \(host)\r
            User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r
            Accept: */*\r
            Connection: keep-alive\r
            \r

            """
        return Data(header.utf8)
    }

    /// Builds a synthetic TLS 1.3 ClientHello with the given SNI.
    private static func buildTLSClientHello(host: String) -> Data {
        var hello = RealityTLSModifier.makeBaseClientHello(sni: host)
        RealityTLSModifier.addPadding(Int.random(in: 32 ... 128), to: &hello)
        return RealityTLSModifier.serializeClientHello(hello)
    }

    // MARK: - Diagnostic

    /// Whether the handler is in full streaming mode (header sent
    /// and response stripped).
    public var isStreaming: Bool {
        isHeaderSent && isResponseStripped
    }
}
