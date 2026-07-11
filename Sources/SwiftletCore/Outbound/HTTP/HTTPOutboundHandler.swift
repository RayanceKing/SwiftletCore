//===----------------------------------------------------------------------===//
//
//  HTTPOutboundHandler.swift
//  SwiftletCore — HTTP CONNECT / HTTPS Outbound Handler
//
//  A SwiftNIO `ChannelDuplexHandler` that implements the HTTP CONNECT
//  tunnelling method.  On channel activation it sends a standard HTTP
//  CONNECT request, parses the proxy's response, and transitions into
//  raw bidirectional streaming once a `200` status is received.
//
//  HTTPS (TLS‑wrapped CONNECT)
//  ---------------------------
//  Set `isTLSEnabled = true` and ensure that `NIOSSLClientHandler` is
//  inserted **before** this handler in the outbound pipeline.  The
//  CONNECT header flows inside the encrypted TLS tunnel.
//
//  State Machine
//  -------------
//  ```
//  channelActive → .httpConnect ──[CONNECT sent]──► .handshakeResponse
//                                                          │
//                                            [200 received & residue sliced]
//                                                          │
//                                                          ▼
//                                                   .rawStreaming
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Handler

/// A `ChannelDuplexHandler` that performs an HTTP CONNECT handshake and
/// then becomes a transparent bidirectional relay.
///
/// - Important: Not shareable — one instance per outbound channel.
public final class HTTPOutboundHandler: ChannelDuplexHandler,
                                         RemovableChannelHandler,
                                         @unchecked Sendable {

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - State

    public enum State: Sendable, CustomStringConvertible {
        /// CONNECT request has been sent; waiting for the HTTP response.
        case httpConnect
        /// Parsing the proxy's HTTP response, looking for `200`.
        case handshakeResponse
        /// Handshake complete — transparent bidirectional relay.
        case rawStreaming
        /// Irrecoverable error.
        case failed(Error)

        public var description: String {
            switch self {
            case .httpConnect:        return "HTTP_CONNECT"
            case .handshakeResponse:  return "HANDSHAKE_RESPONSE"
            case .rawStreaming:       return "RAW_STREAMING"
            case .failed:             return "FAILED"
            }
        }
    }

    // MARK: - Configuration

    /// Destination host for the CONNECT request.
    private let destinationHost: String
    /// Destination port.
    private let destinationPort: UInt16
    /// Whether this connection is wrapped in TLS (informational — the
    /// caller must configure `NIOSSLClientHandler` in the pipeline).
    public let isTLSEnabled: Bool

    /// Pre‑built CONNECT header string.
    public let connectHeader: String

    // MARK: - Mutable State

    public private(set) var state: State = .httpConnect

    /// Accumulates inbound bytes until the HTTP response is fully received.
    private var handshakeBuffer = Data()

    /// Buffers outbound writes that arrive before `.rawStreaming`.
    private var pendingWrites: [(
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    )] = []

    // MARK: - Initialisation

    /// - Parameters:
    ///   - host: Destination hostname or IP.
    ///   - port: Destination port.
    ///   - tlsEnabled: Whether TLS is configured in the pipeline (default `false`).
    public init(
        host: String,
        port: UInt16,
        tlsEnabled: Bool = false
    ) {
        self.destinationHost = host
        self.destinationPort = port
        self.isTLSEnabled = tlsEnabled
        self.connectHeader = "CONNECT \(host):\(port) HTTP/1.1\r\nHost: \(host)\r\n\r\n"
    }

    // MARK: - Channel Lifecycle

    public func channelActive(context: ChannelHandlerContext) {
        // Flush the CONNECT header as the very first bytes.
        let headerBytes = Array(connectHeader.utf8)
        var buffer = context.channel.allocator.buffer(capacity: headerBytes.count)
        buffer.writeBytes(headerBytes)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)

        state = .handshakeResponse
        context.fireChannelActive()
    }

    // MARK: - Inbound (Read) Path

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Zero‑copy fast‑path for established connections.
        if case .rawStreaming = state {
            context.fireChannelRead(data)
            return
        }

        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        handshakeBuffer.append(contentsOf: bytes)

        if case .handshakeResponse = state {
            handleHandshakeResponse(context: context)
        }
    }

    /// Scans the accumulated buffer for an HTTP `200` status line.
    /// When found, extracts any trailing residue bytes (payload that
    /// arrived after the response headers) and emits them, then
    /// transitions to `.rawStreaming`.
    private func handleHandshakeResponse(context: ChannelHandlerContext) {
        guard let responseString = String(data: handshakeBuffer, encoding: .utf8) else {
            // Non‑UTF‑8 data — cannot parse, continue accumulating.
            return
        }

        // Look for the HTTP status line: "HTTP/1.x 200"
        guard responseString.range(of: "HTTP/") != nil else { return }

        // Find the double‑CRLF that marks end of HTTP headers.
        guard let headerEnd = responseString.range(of: "\r\n\r\n") else {
            // Headers not complete yet — wait for more data.
            return
        }

        let statusPrefix = String(responseString.prefix(20))
        let isSuccess = statusPrefix.contains("200")

        // Calculate where the payload begins (after the double CRLF).
        let headerEndOffset = handshakeBuffer.count
            - responseString[headerEnd.upperBound...].utf8.count

        // Slice out any residue bytes that arrived after the headers.
        let residue: Data
        if headerEndOffset < handshakeBuffer.count {
            residue = handshakeBuffer.subdata(
                in: headerEndOffset ..< handshakeBuffer.count
            )
        } else {
            residue = Data()
        }

        // Discard the handshake buffer.
        handshakeBuffer = Data()

        if isSuccess {
            // Transition to streaming.
            state = .rawStreaming

            // Flush all buffered writes.
            let pending = pendingWrites
            pendingWrites.removeAll()
            for item in pending {
                context.write(item.data, promise: item.promise)
            }
            context.flush()

            // Emit any residue bytes that followed the HTTP response.
            if !residue.isEmpty {
                var out = context.channel.allocator.buffer(
                    capacity: residue.count
                )
                out.writeBytes(residue)
                context.fireChannelRead(wrapInboundOut(out))
            }
        } else {
            fail(context: context,
                 error: HTTPOutboundError.httpStatusNotOK(statusPrefix))
        }
    }

    // MARK: - Outbound (Write) Path

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        switch state {
        case .rawStreaming:
            context.write(data, promise: promise)
        case .httpConnect, .handshakeResponse:
            pendingWrites.append((data, promise))
        case .failed:
            promise?.fail(HTTPOutboundError.connectionFailed)
        }
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        handshakeBuffer = Data()
        pendingWrites.removeAll()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        handshakeBuffer = Data()
        pendingWrites.removeAll()
        context.close(mode: .all, promise: nil)
        context.fireErrorCaught(error)
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        context.close(mode: .all, promise: nil)
    }
}

// MARK: - Errors

public enum HTTPOutboundError: Error, Sendable, Equatable {
    case httpStatusNotOK(String)
    case connectionFailed
}
