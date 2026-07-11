//===----------------------------------------------------------------------===//
//
//  HTTPInboundHandler.swift
//  SwiftletCore — HTTP CONNECT Inbound Proxy Server
//
//  A SwiftNIO `ChannelInboundHandler` that implements the server side of
//  the HTTP CONNECT tunnelling method (RFC 7231 §4.3.6).  It parses the
//  client's CONNECT request, extracts the target host and port, responds
//  with `HTTP/1.1 200 Connection Established`, and transitions into a
//  zero‑copy raw‑streaming relay.
//
//  Pipeline placement
//  ------------------
//  ```
//  [Local client] → HTTPInboundHandler → [RoutingEngine] → [Outbound]
//  ```
//  After the 200 response is flushed, this handler becomes a transparent
//  pass‑through so raw TCP bytes flow bidirectionally without framing.
//
//  State Machine
//  -------------
//  ```
//  channelRead → .parsingConnect ──[CONNECT parsed + 200 sent]──► .rawStreaming
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Parse Result

/// The extracted target from a CONNECT request.
public struct HTTPConnectTarget: Sendable, Equatable {
    /// Destination hostname or IP.
    public let host: String
    /// Destination port.
    public let port: UInt16
}

// MARK: - Handler

/// Parses an HTTP CONNECT request from a local client, responds with a
/// 200 status, and then becomes a transparent pass‑through relay.
///
/// - Important: Not shareable — one instance per inbound channel.
public final class HTTPInboundHandler: ChannelInboundHandler,
                                        RemovableChannelHandler,
                                        @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer

    // MARK: - State

    public enum State: Sendable, CustomStringConvertible {
        /// Accumulating bytes, looking for a complete CONNECT request.
        case parsingConnect
        /// CONNECT parsed and 200 sent — transparent pass‑through active.
        case rawStreaming
        /// Irrecoverable error.
        case failed(Error)

        public var description: String {
            switch self {
            case .parsingConnect: return "PARSING_CONNECT"
            case .rawStreaming:   return "RAW_STREAMING"
            case .failed:         return "FAILED"
            }
        }
    }

    // MARK: - Stored Properties

    public private(set) var state: State = .parsingConnect

    /// Accumulates raw bytes until the double‑CRLF is found.
    private var parseBuffer = Data()

    /// The parsed CONNECT target (set once parsing completes).
    public private(set) var connectTarget: HTTPConnectTarget?

    /// Maximum number of bytes to accumulate before giving up (prevents
    /// memory exhaustion from a misbehaving client).  8 KiB is more than
    /// enough for a well‑formed CONNECT header.
    private static let maxParseBytes = 8192

    // MARK: - ChannelInboundHandler

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        // Zero‑copy pass‑through once streaming is active.
        if case .rawStreaming = state {
            context.fireChannelRead(data)
            return
        }

        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        parseBuffer.append(contentsOf: bytes)

        // Safety valve: reject oversized headers.
        guard parseBuffer.count <= Self.maxParseBytes else {
            fail(context: context,
                 error: HTTPInboundError.headerTooLarge(parseBuffer.count))
            return
        }

        if case .parsingConnect = state {
            handleParsing(context: context)
        }
    }

    // MARK: - Parsing

    /// Scans the accumulated buffer for a complete CONNECT request.
    /// When found, extracts the target, sends the 200 response, and
    /// transitions to `.rawStreaming`.
    private func handleParsing(context: ChannelHandlerContext) {
        // We need the complete request line + headers terminated by \r\n\r\n.
        guard let headerEnd = parseBuffer.range(of: Data("\r\n\r\n".utf8)) else {
            return // wait for more data
        }

        let headerData = parseBuffer.subdata(in: 0 ..< headerEnd.lowerBound)
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            fail(context: context,
                 error: HTTPInboundError.invalidUTF8)
            return
        }

        // Parse the request line: "CONNECT host:port HTTP/1.1"
        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            fail(context: context,
                 error: HTTPInboundError.missingRequestLine)
            return
        }

        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            fail(context: context,
                 error: HTTPInboundError.invalidRequestLine(requestLine))
            return
        }

        let method = parts[0].uppercased()
        guard method == "CONNECT" else {
            fail(context: context,
                 error: HTTPInboundError.unsupportedMethod(method))
            return
        }

        let target = parts[1]
        let hostPort = target.components(separatedBy: ":")
        guard hostPort.count == 2,
              let port = UInt16(hostPort[1]) else {
            fail(context: context,
                 error: HTTPInboundError.invalidTarget(target))
            return
        }

        let connectTarget = HTTPConnectTarget(
            host: hostPort[0],
            port: port
        )
        self.connectTarget = connectTarget

        // ---- Slice residue bytes (payload after \r\n\r\n) ---------------
        let residueStart = headerEnd.upperBound
        let residue: Data
        if residueStart < parseBuffer.count {
            residue = parseBuffer.subdata(
                in: residueStart ..< parseBuffer.count
            )
        } else {
            residue = Data()
        }

        // Discard the parse buffer.
        parseBuffer = Data()

        // ---- Send 200 response ------------------------------------------
        let response = "HTTP/1.1 200 Connection Established\r\n\r\n"
        var out = context.channel.allocator.buffer(
            capacity: response.utf8.count
        )
        out.writeString(response)
        context.writeAndFlush(wrapInboundOut(out), promise: nil)

        // ---- Transition to raw streaming --------------------------------
        state = .rawStreaming

        // If the client sent payload bytes immediately after the CONNECT
        // header (pipelining), emit them now.
        if !residue.isEmpty {
            var residueBuf = context.channel.allocator.buffer(
                capacity: residue.count
            )
            residueBuf.writeBytes(residue)
            context.fireChannelRead(wrapInboundOut(residueBuf))
        }
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        parseBuffer = Data()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        parseBuffer = Data()
        context.close(mode: .all, promise: nil)
        context.fireErrorCaught(error)
    }

    // MARK: - Testing Hook

    /// Internal hook that mirrors `channelRead`'s accumulation + parsing
    /// without requiring a full `ChannelHandlerContext`.  Used by unit
    /// tests to exercise the parsing state machine directly.
    func simulateIncomingBytes(_ data: Data) {
        guard case .parsingConnect = state else { return }
        parseBuffer.append(contentsOf: data)

        guard parseBuffer.count <= Self.maxParseBytes else {
            state = .failed(HTTPInboundError.headerTooLarge(parseBuffer.count))
            return
        }

        // Attempt to parse.
        guard let headerEnd = parseBuffer.range(of: Data("\r\n\r\n".utf8)) else {
            return
        }

        let headerData = parseBuffer.subdata(in: 0 ..< headerEnd.lowerBound)
        guard let headerString = String(data: headerData, encoding: .utf8) else {
            state = .failed(HTTPInboundError.invalidUTF8)
            return
        }

        let lines = headerString.components(separatedBy: "\r\n")
        guard let requestLine = lines.first else {
            state = .failed(HTTPInboundError.missingRequestLine)
            return
        }

        let parts = requestLine.components(separatedBy: " ")
        guard parts.count >= 2 else {
            state = .failed(HTTPInboundError.invalidRequestLine(requestLine))
            return
        }

        let method = parts[0].uppercased()
        guard method == "CONNECT" else {
            state = .failed(HTTPInboundError.unsupportedMethod(method))
            return
        }

        let target = parts[1]
        let hostPort = target.components(separatedBy: ":")
        guard hostPort.count == 2, let port = UInt16(hostPort[1]) else {
            state = .failed(HTTPInboundError.invalidTarget(target))
            return
        }

        let connectTarget = HTTPConnectTarget(host: hostPort[0], port: port)
        self.connectTarget = connectTarget

        // Discard parse buffer and transition.
        parseBuffer = Data()
        state = .rawStreaming
    }

    private func fail(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        context.close(mode: .all, promise: nil)
    }
}

// MARK: - Errors

public enum HTTPInboundError: Error, Sendable, Equatable {
    case headerTooLarge(Int)
    case invalidUTF8
    case missingRequestLine
    case invalidRequestLine(String)
    case unsupportedMethod(String)
    case invalidTarget(String)
}
