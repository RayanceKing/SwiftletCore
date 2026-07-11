//===----------------------------------------------------------------------===//
//
//  Socks5Decoder.swift
//  SwiftletCore — SOCKS5 Frame Decoder
//
//  A `ByteToMessageDecoder` that incrementally parses the two‑phase SOCKS5
//  client handshake (greeting → request) directly from the wire.  It enforces
//  strict RFC 1928 compliance and avoids buffer‑overflow or memory‑leak risks
//  by leveraging SwiftNIO's safe `ByteBuffer` read API exclusively — no raw
//  pointers are used.
//
//  Decoding phases
//  ---------------
//  1. **Greeting**   `[VER=0x05 | NMETHODS | METHODS…]`
//  2. **Request**    `[VER=0x05 | CMD | RSV=0x00 | ATYP | DST.ADDR | DST.PORT]`
//
//  Each successfully parsed message is fired into the pipeline as a
//  `Socks5InboundMessage` so the downstream `Socks5InboundHandler` can
//  implement the state machine without worrying about wire‑format details.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

/// Incremental, two‑phase decoder for the SOCKS5 client handshake.
///
/// This decoder is **not** shareable across channels — it carries mutable
/// parsing state.  A fresh instance must be installed for every inbound
/// connection.
public final class Socks5Decoder: ByteToMessageDecoder, RemovableChannelHandler, @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = Socks5InboundMessage

    // MARK: - Internal Decode State

    /// Tracks which RFC‑1928 frame the decoder is currently expecting.
    private enum Phase {
        case greeting
        case request
    }

    private var phase: Phase = .greeting

    // MARK: - ByteToMessageDecoder

    public func decode(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer
    ) throws -> DecodingState {
        switch phase {
        case .greeting:
            return try decodeGreeting(context: context, buffer: &buffer)
        case .request:
            return try decodeRequest(context: context, buffer: &buffer)
        }
    }

    /// Called when the channel is being closed and there may still be
    /// unprocessed bytes in the accumulator.  We attempt one final decode;
    /// any remaining incomplete data is silently discarded (the connection
    /// is shutting down anyway).
    public func decodeLast(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer
    ) throws -> DecodingState {
        _ = try? decode(context: context, buffer: &buffer)
        return .needMoreData
    }

    // MARK: - Private: Greeting Decode

    /// Wire format:
    /// ```
    /// +----+----------+----------+
    /// |VER | NMETHODS | METHODS  |
    /// +----+----------+----------+
    /// | 1  |    1     | 1 to 255 |
    /// +----+----------+----------+
    /// ```
    private func decodeGreeting(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer
    ) throws -> DecodingState {
        // Need at minimum VER + NMETHODS (2 bytes).
        guard buffer.readableBytes >= 2 else {
            return .needMoreData
        }

        let startIndex = buffer.readerIndex

        // Peek VER — do not consume yet.
        guard let version: UInt8 = buffer.getInteger(at: startIndex) else {
            return .needMoreData
        }
        guard version == Socks5Constants.version else {
            throw Socks5Error.invalidVersion(version)
        }

        // Peek NMETHODS.
        guard let nmethods: UInt8 = buffer.getInteger(at: startIndex + 1) else {
            return .needMoreData
        }

        let totalRequired = 2 + Int(nmethods)
        guard buffer.readableBytes >= totalRequired else {
            return .needMoreData
        }

        // Consume VER + NMETHODS.
        buffer.moveReaderIndex(forwardBy: 2)

        // Read each offered method byte.
        var methods: [Socks5AuthMethod] = []
        methods.reserveCapacity(Int(nmethods))
        for _ in 0 ..< nmethods {
            guard let raw: UInt8 = buffer.readInteger() else {
                return .needMoreData
            }
            // Unrecognised method bytes are mapped to `.noAcceptable` so the
            // downstream handler can properly reject the greeting.
            methods.append(Socks5AuthMethod(rawValue: raw) ?? .noAcceptable)
        }

        // Advance to the next protocol phase.
        phase = .request

        // Deliver the parsed greeting downstream.
        let greeting = Socks5Greeting(methods: methods)
        context.fireChannelRead(wrapInboundOut(.greeting(greeting)))
        return .continue
    }

    // MARK: - Private: Request Decode

    /// Wire format:
    /// ```
    /// +----+-----+-------+------+----------+----------+
    /// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    /// +----+-----+-------+------+----------+----------+
    /// | 1  |  1  | X'00' |  1   | Variable |    2     |
    /// +----+-----+-------+------+----------+----------+
    /// ```
    /// Address lengths:
    ///  - IPv4:   4 bytes → 10 bytes total (4‑byte header + 4‑byte addr + 2‑byte port)
    ///  - Domain:  1 + len →  7 + len bytes total
    ///  - IPv6:  16 bytes → 22 bytes total
    private func decodeRequest(
        context: ChannelHandlerContext,
        buffer: inout ByteBuffer
    ) throws -> DecodingState {
        // Need the 4‑byte fixed header: VER + CMD + RSV + ATYP.
        guard buffer.readableBytes >= 4 else {
            return .needMoreData
        }

        let startIndex = buffer.readerIndex

        // --- VER ----------------------------------------------------------
        guard let version: UInt8 = buffer.getInteger(at: startIndex) else {
            return .needMoreData
        }
        guard version == Socks5Constants.version else {
            throw Socks5Error.invalidVersion(version)
        }

        // --- CMD ----------------------------------------------------------
        guard let commandRaw: UInt8 = buffer.getInteger(at: startIndex + 1) else {
            return .needMoreData
        }
        guard let command = Socks5Command(rawValue: commandRaw) else {
            throw Socks5Error.invalidCommand(commandRaw)
        }

        // --- RSV ----------------------------------------------------------
        guard let reserved: UInt8 = buffer.getInteger(at: startIndex + 2) else {
            return .needMoreData
        }
        guard reserved == Socks5Constants.reserved else {
            throw Socks5Error.invalidReservedField(reserved)
        }

        // --- ATYP ---------------------------------------------------------
        guard let atypRaw: UInt8 = buffer.getInteger(at: startIndex + 3) else {
            return .needMoreData
        }
        guard let atyp = Socks5AddressType(rawValue: atypRaw) else {
            throw Socks5Error.invalidAddressType(atypRaw)
        }

        // Consume the 4‑byte fixed header.
        buffer.moveReaderIndex(forwardBy: 4)

        // --- DST.ADDR + DST.PORT -----------------------------------------

        let target: Socks5Target

        switch atyp {
        case .ipv4:
            // IPv4: 4 address bytes + 2 port bytes.
            guard buffer.readableBytes >= 6 else { return .needMoreData }

            let octets = buffer.readBytes(length: 4)!                // safe — we checked ≥ 6
            let address = octets.map { String($0) }.joined(separator: ".")
            let port    = buffer.readInteger(as: UInt16.self)!       // safe
            target = .ipv4(address: address, port: Int(port))

        case .domainName:
            // Domain: 1 length byte | N domain bytes | 2 port bytes.
            // Minimum total beyond the 4‑byte header = 1 + 1 + 2 = 4 bytes.
            guard buffer.readableBytes >= 1 else { return .needMoreData }

            let domainLenIndex = buffer.readerIndex
            guard let domainLength: UInt8 = buffer.getInteger(at: domainLenIndex) else {
                return .needMoreData
            }
            guard (1 ... 255).contains(domainLength) else {
                throw Socks5Error.invalidDomainLength(Int(domainLength))
            }

            let totalNeeded = 1 + Int(domainLength) + 2   // len byte + name + port
            guard buffer.readableBytes >= totalNeeded else {
                return .needMoreData
            }

            buffer.moveReaderIndex(forwardBy: 1)            // consume length byte
            let domainBytes = buffer.readBytes(length: Int(domainLength))!
            guard let domain = String(bytes: domainBytes, encoding: .utf8) else {
                throw Socks5Error.invalidDomainLength(Int(domainLength))
            }
            let port = buffer.readInteger(as: UInt16.self)!
            target = .domain(name: domain, port: Int(port))

        case .ipv6:
            // IPv6: 16 address bytes + 2 port bytes.
            guard buffer.readableBytes >= 18 else { return .needMoreData }

            let bytes = buffer.readBytes(length: 16)!
            // Format the 16 raw bytes as a compressed IPv6 string.
            let address = Socks5Decoder.formatIPv6(bytes)
            let port    = buffer.readInteger(as: UInt16.self)!
            target = .ipv6(address: address, port: Int(port))
        }

        // Deliver the parsed request downstream.
        let request = Socks5Request(command: command, target: target)
        context.fireChannelRead(wrapInboundOut(.request(request)))
        return .continue
    }

    // MARK: - IPv6 Formatting Helper

    /// Converts 16 raw network‑order bytes into a standard colon‑separated,
    /// zero‑compressed IPv6 string (e.g. `"::1"`, `"fe80::1"`).
    ///
    /// This avoids pulling in a full IP‑address library for a single
    /// formatting operation.
    private static func formatIPv6(_ bytes: [UInt8]) -> String {
        precondition(bytes.count == 16, "IPv6 address must be exactly 16 bytes")

        // Convert to 8 groups of 16‑bit values in network byte order.
        let groups: [UInt16] = stride(from: 0, to: 16, by: 2).map { i in
            (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
        }

        // Find the longest run of consecutive zero groups for `::` compression.
        var bestStart = -1
        var bestLen  = 0
        var curStart = -1
        var curLen   = 0

        for (i, group) in groups.enumerated() {
            if group == 0 {
                if curStart == -1 { curStart = i }
                curLen += 1
            } else {
                if curLen > bestLen {
                    (bestStart, bestLen) = (curStart, curLen)
                }
                curStart = -1
                curLen   = 0
            }
        }
        if curLen > bestLen {
            (bestStart, bestLen) = (curStart, curLen)
        }

        // Only compress runs longer than 1 zero group (per RFC 5952 §4.2.2).
        if bestLen <= 1 {
            // No compression — render all 8 groups.
            return groups.map { String(format: "%x", $0) }.joined(separator: ":")
        }

        var parts: [String] = []

        // Groups before the compressed run.
        if bestStart > 0 {
            for i in 0 ..< bestStart {
                parts.append(String(format: "%x", groups[i]))
            }
        }

        // The `::` compression marker.
        parts.append("")

        // Groups after the compressed run.
        let afterEnd = bestStart + bestLen
        if afterEnd < 8 {
            for i in afterEnd ..< 8 {
                parts.append(String(format: "%x", groups[i]))
            }
        }

        return parts.joined(separator: ":")
    }
}
