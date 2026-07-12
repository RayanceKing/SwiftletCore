//===----------------------------------------------------------------------===//
//
//  TUICStreamDecoder.swift
//  SwiftletCore — TUIC v5 Stream‑Multiplexing Frame Decoder
//
//  A boundary‑safe, memory‑efficient decoder that parses complete
//  TUIC v5 frames from a SwiftNIO `ByteBuffer`.  It is designed for
//  the QUIC‑stream receive path where datagram boundaries may not
//  align with frame boundaries — partial reads return `nil` cleanly
//  so the caller can accumulate more bytes without losing state.
//
//  Safety guarantees
//  -----------------
//  • **Peek‑before‑consume**: header fields are inspected via
//    `getInteger(at:)` / `getBytes(at:length:)` without advancing
//    the reader index.  Only when the full frame is known to be
//    present are bytes consumed.
//  • **Nil‑on‑incomplete**: returns `nil` (not a thrown error) when
//    the buffer contains fewer bytes than the minimum frame size or
//    the variable‑length payload.
//  • **Strict type validation**: unknown frame type bytes throw
//    `TUICFrameParseError.invalidFrameType`.
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

// MARK: - TUIC Stream Decoder

/// Parses TUIC v5 frames from a `ByteBuffer` with strict boundary
/// enforcement and nil‑on‑insufficient‑data semantics.
public enum TUICStreamDecoder {

    // MARK: - Public API

    /// Attempts to decode a single complete TUIC v5 frame from `buffer`.
    ///
    /// The decoder peeks at the frame header to determine how many bytes
    /// are needed, and **only consumes bytes from the buffer if the
    /// entire frame is present**.  This means:
    ///
    /// - Returns `nil` when more bytes are needed (no side effects).
    /// - Returns a `TUICFrame` and advances `readerIndex` on success.
    /// - Throws `TUICFrameParseError` for irrecoverable protocol errors
    ///   (invalid type byte, malformed address).
    ///
    /// - Parameter buffer: The accumulation buffer (mutated in‑place on
    ///   successful decode only).
    /// - Returns: A parsed frame, or `nil` if data is insufficient.
    /// - Throws: `TUICFrameParseError` on unrecoverable framing errors.
    public static func decodeNextFrame(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        let available = buffer.readableBytes

        // ---- Need at least 1 byte for the type tag ------------------------
        guard available >= 1 else { return nil }

        guard let typeByte: UInt8 = buffer.getInteger(at: buffer.readerIndex)
        else { return nil }

        guard let frameType = TUICFrameType(rawValue: typeByte) else {
            throw TUICFrameParseError.invalidFrameType(typeByte)
        }

        switch frameType {
        case .authenticate:
            return try decodeAuthenticate(from: &buffer)

        case .connect:
            return try decodeConnect(from: &buffer)

        case .packet:
            return try decodePacket(from: &buffer)

        case .disconnect:
            return try decodeDisconnect(from: &buffer)

        case .heartbeat:
            return try decodeHeartbeat(from: &buffer)
        }
    }

    // MARK: - Authenticate (0x00)

    /// Decodes a fixed‑size Authenticate frame.
    ///
    /// Requires exactly 18 bytes: type(1) + uuid(16) + udpMode(1).
    private static func decodeAuthenticate(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        guard buffer.readableBytes >= TUICFrameEncoder.authenticateSize else {
            return nil
        }

        // ---- Consume type byte --------------------------------------------
        buffer.moveReaderIndex(forwardBy: 1)

        // ---- Read UUID (16 raw bytes) -------------------------------------
        guard let uuidBytes = buffer.readBytes(length: 16) else {
            return nil
        }

        let uuidTuple: uuid_t = (
            uuidBytes[0],  uuidBytes[1],  uuidBytes[2],  uuidBytes[3],
            uuidBytes[4],  uuidBytes[5],  uuidBytes[6],  uuidBytes[7],
            uuidBytes[8],  uuidBytes[9],  uuidBytes[10], uuidBytes[11],
            uuidBytes[12], uuidBytes[13], uuidBytes[14], uuidBytes[15]
        )
        let uuid = UUID(uuid: uuidTuple)

        // ---- Read UDP Mode ------------------------------------------------
        guard let udpMode: UInt8 = buffer.readInteger() else {
            return nil
        }

        return .authenticate(uuid: uuid, udpMode: udpMode)
    }

    // MARK: - Connect (0x01)

    /// Decodes a variable‑length Connect frame.
    ///
    /// Layout: `[type] [addrType] [addr bytes] [port]`.
    ///
    /// The address length depends on `addrType`:
    /// - `ipv4`  → 4 bytes → minimum frame = 8 bytes
    /// - `ipv6`  → 16 bytes → minimum frame = 20 bytes
    /// - `domain` → 1‑byte length prefix + N bytes → minimum = 5 + N
    private static func decodeConnect(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        let base = buffer.readerIndex
        let available = buffer.readableBytes

        // ---- Peek address type (byte 1) -----------------------------------
        guard available >= 2 else { return nil }
        guard let addrTypeRaw: UInt8 = buffer.getInteger(at: base + 1)
        else { return nil }

        guard let addrType = TUICAddressType(rawValue: addrTypeRaw) else {
            throw TUICFrameParseError.invalidAddressType(addrTypeRaw)
        }

        // ---- Determine total frame size -----------------------------------
        let requiredBytes: Int
        switch addrType {
        case .ipv4:
            requiredBytes = 8  // type(1) + addrType(1) + ipv4(4) + port(2)

        case .ipv6:
            requiredBytes = 20 // type(1) + addrType(1) + ipv6(16) + port(2)

        case .domain:
            // Need at least 3 bytes to read domain length.
            guard available >= 3 else { return nil }
            guard let domainLen: UInt8 = buffer.getInteger(at: base + 2)
            else { return nil }
            requiredBytes = 5 + Int(domainLen) // type(1) + addrType(1) + len(1) + domain + port(2)
        }

        guard available >= requiredBytes else { return nil }

        // ---- Consume the complete frame -----------------------------------
        // Advance past type byte.
        buffer.moveReaderIndex(forwardBy: 1)

        // Read address type byte.
        guard let _: UInt8 = buffer.readInteger() else { return nil }
        // (addrTypeRaw was already validated above)

        // Read address.
        let address: String
        switch addrType {
        case .ipv4:
            guard let raw = buffer.readBytes(length: 4) else { return nil }
            address = "\(raw[0]).\(raw[1]).\(raw[2]).\(raw[3])"

        case .ipv6:
            guard let raw = buffer.readBytes(length: 16) else { return nil }
            address = formatIPv6(raw)

        case .domain:
            guard let domainLen: UInt8 = buffer.readInteger() else { return nil }
            guard let domainBytes = buffer.readBytes(length: Int(domainLen))
            else { return nil }
            address = String(decoding: domainBytes, as: UTF8.self)
        }

        // Read port (big‑endian).
        guard let port: UInt16 = buffer.readInteger(endianness: .big)
        else { return nil }

        return .connect(addressType: addrType, address: address, port: port)
    }

    // MARK: - Packet (0x02)

    /// Decodes a variable‑length Packet frame.
    ///
    /// Layout: `[type] [sessionID BE-UInt16] [length BE-UInt16] [payload]`.
    ///
    /// Minimum frame = 5 bytes (header only, empty payload).
    private static func decodePacket(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        let base = buffer.readerIndex
        let available = buffer.readableBytes

        // ---- Peek payload length (bytes 3‑4) ------------------------------
        guard available >= TUICFrameEncoder.packetHeaderSize else {
            return nil
        }
        guard let payloadLen: UInt16 = buffer.getInteger(
            at: base + 3, endianness: .big, as: UInt16.self
        ) else { return nil }

        let totalRequired = TUICFrameEncoder.packetHeaderSize + Int(payloadLen)
        guard available >= totalRequired else { return nil }

        // ---- Consume header -----------------------------------------------
        buffer.moveReaderIndex(forwardBy: 1) // skip type

        guard let sessionID: UInt16 = buffer.readInteger(endianness: .big)
        else { return nil }
        guard let _: UInt16 = buffer.readInteger(endianness: .big)
        else { return nil } // length field (already validated)

        // ---- Read payload -------------------------------------------------
        guard let payload = buffer.readBytes(length: Int(payloadLen))
        else { return nil }

        return .packet(sessionID: sessionID, payload: Data(payload))
    }

    // MARK: - Disconnect (0x03)

    /// Decodes a fixed‑size Disconnect frame.
    ///
    /// Requires exactly 3 bytes: type(1) + sessionID(2).
    private static func decodeDisconnect(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        guard buffer.readableBytes >= TUICFrameEncoder.disconnectSize else {
            return nil
        }

        buffer.moveReaderIndex(forwardBy: 1) // skip type

        guard let sessionID: UInt16 = buffer.readInteger(endianness: .big)
        else { return nil }

        return .disconnect(sessionID: sessionID)
    }

    // MARK: - Heartbeat (0x04)

    /// Decodes a fixed‑size Heartbeat frame.
    ///
    /// Requires exactly 1 byte: the type tag itself.
    private static func decodeHeartbeat(
        from buffer: inout ByteBuffer
    ) throws -> TUICFrame? {
        guard buffer.readableBytes >= TUICFrameEncoder.heartbeatSize else {
            return nil
        }

        buffer.moveReaderIndex(forwardBy: 1) // consume type
        return .heartbeat
    }

    // MARK: - IPv6 Formatting

    /// Formats 16 raw bytes as an RFC 5952 compressed IPv6 string.
    private static func formatIPv6(_ bytes: [UInt8]) -> String {
        var groups = [String]()
        groups.reserveCapacity(8)
        for i in stride(from: 0, to: 16, by: 2) {
            let value = (UInt16(bytes[i]) << 8) | UInt16(bytes[i + 1])
            groups.append(String(value, radix: 16))
        }

        // Find the longest run of zero groups for `::` compression.
        var bestStart = -1
        var bestLen  = 0
        var curStart = -1
        for (i, g) in groups.enumerated() {
            if g == "0" {
                if curStart == -1 { curStart = i }
                let curLen = i - curStart + 1
                if curLen > bestLen {
                    bestStart = curStart
                    bestLen   = curLen
                }
            } else {
                curStart = -1
            }
        }

        // Only compress runs of 2 or more zeros.
        if bestLen >= 2 {
            let prefix = groups[0 ..< bestStart]
            let suffix = groups[(bestStart + bestLen)...]
            let parts = prefix + [""] + suffix
            return parts.joined(separator: ":")
        }

        return groups.joined(separator: ":")
    }
}

// MARK: - Parse Errors

/// Errors that may be thrown during TUIC frame parsing.
public enum TUICFrameParseError: Error, Sendable, Equatable {
    /// The frame type byte does not match any known TUIC v5 type.
    case invalidFrameType(UInt8)
    /// The address type byte in a Connect frame is unrecognised.
    case invalidAddressType(UInt8)
}
