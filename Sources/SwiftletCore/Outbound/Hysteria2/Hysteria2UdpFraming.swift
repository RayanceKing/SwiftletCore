//===----------------------------------------------------------------------===//
//
//  Hysteria2UdpFraming.swift
//  SwiftletCore — Hysteria 2 UDP Packet Framing (0x402 / 0x403)
//
//  Wire formats:
//
//  **UDP Request Frame (0x402)** — Initialises a UDP session
//  ```
//  [QUIC Varint] 0x402       — UDPRequest command ID
//  [QUIC Varint] Session ID   — unique user‑space tracker
//  ```
//
//  **UDP Data Frame (0x403)** — Relays a single UDP datagram
//  ```
//  [QUIC Varint] 0x403        — UDPData command ID
//  [QUIC Varint] Session ID
//  [QUIC Varint] Packet Index  — sequence / ordering
//  [QUIC Varint] Payload Len L
//  [L bytes]    Raw UDP payload
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Commands

public enum Hysteria2UDPCommand {
    public static let udpRequest: UInt64 = 0x402
    public static let udpData:    UInt64 = 0x403
}

// MARK: - UDP Request Frame

/// Builds a Hysteria 2 UDP session initialisation frame.
public enum Hysteria2UDPRequestBuilder {

    /// Serialises a UDP request frame that asks the server to open a
    /// new UDP session with the given identifier.
    ///
    /// - Parameter sessionID: A unique user‑space tracker for this session.
    /// - Returns: The binary frame.
    public static func build(sessionID: UInt16) -> Data {
        var data = Data()
        data.append(contentsOf: QUICVarint.encode(Hysteria2UDPCommand.udpRequest))
        data.append(contentsOf: QUICVarint.encode(UInt64(sessionID)))
        return data
    }
}

// MARK: - UDP Data Frame

/// Builds and parses Hysteria 2 UDP data‑relay frames.
public enum Hysteria2UDPDataBuilder {

    // MARK: - Build

    /// Serialises a UDP data frame carrying a raw payload.
    ///
    /// - Parameters:
    ///   - sessionID: The UDP session identifier.
    ///   - packetIndex: Monotonically increasing packet counter.
    ///   - payload: The raw UDP datagram bytes (e.g. DNS query).
    /// - Returns: The binary frame.
    public static func build(
        sessionID: UInt16,
        packetIndex: UInt64,
        payload: Data
    ) -> Data {
        var data = Data()
        data.append(contentsOf: QUICVarint.encode(Hysteria2UDPCommand.udpData))
        data.append(contentsOf: QUICVarint.encode(UInt64(sessionID)))
        data.append(contentsOf: QUICVarint.encode(packetIndex))
        data.append(contentsOf: QUICVarint.encode(UInt64(payload.count)))
        data.append(payload)
        return data
    }

    // MARK: - Parse

    /// Parsed result of a UDP data frame.
    public struct Parsed: Sendable, Equatable {
        public let sessionID: UInt16
        public let packetIndex: UInt64
        public let payload: Data
    }

    /// Errors thrown during UDP data frame parsing.
    public enum ParseError: Error, Sendable, Equatable {
        case insufficientData(needed: Int, available: Int)
        case invalidCommand(UInt64)
    }

    /// Parses a raw Hysteria 2 UDP data frame.
    ///
    /// - Parameter data: The complete frame bytes.
    /// - Returns: A `Parsed` struct with session ID, packet index, and payload.
    /// - Throws: `ParseError` if the frame is malformed or truncated.
    public static func parse(_ data: Data) throws -> Parsed {
        var offset = 0

        // 1. Command ID
        let (cmd, cmdLen) = try decodeVarint(data, offset: offset)
        offset += cmdLen
        guard cmd == Hysteria2UDPCommand.udpData else {
            throw ParseError.invalidCommand(cmd)
        }

        // 2. Session ID
        let (sid, sidLen) = try decodeVarint(data, offset: offset)
        offset += sidLen

        // 3. Packet Index
        let (pktIdx, pktLen) = try decodeVarint(data, offset: offset)
        offset += pktLen

        // 4. Payload Length
        let (payloadLen, payLenSize) = try decodeVarint(data, offset: offset)
        offset += payLenSize

        // 5. Payload
        let totalNeeded = offset + Int(payloadLen)
        guard data.count >= totalNeeded else {
            throw ParseError.insufficientData(
                needed: totalNeeded, available: data.count
            )
        }

        let payload = data.subdata(in: offset ..< totalNeeded)

        return Parsed(
            sessionID: UInt16(sid),
            packetIndex: pktIdx,
            payload: payload
        )
    }

    /// Decodes a QUIC varint at the given offset within `data`.
    private static func decodeVarint(
        _ data: Data,
        offset: Int
    ) throws -> (value: UInt64, consumed: Int) {
        let slice = data.subdata(in: offset ..< data.count)
        return try QUICVarint.decode(slice)
    }
}
