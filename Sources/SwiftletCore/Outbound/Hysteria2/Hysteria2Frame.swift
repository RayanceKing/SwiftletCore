//===----------------------------------------------------------------------===//
//
//  Hysteria2Frame.swift
//  SwiftletCore — Hysteria 2 Custom UDP Frame Serialization
//
//  Implements compact binary frame types for the Hysteria 2 QUIC‑like
//  transport protocol.  Every UDP datagram carries exactly one frame.
//
//  Frame Layouts
//  -------------
//  **Data Frame (TCP Stream / UDP Packet)**:
//  ```
//  [1] Type       = 0x00 (TCP) | 0x01 (UDP)
//  [2] Stream ID  = big‑endian UInt16
//  [2] Length     = big‑endian UInt16
//  [L] Payload
//  ```
//
//  **Auth Frame**:
//  ```
//  [1] Type       = 0x02
//  [1] Auth Len   = A
//  [A] Secret
//  ```
//
//  **Ping Frame**:
//  ```
//  [1] Type       = 0x03
//  [1] Data Len   = P
//  [P] Data       (often empty, P = 0)
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Frame Type

/// Hysteria 2 frame type constants.
public enum Hysteria2FrameType: UInt8, Sendable, Equatable {
    case tcpData  = 0x00
    case udpData  = 0x01
    case auth     = 0x02
    case ping     = 0x03
}

// MARK: - Frame

/// A parsed or constructed Hysteria 2 protocol frame.
public enum Hysteria2Frame: Sendable, Equatable {
    /// Carries TCP stream data.
    case tcpData(streamID: UInt16, payload: Data)
    /// Carries UDP packet data.
    case udpData(sessionID: UInt16, payload: Data)
    /// Authentication handshake.
    case auth(secret: Data)
    /// Keepalive ping.
    case ping(data: Data)

    /// The frame type tag.
    public var type: Hysteria2FrameType {
        switch self {
        case .tcpData: return .tcpData
        case .udpData: return .udpData
        case .auth:    return .auth
        case .ping:    return .ping
        }
    }
}

// MARK: - Frame Builder

/// Builds raw Hysteria 2 frame bytes.
public enum Hysteria2FrameBuilder {

    /// Data frame header size (type + streamID + length).
    public static let dataHeaderSize = 5

    /// Serialises a frame into its wire‑format byte representation.
    public static func build(_ frame: Hysteria2Frame) -> Data {
        var data = Data()

        switch frame {
        case .tcpData(let streamID, let payload):
            data.append(Hysteria2FrameType.tcpData.rawValue)
            writeUInt16(streamID, to: &data)
            writeUInt16(UInt16(payload.count), to: &data)
            data.append(payload)

        case .udpData(let sessionID, let payload):
            data.append(Hysteria2FrameType.udpData.rawValue)
            writeUInt16(sessionID, to: &data)
            writeUInt16(UInt16(payload.count), to: &data)
            data.append(payload)

        case .auth(let secret):
            data.append(Hysteria2FrameType.auth.rawValue)
            data.append(UInt8(secret.count))
            data.append(secret)

        case .ping(let pingData):
            data.append(Hysteria2FrameType.ping.rawValue)
            data.append(UInt8(pingData.count))
            data.append(pingData)
        }

        return data
    }

    private static func writeUInt16(_ value: UInt16, to data: inout Data) {
        data.append(UInt8(value >> 8))
        data.append(UInt8(value & 0xFF))
    }
}

// MARK: - Frame Parser

/// Parses raw bytes into Hysteria 2 frames with strict bounds checking.
public enum Hysteria2FrameParser {

    /// Errors thrown during frame parsing.
    public enum ParseError: Error, Sendable, Equatable {
        case insufficientData(needed: Int, available: Int)
        case invalidFrameType(UInt8)
        case invalidPayloadLength(Int)
    }

    /// Parses a single Hysteria 2 frame from raw bytes.
    ///
    /// - Parameter data: The complete UDP datagram payload.
    /// - Returns: A parsed `Hysteria2Frame`.
    /// - Throws: `ParseError` if the data is malformed or truncated.
    public static func parse(_ data: Data) throws -> Hysteria2Frame {
        guard data.count >= 1 else {
            throw ParseError.insufficientData(needed: 1, available: data.count)
        }

        let rawType = data[0]
        guard let frameType = Hysteria2FrameType(rawValue: rawType) else {
            throw ParseError.invalidFrameType(rawType)
        }

        switch frameType {
        case .tcpData, .udpData:
            return try parseDataFrame(type: frameType, data: data)

        case .auth:
            return try parseAuthFrame(data: data)

        case .ping:
            return try parsePingFrame(data: data)
        }
    }

    // MARK: - Data Frame Parser

    private static func parseDataFrame(
        type: Hysteria2FrameType,
        data: Data
    ) throws -> Hysteria2Frame {
        // Need: 1 (type) + 2 (streamID) + 2 (length) = 5 bytes minimum.
        guard data.count >= 5 else {
            throw ParseError.insufficientData(needed: 5, available: data.count)
        }

        let streamID = (UInt16(data[1]) << 8) | UInt16(data[2])
        let payloadLen = Int((UInt16(data[3]) << 8) | UInt16(data[4]))

        let totalNeeded = 5 + payloadLen
        guard data.count >= totalNeeded else {
            throw ParseError.insufficientData(
                needed: totalNeeded, available: data.count
            )
        }

        let payload = data.subdata(in: 5 ..< totalNeeded)

        switch type {
        case .tcpData:
            return .tcpData(streamID: streamID, payload: payload)
        case .udpData:
            return .udpData(sessionID: streamID, payload: payload)
        default:
            throw ParseError.invalidFrameType(type.rawValue)
        }
    }

    // MARK: - Auth Frame Parser

    private static func parseAuthFrame(data: Data) throws -> Hysteria2Frame {
        guard data.count >= 2 else {
            throw ParseError.insufficientData(needed: 2, available: data.count)
        }

        let authLen = Int(data[1])
        let totalNeeded = 2 + authLen
        guard data.count >= totalNeeded else {
            throw ParseError.insufficientData(
                needed: totalNeeded, available: data.count
            )
        }

        let secret = data.subdata(in: 2 ..< totalNeeded)
        return .auth(secret: secret)
    }

    // MARK: - Ping Frame Parser

    private static func parsePingFrame(data: Data) throws -> Hysteria2Frame {
        guard data.count >= 2 else {
            throw ParseError.insufficientData(needed: 2, available: data.count)
        }

        let pingLen = Int(data[1])
        let totalNeeded = 2 + pingLen
        guard data.count >= totalNeeded else {
            throw ParseError.insufficientData(
                needed: totalNeeded, available: data.count
            )
        }

        let pingData = data.subdata(in: 2 ..< totalNeeded)
        return .ping(data: pingData)
    }
}

// MARK: - Payload Obfuscation

/// Hooks for random‑padding injection to defeat DPI length‑distribution
/// analysis.
public enum Hysteria2Obfuscator {

    /// Appends random padding bytes to a `ByteBuffer` in‑place so the
    /// UDP datagram length distribution is masked.
    ///
    /// - Parameters:
    ///   - buffer: The buffer to pad (mutated in‑place).
    ///   - maxPadding: Maximum number of padding bytes to add (0 disables).
    public static func obfuscatePayload(
        _ buffer: inout ByteBuffer,
        maxPadding: Int = 64
    ) {
        guard maxPadding > 0 else { return }
        let padLen = Int.random(in: 0 ... maxPadding)
        guard padLen > 0 else { return }

        var padding = [UInt8](repeating: 0, count: padLen)
        _ = SecRandomCopyBytes(kSecRandomDefault, padLen, &padding)
        buffer.writeBytes(padding)
    }

    /// Strips trailing random padding bytes.  Because the Hysteria 2
    /// frame header carries the true payload length, the padding is
    /// simply ignored during parsing — this method is provided for
    /// cases where padding is applied outside the framed payload.
    public static func stripPadding(_ data: inout Data, knownPayloadLength: Int) {
        if data.count > knownPayloadLength {
            data = data.prefix(knownPayloadLength)
        }
    }
}
