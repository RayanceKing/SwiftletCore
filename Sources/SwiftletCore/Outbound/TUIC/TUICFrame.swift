//===----------------------------------------------------------------------===//
//
//  TUICFrame.swift
//  SwiftletCore — TUIC v5 Binary Frame Definitions & Zero‑Copy Encoder
//
//  TUIC v5 bypasses heavyweight application‑layer framing (HTTP/3) and
//  interacts directly with raw QUIC stream allocations via compact,
//  fixed‑layout binary frames.  Each frame carries a single‑byte type
//  tag followed by type‑specific payload fields in big‑endian order.
//
//  Frame Layouts
//  -------------
//  **Authenticate (0x00)** — 18 bytes total:
//  ```
//  [1]  Type       = 0x00
//  [16] UUID       = raw binary UUID bytes
//  [1]  UDP Mode   = 0x00 (TCP only) / 0x01 (UDP enabled)
//  ```
//
//  **Connect (0x01)** — variable length:
//  ```
//  [1]  Type       = 0x01
//  [1]  Addr Type  = 0x00 (IPv4) | 0x01 (IPv6) | 0x02 (Domain)
//  [n]  Address    = 4 / 16 / (1‑byte len + bytes)
//  [2]  Port       = big‑endian UInt16
//  ```
//
//  **Packet (0x02)** — variable length:
//  ```
//  [1]  Type       = 0x02
//  [2]  Session ID = big‑endian UInt16
//  [2]  Length     = big‑endian UInt16
//  [L]  Payload
//  ```
//
//  **Disconnect (0x03)** — 3 bytes:
//  ```
//  [1]  Type       = 0x03
//  [2]  Session ID = big‑endian UInt16
//  ```
//
//  **Heartbeat (0x04)** — 1 byte:
//  ```
//  [1]  Type       = 0x04
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

// MARK: - Frame Type Tag

/// TUIC v5 frame type constants (on‑wire byte values).
public enum TUICFrameType: UInt8, Sendable, Equatable, CaseIterable {
    case authenticate = 0x00
    case connect      = 0x01
    case packet       = 0x02
    case disconnect   = 0x03
    case heartbeat    = 0x04
}

// MARK: - Address Type

/// Address type constants for the Connect (0x01) frame.
public enum TUICAddressType: UInt8, Sendable, Equatable {
    case ipv4   = 0x00
    case ipv6   = 0x01
    case domain = 0x02
}

// MARK: - TUIC Frame

/// A parsed or constructed TUIC v5 protocol frame.
///
/// Supports all five frame types in the TUIC v5 specification, each
/// carrying the minimum fields needed to drive a QUIC‑stream‑level
/// proxy session.
public enum TUICFrame: Sendable, Equatable {

    /// Authenticates a TUIC session (Type 0x00).
    ///
    /// - Parameters:
    ///   - uuid: The user's TUIC UUID (16 raw bytes).
    ///   - udpMode: `0x00` = TCP only, `0x01` = UDP relaying enabled.
    case authenticate(uuid: UUID, udpMode: UInt8)

    /// Opens a new stream to a remote destination (Type 0x01).
    ///
    /// - Parameters:
    ///   - addressType: The address encoding (`ipv4` / `ipv6` / `domain`).
    ///   - address: The destination hostname or IP string.
    ///   - port: Destination port.
    case connect(addressType: TUICAddressType, address: String, port: UInt16)

    /// Carries payload data for an established stream (Type 0x02).
    ///
    /// - Parameters:
    ///   - sessionID: The stream / session identifier.
    ///   - payload: Raw relay data bytes.
    case packet(sessionID: UInt16, payload: Data)

    /// Tears down a specific stream (Type 0x03).
    ///
    /// - Parameter sessionID: The stream to close.
    case disconnect(sessionID: UInt16)

    /// Keepalive ping (Type 0x04).  Carries no payload.
    case heartbeat

    // MARK: - Frame Type Accessor

    /// The frame type tag for this frame.
    public var frameType: TUICFrameType {
        switch self {
        case .authenticate: return .authenticate
        case .connect:     return .connect
        case .packet:      return .packet
        case .disconnect:  return .disconnect
        case .heartbeat:   return .heartbeat
        }
    }
}

// MARK: - TUIC Frame Encoder

/// Zero‑copy encoder that serialises `TUICFrame` values directly into
/// a SwiftNIO `ByteBuffer`.
///
/// All multi‑byte integers are written in **big‑endian** order per the
/// TUIC v5 wire specification.
public enum TUICFrameEncoder {

    // MARK: - Fixed Frame Sizes

    /// Authenticate frame is always exactly 18 bytes.
    public static let authenticateSize = 18

    /// Minimum Connect frame size: type(1) + addrType(1) + ipv4(4) + port(2) = 8.
    public static let connectMinSize = 8

    /// Disconnect frame is exactly 3 bytes.
    public static let disconnectSize = 3

    /// Heartbeat frame is exactly 1 byte.
    public static let heartbeatSize = 1

    /// Packet frame minimum size: type(1) + sessionID(2) + length(2) = 5.
    public static let packetHeaderSize = 5

    // MARK: - Encode into ByteBuffer

    /// Serialises `frame` into `buffer` in its TUIC v5 wire format.
    ///
    /// Uses `writeInteger` for multi‑byte fields (zero‑copy via
    /// ByteBuffer's pointer‑stable storage when possible) and
    /// `writeBytes` for raw data.
    ///
    /// - Parameters:
    ///   - frame: The frame to serialise.
    ///   - buffer: The target buffer (mutated in‑place).
    public static func encode(_ frame: TUICFrame, into buffer: inout ByteBuffer) {
        switch frame {
        case .authenticate(let uuid, let udpMode):
            encodeAuthenticate(uuid: uuid, udpMode: udpMode, into: &buffer)

        case .connect(let addressType, let address, let port):
            encodeConnect(
                addressType: addressType,
                address: address,
                port: port,
                into: &buffer
            )

        case .packet(let sessionID, let payload):
            encodePacket(
                sessionID: sessionID,
                payload: payload,
                into: &buffer
            )

        case .disconnect(let sessionID):
            encodeDisconnect(sessionID: sessionID, into: &buffer)

        case .heartbeat:
            buffer.writeInteger(TUICFrameType.heartbeat.rawValue)
        }
    }

    /// Serialises `frame` and returns a fresh `ByteBuffer`.
    ///
    /// - Parameters:
    ///   - frame: The frame to serialise.
    ///   - allocator: A `ByteBufferAllocator` (defaults to the global pool).
    /// - Returns: A new buffer containing the serialised frame.
    public static func encode(
        _ frame: TUICFrame,
        allocator: ByteBufferAllocator = ByteBufferAllocator()
    ) -> ByteBuffer {
        var buffer = allocator.buffer(capacity: 256)
        encode(frame, into: &buffer)
        return buffer
    }

    // MARK: - Per‑Type Encoders

    /// Encodes an Authenticate frame (Type 0x00).
    ///
    /// Layout: `[0x00] [16‑byte UUID] [udpMode]`  →  18 bytes.
    private static func encodeAuthenticate(
        uuid: UUID,
        udpMode: UInt8,
        into buffer: inout ByteBuffer
    ) {
        buffer.writeInteger(TUICFrameType.authenticate.rawValue)
        buffer.writeBytes(TUICFrameEncoder.uuidBytes(from: uuid))
        buffer.writeInteger(udpMode)
    }

    /// Encodes a Connect frame (Type 0x01).
    ///
    /// Layout:
    /// ```
    /// [0x01] [addrType] [address bytes] [port BE-UInt16]
    /// ```
    private static func encodeConnect(
        addressType: TUICAddressType,
        address: String,
        port: UInt16,
        into buffer: inout ByteBuffer
    ) {
        buffer.writeInteger(TUICFrameType.connect.rawValue)
        buffer.writeInteger(addressType.rawValue)

        switch addressType {
        case .ipv4:
            guard let ipv4Bytes = TUICFrameEncoder.parseIPv4(address) else {
                // Write a zeroed placeholder — caller should validate.
                buffer.writeBytes([UInt8](repeating: 0, count: 4))
                break
            }
            buffer.writeBytes(ipv4Bytes)

        case .ipv6:
            guard let ipv6Bytes = TUICFrameEncoder.parseIPv6(address) else {
                buffer.writeBytes([UInt8](repeating: 0, count: 16))
                break
            }
            buffer.writeBytes(ipv6Bytes)

        case .domain:
            let utf8 = address.utf8
            buffer.writeInteger(UInt8(utf8.count))
            buffer.writeBytes(utf8)
        }

        buffer.writeInteger(port, endianness: .big, as: UInt16.self)
    }

    /// Encodes a Packet frame (Type 0x02).
    ///
    /// Layout: `[0x02] [sessionID BE-UInt16] [length BE-UInt16] [payload]`.
    private static func encodePacket(
        sessionID: UInt16,
        payload: Data,
        into buffer: inout ByteBuffer
    ) {
        buffer.writeInteger(TUICFrameType.packet.rawValue)
        buffer.writeInteger(sessionID, endianness: .big, as: UInt16.self)
        buffer.writeInteger(UInt16(payload.count), endianness: .big, as: UInt16.self)
        buffer.writeBytes(payload)
    }

    /// Encodes a Disconnect frame (Type 0x03).
    ///
    /// Layout: `[0x03] [sessionID BE-UInt16]`  →  3 bytes.
    private static func encodeDisconnect(
        sessionID: UInt16,
        into buffer: inout ByteBuffer
    ) {
        buffer.writeInteger(TUICFrameType.disconnect.rawValue)
        buffer.writeInteger(sessionID, endianness: .big, as: UInt16.self)
    }

    // MARK: - Helpers

    /// Extracts 16 raw bytes from a `UUID`.
    public static func uuidBytes(from uuid: UUID) -> [UInt8] {
        let u = uuid.uuid
        return [
            u.0,  u.1,  u.2,  u.3,  u.4,  u.5,  u.6,  u.7,
            u.8,  u.9,  u.10, u.11, u.12, u.13, u.14, u.15,
        ]
    }

    /// Parses an IPv4 address string into 4 network‑order bytes.
    ///
    /// - Returns: A 4‑byte array, or `nil` if the string is invalid.
    public static func parseIPv4(_ string: String) -> [UInt8]? {
        let components = string.split(separator: ".", omittingEmptySubsequences: false)
        guard components.count == 4 else { return nil }
        var bytes = [UInt8]()
        for comp in components {
            guard let val = UInt8(comp), String(val) == comp else { return nil }
            bytes.append(val)
        }
        return bytes
    }

    /// Parses an IPv6 address string into 16 network‑order bytes using
    /// the system resolver.  Falls back to a manual expanded‑form parser.
    public static func parseIPv6(_ string: String) -> [UInt8]? {
        // Use inet_pton via POSIX when available; fall back to a
        // manual parser for sandboxed environments.
        var addr = sockaddr_in6()
        addr.sin6_len    = UInt8(MemoryLayout<sockaddr_in6>.size)
        addr.sin6_family = sa_family_t(AF_INET6)
        let result = string.withCString { ptr in
            inet_pton(AF_INET6, ptr, &addr.sin6_addr)
        }
        if result == 1 {
            return withUnsafeBytes(of: addr.sin6_addr) { Array($0) }
        }
        // Fallback: simplified expanded‑form parser.
        return TUICFrameEncoder.manualParseIPv6(string)
    }

    /// Manual IPv6 parser that handles `::` abbreviation and canonical
    /// full‑expansion forms.
    private static func manualParseIPv6(_ string: String) -> [UInt8]? {
        var groups = string.split(separator: ":", omittingEmptySubsequences: false)
        guard groups.count <= 8 else { return nil }

        // Handle :: abbreviation.
        if let doubleColon = groups.firstIndex(of: "") {
            let fillCount = 8 - (groups.count - 1)
            groups.replaceSubrange(
                doubleColon ... doubleColon,
                with: Array(repeating: "0", count: fillCount)
            )
        }
        guard groups.count == 8 else { return nil }

        var bytes = [UInt8]()
        bytes.reserveCapacity(16)
        for group in groups {
            guard let val = UInt16(group, radix: 16) else { return nil }
            bytes.append(UInt8(val >> 8))
            bytes.append(UInt8(val & 0xFF))
        }
        return bytes
    }
}
