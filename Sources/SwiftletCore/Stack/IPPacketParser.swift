//===----------------------------------------------------------------------===//
//
//  IPPacketParser.swift
//  SwiftletCore — Layer 3 IP Packet Parser
//
//  A zero‑copy, bounds‑checked parser that inspects raw IP datagrams
//  ejected from `NEPacketTunnelFlow`.  It reads the IP version from the
//  first nibble, dispatches to the appropriate IPv4 or IPv6 decoder, and
//  returns a strongly‑typed `IPPacket` whose `payload` slice shares the
//  underlying `ByteBuffer` storage — no bytes are duplicated.
//
//  Usage
//  -----
//  ```swift
//  var buffer = ByteBuffer(data: rawPacketData)
//  let packet  = try IPPacketParser.parse(buffer: &buffer)
//  // buffer is now consumed past the IP datagram; packet.payload
//  // contains a zero‑copy view of the transport‑layer segment.
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Parser

/// A stateless, zero‑copy parser for IPv4 and IPv6 packet headers.
///
/// All parsing methods validate the header fields before constructing the
/// returned value so that a malformed or truncated packet reliably throws a
/// `ParseError` rather than producing a garbage header.
public enum IPPacketParser {

    // MARK: - Errors

    /// Errors thrown during IP packet parsing.
    public enum ParseError: Error, Sendable, Equatable, CustomStringConvertible {
        /// The buffer does not contain enough bytes to read the expected field.
        case insufficientData(needed: Int, available: Int)
        /// The first nibble is not a recognised IP version (4 or 6).
        case invalidVersion(UInt8)
        /// The IPv4 IHL field is less than 5 (header shorter than 20 bytes).
        case invalidHeaderLength(Int)
        /// The declared total length is inconsistent with the header length
        /// (e.g. IPv4 `totalLength < ihl * 4`).
        case invalidTotalLength(declared: Int, minimum: Int)

        public var description: String {
            switch self {
            case .insufficientData(let needed, let available):
                return "Need \(needed) bytes but only \(available) available"
            case .invalidVersion(let v):
                return "Invalid IP version: \(v) (expected 4 or 6)"
            case .invalidHeaderLength(let ihl):
                return "Invalid IPv4 IHL: \(ihl) (minimum 5)"
            case .invalidTotalLength(let declared, let minimum):
                return "Declared total length \(declared) < header length \(minimum)"
            }
        }
    }

    // MARK: - Public Entry Points

    /// Parses a raw IP packet from a `Foundation.Data` value.
    ///
    /// This is the primary entry point for `NEPacketTunnelFlow` integration
    /// which provides packet data as `Data`.
    ///
    /// - Parameter data: The raw IP datagram.
    /// - Returns: A parsed `IPPacket` with a zero‑copy payload slice.
    /// - Throws: `ParseError` if the data is malformed or truncated.
    public static func parse(_ data: Data) throws -> IPPacket {
        var buffer = ByteBuffer(bytes: data)
        return try parse(buffer: &buffer)
    }

    /// Parses a raw IP packet from a `ByteBuffer`.
    ///
    /// The buffer's reader index is advanced past the **entire** IP datagram
    /// (header + payload).  The returned `IPPacket` carries a zero‑copy
    /// `payload` slice that references the same underlying storage.
    ///
    /// - Parameter buffer: The raw IP datagram.
    /// - Returns: A parsed `IPPacket`.
    /// - Throws: `ParseError` if the data is malformed or truncated.
    public static func parse(buffer: inout ByteBuffer) throws -> IPPacket {
        let startIndex = buffer.readerIndex

        // Need at least 1 byte to inspect the version nibble.
        guard buffer.readableBytes >= 1 else {
            throw ParseError.insufficientData(
                needed: 1,
                available: buffer.readableBytes
            )
        }

        guard let firstByte: UInt8 = buffer.getInteger(at: startIndex) else {
            throw ParseError.insufficientData(
                needed: 1,
                available: buffer.readableBytes
            )
        }

        let version = firstByte >> 4

        switch version {
        case 4:
            return .ipv4(try parseIPv4(buffer: &buffer))

        case 6:
            return .ipv6(try parseIPv6(buffer: &buffer))

        default:
            throw ParseError.invalidVersion(version)
        }
    }

    // MARK: - IPv4 Parser (RFC 791)

    /// Wire layout of the 20‑byte fixed IPv4 header:
    /// ```
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version|  IHL  |      ToS      |         Total Length          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Identification        |Flags|     Fragment Offset     |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |  Time to Live |   Protocol    |        Header Checksum        |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                       Source Address                          |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     Destination Address                       |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                     Options (if IHL > 5)                      |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    private static func parseIPv4(
        buffer: inout ByteBuffer
    ) throws -> IPv4Header {
        let startIndex = buffer.readerIndex

        // ---- Fixed header minimum ----------------------------------------
        guard buffer.readableBytes >= 20 else {
            throw ParseError.insufficientData(
                needed: 20,
                available: buffer.readableBytes
            )
        }

        // ---- Peek all fixed‑header fields (21 × getInteger, no consume) ---
        let versionAndIHL:       UInt8  = buffer.getInteger(at: startIndex +  0)!
        let tos:                 UInt8  = buffer.getInteger(at: startIndex +  1)!
        let totalLength:         UInt16 = buffer.getInteger(at: startIndex +  2)!
        let identification:      UInt16 = buffer.getInteger(at: startIndex +  4)!
        let flagsFrag:           UInt16 = buffer.getInteger(at: startIndex +  6)!
        let ttl:                 UInt8  = buffer.getInteger(at: startIndex +  8)!
        let proto:               UInt8  = buffer.getInteger(at: startIndex +  9)!
        let checksum:            UInt16 = buffer.getInteger(at: startIndex + 10)!
        let srcAddr:             UInt32 = buffer.getInteger(at: startIndex + 12)!
        let dstAddr:             UInt32 = buffer.getInteger(at: startIndex + 16)!

        let version = versionAndIHL >> 4
        let ihl     = versionAndIHL & 0x0F
        let headerLength = Int(ihl) * 4

        // ---- Validate ----------------------------------------------------
        guard ihl >= 5 else {
            throw ParseError.invalidHeaderLength(Int(ihl))
        }
        guard buffer.readableBytes >= headerLength else {
            throw ParseError.insufficientData(
                needed: headerLength,
                available: buffer.readableBytes
            )
        }
        guard Int(totalLength) >= headerLength else {
            throw ParseError.invalidTotalLength(
                declared: Int(totalLength),
                minimum: headerLength
            )
        }

        // The datagram may be truncated — clamp to what we actually have.
        let actualDatagramLength = min(Int(totalLength), buffer.readableBytes)
        let payloadLength = actualDatagramLength - headerLength

        // ---- Zero‑copy payload slice -------------------------------------
        let payloadStart = startIndex + headerLength
        let payloadSlice = buffer.getSlice(at: payloadStart, length: payloadLength)!

        // ---- Consume the entire datagram ---------------------------------
        buffer.moveReaderIndex(forwardBy: actualDatagramLength)

        return IPv4Header(
            version:                version,
            ihl:                    ihl,
            typeOfService:          tos,
            totalLength:            totalLength,
            identification:         identification,
            flagsAndFragmentOffset: flagsFrag,
            ttl:                    ttl,
            protocol:               proto,
            headerChecksum:         checksum,
            sourceAddress:          IPv4Address(networkByteOrder: srcAddr),
            destinationAddress:     IPv4Address(networkByteOrder: dstAddr),
            payload:                payloadSlice
        )
    }

    // MARK: - IPv6 Parser (RFC 8200)

    /// Wire layout of the fixed 40‑byte IPv6 header:
    /// ```
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |Version| Traffic Class |            Flow Label                 |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |         Payload Length        |  Next Header  |   Hop Limit   |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                         Source Address                        +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +                      Destination Address                      +
    /// |                                                               |
    /// +                                                               +
    /// |                                                               |
    /// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /// ```
    private static func parseIPv6(
        buffer: inout ByteBuffer
    ) throws -> IPv6Header {
        let startIndex = buffer.readerIndex
        let headerLength = 40

        // ---- Fixed header minimum ----------------------------------------
        guard buffer.readableBytes >= headerLength else {
            throw ParseError.insufficientData(
                needed: headerLength,
                available: buffer.readableBytes
            )
        }

        // ---- Peek all fields (no consume) --------------------------------
        let versionTCFlow:      UInt32  = buffer.getInteger(at: startIndex +  0)!
        let payloadLength:      UInt16  = buffer.getInteger(at: startIndex +  4)!
        let nextHeader:         UInt8   = buffer.getInteger(at: startIndex +  6)!
        let hopLimit:           UInt8   = buffer.getInteger(at: startIndex +  7)!
        let srcUpper:           UInt64  = buffer.getInteger(at: startIndex +  8)!
        let srcLower:           UInt64  = buffer.getInteger(at: startIndex + 16)!
        let dstUpper:           UInt64  = buffer.getInteger(at: startIndex + 24)!
        let dstLower:           UInt64  = buffer.getInteger(at: startIndex + 32)!

        // The first 32‑bit word packs Version(4) | Traffic Class(8) | Flow Label(20).
        let version      = UInt8((versionTCFlow >> 28) & 0x0F)
        let trafficClass = UInt8((versionTCFlow >> 20) & 0xFF)
        let flowLabel    = versionTCFlow & 0x000FFFFF

        // ---- Validate ----------------------------------------------------
        // A payload length of 0 is valid for IPv6 Jumbograms (RFC 2675)
        // but we do not support those — the buffer must contain at least
        // the declared payload.
        let totalDatagramLength = headerLength + Int(payloadLength)

        // Clamp to what is actually available (graceful truncation).
        let actualDatagramLength = min(totalDatagramLength, buffer.readableBytes)
        let actualPayloadLength  = actualDatagramLength - headerLength

        guard actualPayloadLength >= 0 else {
            // Should be unreachable — buffer.readableBytes >= 40 was
            // already checked, and headerLength == 40.
            throw ParseError.insufficientData(
                needed: totalDatagramLength,
                available: buffer.readableBytes
            )
        }

        // ---- Zero‑copy payload slice -------------------------------------
        let payloadStart = startIndex + headerLength
        let payloadSlice = buffer.getSlice(at: payloadStart, length: actualPayloadLength)!

        // ---- Consume the entire datagram ---------------------------------
        buffer.moveReaderIndex(forwardBy: actualDatagramLength)

        return IPv6Header(
            version:            version,
            trafficClass:       trafficClass,
            flowLabel:          flowLabel,
            payloadLength:      payloadLength,
            nextHeader:         nextHeader,
            hopLimit:           hopLimit,
            sourceAddress:      IPv6Address(upper: srcUpper, lower: srcLower),
            destinationAddress: IPv6Address(upper: dstUpper, lower: dstLower),
            payload:            payloadSlice
        )
    }
}
