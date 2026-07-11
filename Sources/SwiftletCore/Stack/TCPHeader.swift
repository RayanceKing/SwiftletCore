//===----------------------------------------------------------------------===//
//
//  TCPHeader.swift
//  SwiftletCore — TCP Header Types, Parser & Builder
//
//  Provides a type‑safe representation of TCP segment headers, a zero‑copy
//  parser from `ByteBuffer`, and a builder for constructing handshake
//  segments (SYN‑ACK, RST) for the TUN2Socks virtual TCP stack.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

// MARK: - TCP Flags

/// TCP control bits (RFC 793 §3.1).
///
/// The flags occupy bits 0–7 of the 14th byte of the TCP header (after the
/// Data Offset nibble and the 3 reserved bits).  The raw value matches the
/// byte that immediately follows the Data Offset nibble so that it can be
/// written directly to the wire.
public struct TCPFlags: OptionSet, Sendable, Equatable {
    public let rawValue: UInt8

    public init(rawValue: UInt8) { self.rawValue = rawValue }

    public static let fin = TCPFlags(rawValue: 1 << 0)
    public static let syn = TCPFlags(rawValue: 1 << 1)
    public static let rst = TCPFlags(rawValue: 1 << 2)
    public static let psh = TCPFlags(rawValue: 1 << 3)
    public static let ack = TCPFlags(rawValue: 1 << 4)
    public static let urg = TCPFlags(rawValue: 1 << 5)
    public static let ece = TCPFlags(rawValue: 1 << 6)
    public static let cwr = TCPFlags(rawValue: 1 << 7)
}

// MARK: - TCP Header

/// Parsed fields of a TCP segment header (RFC 793).
///
/// The `payload` slice is a **zero‑copy** view into the original packet
/// buffer starting immediately after the TCP header (including any options).
public struct TCPHeader: Sendable {

    /// Source port.
    public let sourcePort: UInt16
    /// Destination port.
    public let destinationPort: UInt16
    /// Sequence number.
    public let sequenceNumber: UInt32
    /// Acknowledgment number (meaningful only when `.ack` is set).
    public let acknowledgmentNumber: UInt32
    /// Header length in 32‑bit words (minimum 5 = 20 bytes).
    public let dataOffset: UInt8
    /// TCP control flags.
    public let flags: TCPFlags
    /// Receive window size.
    public let windowSize: UInt16
    /// TCP checksum.
    public let checksum: UInt16
    /// Urgent pointer (meaningful only when `.urg` is set).
    public let urgentPointer: UInt16
    /// Zero‑copy payload slice.
    public let payload: ByteBuffer

    // MARK: Derived Properties

    /// Header length in bytes (`dataOffset * 4`).
    public var headerLength: Int { Int(dataOffset) * 4 }

    /// Whether the SYN flag is set without ACK (connection initiation).
    public var isSYNOnly: Bool { flags.contains(.syn) && !flags.contains(.ack) }

    /// Whether both SYN and ACK are set (handshake reply).
    public var isSYNACK: Bool { flags.contains(.syn) && flags.contains(.ack) }

    /// Whether this is a RST segment (connection reset).
    public var isRST: Bool { flags.contains(.rst) }

    /// Whether this is a FIN segment (graceful close).
    public var isFIN: Bool { flags.contains(.fin) }

    /// Payload length in bytes.
    public var payloadLength: Int { payload.readableBytes }
}

// MARK: - TCP Parser

/// A zero‑copy parser for TCP segment headers.
///
/// Parses the fixed 20‑byte TCP header from a `ByteBuffer`, handles variable‑
/// length options via the Data Offset field, and returns a `TCPHeader` whose
/// `payload` slice shares the original buffer's storage.
public enum TCPParser {

    /// Errors thrown during TCP segment parsing.
    public enum ParseError: Error, Sendable, Equatable {
        case insufficientData(needed: Int, available: Int)
        case invalidDataOffset(UInt8)
    }

    /// Parses a TCP header from a `ByteBuffer`.
    ///
    /// The buffer's reader index is advanced past the **entire** TCP segment
    /// (header + payload).  The returned `TCPHeader.payload` is a zero‑copy
    /// slice that references the same underlying storage.
    ///
    /// - Parameter buffer: The TCP segment bytes.
    /// - Returns: A parsed `TCPHeader`.
    /// - Throws: `ParseError` if the segment is malformed or truncated.
    public static func parse(buffer: inout ByteBuffer) throws -> TCPHeader {
        let startIndex = buffer.readerIndex

        // ---- Fixed header minimum (20 bytes) -----------------------------
        guard buffer.readableBytes >= 20 else {
            throw ParseError.insufficientData(needed: 20, available: buffer.readableBytes)
        }

        // ---- Peek all fixed fields (no consume) --------------------------
        let srcPort:  UInt16 = buffer.getInteger(at: startIndex +  0)!
        let dstPort:  UInt16 = buffer.getInteger(at: startIndex +  2)!
        let seq:      UInt32 = buffer.getInteger(at: startIndex +  4)!
        let ack:      UInt32 = buffer.getInteger(at: startIndex +  8)!
        let offsetFlags: UInt16 = buffer.getInteger(at: startIndex + 12)!
        let window:   UInt16 = buffer.getInteger(at: startIndex + 14)!
        let checksum: UInt16 = buffer.getInteger(at: startIndex + 16)!
        let urgent:   UInt16 = buffer.getInteger(at: startIndex + 18)!

        // Data Offset occupies the upper 4 bits of the 13th byte (big-endian).
        let dataOffset = UInt8((offsetFlags >> 12) & 0x0F)
        let flagsRaw   = UInt8(offsetFlags & 0x01FF)
        let flags      = TCPFlags(rawValue: flagsRaw)

        // ---- Validate ----------------------------------------------------
        guard dataOffset >= 5 else {
            throw ParseError.invalidDataOffset(dataOffset)
        }
        let headerLength = Int(dataOffset) * 4
        guard buffer.readableBytes >= headerLength else {
            throw ParseError.insufficientData(
                needed: headerLength,
                available: buffer.readableBytes
            )
        }

        // The TCP payload length is implicit — everything after the header.
        let payloadStart  = startIndex + headerLength
        let payloadLength = buffer.readableBytes - headerLength

        // ---- Zero‑copy payload slice ------------------------------------
        let payloadSlice = buffer.getSlice(at: payloadStart, length: payloadLength)!

        // ---- Consume the entire segment ----------------------------------
        buffer.moveReaderIndex(forwardBy: buffer.readableBytes)

        return TCPHeader(
            sourcePort:            srcPort,
            destinationPort:       dstPort,
            sequenceNumber:        seq,
            acknowledgmentNumber:  ack,
            dataOffset:            dataOffset,
            flags:                 flags,
            windowSize:            window,
            checksum:              checksum,
            urgentPointer:         urgent,
            payload:               payloadSlice
        )
    }
}

// MARK: - TCP Builder

/// A stateless builder for constructing raw TCP segment byte arrays suitable
/// for the TUN2Socks virtual TCP handshake.
public enum TCPBuilder {

    /// Builds a 20‑byte TCP SYN‑ACK segment (no options).
    ///
    /// The *checksum* field is set to zero — the caller must compute the
    /// checksum over the pseudo‑header + this segment and write the result
    /// into bytes 16–17 before transmission.
    ///
    /// - Parameters:
    ///   - srcPort: Server port (the port the client originally targeted).
    ///   - dstPort: Client port (the ephemeral source port).
    ///   - serverSeq: Server's initial sequence number (ISN).
    ///   - clientAck: Client's sequence number + 1.
    ///   - windowSize: Advertised receive window (default 65535).
    /// - Returns: A 20‑byte TCP header.
    public static func synAck(
        srcPort: UInt16,
        dstPort: UInt16,
        serverSeq: UInt32,
        clientAck: UInt32,
        windowSize: UInt16 = 65535
    ) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)

        // Source Port
        bytes[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        bytes[1] = UInt8(truncatingIfNeeded: srcPort)

        // Destination Port
        bytes[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: dstPort)

        // Sequence Number
        bytes[4] = UInt8(truncatingIfNeeded: serverSeq >> 24)
        bytes[5] = UInt8(truncatingIfNeeded: serverSeq >> 16)
        bytes[6] = UInt8(truncatingIfNeeded: serverSeq >>  8)
        bytes[7] = UInt8(truncatingIfNeeded: serverSeq)

        // Acknowledgment Number
        bytes[8]  = UInt8(truncatingIfNeeded: clientAck >> 24)
        bytes[9]  = UInt8(truncatingIfNeeded: clientAck >> 16)
        bytes[10] = UInt8(truncatingIfNeeded: clientAck >>  8)
        bytes[11] = UInt8(truncatingIfNeeded: clientAck)

        // Data Offset (5) + Reserved (0) — upper 4 bits = 0x50
        bytes[12] = 0x50
        // Flags: SYN | ACK = 0x12
        bytes[13] = (TCPFlags.syn.rawValue | TCPFlags.ack.rawValue)

        // Window Size
        bytes[14] = UInt8(truncatingIfNeeded: windowSize >> 8)
        bytes[15] = UInt8(truncatingIfNeeded: windowSize)

        // Checksum (placeholder — computed later)
        bytes[16] = 0x00
        bytes[17] = 0x00

        // Urgent Pointer
        bytes[18] = 0x00
        bytes[19] = 0x00

        return bytes
    }

    /// Builds a 20‑byte TCP RST segment.
    ///
    /// Used to tear down a connection that has no registered session.
    public static func rst(
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32 = 0
    ) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)

        bytes[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        bytes[1] = UInt8(truncatingIfNeeded: srcPort)
        bytes[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: dstPort)
        bytes[4] = UInt8(truncatingIfNeeded: seq >> 24)
        bytes[5] = UInt8(truncatingIfNeeded: seq >> 16)
        bytes[6] = UInt8(truncatingIfNeeded: seq >>  8)
        bytes[7] = UInt8(truncatingIfNeeded: seq)
        bytes[8] = UInt8(truncatingIfNeeded: ack >> 24)
        bytes[9] = UInt8(truncatingIfNeeded: ack >> 16)
        bytes[10] = UInt8(truncatingIfNeeded: ack >>  8)
        bytes[11] = UInt8(truncatingIfNeeded: ack)
        bytes[12] = 0x50
        bytes[13] = TCPFlags.rst.rawValue | (seq != 0 ? TCPFlags.ack.rawValue : 0)
        bytes[14] = 0x00; bytes[15] = 0x00  // window 0
        bytes[16] = 0x00; bytes[17] = 0x00  // checksum placeholder
        bytes[18] = 0x00; bytes[19] = 0x00

        return bytes
    }
}
