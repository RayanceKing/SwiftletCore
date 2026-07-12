//===----------------------------------------------------------------------===//
//
//  QUICVarint.swift
//  SwiftletCore — QUIC Variable‑Length Integer Codec (RFC 9000 §16)
//
//  Encodes and decodes the QUIC transport parameter varint format where
//  the top two bits of the first byte encode the total length:
//
//    • `00` → 1 byte  (6‑bit value, 0 … 63)
//    • `01` → 2 bytes (14‑bit value, 0 … 16 383)
//    • `10` → 4 bytes (30‑bit value, 0 … 1 073 741 823)
//    • `11` → 8 bytes (62‑bit value, 0 … 4 611 686 018 427 387 903)
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - QUIC Varint

/// RFC 9000 §16 variable‑length integer encoder / decoder.
public enum QUICVarint {

    // MARK: - Encoding Boundaries

    public static let max1Byte:  UInt64 = 63
    public static let max2Byte:  UInt64 = 16_383
    public static let max4Byte:  UInt64 = 1_073_741_823
    public static let max8Byte:  UInt64 = 4_611_686_018_427_387_903

    // MARK: - Encode

    /// Encodes a `UInt64` into the QUIC varint wire format.
    ///
    /// - Parameter value: The value to encode (must be ≤ `max8Byte`).
    /// - Returns: 1, 2, 4, or 8 bytes.
    public static func encode(_ value: UInt64) -> [UInt8] {
        precondition(value <= max8Byte, "Value \(value) exceeds QUIC varint max")

        switch value {
        case 0 ... max1Byte:
            return [UInt8(value & 0x3F)]

        case (max1Byte + 1) ... max2Byte:
            let v = UInt16(value)
            return [
                UInt8((v >> 8) & 0x3F) | 0x40,
                UInt8( v       & 0xFF),
            ]

        case (max2Byte + 1) ... max4Byte:
            let v = UInt32(value)
            return [
                UInt8((v >> 24) & 0x3F) | 0x80,
                UInt8((v >> 16) & 0xFF),
                UInt8((v >>  8) & 0xFF),
                UInt8( v        & 0xFF),
            ]

        default: // 8‑byte
            return [
                UInt8((value >> 56) & 0x3F) | 0xC0,
                UInt8((value >> 48) & 0xFF),
                UInt8((value >> 40) & 0xFF),
                UInt8((value >> 32) & 0xFF),
                UInt8((value >> 24) & 0xFF),
                UInt8((value >> 16) & 0xFF),
                UInt8((value >>  8) & 0xFF),
                UInt8( value        & 0xFF),
            ]
        }
    }

    // MARK: - Decode

    /// Decodes a QUIC varint from raw bytes.
    ///
    /// - Parameter data: The raw bytes starting at the varint.
    /// - Returns: A tuple of `(decodedValue, bytesConsumed)`.
    /// - Throws: `QUICVarintError` if the data is truncated.
    public static func decode(_ data: Data) throws -> (value: UInt64, consumed: Int) {
        guard data.count >= 1 else {
            throw QUICVarintError.insufficientData(needed: 1, available: data.count)
        }

        let firstByte = data[0]
        let length = encodedLength(from: firstByte)

        guard data.count >= length else {
            throw QUICVarintError.insufficientData(
                needed: length, available: data.count
            )
        }

        let value: UInt64
        switch length {
        case 1:
            value = UInt64(firstByte & 0x3F)

        case 2:
            value = UInt64(firstByte & 0x3F) << 8
                  | UInt64(data[1])

        case 4:
            value = UInt64(firstByte & 0x3F) << 24
                  | UInt64(data[1]) << 16
                  | UInt64(data[2]) <<  8
                  | UInt64(data[3])

        case 8:
            value = UInt64(firstByte & 0x3F) << 56
                  | UInt64(data[1]) << 48
                  | UInt64(data[2]) << 40
                  | UInt64(data[3]) << 32
                  | UInt64(data[4]) << 24
                  | UInt64(data[5]) << 16
                  | UInt64(data[6]) <<  8
                  | UInt64(data[7])

        default:
            throw QUICVarintError.invalidEncoding(firstByte)
        }

        return (value, length)
    }

    /// Returns the encoded byte length by inspecting the top two bits.
    public static func encodedLength(from firstByte: UInt8) -> Int {
        switch firstByte >> 6 {
        case 0:  return 1
        case 1:  return 2
        case 2:  return 4
        default: return 8
        }
    }
}

// MARK: - Errors

public enum QUICVarintError: Error, Sendable, Equatable {
    case insufficientData(needed: Int, available: Int)
    case invalidEncoding(UInt8)
}
