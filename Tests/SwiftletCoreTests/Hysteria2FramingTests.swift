//===----------------------------------------------------------------------===//
//
//  Hysteria2FramingTests.swift
//  SwiftletCore — QUIC Varint + Hysteria 2 Framing Unit Tests
//
//  Validates:
//  • QUIC varint encode/decode round‑trip across all boundary values
//  • Correct byte‑length selection (1/2/4/8) per RFC 9000 §16
//  • Truncated varint decoding throws expected errors
//  • Auth header contains all required pseudo‑header fields
//  • TCP request frame has 0x401 command ID, correct address, and padding
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - QUIC Varint Encode

@Suite("QUICVarint — Encode")
struct QUICVarintEncodeTests {

    @Test func zeroEncodesToOneByte() {
        let bytes = QUICVarint.encode(0)
        #expect(bytes.count == 1)
        #expect(bytes[0] == 0x00)
    }

    @Test func max1ByteEncodesToOneByte() {
        let bytes = QUICVarint.encode(63)
        #expect(bytes.count == 1)
        #expect(bytes[0] == 0x3F)
    }

    @Test func min2ByteEncodesToTwoBytes() {
        let bytes = QUICVarint.encode(64)
        #expect(bytes.count == 2)
        // 64 = 0x40 → top 2 bits = 01, remaining = 00_0000_0100_0000
        #expect(bytes[0] == 0x40) // 01_000000
        #expect(bytes[1] == 0x40) // 01000000
    }

    @Test func max2ByteEncodesToTwoBytes() {
        let bytes = QUICVarint.encode(16_383)
        #expect(bytes.count == 2)
        #expect(bytes[0] == 0x7F) // 01_111111
        #expect(bytes[1] == 0xFF)
    }

    @Test func min4ByteEncodesToFourBytes() {
        let bytes = QUICVarint.encode(16_384)
        #expect(bytes.count == 4)
        #expect((bytes[0] & 0xC0) == 0x80) // top 2 bits = 10
    }

    @Test func max4ByteEncodesToFourBytes() {
        let bytes = QUICVarint.encode(1_073_741_823)
        #expect(bytes.count == 4)
        #expect((bytes[0] & 0xC0) == 0x80)
        #expect(bytes[1] == 0xFF)
        #expect(bytes[2] == 0xFF)
        #expect(bytes[3] == 0xFF)
    }

    @Test func min8ByteEncodesToEightBytes() {
        let bytes = QUICVarint.encode(1_073_741_824)
        #expect(bytes.count == 8)
        #expect((bytes[0] & 0xC0) == 0xC0) // top 2 bits = 11
    }

    @Test func encodedLengthFromFirstByte() {
        #expect(QUICVarint.encodedLength(from: 0x00) == 1)
        #expect(QUICVarint.encodedLength(from: 0x3F) == 1)
        #expect(QUICVarint.encodedLength(from: 0x40) == 2)
        #expect(QUICVarint.encodedLength(from: 0x7F) == 2)
        #expect(QUICVarint.encodedLength(from: 0x80) == 4)
        #expect(QUICVarint.encodedLength(from: 0xBF) == 4)
        #expect(QUICVarint.encodedLength(from: 0xC0) == 8)
        #expect(QUICVarint.encodedLength(from: 0xFF) == 8)
    }
}

// MARK: - QUIC Varint Decode

@Suite("QUICVarint — Decode")
struct QUICVarintDecodeTests {

    @Test func roundTripAcrossBoundaries() throws {
        let values: [UInt64] = [
            0, 1, 42,
            63,          // max 1‑byte
            64,          // min 2‑byte
            255, 1000,
            16_383,      // max 2‑byte
            16_384,      // min 4‑byte
            1_000_000,
            1_073_741_823, // max 4‑byte
            1_073_741_824, // min 8‑byte
            0x3FFF_FFFF_FFFF_FFFF, // large 8‑byte
        ]

        for value in values {
            let encoded  = QUICVarint.encode(value)
            let (decoded, consumed) = try QUICVarint.decode(Data(encoded))
            #expect(decoded == value, "Round‑trip failed for \(value)")
            #expect(consumed == encoded.count)
        }
    }

    @Test func decodeEmptyDataThrows() {
        #expect(throws: QUICVarintError.insufficientData(needed: 1, available: 0)) {
            _ = try QUICVarint.decode(Data())
        }
    }

    @Test func decodeTruncated2ByteThrows() {
        let data = Data([0x40]) // declares 2 bytes, only 1 provided
        #expect(throws: QUICVarintError.insufficientData(needed: 2, available: 1)) {
            _ = try QUICVarint.decode(data)
        }
    }

    @Test func decodeTruncated4ByteThrows() {
        let data = Data([0x80, 0x00, 0x00]) // declares 4 bytes, only 3
        #expect(throws: QUICVarintError.insufficientData(needed: 4, available: 3)) {
            _ = try QUICVarint.decode(data)
        }
    }

    @Test func decodeReturnsCorrectConsumedCount() throws {
        // Encode value 42 (1 byte) followed by extra data.
        var data = Data(QUICVarint.encode(42))
        data.append(contentsOf: [0xFF, 0xFF]) // trailing garbage

        let (value, consumed) = try QUICVarint.decode(data)
        #expect(value == 42)
        #expect(consumed == 1) // only 1 byte consumed, trailer ignored
    }
}

// MARK: - Auth Header

@Suite("Hysteria2HandshakeBuilder — Auth")
struct Hysteria2AuthHeaderTests {

    @Test func authHeaderIsNonEmpty() {
        let frame = Hysteria2HandshakeBuilder.buildAuthHeader(
            authSecret: "test-secret-key",
            maxRxBps: 0,
            paddingLength: 32
        )
        #expect(!frame.isEmpty)
    }

    @Test func authHeaderContainsRequiredPseudoHeaders() {
        let frame = Hysteria2HandshakeBuilder.buildAuthHeader(
            authSecret: "my-auth-secret",
            maxRxBps: 1_000_000,
            paddingLength: 16
        )

        let frameString = String(data: frame, encoding: .utf8) ?? ""
        #expect(frameString.contains(":method"))
        #expect(frameString.contains("POST"))
        #expect(frameString.contains(":path"))
        #expect(frameString.contains("/auth"))
        #expect(frameString.contains(":host"))
        #expect(frameString.contains("hysteria"))
        #expect(frameString.contains("Hysteria-Auth"))
        #expect(frameString.contains("my-auth-secret"))
        #expect(frameString.contains("Hysteria-CC-RX"))
        #expect(frameString.contains("1000000"))
    }

    @Test func authHeaderStartsWithVarintLength() {
        let frame = Hysteria2HandshakeBuilder.buildAuthHeader(
            authSecret: "secret",
            maxRxBps: 0,
            paddingLength: 8
        )

        // First byte(s) should be a valid QUIC varint encoding the
        // total headers block length.
        let firstByte = frame[0]
        let varintLen = QUICVarint.encodedLength(from: firstByte)
        #expect(varintLen >= 1)

        // Decode the length prefix.
        let (totalLen, _) = try! QUICVarint.decode(frame)
        // The remaining bytes after the length prefix equal totalLen.
        #expect(frame.count - varintLen == Int(totalLen))
    }

    @Test func authHeaderWithZeroPadding() {
        let frame = Hysteria2HandshakeBuilder.buildAuthHeader(
            authSecret: "no-pad",
            maxRxBps: 0,
            paddingLength: 0
        )
        let str = String(data: frame, encoding: .utf8) ?? ""
        #expect(str.contains("Hysteria-Padding"))
    }
}

// MARK: - TCP Request Frame

@Suite("Hysteria2HandshakeBuilder — TCP Request")
struct Hysteria2TCPRequestTests {

    @Test func tcpRequestStartsWith0x401Command() throws {
        let frame = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "example.com",
            port: 443,
            paddingLength: 0
        )

        // First varint must decode to 0x401.
        let (cmd, consumed) = try QUICVarint.decode(frame)
        #expect(cmd == 0x401)
        #expect(consumed > 0)
    }

    @Test func tcpRequestContainsAddressString() {
        let frame = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "api.github.com",
            port: 443,
            paddingLength: 0
        )

        let str = String(data: frame, encoding: .utf8) ?? ""
        #expect(str.contains("api.github.com:443"))
    }

    @Test func tcpRequestContainsIPAddress() {
        let frame = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "10.0.0.1",
            port: 8080,
            paddingLength: 0
        )

        let str = String(data: frame, encoding: .utf8) ?? ""
        #expect(str.contains("10.0.0.1:8080"))
    }

    @Test func tcpRequestPaddingIncreasesSize() {
        let f0  = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "example.com", port: 443, paddingLength: 0
        )
        let f64 = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "example.com", port: 443, paddingLength: 64
        )
        #expect(f64.count > f0.count)
        #expect(f64.count - f0.count >= 64)
    }

    @Test func tcpRequestCompletelyParsable() throws {
        let frame = Hysteria2HandshakeBuilder.buildTCPRequest(
            address: "host.example.com",
            port: 8443,
            paddingLength: 32
        )

        var offset = 0

        // 1. Command ID
        let (cmd, cmdLen) = try QUICVarint.decode(
            frame.subdata(in: offset ..< frame.count)
        )
        #expect(cmd == 0x401)
        offset += cmdLen

        // 2. Address length
        let (addrLen, addrLenSize) = try QUICVarint.decode(
            frame.subdata(in: offset ..< frame.count)
        )
        offset += addrLenSize

        // 3. Address bytes
        let addrEnd = offset + Int(addrLen)
        let addrBytes = frame.subdata(in: offset ..< addrEnd)
        let addrString = String(data: addrBytes, encoding: .utf8)!
        #expect(addrString == "host.example.com:8443")
        offset = addrEnd

        // 4. Padding length
        let (padLen, padLenSize) = try QUICVarint.decode(
            frame.subdata(in: offset ..< frame.count)
        )
        offset += padLenSize
        #expect(padLen == 32)

        // 5. Padding bytes
        let padEnd = offset + Int(padLen)
        #expect(padEnd <= frame.count)
    }

    @Test func tcpRequestCommandConstantIsCorrect() {
        #expect(Hysteria2HandshakeBuilder.tcpRequestCommand == 0x401)
    }
}

// MARK: - Error Types

@Suite("QUICVarintError")
struct QUICVarintErrorTests {

    @Test func errorEquality() {
        let e1 = QUICVarintError.insufficientData(needed: 2, available: 1)
        let e2 = QUICVarintError.insufficientData(needed: 2, available: 1)
        let e3 = QUICVarintError.insufficientData(needed: 4, available: 1)
        #expect(e1 == e2)
        #expect(e1 != e3)
        #expect(e1 != QUICVarintError.invalidEncoding(0xFF))
    }
}
