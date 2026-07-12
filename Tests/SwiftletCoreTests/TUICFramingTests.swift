//===----------------------------------------------------------------------===//
//
//  TUICFramingTests.swift
//  SwiftletCore — TUIC v5 Frame Serialization & Decoding Unit Tests
//
//  Validates:
//  • Authenticate frame is exactly 18 bytes with correct field offsets
//  • Connect frame handles IPv4 / IPv6 / domain address types correctly
//  • Packet frame encodes session ID + length in big‑endian
//  • Disconnect and Heartbeat fixed‑size frames
//  • Round‑trip encode → decode for all five frame types
//  • Partial‑read semantics: decoder returns nil without consuming
//    bytes when the buffer is incomplete
//  • Invalid type / address bytes throw parse errors
//  • UUID helper and IPv4/IPv6 address parsers
//  • Buffer reader index integrity after nil decode
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - Frame Type Enum

@Suite("TUICFrameType")
struct TUICFrameTypeTests {

    @Test func rawValues() {
        #expect(TUICFrameType.authenticate.rawValue == 0x00)
        #expect(TUICFrameType.connect.rawValue      == 0x01)
        #expect(TUICFrameType.packet.rawValue       == 0x02)
        #expect(TUICFrameType.disconnect.rawValue   == 0x03)
        #expect(TUICFrameType.heartbeat.rawValue    == 0x04)
    }

    @Test func allCasesCoverage() {
        let all = TUICFrameType.allCases
        #expect(all.count == 5)
        #expect(all.contains(.authenticate))
        #expect(all.contains(.connect))
        #expect(all.contains(.packet))
        #expect(all.contains(.disconnect))
        #expect(all.contains(.heartbeat))
    }

    @Test func equatability() {
        #expect(TUICFrameType.authenticate == TUICFrameType.authenticate)
        #expect(TUICFrameType.authenticate != TUICFrameType.connect)
    }
}

// MARK: - Address Type Enum

@Suite("TUICAddressType")
struct TUICAddressTypeTests {

    @Test func rawValues() {
        #expect(TUICAddressType.ipv4.rawValue   == 0x00)
        #expect(TUICAddressType.ipv6.rawValue   == 0x01)
        #expect(TUICAddressType.domain.rawValue == 0x02)
    }
}

// MARK: - UUID Helper

@Suite("TUIC UUID Helper")
struct TUICUUIDHelperTests {

    @Test func produces16Bytes() {
        let uuid = UUID()
        let bytes = TUICFrameEncoder.uuidBytes(from: uuid)
        #expect(bytes.count == 16)
    }

    @Test func roundTripsThroughUUID() {
        let original = UUID()
        let bytes = TUICFrameEncoder.uuidBytes(from: original)
        let tuple: uuid_t = (
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        )
        let restored = UUID(uuid: tuple)
        #expect(restored == original)
    }

    @Test func differentUUIDsProduceDifferentBytes() {
        let a = UUID()
        let b = UUID()
        #expect(TUICFrameEncoder.uuidBytes(from: a)
            != TUICFrameEncoder.uuidBytes(from: b))
    }
}

// MARK: - IPv4 Parser

@Suite("TUIC IPv4 Parser")
struct TUICIPv4ParserTests {

    @Test func parsesValidIPv4() {
        let result = TUICFrameEncoder.parseIPv4("192.168.1.1")
        #expect(result == [192, 168, 1, 1])
    }

    @Test func parsesAllZeros() {
        let result = TUICFrameEncoder.parseIPv4("0.0.0.0")
        #expect(result == [0, 0, 0, 0])
    }

    @Test func parsesAll255() {
        let result = TUICFrameEncoder.parseIPv4("255.255.255.255")
        #expect(result == [255, 255, 255, 255])
    }

    @Test func rejectsTooFewComponents() {
        #expect(TUICFrameEncoder.parseIPv4("192.168.1") == nil)
    }

    @Test func rejectsTooManyComponents() {
        #expect(TUICFrameEncoder.parseIPv4("1.2.3.4.5") == nil)
    }

    @Test func rejectsOutOfRangeOctet() {
        #expect(TUICFrameEncoder.parseIPv4("256.0.0.0") == nil)
    }

    @Test func rejectsNonNumeric() {
        #expect(TUICFrameEncoder.parseIPv4("abc.def.ghi.jkl") == nil)
    }
}

// MARK: - IPv6 Parser

@Suite("TUIC IPv6 Parser")
struct TUICIPv6ParserTests {

    @Test func parsesFullIPv6() {
        let result = TUICFrameEncoder.parseIPv6(
            "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        )
        #expect(result != nil)
        #expect(result!.count == 16)
    }

    @Test func parsesLoopback() {
        let result = TUICFrameEncoder.parseIPv6("::1")
        #expect(result != nil)
        #expect(result!.count == 16)
    }

    @Test func rejectsNonsense() {
        let result = TUICFrameEncoder.parseIPv6("not-an-ip")
        #expect(result == nil)
    }

    @Test func manualParserHandlesAbbreviation() {
        let result = TUICFrameEncoder.parseIPv6("::1")
        #expect(result != nil)
        #expect(result!.count == 16)
    }
}

// MARK: - Frame Type Accessor

@Suite("TUICFrame — frameType Accessor")
struct TUICFrameTypeAccessorTests {

    @Test func authenticateHasCorrectType() {
        let frame = TUICFrame.authenticate(uuid: UUID(), udpMode: 0)
        #expect(frame.frameType == .authenticate)
    }

    @Test func connectHasCorrectType() {
        let frame = TUICFrame.connect(
            addressType: .domain, address: "example.com", port: 443
        )
        #expect(frame.frameType == .connect)
    }

    @Test func packetHasCorrectType() {
        let frame = TUICFrame.packet(sessionID: 1, payload: Data())
        #expect(frame.frameType == .packet)
    }

    @Test func disconnectHasCorrectType() {
        let frame = TUICFrame.disconnect(sessionID: 42)
        #expect(frame.frameType == .disconnect)
    }

    @Test func heartbeatHasCorrectType() {
        #expect(TUICFrame.heartbeat.frameType == .heartbeat)
    }
}

// MARK: - Sizes

@Suite("TUICFrameEncoder — Constants")
struct TUICFrameEncoderConstantsTests {

    @Test func authenticateSize() {
        #expect(TUICFrameEncoder.authenticateSize == 18)
    }

    @Test func connectMinSize() {
        #expect(TUICFrameEncoder.connectMinSize == 8)
    }

    @Test func disconnectSize() {
        #expect(TUICFrameEncoder.disconnectSize == 3)
    }

    @Test func heartbeatSize() {
        #expect(TUICFrameEncoder.heartbeatSize == 1)
    }

    @Test func packetHeaderSize() {
        #expect(TUICFrameEncoder.packetHeaderSize == 5)
    }
}

// MARK: - Authenticate Frame Encode

@Suite("TUIC — Authenticate Frame Encode (0x00)")
struct TUICAuthenticateEncodeTests {

    private let testUUID = UUID(uuidString: "DEADBEEF-1234-5678-9ABC-DEF012345678")!

    @Test func encodeProduces18Bytes() {
        let buffer = TUICFrameEncoder.encode(
            .authenticate(uuid: testUUID, udpMode: 0x01)
        )
        #expect(buffer.readableBytes == 18)
    }

    @Test func firstByteIs0x00() {
        let buffer = TUICFrameEncoder.encode(
            .authenticate(uuid: testUUID, udpMode: 0x00)
        )
        guard let type: UInt8 = buffer.getInteger(at: 0) else {
            Issue.record("Could not read type byte")
            return
        }
        #expect(type == 0x00)
    }

    @Test func uuidAtCorrectOffset() {
        let buffer = TUICFrameEncoder.encode(
            .authenticate(uuid: testUUID, udpMode: 0x00)
        )
        // UUID bytes should be at offset 1..<17.
        guard let storedUUIDBytes = buffer.getBytes(at: 1, length: 16) else {
            Issue.record("Could not read UUID bytes")
            return
        }
        #expect(storedUUIDBytes == TUICFrameEncoder.uuidBytes(from: testUUID))
    }

    @Test func udpModeAtCorrectOffset() {
        let buffer = TUICFrameEncoder.encode(
            .authenticate(uuid: testUUID, udpMode: 0x01)
        )
        guard let mode: UInt8 = buffer.getInteger(at: 17) else {
            Issue.record("Could not read UDP mode byte")
            return
        }
        #expect(mode == 0x01)
    }

    @Test func udpModeDefaultEnabled() {
        let buffer = TUICFrameEncoder.encode(
            .authenticate(uuid: testUUID, udpMode: 0x01)
        )
        guard let mode: UInt8 = buffer.getInteger(at: 17) else {
            Issue.record("Could not read UDP mode byte")
            return
        }
        #expect(mode == 0x01)
    }
}

// MARK: - Connect Frame Encode

@Suite("TUIC — Connect Frame Encode (0x01)")
struct TUICConnectEncodeTests {

    @Test func ipv4ConnectProduces8Bytes() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "10.0.0.1", port: 8080)
        )
        #expect(buffer.readableBytes == 8)
    }

    @Test func ipv4ConnectTypeByte() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "10.0.0.1", port: 8080)
        )
        guard let type: UInt8 = buffer.getInteger(at: 0) else {
            Issue.record("Missing type byte")
            return
        }
        #expect(type == 0x01)
    }

    @Test func ipv4ConnectAddressTypeByte() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "10.0.0.1", port: 8080)
        )
        guard let at: UInt8 = buffer.getInteger(at: 1) else {
            Issue.record("Missing address type byte")
            return
        }
        #expect(at == 0x00)
    }

    @Test func ipv4ConnectAddressBytes() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "172.16.254.1", port: 8080)
        )
        guard let addr = buffer.getBytes(at: 2, length: 4) else {
            Issue.record("Missing address bytes")
            return
        }
        #expect(addr == [172, 16, 254, 1])
    }

    @Test func ipv4ConnectPortBigEndian() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "10.0.0.1", port: 0x01BB) // 443
        )
        guard let port: UInt16 = buffer.getInteger(
            at: 6, endianness: .big, as: UInt16.self
        ) else {
            Issue.record("Missing port")
            return
        }
        #expect(port == 443)
    }

    @Test func ipv6ConnectProduces20Bytes() {
        let buffer = TUICFrameEncoder.encode(
            .connect(
                addressType: .ipv6,
                address: "2001:db8::1",
                port: 443
            )
        )
        #expect(buffer.readableBytes == 20)
    }

    @Test func domainConnectEncodesLengthPrefix() {
        let buffer = TUICFrameEncoder.encode(
            .connect(
                addressType: .domain,
                address: "example.com",
                port: 443
            )
        )
        guard let domainLen: UInt8 = buffer.getInteger(at: 2) else {
            Issue.record("Missing domain length")
            return
        }
        #expect(domainLen == 11) // "example.com" is 11 bytes
    }

    @Test func domainConnectEncodesDomainBytes() {
        let buffer = TUICFrameEncoder.encode(
            .connect(
                addressType: .domain,
                address: "test.local",
                port: 443
            )
        )
        guard let domainLen: UInt8 = buffer.getInteger(at: 2) else {
            Issue.record("Missing domain length")
            return
        }
        let domainBytes = buffer.getBytes(at: 3, length: Int(domainLen)) ?? []
        let domain = String(decoding: domainBytes, as: UTF8.self)
        #expect(domain == "test.local")
    }

    @Test func domainConnectPortBigEndian() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .domain, address: "x.io", port: 9999)
        )
        let domainLen = buffer.getInteger(at: 2, as: UInt8.self) ?? 0
        let portOffset = 3 + Int(domainLen)
        guard let port: UInt16 = buffer.getInteger(
            at: portOffset, endianness: .big, as: UInt16.self
        ) else {
            Issue.record("Missing port")
            return
        }
        #expect(port == 9999)
    }

    @Test func domainConnectTotalSizeCorrect() {
        let buffer = TUICFrameEncoder.encode(
            .connect(addressType: .domain, address: "a.co", port: 80)
        )
        // "a.co" = 4 bytes → total = 1 + 1 + 1 + 4 + 2 = 9
        #expect(buffer.readableBytes == 9)
    }
}

// MARK: - Packet Frame Encode

@Suite("TUIC — Packet Frame Encode (0x02)")
struct TUICPacketEncodeTests {

    @Test func emptyPayloadPacket() {
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 1, payload: Data())
        )
        #expect(buffer.readableBytes == 5) // header only
    }

    @Test func typeByteIs0x02() {
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 1, payload: Data())
        )
        guard let type: UInt8 = buffer.getInteger(at: 0) else {
            Issue.record("Missing type")
            return
        }
        #expect(type == 0x02)
    }

    @Test func sessionIDBigEndian() {
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 0x1234, payload: Data([0xAA]))
        )
        guard let sid: UInt16 = buffer.getInteger(
            at: 1, endianness: .big, as: UInt16.self
        ) else {
            Issue.record("Missing session ID")
            return
        }
        #expect(sid == 0x1234)
    }

    @Test func lengthFieldBigEndian() {
        let payload = Data([UInt8](repeating: 0xCC, count: 100))
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 7, payload: payload)
        )
        guard let len: UInt16 = buffer.getInteger(
            at: 3, endianness: .big, as: UInt16.self
        ) else {
            Issue.record("Missing length")
            return
        }
        #expect(len == 100)
    }

    @Test func payloadAppendedAfterHeader() {
        let payload = Data("TUIC relay payload".utf8)
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 42, payload: payload)
        )
        guard let storedPayload = buffer.getBytes(
            at: 5, length: payload.count
        ) else {
            Issue.record("Missing payload")
            return
        }
        #expect(Data(storedPayload) == payload)
    }

    @Test func totalSizeMatchesHeaderPlusPayload() {
        let payload = Data([UInt8](repeating: 0x77, count: 255))
        let buffer = TUICFrameEncoder.encode(
            .packet(sessionID: 1, payload: payload)
        )
        #expect(buffer.readableBytes == 5 + payload.count)
    }
}

// MARK: - Disconnect Frame Encode

@Suite("TUIC — Disconnect Frame Encode (0x03)")
struct TUICDisconnectEncodeTests {

    @Test func encodeProduces3Bytes() {
        let buffer = TUICFrameEncoder.encode(
            .disconnect(sessionID: 42)
        )
        #expect(buffer.readableBytes == 3)
    }

    @Test func typeByteIs0x03() {
        let buffer = TUICFrameEncoder.encode(
            .disconnect(sessionID: 0)
        )
        guard let type: UInt8 = buffer.getInteger(at: 0) else {
            Issue.record("Missing type")
            return
        }
        #expect(type == 0x03)
    }

    @Test func sessionIDBigEndian() {
        let buffer = TUICFrameEncoder.encode(
            .disconnect(sessionID: 0xAABB)
        )
        guard let sid: UInt16 = buffer.getInteger(
            at: 1, endianness: .big, as: UInt16.self
        ) else {
            Issue.record("Missing session ID")
            return
        }
        #expect(sid == 0xAABB)
    }
}

// MARK: - Heartbeat Frame Encode

@Suite("TUIC — Heartbeat Frame Encode (0x04)")
struct TUICHeartbeatEncodeTests {

    @Test func encodeProduces1Byte() {
        let buffer = TUICFrameEncoder.encode(.heartbeat)
        #expect(buffer.readableBytes == 1)
    }

    @Test func singleByteIs0x04() {
        let buffer = TUICFrameEncoder.encode(.heartbeat)
        guard let type: UInt8 = buffer.getInteger(at: 0) else {
            Issue.record("Missing type")
            return
        }
        #expect(type == 0x04)
    }
}

// MARK: - Round‑Trip: Encode → Decode

@Suite("TUIC — Round‑Trip Encode → Decode")
struct TUICRoundTripTests {

    @Test func authenticateRoundTrip() throws {
        let uuid = UUID()
        let original = TUICFrame.authenticate(uuid: uuid, udpMode: 1)
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .authenticate(let dUUID, let dMode) = decoded else {
            Issue.record("Wrong frame type: \(String(describing: decoded))")
            return
        }
        #expect(dUUID == uuid)
        #expect(dMode == 1)
    }

    @Test func ipv4ConnectRoundTrip() throws {
        let original = TUICFrame.connect(
            addressType: .ipv4, address: "10.20.30.40", port: 9090
        )
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .connect(let at, let addr, let port) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(at == .ipv4)
        #expect(addr == "10.20.30.40")
        #expect(port == 9090)
    }

    @Test func ipv6ConnectRoundTrip() throws {
        let original = TUICFrame.connect(
            addressType: .ipv6,
            address: "2001:db8:85a3::8a2e:370:7334",
            port: 443
        )
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .connect(let at, _, let port) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(at == .ipv6)
        #expect(port == 443)
    }

    @Test func domainConnectRoundTrip() throws {
        let original = TUICFrame.connect(
            addressType: .domain,
            address: "sub.example.org",
            port: 8443
        )
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .connect(let at, let addr, let port) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(at == .domain)
        #expect(addr == "sub.example.org")
        #expect(port == 8443)
    }

    @Test func packetRoundTrip() throws {
        let payload = Data("TUIC stream payload data".utf8)
        let original = TUICFrame.packet(sessionID: 0x5678, payload: payload)
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .packet(let sid, let pld) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(sid == 0x5678)
        #expect(pld == payload)
    }

    @Test func packetEmptyPayloadRoundTrip() throws {
        let original = TUICFrame.packet(sessionID: 1, payload: Data())
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .packet(let sid, let pld) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(sid == 1)
        #expect(pld.isEmpty)
    }

    @Test func disconnectRoundTrip() throws {
        let original = TUICFrame.disconnect(sessionID: 0xDEAD)
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .disconnect(let sid) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(sid == 0xDEAD)
    }

    @Test func heartbeatRoundTrip() throws {
        var buffer = TUICFrameEncoder.encode(.heartbeat)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        #expect(decoded == .heartbeat)
    }
}

// MARK: - Partial‑Read (Nil‑on‑Incomplete) Semantics

@Suite("TUIC — Partial Read Handling")
struct TUICPartialReadTests {

    // MARK: Empty / Too‑short

    @Test func emptyBufferReturnsNil() throws {
        var buffer = ByteBuffer()
        let result = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        #expect(result == nil)
    }

    @Test func missingAuthenticateBytesReturnsNil() throws {
        let uuid = UUID()
        let full = TUICFrameEncoder.encode(
            .authenticate(uuid: uuid, udpMode: 0)
        )
        // Provide only 17 of the 18 needed bytes.
        var truncated = ByteBuffer(bytes: full.getBytes(at: 0, length: 17) ?? [])
        let result = try TUICStreamDecoder.decodeNextFrame(from: &truncated)
        #expect(result == nil)
    }

    @Test func missingConnectIPv4BytesReturnsNil() throws {
        let full = TUICFrameEncoder.encode(
            .connect(addressType: .ipv4, address: "1.2.3.4", port: 80)
        )
        // Provide 7 of 8 bytes.
        var truncated = ByteBuffer(bytes: full.getBytes(at: 0, length: 7) ?? [])
        let result = try TUICStreamDecoder.decodeNextFrame(from: &truncated)
        #expect(result == nil)
    }

    @Test func missingDomainLengthByteReturnsNil() throws {
        // Provide only type + addrType (2 bytes) — not enough to even
        // read the domain length prefix.
        let full = TUICFrameEncoder.encode(
            .connect(addressType: .domain, address: "example.com", port: 443)
        )
        var truncated = ByteBuffer(bytes: full.getBytes(at: 0, length: 2) ?? [])
        let result = try TUICStreamDecoder.decodeNextFrame(from: &truncated)
        #expect(result == nil)
    }

    @Test func truncatedDomainPayloadReturnsNil() throws {
        // Provide type + addrType + domainLen + partial domain.
        // "example.com" = 11 bytes → encode: 1+1+1+11+2 = 16 bytes.
        // Provide only 10 bytes — enough for header but not full domain.
        let full = TUICFrameEncoder.encode(
            .connect(addressType: .domain, address: "example.com", port: 443)
        )
        var truncated = ByteBuffer(bytes: full.getBytes(at: 0, length: 10) ?? [])
        let result = try TUICStreamDecoder.decodeNextFrame(from: &truncated)
        #expect(result == nil)
    }

    @Test func missingPacketHeaderBytesReturnsNil() throws {
        var buffer = ByteBuffer(bytes: [0x02, 0x00, 0x01]) // only 3 bytes
        let result = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        #expect(result == nil)
    }

    @Test func truncatedPacketPayloadReturnsNil() throws {
        // Encode a packet with 100 bytes of payload → 5 + 100 = 105 bytes.
        let payload = Data([UInt8](repeating: 0xAA, count: 100))
        let full = TUICFrameEncoder.encode(
            .packet(sessionID: 1, payload: payload)
        )
        // Provide only the header (5 bytes) — payload missing.
        var truncated = ByteBuffer(bytes: full.getBytes(at: 0, length: 5) ?? [])
        // This should succeed with empty payload since length=100 but
        // buffer only has 5 bytes. The decoder should return nil.
        let result = try TUICStreamDecoder.decodeNextFrame(from: &truncated)
        #expect(result == nil)
    }

    @Test func missingDisconnectBytesReturnsNil() throws {
        // Only 2 of 3 bytes.
        var buffer = ByteBuffer(bytes: [0x03, 0x00])
        let result = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        #expect(result == nil)
    }

    // MARK: Buffer Integrity

    @Test func nilDecodeDoesNotAdvanceReaderIndex() throws {
        // Provide an incomplete authenticate frame.
        var buffer = ByteBuffer(bytes: [0x00, 0x01, 0x02]) // 3 bytes
        let originalReader = buffer.readerIndex
        _ = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        #expect(buffer.readerIndex == originalReader)
    }

    @Test func nilDecodePreservesBufferContents() throws {
        let originalBytes: [UInt8] = [0x01, 0x02, 0x03]
        var buffer = ByteBuffer(bytes: originalBytes)
        _ = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        let remaining = buffer.getBytes(
            at: buffer.readerIndex,
            length: buffer.readableBytes
        )
        #expect(remaining == originalBytes)
    }

    // MARK: Consecutive Frames

    @Test func decodeTwoConsecutiveFrames() throws {
        // Encode two frames back‑to‑back in one buffer.
        let hb = TUICFrameEncoder.encode(.heartbeat)
        let disc = TUICFrameEncoder.encode(.disconnect(sessionID: 99))

        var combined = ByteBuffer()
        combined.writeBytes(hb.getBytes(at: 0, length: hb.readableBytes) ?? [])
        combined.writeBytes(disc.getBytes(at: 0, length: disc.readableBytes) ?? [])

        // Decode first frame.
        let frame1 = try TUICStreamDecoder.decodeNextFrame(from: &combined)
        #expect(frame1 == .heartbeat)

        // Decode second frame.
        let frame2 = try TUICStreamDecoder.decodeNextFrame(from: &combined)
        guard case .disconnect(let sid) = frame2 else {
            Issue.record("Expected disconnect, got \(String(describing: frame2))")
            return
        }
        #expect(sid == 99)
    }
}

// MARK: - Error Handling

@Suite("TUIC — Parse Error Handling")
struct TUICParseErrorTests {

    @Test func invalidTypeByteThrows() {
        var buffer = ByteBuffer(bytes: [0xFF])
        #expect(throws: TUICFrameParseError.self) {
            _ = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        }
    }

    @Test func invalidTypeByteErrorCarriesValue() {
        var buffer = ByteBuffer(bytes: [0xFE])
        do {
            _ = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
            Issue.record("Expected throw")
        } catch let error as TUICFrameParseError {
            if case .invalidFrameType(let raw) = error {
                #expect(raw == 0xFE)
            } else {
                Issue.record("Wrong error case: \(error)")
            }
        } catch {
            Issue.record("Wrong error type: \(error)")
        }
    }

    @Test func invalidAddressTypeThrows() {
        // Build a connect frame with an invalid address type byte.
        var buffer = ByteBuffer(bytes: [0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x50])
        #expect(throws: TUICFrameParseError.self) {
            _ = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
        }
    }

    @Test func parseErrorEquatability() {
        let e1 = TUICFrameParseError.invalidFrameType(0x05)
        let e2 = TUICFrameParseError.invalidFrameType(0x05)
        let e3 = TUICFrameParseError.invalidFrameType(0x06)
        let e4 = TUICFrameParseError.invalidAddressType(0xFF)

        #expect(e1 == e2)
        #expect(e1 != e3)
        #expect(e1 != e4)
    }
}

// MARK: - TUICFrame Equatability

@Suite("TUICFrame — Equatability")
struct TUICFrameEquatabilityTests {

    @Test func authenticateEquality() {
        let uuid = UUID()
        let a = TUICFrame.authenticate(uuid: uuid, udpMode: 0)
        let b = TUICFrame.authenticate(uuid: uuid, udpMode: 0)
        let c = TUICFrame.authenticate(uuid: UUID(), udpMode: 0)
        #expect(a == b)
        #expect(a != c)
    }

    @Test func connectEquality() {
        let a = TUICFrame.connect(
            addressType: .domain, address: "x.com", port: 80
        )
        let b = TUICFrame.connect(
            addressType: .domain, address: "x.com", port: 80
        )
        let c = TUICFrame.connect(
            addressType: .domain, address: "x.com", port: 443
        )
        #expect(a == b)
        #expect(a != c)
    }

    @Test func packetEquality() {
        let a = TUICFrame.packet(sessionID: 1, payload: Data([0xAA]))
        let b = TUICFrame.packet(sessionID: 1, payload: Data([0xAA]))
        let c = TUICFrame.packet(sessionID: 2, payload: Data([0xAA]))
        #expect(a == b)
        #expect(a != c)
    }

    @Test func differentTypesNotEqual() {
        #expect(TUICFrame.heartbeat != TUICFrame.disconnect(sessionID: 0))
    }
}

// MARK: - Performance: Large Packet Round‑Trip

@Suite("TUIC — Large Packet & Stress")
struct TUICLargePacketTests {

    @Test func largePayloadRoundTrip() throws {
        let payload = Data([UInt8](repeating: 0x42, count: 16_384)) // 16 KB
        let original = TUICFrame.packet(sessionID: 0xFFFF, payload: payload)
        var buffer = TUICFrameEncoder.encode(original)
        let decoded = try TUICStreamDecoder.decodeNextFrame(from: &buffer)

        guard case .packet(let sid, let pld) = decoded else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(sid == 0xFFFF)
        #expect(pld == payload)
    }

    @Test func manyHeartbeats() throws {
        var buffer = ByteBuffer()
        for _ in 0 ..< 100 {
            TUICFrameEncoder.encode(.heartbeat, into: &buffer)
        }
        #expect(buffer.readableBytes == 100)

        for _ in 0 ..< 100 {
            let frame = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
            #expect(frame == .heartbeat)
        }
        #expect(buffer.readableBytes == 0)
    }
}

// MARK: - Encode‑into‑Buffer Variant

@Suite("TUIC — Encode into Buffer Variant")
struct TUICEncodeIntoBufferTests {

    @Test func multipleFramesInOneBuffer() {
        var buffer = ByteBuffer()
        TUICFrameEncoder.encode(.heartbeat, into: &buffer)
        TUICFrameEncoder.encode(
            .disconnect(sessionID: 7), into: &buffer
        )
        TUICFrameEncoder.encode(
            .packet(sessionID: 3, payload: Data([0x01, 0x02])),
            into: &buffer
        )

        // 1 + 3 + (5 + 2) = 11 bytes
        #expect(buffer.readableBytes == 11)
    }
}
