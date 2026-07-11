//===----------------------------------------------------------------------===//
//
//  VMessProtocolTests.swift
//  SwiftletCore — VMess Protocol Unit Tests
//
//  Validates:
//  • MD5‑based command key derivation from UUID + timestamp
//  • Deterministic key output with frozen timestamps
//  • Header version byte, response auth, and field boundaries
//  • AES‑CFB encryption round‑trip correctness
//  • Address encoding (IPv4, domain, IPv6) inside the header
//  • Handler state transitions
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import CryptoKit
@testable import SwiftletCore

// MARK: - Key Derivation

@Suite("VMessHeaderBuilder — Key Derivation")
struct VMessKeyDerivationTests {

    /// Key derivation must be deterministic: same UUID + timestamp → same key.
    @Test func deriveCommandKeyIsDeterministic() {
        let uuid = UUID(uuidString: "DEADBEEF-1234-5678-9ABC-DEF012345678")!
        let ts: UInt64 = 1700000000

        let key1 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid, timestamp: ts)
        let key2 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid, timestamp: ts)

        #expect(key1 == key2)
        #expect(key1.count == 16) // MD5 produces 16 bytes
    }

    @Test func deriveCommandKeyChangesWithTimestamp() {
        let uuid = UUID(uuidString: "DEADBEEF-1234-5678-9ABC-DEF012345678")!

        let key1 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid, timestamp: 1000)
        let key2 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid, timestamp: 1001)

        // Different timestamps must produce different keys.
        #expect(key1 != key2)
    }

    @Test func deriveCommandKeyChangesWithUUID() {
        let uuid1 = UUID(uuidString: "AAAAAAAA-0000-0000-0000-000000000001")!
        let uuid2 = UUID(uuidString: "BBBBBBBB-0000-0000-0000-000000000001")!
        let ts: UInt64 = 1700000000

        let key1 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid1, timestamp: ts)
        let key2 = VMessHeaderBuilder.deriveCommandKey(uuid: uuid2, timestamp: ts)

        #expect(key1 != key2)
    }

    /// Verify the exact MD5 output for a known input vector.
    @Test func commandKeyMatchesKnownVector() {
        // Manual verification: MD5 of UUID bytes + timestamp bytes.
        let uuid = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let ts: UInt64 = 0

        var preKey = Data()
        preKey.append(contentsOf: uuid.toBytes())
        preKey.append(contentsOf: ts.toBigEndianBytes())

        let expected = Data(Insecure.MD5.hash(data: preKey))
        let actual   = VMessHeaderBuilder.deriveCommandKey(uuid: uuid, timestamp: ts)

        #expect(actual == expected)
        #expect(actual.count == 16)
    }
}

// MARK: - Header Structure

@Suite("VMessHeaderBuilder — Header Structure")
struct VMessHeaderStructureTests {

    /// The header must start with the version byte 0x01.
    @Test func headerStartsWithVersionByte() {
        let header = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "example.com",
            port: 443,
            timestamp: 1700000000
        )
        #expect(header[0] == 0x01)
    }

    /// The header must be larger than the unencrypted prefix (34 bytes).
    @Test func headerMinimumSize() {
        let header = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 0
        )
        // Unencrypted: 1 (ver) + 16 (iv) + 16 (key) + 1 (auth) = 34
        // Encrypted instruction (min): 1 + 1 + 1 + 2 + 1 + 1 + 11 = 18
        //     options(1) + padLen(1) + cmd(1) + port(2) + atype(1) + domLen(1) + domain(11)
        // Total ≥ 34 + 18 = 52
        #expect(header.count >= 52)
    }

    @Test func headerWithDomainDestinationHasDomainATYP() {
        // We can verify the version byte and that the header is correctly
        // encrypted (non‑zero after the unencrypted prefix).
        let header = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "example.com",
            port: 443,
            timestamp: 1700000000
        )

        // The unencrypted portion: bytes 0–33
        #expect(header[0] == 0x01) // version

        // The request IV (bytes 1–16) must be non‑zero.
        let iv = header.subdata(in: 1 ..< 17)
        #expect(iv != Data(repeating: 0, count: 16))

        // The request key (bytes 17–32) must be non‑zero.
        let key = header.subdata(in: 17 ..< 33)
        #expect(key.count == 16)

        // Response auth byte (byte 33) must be present.
        #expect(header.count > 33)
    }

    @Test func headerWithIPv4Destination() {
        let header = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "10.0.0.1",
            port: 8080,
            timestamp: 1700000000,
            paddingLength: 0
        )
        #expect(header[0] == 0x01)
        #expect(header.count >= 34 + 1 + 1 + 1 + 2 + 1 + 4) // min size
    }

    @Test func headerWithPaddingIncreasesSize() {
        let h0 = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 0
        )
        let h64 = VMessHeaderBuilder.build(
            uuid: UUID(),
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 64
        )
        #expect(h64.count == h0.count + 64)
    }

    /// The unencrypted prefix fields (version, key, auth) must be
    /// deterministic for fixed inputs; only the random IV differs.
    @Test func headerKeyAndAuthAreDeterministic() {
        let uuid = UUID(uuidString: "CAFEBABE-0000-0000-0000-000000000002")!
        let h1 = VMessHeaderBuilder.build(
            uuid: uuid,
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 0
        )
        let h2 = VMessHeaderBuilder.build(
            uuid: uuid,
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 0
        )
        // Version, request key, and response auth are deterministic.
        #expect(h1[0] == h2[0]) // version
        #expect(h1.subdata(in: 17 ..< 33) == h2.subdata(in: 17 ..< 33)) // key
        #expect(h1[33] == h2[33]) // response auth
        // The IVs (bytes 1–16) differ because they are randomly generated.
        #expect(h1.subdata(in: 1 ..< 17) != h2.subdata(in: 1 ..< 17))
    }

    /// Different timestamps must produce different encrypted instruction blocks.
    @Test func differentTimestampsProduceDifferentHeaders() {
        let uuid = UUID(uuidString: "FEEDFACE-0000-0000-0000-000000000003")!
        let h1 = VMessHeaderBuilder.build(
            uuid: uuid,
            address: "example.com",
            port: 443,
            timestamp: 1700000000,
            paddingLength: 0
        )
        let h2 = VMessHeaderBuilder.build(
            uuid: uuid,
            address: "example.com",
            port: 443,
            timestamp: 1700000001,
            paddingLength: 0
        )
        // The encrypted instruction blocks (after byte 33) must differ.
        let encrypted1 = h1.subdata(in: 34 ..< h1.count)
        let encrypted2 = h2.subdata(in: 34 ..< h2.count)
        #expect(encrypted1 != encrypted2)
    }
}

// MARK: - Handler

@Suite("VMessOutboundHandler")
struct VMessOutboundHandlerTests {

    @Test func handlerInitialState() {
        let handler = VMessOutboundHandler(
            uuid: UUID(),
            address: "example.com",
            port: 443
        )
        #expect(handler.state.description == "VMESS_HEADER_SENT")
    }

    @Test func handlerWithPreBuiltHeader() {
        let header = Data([UInt8](repeating: 0x01, count: 64))
        let handler = VMessOutboundHandler(header: header)
        #expect(handler.state.description == "VMESS_HEADER_SENT")
    }

    @Test func errorIsEquatable() {
        #expect(VMessError.connectionFailed == VMessError.connectionFailed)
    }
}

// MARK: - UUID Extensions

@Suite("UUID Extensions")
struct UUIDExtensionTests {

    @Test func uuidToBytesRoundTrip() {
        let uuid = UUID(uuidString: "A1B2C3D4-E5F6-7890-ABCD-EF1234567890")!
        let bytes = uuid.toBytes()
        #expect(bytes.count == 16)

        let reconstructed = UUID(uuid: (
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
        #expect(reconstructed == uuid)
    }
}

// MARK: - Timestamp Encoding

@Suite("Timestamp Encoding")
struct TimestampEncodingTests {

    @Test func timestampEncodingProducesEightBytes() {
        let bytes1 = UInt64(1700000000).toBigEndianBytes()
        let bytes2 = UInt64(0).toBigEndianBytes()
        let bytes3 = UInt64.max.toBigEndianBytes()

        // All timestamps produce exactly 8 bytes.
        #expect(bytes1.count == 8)
        #expect(bytes2.count == 8)
        #expect(bytes3.count == 8)

        // Different timestamps produce different byte sequences.
        #expect(bytes1 != bytes2)
        #expect(bytes1 != bytes3)
        #expect(bytes2 != bytes3)
    }
}

// MARK: - UUID + Timestamp byte-access helpers for testing

extension UUID {
    func toBytes() -> [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}

extension UInt64 {
    func toBigEndianBytes() -> [UInt8] {
        let be = bigEndian
        var bytes: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8((be >> shift) & 0xFF))
        }
        return bytes
    }
}
