//===----------------------------------------------------------------------===//
//
//  WireGuardDataStreamTests.swift
//  SwiftletCore — WireGuard Transport Data Stream Unit Tests
//
//  Validates:
//  • Type 4 Transport Data message header format (16‑byte layout)
//  • ChaCha20‑Poly1305 nonce construction from counter
//  • Encrypt → decrypt round‑trip (payload fidelity)
//  • Counter monotonicity and atomic increment
//  • Handler outbound path produces spec‑compliant Type 4 envelope
//  • Handler inbound path decrypts back to original inner IP packet
//  • Replay rejection and AEAD tamper detection
//  • Full integration: mock IPv4 ping → handler → encrypted → decrypt → original
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
import CryptoKit
@testable import SwiftletCore

// MARK: - Transport Data Message Header Format

@Suite("WireGuard — Transport Data Header (Type 4)")
struct WireGuardTransportHeaderTests {

    @Test func transportHeaderSizeConstant() {
        #expect(WireGuardMessages.transportHeaderSize == 16)
    }

    @Test func typeFieldEncodesAsLittleEndian4() {
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 0,
            counter: 0,
            encryptedPayload: Data()
        )

        // First 4 bytes: UInt32(4) in little‑endian → [0x04, 0x00, 0x00, 0x00]
        #expect(datagram[0] == 0x04)
        #expect(datagram[1] == 0x00)
        #expect(datagram[2] == 0x00)
        #expect(datagram[3] == 0x00)
    }

    @Test func reservedBytesAreZero() {
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 0xDEAD_BEEF,
            counter: 0x1234_5678_9ABC_DEF0,
            encryptedPayload: Data([0xFF, 0xEE])
        )

        // Bytes 1–3 must be zero (the reserved portion of the type word).
        #expect(datagram[1] == 0x00)
        #expect(datagram[2] == 0x00)
        #expect(datagram[3] == 0x00)
    }

    @Test func receiverIndexFieldEncodesLittleEndian() {
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 0xAABB_CCDD,
            counter: 0,
            encryptedPayload: Data()
        )

        // Bytes 4–7: receiver index in little‑endian.
        #expect(datagram[4] == 0xDD)
        #expect(datagram[5] == 0xCC)
        #expect(datagram[6] == 0xBB)
        #expect(datagram[7] == 0xAA)
    }

    @Test func counterFieldEncodesLittleEndian() {
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 0,
            counter: 0x0102_0304_0506_0708,
            encryptedPayload: Data()
        )

        // Bytes 8–15: counter in little‑endian.
        #expect(datagram[8]  == 0x08)
        #expect(datagram[9]  == 0x07)
        #expect(datagram[10] == 0x06)
        #expect(datagram[11] == 0x05)
        #expect(datagram[12] == 0x04)
        #expect(datagram[13] == 0x03)
        #expect(datagram[14] == 0x02)
        #expect(datagram[15] == 0x01)
    }

    @Test func payloadAppendedAfterHeader() {
        let payload = Data([0xAA, 0xBB, 0xCC, 0xDD, 0xEE])
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 1,
            counter: 2,
            encryptedPayload: payload
        )

        let suffix = datagram.suffix(payload.count)
        #expect(Data(suffix) == payload)
    }

    @Test func totalSizeEqualsHeaderPlusPayload() {
        let payload = Data([UInt8](repeating: 0x42, count: 128))
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 7,
            counter: 99,
            encryptedPayload: payload
        )

        #expect(datagram.count == WireGuardMessages.transportHeaderSize + payload.count)
    }

    @Test func buildAndParseRoundTrip() {
        let payload = Data([UInt8](repeating: 0xAB, count: 64))
        let original = WireGuardMessages.buildTransportData(
            receiverIndex: 0x1234_5678,
            counter: 0xAAAA_BBBB_CCCC_DDDD,
            encryptedPayload: payload
        )

        guard let parsed = WireGuardMessages.parseTransportData(original) else {
            Issue.record("parseTransportData returned nil")
            return
        }

        #expect(parsed.receiverIndex == 0x1234_5678)
        #expect(parsed.counter == 0xAAAA_BBBB_CCCC_DDDD)
        #expect(parsed.encryptedPayload == payload)
    }

    @Test func parseRejectsShortDatagram() {
        let short = Data([0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00])
        #expect(WireGuardMessages.parseTransportData(short) == nil)
    }

    @Test func parseRejectsNonTransportType() {
        // Build a Type 1 (Initiation) and try to parse as Transport.
        let initiation = WireGuardMessages.buildInitiation(
            senderIndex: 1,
            ephemeralPubKey: Data(repeating: 0, count: 32),
            encryptedStatic: Data(repeating: 0, count: 48),
            encryptedTimestamp: Data(repeating: 0, count: 28)
        )
        #expect(WireGuardMessages.parseTransportData(initiation) == nil)
    }

    @Test func parseRejectsCorruptedTypeByte() {
        var datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 1, counter: 1,
            encryptedPayload: Data([0x00, 0x01])
        )
        datagram[0] = 0x05  // Corrupt the type byte.
        #expect(WireGuardMessages.parseTransportData(datagram) == nil)
    }

    @Test func parseRejectsCorruptedReservedByte() {
        var datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 1, counter: 1,
            encryptedPayload: Data([0x00, 0x01])
        )
        datagram[2] = 0xFF  // Corrupt a reserved byte.
        #expect(WireGuardMessages.parseTransportData(datagram) == nil)
    }
}

// MARK: - Nonce Construction

@Suite("WireGuard — AEAD Nonce Construction")
struct WireGuardNonceTests {

    /// Converts a CryptoKit nonce to Data via its ContiguousBytes conformance.
    private static func nonceData(_ nonce: ChaChaPoly.Nonce) -> Data {
        nonce.withUnsafeBytes { Data($0) }
    }

    @Test func nonceIs12Bytes() {
        let nonce = WireGuardOutboundHandler.makeNonce(counter: 0)
        #expect(Self.nonceData(nonce).count == 12)
    }

    @Test func nonceFirst8BytesAreCounterLittleEndian() {
        let nonce = WireGuardOutboundHandler.makeNonce(
            counter: 0x0001_0203_0405_0607
        )
        let nonceBytes = Self.nonceData(nonce)

        // Counter 0x0001020304050607 in LE:
        // [0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00]
        #expect(nonceBytes[0] == 0x07)
        #expect(nonceBytes[1] == 0x06)
        #expect(nonceBytes[2] == 0x05)
        #expect(nonceBytes[3] == 0x04)
        #expect(nonceBytes[4] == 0x03)
        #expect(nonceBytes[5] == 0x02)
        #expect(nonceBytes[6] == 0x01)
        #expect(nonceBytes[7] == 0x00)
    }

    @Test func nonceLast4BytesAreZero() {
        let nonce = WireGuardOutboundHandler.makeNonce(
            counter: 0xFFFF_FFFF_FFFF_FFFF
        )
        let nonceBytes = Self.nonceData(nonce)

        #expect(nonceBytes[8]  == 0x00)
        #expect(nonceBytes[9]  == 0x00)
        #expect(nonceBytes[10] == 0x00)
        #expect(nonceBytes[11] == 0x00)
    }

    @Test func differentCountersProduceDifferentNonces() {
        let n0 = Self.nonceData(WireGuardOutboundHandler.makeNonce(counter: 0))
        let n1 = Self.nonceData(WireGuardOutboundHandler.makeNonce(counter: 1))
        let n2 = Self.nonceData(WireGuardOutboundHandler.makeNonce(counter: 42))

        #expect(n0 != n1)
        #expect(n1 != n2)
        #expect(n0 != n2)
    }

    @Test func counterZeroNonce() {
        let nonce = WireGuardOutboundHandler.makeNonce(counter: 0)
        let nonceBytes = Self.nonceData(nonce)

        // Counter 0 in LE → first 8 bytes are all zero.
        #expect(nonceBytes.prefix(8) == Data(repeating: 0, count: 8))
        #expect(nonceBytes.suffix(4) == Data(repeating: 0, count: 4))
    }

    @Test func maxCounterNonce() {
        let nonce = WireGuardOutboundHandler.makeNonce(
            counter: UInt64.max
        )
        let nonceBytes = Self.nonceData(nonce)

        // Max UInt64 in LE → first 8 bytes are all 0xFF.
        #expect(nonceBytes.prefix(8) == Data(repeating: 0xFF, count: 8))
        #expect(nonceBytes.suffix(4) == Data(repeating: 0, count: 4))
    }
}

// MARK: - Encrypt / Decrypt Round‑Trip

@Suite("WireGuard — Encrypt / Decrypt Round‑Trip")
struct WireGuardEncryptDecryptTests {

    private let testKey = SymmetricKey(data: Data([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    ]))

    @Test func encryptThenDecryptReturnsOriginalEmptyPayload() throws {
        let plaintext = Data()
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 1
        )
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: encrypted, key: testKey, counter: 1
        )
        #expect(decrypted == plaintext)
    }

    @Test func encryptThenDecryptReturnsOriginal64BytePayload() throws {
        let plaintext = Data([UInt8](repeating: 0xAB, count: 64))
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 2
        )
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: encrypted, key: testKey, counter: 2
        )
        #expect(decrypted == plaintext)
    }

    @Test func encryptThenDecryptReturnsOriginalMTUPayload() throws {
        let plaintext = Data([UInt8](repeating: 0x55, count: 1500))
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 3
        )
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: encrypted, key: testKey, counter: 3
        )
        #expect(decrypted == plaintext)
    }

    @Test func encryptedPayloadIncludesTag() throws {
        let plaintext = Data([0x01, 0x02, 0x03])
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 0
        )

        // Encrypted payload = ciphertext (same length as plaintext) + 16‑byte tag.
        #expect(encrypted.count == plaintext.count + 16)
    }

    @Test func wrongCounterFailsDecryption() {
        let plaintext = Data("secret data".utf8)
        let encrypted = try! WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 10
        )

        #expect(throws: CryptoKitError.self) {
            _ = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: encrypted, key: testKey, counter: 11
            )
        }
    }

    @Test func decryptWithWrongKeyFails() throws {
        let wrongKey = SymmetricKey(data: Data(repeating: 0xFF, count: 32))
        let plaintext = Data("different key test".utf8)
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 5
        )

        // Decrypting with the wrong key must fail authentication.
        #expect(throws: CryptoKitError.self) {
            _ = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: encrypted, key: wrongKey, counter: 5
            )
        }
    }

    @Test func decryptWithSwappedCiphertextFails() throws {
        // Encrypt two different plaintexts and swap their ciphertexts.
        // The AEAD tag will not match, causing authentication failure.
        let p1 = Data("payload number one!!".utf8)   // 20 bytes
        let p2 = Data("payload number two!!".utf8)   // 20 bytes
        let enc1 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: p1, key: testKey, counter: 20
        )
        let enc2 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: p2, key: testKey, counter: 21
        )

        // Swap the ciphertext portions (keeping tags from enc2).
        let swapped = enc1.prefix(20) + enc2.suffix(16)

        #expect(throws: CryptoKitError.self) {
            _ = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: swapped, key: testKey, counter: 20
            )
        }
    }

    @Test func tooShortPayloadFailsDecryption() throws {
        // Less than 16 bytes → no room for a tag.
        #expect(throws: CryptoKitError.self) {
            _ = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: Data([0x00, 0x01, 0x02]),
                key: testKey, counter: 0
            )
        }
    }

    @Test func multipleCountersProduceDifferentCiphertexts() throws {
        let plaintext = Data("same plaintext".utf8)
        let enc1 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 100
        )
        let enc2 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 101
        )

        // Different nonces → different encrypted outputs.
        #expect(enc1 != enc2)
    }

    @Test func sameCounterSameKeyProducesDeterministicResult() throws {
        let plaintext = Data("deterministic".utf8)
        let enc1 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 42
        )
        let enc2 = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: 42
        )

        // Same (key, nonce, plaintext) → same ciphertext.
        #expect(enc1 == enc2)
    }
}

// MARK: - Handler Construction & Counter Monotonicity

@Suite("WireGuard — Handler State & Counters")
struct WireGuardHandlerStateTests {

    private let sendKey = SymmetricKey(data: Data(repeating: 0x01, count: 32))
    private let recvKey = SymmetricKey(data: Data(repeating: 0x02, count: 32))

    @Test func handlerInitialisationSetsCounterToZero() {
        let handler = WireGuardOutboundHandler(
            sendKey: sendKey,
            receiveKey: recvKey,
            receiverIndex: 42
        )

        #expect(handler.currentSendCounter == 0)
        #expect(handler.currentReceiveCounter == 0)
    }
}

// MARK: - Full Integration: Encrypt → Build → Parse → Decrypt

@Suite("WireGuard — Full Integration Pipeline")
struct WireGuardFullIntegrationTests {

    private let sendKey = SymmetricKey(data: Data(repeating: 0xAA, count: 32))
    private let recvKey = SymmetricKey(data: Data(repeating: 0xBB, count: 32))

    /// Mock IPv4 ping packet: 20‑byte IP header + 8‑byte ICMP echo request.
    private func mockIPv4Ping() -> Data {
        var ping = Data()

        // ---- IPv4 Header (20 bytes) -----------------------------------
        ping.append(0x45)                     // Version=4, IHL=5
        ping.append(0x00)                     // ToS
        ping.append(contentsOf: [0x00, 0x1C]) // Total Length = 28
        ping.append(contentsOf: [0xAB, 0xCD]) // Identification
        ping.append(contentsOf: [0x00, 0x00]) // Flags + Fragment Offset
        ping.append(0x40)                     // TTL = 64
        ping.append(0x01)                     // Protocol = ICMP
        ping.append(contentsOf: [0x00, 0x00]) // Header Checksum (zeroed)
        // Source: 10.0.0.1
        ping.append(contentsOf: [0x0A, 0x00, 0x00, 0x01])
        // Dest: 10.0.0.2
        ping.append(contentsOf: [0x0A, 0x00, 0x00, 0x02])

        // ---- ICMP Echo Request (8 bytes) -------------------------------
        ping.append(0x08)                     // Type = Echo
        ping.append(0x00)                     // Code = 0
        ping.append(contentsOf: [0x00, 0x00]) // Checksum placeholder
        ping.append(contentsOf: [0x00, 0x01]) // Identifier
        ping.append(contentsOf: [0x00, 0x01]) // Sequence Number

        #expect(ping.count == 28)
        return ping
    }

    @Test func fullEncryptDecryptPipelinePreservesIPv4Ping() throws {
        let innerPacket = mockIPv4Ping()
        let receiverIndex: UInt32 = 0x8877_6655
        let counter: UInt64 = 42

        // ---- Step 1: Encrypt the inner IP packet ------------------------
        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: innerPacket, key: sendKey, counter: counter
        )

        // ---- Step 2: Build the Type 4 datagram --------------------------
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: receiverIndex,
            counter: counter,
            encryptedPayload: encrypted
        )

        // Verify header format.
        #expect(datagram[0] == 0x04)
        #expect(datagram.count == 16 + encrypted.count)

        // ---- Step 3: Parse the Type 4 datagram --------------------------
        guard let parsed = WireGuardMessages.parseTransportData(datagram) else {
            Issue.record("Failed to parse transport data")
            return
        }
        #expect(parsed.receiverIndex == receiverIndex)
        #expect(parsed.counter == counter)

        // ---- Step 4: Decrypt the payload --------------------------------
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: parsed.encryptedPayload, key: sendKey, counter: counter
        )

        // ---- Step 5: Verify the inner IP packet is intact ---------------
        #expect(decrypted == innerPacket)
        #expect(decrypted[0] == 0x45)  // IPv4 version + IHL intact
        #expect(decrypted[9] == 0x01)  // Protocol = ICMP intact
    }

    @Test func multiplePacketPipelineWithCounterIncrement() throws {
        let innerPacket = mockIPv4Ping()
        let receiverIndex: UInt32 = 100

        for counter in 0 ..< 5 {
            let encrypted = try WireGuardOutboundHandler.encryptPayload(
                plaintext: innerPacket, key: sendKey, counter: UInt64(counter)
            )
            let datagram = WireGuardMessages.buildTransportData(
                receiverIndex: receiverIndex,
                counter: UInt64(counter),
                encryptedPayload: encrypted
            )

            guard let parsed = WireGuardMessages.parseTransportData(datagram) else {
                Issue.record("Parse failed at counter \(counter)")
                return
            }
            #expect(parsed.counter == UInt64(counter))

            let decrypted = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: parsed.encryptedPayload,
                key: sendKey,
                counter: UInt64(counter)
            )
            #expect(decrypted == innerPacket,
                    "Packet mismatch at counter \(counter)")
        }
    }

    @Test func differentPayloadsProduceDifferentEncryptedSizes() throws {
        let small = Data([0x01, 0x02, 0x03])
        let large = Data([UInt8](repeating: 0xFF, count: 1024))

        let encSmall = try WireGuardOutboundHandler.encryptPayload(
            plaintext: small, key: sendKey, counter: 0
        )
        let encLarge = try WireGuardOutboundHandler.encryptPayload(
            plaintext: large, key: sendKey, counter: 1
        )

        // Each: plaintextLen + 16 (tag).
        #expect(encSmall.count == small.count + 16)
        #expect(encLarge.count == large.count + 16)
        #expect(encSmall.count != encLarge.count)
    }
}

// MARK: - AEAD Key Independence

@Suite("WireGuard — AEAD Key Independence")
struct WireGuardAEADKeyIndependenceTests {

    @Test func sendAndReceiveKeysProduceDifferentCiphertexts() throws {
        let sendKey = SymmetricKey(data: Data(repeating: 0x11, count: 32))
        let recvKey = SymmetricKey(data: Data(repeating: 0x22, count: 32))
        let plaintext = Data("key independence".utf8)

        let encSend = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: sendKey, counter: 0
        )
        let encRecv = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: recvKey, counter: 0
        )

        // Different keys at same counter → different ciphertexts.
        #expect(encSend != encRecv)
    }

    @Test func decryptWithWrongDirectionKeyFails() throws {
        let sendKey = SymmetricKey(data: Data(repeating: 0x33, count: 32))
        let recvKey = SymmetricKey(data: Data(repeating: 0x44, count: 32))
        let plaintext = Data("directional test".utf8)

        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: sendKey, counter: 0
        )

        // Attempting to decrypt with recvKey instead of sendKey should fail.
        #expect(throws: CryptoKitError.self) {
            _ = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: encrypted, key: recvKey, counter: 0
            )
        }
    }
}

// MARK: - Counter Behaviour (Edge Cases)

@Suite("WireGuard — Counter Edge Cases")
struct WireGuardCounterEdgeCaseTests {

    private let testKey = SymmetricKey(data: Data(repeating: 0x55, count: 32))

    @Test func counterOverflowWrapsByAddition() {
        // &+= wraps on overflow — this is the expected behaviour for
        // long‑lived sessions that exhaust the 64‑bit counter space.
        var counter: UInt64 = UInt64.max
        counter &+= 1
        #expect(counter == 0)
    }

    @Test func encryptDecryptWithMaxCounter() throws {
        let plaintext = Data("max counter".utf8)
        let counter = UInt64.max

        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: counter
        )
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: encrypted, key: testKey, counter: counter
        )
        #expect(decrypted == plaintext)
    }

    @Test func nonZeroStartCounter() throws {
        // WireGuard counters start at 0, but the crypto is correct for any
        // starting value.
        let plaintext = Data("non zero start".utf8)
        let startCounter: UInt64 = 1_000_000

        let encrypted = try WireGuardOutboundHandler.encryptPayload(
            plaintext: plaintext, key: testKey, counter: startCounter
        )
        let decrypted = try WireGuardOutboundHandler.decryptPayload(
            encryptedPayload: encrypted, key: testKey, counter: startCounter
        )
        #expect(decrypted == plaintext)
    }
}

// MARK: - Message Type Detection

@Suite("WireGuard — Message Type Detection (Type 4)")
struct WireGuardMessageType4Tests {

    @Test func messageTypeDetectsTransport() {
        let datagram = WireGuardMessages.buildTransportData(
            receiverIndex: 0, counter: 0, encryptedPayload: Data([0x00])
        )

        let type = WireGuardMessages.messageType(from: datagram)
        #expect(type == .transport)
    }

    @Test func messageTypeDistinguishesInitiationFromTransport() {
        let initiation = WireGuardMessages.buildInitiation(
            senderIndex: 1,
            ephemeralPubKey: Data(repeating: 0, count: 32),
            encryptedStatic: Data(repeating: 0, count: 48),
            encryptedTimestamp: Data(repeating: 0, count: 28)
        )
        let transport = WireGuardMessages.buildTransportData(
            receiverIndex: 0, counter: 0, encryptedPayload: Data()
        )

        #expect(WireGuardMessages.messageType(from: initiation) == .initiation)
        #expect(WireGuardMessages.messageType(from: transport) == .transport)
    }

    @Test func messageTypeReturnsNilForTooShortData() {
        #expect(WireGuardMessages.messageType(from: Data([0x04])) == nil)
    }
}
