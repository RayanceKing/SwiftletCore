//===----------------------------------------------------------------------===//
//
//  WireGuardNoiseTests.swift
//  SwiftletCore — WireGuard Noise Protocol Unit Tests
//
//  Validates:
//  • Handshake Initiation message is exactly 148 bytes
//  • Handshake Response message is exactly 92 bytes
//  • Type field encodes correctly in little‑endian
//  • Noise machine produces valid Curve25519 ephemeral keys
//  • Noise machine derivation produces non‑zero session keys
//  • Message parsing round‑trips correctly
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import CryptoKit
@testable import SwiftletCore

// MARK: - Message Sizes

@Suite("WireGuardMessages — Sizes")
struct WireGuardMessageSizeTests {

    @Test func initiationSizeConstant() {
        #expect(WireGuardMessages.initiationSize == 148)
    }

    @Test func responseSizeConstant() {
        #expect(WireGuardMessages.responseSize == 92)
    }

    @Test func keySizeConstant() {
        #expect(WireGuardMessages.keySize == 32)
    }

    @Test func macSizeConstant() {
        #expect(WireGuardMessages.macSize == 16)
    }
}

// MARK: - Build Initiation

@Suite("WireGuardMessages — Initiation")
struct WireGuardInitiationTests {

    @Test func buildInitiationProduces148Bytes() {
        let msg = WireGuardMessages.buildInitiation(
            senderIndex: 0x12345678,
            ephemeralPubKey: Data(repeating: 0x01, count: 32),
            encryptedStatic: Data(repeating: 0x02, count: 48),
            encryptedTimestamp: Data(repeating: 0x03, count: 28)
        )

        #expect(msg.count == 148)
    }

    @Test func typeFieldEncodesAsLittleEndian1() {
        let msg = WireGuardMessages.buildInitiation(
            senderIndex: 1,
            ephemeralPubKey: Data(repeating: 0xAA, count: 32),
            encryptedStatic: Data(repeating: 0xBB, count: 48),
            encryptedTimestamp: Data(repeating: 0xCC, count: 28)
        )

        // First 4 bytes = UInt32(1) in little‑endian = [0x01, 0x00, 0x00, 0x00]
        #expect(msg[0] == 0x01)
        #expect(msg[1] == 0x00)
        #expect(msg[2] == 0x00)
        #expect(msg[3] == 0x00)
    }

    @Test func messageTypeDetection() {
        let msg = WireGuardMessages.buildInitiation(
            senderIndex: 1,
            ephemeralPubKey: Data(repeating: 0, count: 32),
            encryptedStatic: Data(repeating: 0, count: 48),
            encryptedTimestamp: Data(repeating: 0, count: 28)
        )

        let type = WireGuardMessages.messageType(from: msg)
        #expect(type == .initiation)
    }

    @Test func senderIndexFieldCorrect() {
        let msg = WireGuardMessages.buildInitiation(
            senderIndex: 0xDEAD_BEEF,
            ephemeralPubKey: Data(repeating: 0, count: 32),
            encryptedStatic: Data(repeating: 0, count: 48),
            encryptedTimestamp: Data(repeating: 0, count: 28)
        )

        // Bytes 4–7: sender index in little‑endian.
        #expect(msg[4] == 0xEF)
        #expect(msg[5] == 0xBE)
        #expect(msg[6] == 0xAD)
        #expect(msg[7] == 0xDE)
    }

    @Test func ephemeralPubKeyFieldCorrectStartOffset() {
        let msg = WireGuardMessages.buildInitiation(
            senderIndex: 0,
            ephemeralPubKey: Data(repeating: 0x42, count: 32),
            encryptedStatic: Data(repeating: 0, count: 48),
            encryptedTimestamp: Data(repeating: 0, count: 28)
        )

        // Ephemeral key starts at byte 8 (after type + sender).
        #expect(msg[8] == 0x42)
        #expect(msg[8 + 31] == 0x42)
    }

    @Test func parseInitiationRoundTrip() {
        let original = WireGuardMessages.buildInitiation(
            senderIndex: 42,
            ephemeralPubKey: Data(repeating: 0xAB, count: 32),
            encryptedStatic: Data(repeating: 0xCD, count: 48),
            encryptedTimestamp: Data(repeating: 0xEF, count: 28)
        )

        guard let parsed = WireGuardMessages.parseInitiation(original) else {
            Issue.record("parseInitiation returned nil")
            return
        }

        #expect(parsed.senderIndex == 42)
        #expect(parsed.ephemeralPubKey == Data(repeating: 0xAB, count: 32))
        #expect(parsed.encryptedStatic == Data(repeating: 0xCD, count: 48))
        #expect(parsed.encryptedTimestamp == Data(repeating: 0xEF, count: 28))
        #expect(parsed.mac1.count == 16)
        #expect(parsed.mac2.count == 16)
    }
}

// MARK: - Build Response

@Suite("WireGuardMessages — Response")
struct WireGuardResponseTests {

    @Test func buildResponseProduces92Bytes() {
        let msg = WireGuardMessages.buildResponse(
            senderIndex: 1,
            receiverIndex: 2,
            ephemeralPubKey: Data(repeating: 0x01, count: 32),
            encryptedNothing: Data(repeating: 0x02, count: 16)
        )

        #expect(msg.count == 92)
    }

    @Test func responseTypeFieldEncodesCorrectly() {
        let msg = WireGuardMessages.buildResponse(
            senderIndex: 1, receiverIndex: 2,
            ephemeralPubKey: Data(repeating: 0, count: 32),
            encryptedNothing: Data(repeating: 0, count: 16)
        )

        let type = WireGuardMessages.messageType(from: msg)
        #expect(type == .response)
    }

    @Test func parseResponseRoundTrip() {
        let original = WireGuardMessages.buildResponse(
            senderIndex: 100,
            receiverIndex: 200,
            ephemeralPubKey: Data(repeating: 0x11, count: 32),
            encryptedNothing: Data(repeating: 0x22, count: 16)
        )

        guard let parsed = WireGuardMessages.parseResponse(original) else {
            Issue.record("parseResponse returned nil")
            return
        }

        #expect(parsed.senderIndex == 100)
        #expect(parsed.receiverIndex == 200)
        #expect(parsed.ephemeralPubKey == Data(repeating: 0x11, count: 32))
        #expect(parsed.encryptedNothing == Data(repeating: 0x22, count: 16))
        #expect(parsed.mac1.count == 16)
        #expect(parsed.mac2.count == 16)
    }
}

// MARK: - Noise Machine

@Suite("WireGuardNoiseMachine")
struct WireGuardNoiseMachineTests {

    @Test func generateStaticKeyPairProduces32BytePublicKey() {
        let privateKey = WireGuardNoiseMachine.generateStaticKeyPair()
        let pubKeyData = WireGuardNoiseMachine.publicKeyData(from: privateKey)
        #expect(pubKeyData.count == 32)
    }

    @Test func publicKeyFromDataRoundTrip() throws {
        let privateKey = WireGuardNoiseMachine.generateStaticKeyPair()
        let pubKeyData = WireGuardNoiseMachine.publicKeyData(from: privateKey)

        let publicKey = try WireGuardNoiseMachine.publicKey(from: pubKeyData)
        #expect(publicKey.rawRepresentation == privateKey.publicKey.rawRepresentation)
    }

    @Test func noiseMachineInitialization() throws {
        let localStatic = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerStatic  = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerPublic  = try WireGuardNoiseMachine.publicKey(
            from: WireGuardNoiseMachine.publicKeyData(from: peerStatic)
        )

        _ = WireGuardNoiseMachine(
            staticPrivate: localStatic,
            peerStaticPublic: peerPublic
        )

        // Should initialise without error.
        #expect(true) // machine initialised
    }

    @Test func generateInitiationComponentsProducesNonZeroKeys() async throws {
        let localStatic = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerStatic  = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerPublic  = try WireGuardNoiseMachine.publicKey(
            from: WireGuardNoiseMachine.publicKeyData(from: peerStatic)
        )

        let machine = WireGuardNoiseMachine(
            staticPrivate: localStatic,
            peerStaticPublic: peerPublic
        )

        let comps = try await machine.generateInitiationComponents()

        // Ephemeral public key must be non‑zero.
        #expect(comps.ephemeralPubKey.count == 32)
        #expect(comps.ephemeralPubKey != Data(repeating: 0, count: 32))

        // Sender index must be non‑zero.
        #expect(comps.senderIndex != 0)

        // Encrypted static must be 48 bytes.
        #expect(comps.encryptedStatic.count == 48)

        // Encrypted timestamp must be 28 bytes.
        #expect(comps.encryptedTimestamp.count == 28)
    }

    @Test func buildInitiationMessageIs148Bytes() async throws {
        let localStatic = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerStatic  = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerPublic  = try WireGuardNoiseMachine.publicKey(
            from: WireGuardNoiseMachine.publicKeyData(from: peerStatic)
        )

        let machine = WireGuardNoiseMachine(
            staticPrivate: localStatic,
            peerStaticPublic: peerPublic
        )

        let msg = try await machine.buildInitiationMessage()
        #expect(msg.count == 148)

        // Verify the type field.
        let type = WireGuardMessages.messageType(from: msg)
        #expect(type == .initiation)
    }

    @Test func sessionKeysAreDerived() async throws {
        let localStatic = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerStatic  = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerPublic  = try WireGuardNoiseMachine.publicKey(
            from: WireGuardNoiseMachine.publicKeyData(from: peerStatic)
        )

        let machine = WireGuardNoiseMachine(
            staticPrivate: localStatic,
            peerStaticPublic: peerPublic
        )

        _ = try await machine.generateInitiationComponents()

        let sendKey = await machine.sendKey
        let recvKey = await machine.receiveKey

        // Session keys must be derived.
        #expect(sendKey != nil)
        #expect(recvKey != nil)

        // Send and receive keys should be different (different info strings).
        let sendData = sendKey!.withUnsafeBytes { Data($0) }
        let recvData = recvKey!.withUnsafeBytes { Data($0) }
        #expect(sendData != recvData)
    }

    @Test func twoMachinesProduceDifferentEphemeralKeys() async throws {
        let peerStatic = WireGuardNoiseMachine.generateStaticKeyPair()
        let peerPublic = try WireGuardNoiseMachine.publicKey(
            from: WireGuardNoiseMachine.publicKeyData(from: peerStatic)
        )

        let machine1 = WireGuardNoiseMachine(
            staticPrivate: WireGuardNoiseMachine.generateStaticKeyPair(),
            peerStaticPublic: peerPublic
        )
        let machine2 = WireGuardNoiseMachine(
            staticPrivate: WireGuardNoiseMachine.generateStaticKeyPair(),
            peerStaticPublic: peerPublic
        )

        let comps1 = try await machine1.generateInitiationComponents()
        let comps2 = try await machine2.generateInitiationComponents()

        // Different ephemeral keys each time.
        #expect(comps1.ephemeralPubKey != comps2.ephemeralPubKey)

        // Different sender indices.
        #expect(comps1.senderIndex != comps2.senderIndex)
    }
}

// MARK: - Message Type

@Suite("WireGuardMessageType")
struct WireGuardMessageTypeTests {

    @Test func rawValues() {
        #expect(WireGuardMessageType.initiation.rawValue == 1)
        #expect(WireGuardMessageType.response.rawValue == 2)
        #expect(WireGuardMessageType.cookieReply.rawValue == 3)
        #expect(WireGuardMessageType.transport.rawValue == 4)
    }
}
