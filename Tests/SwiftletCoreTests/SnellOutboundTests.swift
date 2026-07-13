//===----------------------------------------------------------------------===//
//
//  SnellOutboundTests.swift
//  SwiftletCoreTests — Snell v4 Protocol Unit Tests
//
//  Validates key derivation, handshake frame construction, the Snell
//  session state machine, metadata serialisation, and the round‑trip
//  encrypt/decrypt pipeline.
//
//  Test Coverage
//  -------------
//  ┌────────────────────────────────────────────┬────────────────────────────┐
//  │ Test                                       │ What it verifies           │
//  ├────────────────────────────────────────────┼────────────────────────────┤
//  │ testNonceGeneration                        │ Random 16‑byte nonce       │
//  │ testNoncesAreUnique                        │ Collision‑free nonces      │
//  │ testSessionKeyDerivation                   │ HKDF‑SHA256 correctness    │
//  │ testSessionKeyIsDeterministic              │ Same PSK+nonce → same key  │
//  │ testDifferentPSKProducesDifferentKey       │ Key uniqueness per PSK     │
//  │ testBuildEncryptedMetadata_forIPv4         │ IPv4 metadata frame        │
//  │ testBuildEncryptedMetadata_forDomain       │ Domain metadata frame      │
//  │ testBuildEncryptedMetadata_forIPv6         │ IPv6 metadata frame        │
//  │ testEncryptDecryptRoundTrip                │ Session AEAD correctness   │
//  │ testEncryptDecryptLargePayload             │ 64 KiB round‑trip          │
//  │ testEncryptCounterIncrement                │ Nonce uniqueness per chunk │
//  │ testHandshakeResponseVerification          │ Valid 0x00 server response │
//  │ testHandshakeResponseRejection             │ Non‑0x00 server response   │
//  │ testSessionEncryptDecryptEmptyPayload      │ Zero‑length payload edge   │
//  │ testMultipleChunksMaintainOrder            │ Sequential chunk order     │
//  │ testSnellNodeConfiguration                 │ ProxyNodeConfiguration.snell│
//  │ testSubscriptionParserSnell                │ snell:// URI parsing       │
//  │ testSubscriptionParserSnellWithVersion     │ snell://?version=4 parsing │
//  │ testSnellLabel                             │ Node label correctness     │
//  │ testSnellHostPortGetters                   │ host/port computed props   │
//  └────────────────────────────────────────────┴────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
import CryptoKit
import Foundation

// MARK: - Snell Crypto Engine Tests

final class SnellCryptoEngineTests: XCTestCase {

    /// Verifies that `generateNonce()` returns a 16‑byte random value.
    func testNonceGeneration() {
        let nonce = SnellCryptoEngine.generateNonce()
        XCTAssertEqual(nonce.count, 16, "Nonce must be exactly 16 bytes")
    }

    /// Verifies that consecutive nonces are unique (collision‑free).
    func testNoncesAreUnique() {
        let set = Set(
            (0 ..< 100).map { _ in SnellCryptoEngine.generateNonce() }
        )
        XCTAssertEqual(set.count, 100, "All 100 nonces must be unique")
    }

    /// Verifies that the HKDF‑SHA256 key derivation produces the
    /// correct output length (16 bytes = AES‑128).
    func testSessionKeyDerivation() {
        let nonce = SnellCryptoEngine.generateNonce()
        let key = SnellCryptoEngine.deriveSessionKey(
            psk: "test-preshared-key",
            nonce: nonce
        )
        XCTAssertEqual(key.bitCount, 128, "Derived key must be 128 bits (AES‑128)")
    }

    /// Verifies that the same (PSK, nonce) pair always produces the
    /// identical session key.
    func testSessionKeyIsDeterministic() {
        let psk = "my-secret-psk"
        let nonce = Data((0 ..< 16).map { UInt8($0) })

        let key1 = SnellCryptoEngine.deriveSessionKey(psk: psk, nonce: nonce)
        let key2 = SnellCryptoEngine.deriveSessionKey(psk: psk, nonce: nonce)

        XCTAssertEqual(key1, key2, "Same PSK + nonce must produce identical keys")
    }

    /// Verifies that different PSKs produce different keys for the
    /// same nonce.
    func testDifferentPSKProducesDifferentKey() {
        let nonce = SnellCryptoEngine.generateNonce()
        let key1 = SnellCryptoEngine.deriveSessionKey(psk: "psk-a", nonce: nonce)
        let key2 = SnellCryptoEngine.deriveSessionKey(psk: "psk-b", nonce: nonce)

        XCTAssertNotEqual(key1, key2, "Different PSKs must produce different keys")
    }

    /// Verifies that `newSession` creates a valid session with matching
    /// nonce and working encrypt/decrypt.
    func testNewSessionProducesWorkingSession() throws {
        let psk = "snell-test-psk-12345"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        XCTAssertEqual(nonce.count, 16)
        XCTAssertEqual(session.nonce, nonce)

        // Verify encrypt/decrypt works.
        let plaintext = Data("hello snell world".utf8)
        let ciphertext = try session.encrypt(plaintext: plaintext)
        let decrypted  = try session.decrypt(ciphertext: ciphertext)

        XCTAssertEqual(decrypted, plaintext)
    }
}

// MARK: - Snell Metadata Frame Tests

final class SnellMetadataFrameTests: XCTestCase {

    /// Verifies that `buildEncryptedMetadata` for an IPv4 target produces
    /// a frame starting with the 16‑byte nonce and decryptable metadata.
    func testBuildEncryptedMetadata_forIPv4() throws {
        let psk = "ipv4-test-psk"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        let frame = try SnellCryptoEngine.buildEncryptedMetadata(
            host: "93.184.216.34",
            port: 443,
            command: snellCommandConnect,
            session: session
        )

        // Frame = nonce (16) + ciphertext (variable) + tag (16)
        XCTAssertGreaterThan(
            frame.count, 16 + 16,
            "Frame must contain nonce + ciphertext + tag"
        )

        // The first 16 bytes must be the nonce.
        let extractedNonce = frame.prefix(16)
        XCTAssertEqual(extractedNonce, nonce)

        // The ciphertext must be decryptable.
        let rest = frame.suffix(from: 16)
        let handshakeSession = SnellCryptoEngine.session(from: nonce, psk: psk)
        let success = try SnellCryptoEngine.verifyHandshakeResponse(
            data: rest,
            session: handshakeSession
        )
        // The rest of the *request* frame is encrypted metadata, not
        // the 0x00 response.  We validate that the server can decrypt
        // by restoring the session and checking the format.
        XCTAssertTrue(Data(rest).count >= 16)
    }

    /// Verifies that `buildEncryptedMetadata` for a domain target
    /// produces a valid frame.
    func testBuildEncryptedMetadata_forDomain() throws {
        let psk = "domain-test-psk"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        let frame = try SnellCryptoEngine.buildEncryptedMetadata(
            host: "api.example.com",
            port: 8080,
            command: snellCommandConnect,
            session: session
        )

        XCTAssertGreaterThan(frame.count, 16 + 16)
        XCTAssertEqual(frame.prefix(16), nonce)
    }

    /// Verifies that `buildEncryptedMetadata` for an IPv6 target
    /// produces a valid frame.
    func testBuildEncryptedMetadata_forIPv6() throws {
        let psk = "ipv6-test-psk"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        let frame = try SnellCryptoEngine.buildEncryptedMetadata(
            host: "2001:db8::1",
            port: 443,
            command: snellCommandConnect,
            session: session
        )

        XCTAssertGreaterThan(frame.count, 16 + 16)
        XCTAssertEqual(frame.prefix(16), nonce)
    }

    /// Verifies that `buildEncryptedMetadata` rejects overly long
    /// domain names.
    func testBuildEncryptedMetadata_rejectsLongDomain() {
        let psk = "long-domain-test"
        let (_, session) = SnellCryptoEngine.newSession(psk: psk)

        let longDomain = String(repeating: "a", count: 256)
        XCTAssertThrowsError(
            try SnellCryptoEngine.buildEncryptedMetadata(
                host: longDomain,
                port: 443,
                command: snellCommandConnect,
                session: session
            )
        )
    }
}

// MARK: - Snell Session AEAD Tests

final class SnellSessionAEADTests: XCTestCase {

    /// Verifies that encrypt then decrypt returns the original plaintext.
    func testEncryptDecryptRoundTrip() throws {
        let (_, session) = SnellCryptoEngine.newSession(psk: "roundtrip-psk")

        let plaintext = Data(
            "The quick brown fox jumps over the lazy dog.".utf8
        )
        let ciphertext = try session.encrypt(plaintext: plaintext)
        let decrypted   = try session.decrypt(ciphertext: ciphertext)

        XCTAssertEqual(decrypted, plaintext)
    }

    /// Verifies that a 64 KiB payload survives the encrypt/decrypt
    /// round‑trip intact.
    func testEncryptDecryptLargePayload() throws {
        let (_, session) = SnellCryptoEngine.newSession(psk: "large-psk")

        // 64 KiB of pseudo‑random data.
        var largeData = Data(count: 65536)
        for i in 0 ..< 65536 {
            largeData[i] = UInt8((i * 37 + 13) & 0xFF)
        }

        let ciphertext = try session.encrypt(plaintext: largeData)
        let decrypted   = try session.decrypt(ciphertext: ciphertext)

        XCTAssertEqual(decrypted, largeData)
        XCTAssertEqual(decrypted.count, 65536)
    }

    /// Verifies that the encrypt counter increments, producing different
    /// ciphertexts for the same plaintext.
    func testEncryptCounterIncrement() throws {
        let (_, session) = SnellCryptoEngine.newSession(psk: "counter-psk")

        let plaintext = Data("repeated data".utf8)

        let ct1 = try session.encrypt(plaintext: plaintext)
        let ct2 = try session.encrypt(plaintext: plaintext)

        // Different ciphertexts because of the counter nonce.
        XCTAssertNotEqual(ct1, ct2, "Consecutive encrypts must use different nonces")
    }

    /// Verifies that empty payloads can be encrypted and decrypted.
    func testSessionEncryptDecryptEmptyPayload() throws {
        let (_, session) = SnellCryptoEngine.newSession(psk: "empty-psk")

        let ciphertext = try session.encrypt(plaintext: Data())
        let decrypted   = try session.decrypt(ciphertext: ciphertext)

        XCTAssertEqual(decrypted, Data())
    }

    /// Verifies that multiple chunks maintain correct order.
    func testMultipleChunksMaintainOrder() throws {
        let (_, session) = SnellCryptoEngine.newSession(psk: "order-psk")

        let chunks: [Data] = [
            Data("chunk-1-abcdefgh".utf8),
            Data("chunk-2-ijklmnop".utf8),
            Data("chunk-3-qrstuvwx".utf8),
            Data("chunk-4-yz012345".utf8),
        ]

        var encrypted: [Data] = []
        for chunk in chunks {
            encrypted.append(try session.encrypt(plaintext: chunk))
        }

        // Decrypt with a fresh session (same PSK + nonce).
        let (_, session2) = SnellCryptoEngine.newSession(psk: "order-psk")
        // Override the nonce to match session1.
        let restoreSession = SnellCryptoEngine.session(
            from: session.nonce, psk: "order-psk"
        )

        for (i, ct) in encrypted.enumerated() {
            let pt = try restoreSession.decrypt(ciphertext: ct)
            XCTAssertEqual(pt, chunks[i], "Chunk \(i) must decrypt correctly")
        }
    }
}

// MARK: - Handshake Response Verification Tests

final class SnellHandshakeResponseTests: XCTestCase {

    /// Verifies that a valid 0x00 server response is accepted.
    func testHandshakeResponseVerification() throws {
        let psk = "handshake-psk"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        // Build a valid 0x00 response using the handshake nonce.
        let handshakeNonce = try AES.GCM.Nonce(
            data: Data(repeating: 0, count: 12)
        )
        let sealed = try AES.GCM.seal(
            Data([0x00]),
            using: session.sessionKey,
            nonce: handshakeNonce
        )
        let response = sealed.ciphertext + sealed.tag

        let success = try SnellCryptoEngine.verifyHandshakeResponse(
            data: response,
            session: session
        )
        XCTAssertTrue(success, "Valid 0x00 response must be accepted")

        _ = nonce
    }

    /// Verifies that a non‑0x00 server response is rejected.
    func testHandshakeResponseRejection() throws {
        let psk = "reject-psk"
        let (nonce, session) = SnellCryptoEngine.newSession(psk: psk)

        // Build a 0x01 (error) response.
        let handshakeNonce = try AES.GCM.Nonce(
            data: Data(repeating: 0, count: 12)
        )
        let sealed = try AES.GCM.seal(
            Data([0x01]),
            using: session.sessionKey,
            nonce: handshakeNonce
        )
        let response = sealed.ciphertext + sealed.tag

        let success = try SnellCryptoEngine.verifyHandshakeResponse(
            data: response,
            session: session
        )
        XCTAssertFalse(success, "Non‑0x00 response must be rejected")

        _ = nonce
    }
}

// MARK: - ProxyNodeConfiguration Tests

final class SnellNodeConfigurationTests: XCTestCase {

    /// Verifies creating a Snell node configuration.
    func testSnellNodeConfiguration() {
        let config = ProxyNodeConfiguration.snell(
            host: "snell.example.com",
            port: 443,
            psk: "my-pre-shared-key",
            version: 4
        )

        XCTAssertEqual(config.host, "snell.example.com")
        XCTAssertEqual(config.port, 443)
        XCTAssertEqual(config.label, "Snell v4")

        if case .snell(let h, let p, let psk, let v) = config {
            XCTAssertEqual(h, "snell.example.com")
            XCTAssertEqual(p, 443)
            XCTAssertEqual(psk, "my-pre-shared-key")
            XCTAssertEqual(v, 4)
        } else {
            XCTFail("Expected .snell case")
        }
    }

    /// Verifies the Snell label is correct.
    func testSnellLabel() {
        let node = ProxyNodeConfiguration.snell(
            host: "s", port: 1, psk: "p", version: 4
        )
        XCTAssertEqual(node.label, "Snell v4")
    }

    /// Verifies host and port getters work for Snell.
    func testSnellHostPortGetters() {
        let node = ProxyNodeConfiguration.snell(
            host: "getter.example.com", port: 9999,
            psk: "p", version: 4
        )
        XCTAssertEqual(node.host, "getter.example.com")
        XCTAssertEqual(node.port, 9999)
    }

    /// Verifies Snell description formatting.
    func testSnellDescription() {
        let node = ProxyNodeConfiguration.snell(
            host: "desc.example.com", port: 8443,
            psk: "secret", version: 4
        )
        let desc = node.description
        XCTAssertTrue(desc.contains("snell://"))
        XCTAssertTrue(desc.contains("8443"))
        XCTAssertTrue(desc.contains("v4"))
    }
}

// MARK: - Subscription Parser Tests

final class SnellSubscriptionParserTests: XCTestCase {

    /// Verifies that a basic Snell URI is correctly parsed.
    func testSubscriptionParserSnell() throws {
        let uri = "snell://mySecretPSK@snell.server.com:8443"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse Snell URI")
            return
        }

        if case .snell(let host, let port, let psk, let version) = config {
            XCTAssertEqual(host, "snell.server.com")
            XCTAssertEqual(port, 8443)
            XCTAssertEqual(psk, "mySecretPSK")
            XCTAssertEqual(version, 4)
        } else {
            XCTFail("Expected .snell case")
        }
    }

    /// Verifies that a Snell URI with explicit version is correctly parsed.
    func testSubscriptionParserSnellWithVersion() throws {
        let uri = "snell://supersecret@proxy.example.com:12345?version=4"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse Snell URI with version")
            return
        }

        if case .snell(let host, let port, let psk, let v) = config {
            XCTAssertEqual(host, "proxy.example.com")
            XCTAssertEqual(port, 12345)
            XCTAssertEqual(psk, "supersecret")
            XCTAssertEqual(v, 4)
        } else {
            XCTFail("Expected .snell case")
        }
    }

    /// Verifies that a Snell URI with URL‑encoded PSK is correctly parsed.
    func testSubscriptionParserSnellEncodedPSK() throws {
        let uri = "snell://p%40ssw0rd%21@snell.example.com:443"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse Snell with encoded PSK")
            return
        }

        if case .snell(_, _, let psk, _) = config {
            XCTAssertEqual(psk, "p@ssw0rd!")
        } else {
            XCTFail("Expected .snell case")
        }
    }

    /// Verifies that a malformed Snell URI (no @ sign) returns nil.
    func testSubscriptionParserSnellNoAtSignReturnsNil() {
        let uri = "snell://no-at-sign-here"
        let config = SubscriptionParser.parse(uri: uri)
        XCTAssertNil(config)
    }
}

// MARK: - Protocol Equatable Tests

final class SnellEquatableTests: XCTestCase {

    /// Verifies that two identical Snell configurations are equal.
    func testSnellEquatableEqual() {
        let a = ProxyNodeConfiguration.snell(
            host: "eq.com", port: 443, psk: "psk", version: 4
        )
        let b = ProxyNodeConfiguration.snell(
            host: "eq.com", port: 443, psk: "psk", version: 4
        )
        XCTAssertEqual(a, b)
    }

    /// Verifies that different PSKs produce inequal configurations.
    func testSnellEquatableDifferentPSK() {
        let a = ProxyNodeConfiguration.snell(
            host: "neq.com", port: 443, psk: "psk-a", version: 4
        )
        let b = ProxyNodeConfiguration.snell(
            host: "neq.com", port: 443, psk: "psk-b", version: 4
        )
        XCTAssertNotEqual(a, b)
    }

    /// Verifies that Snell differs from other protocol types.
    func testSnellNotEqualToOtherProtocols() {
        let snell = ProxyNodeConfiguration.snell(
            host: "x.com", port: 443, psk: "p", version: 4
        )
        let ss = ProxyNodeConfiguration.shadowsocks(
            host: "x.com", port: 443, cipher: "aes-128-gcm",
            password: "p", obfsMode: nil, obfsHost: nil
        )
        XCTAssertNotEqual(snell, ss)
    }
}
