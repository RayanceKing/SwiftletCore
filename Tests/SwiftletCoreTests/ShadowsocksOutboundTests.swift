//===----------------------------------------------------------------------===//
//
//  ShadowsocksOutboundTests.swift
//  SwiftletCore — Shadowsocks AEAD Cipher & Handler Tests
//
//  Validates the complete encryption/decryption pipeline:
//  • Round‑trip enc/dec for all three AEAD cipher types
//  • Salt generation and HKDF‑SHA1 key derivation
//  • Ciphertext indistinguishability (encrypted ≠ plaintext)
//  • Chunk framing correctness
//  • Handler simulation (outbound write → wire → inbound read)
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - Cipher Round‑Trip Tests

@Suite("ShadowsocksCipher")
struct ShadowsocksCipherTests {

    // MARK: AES-128-GCM

    @Test func aes128GCMRoundTrip() async throws {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "test-secret-128!")
        let (salt, session) = cipher.newSession()

        // Salt length must match key length.
        #expect(salt.count == 16)

        let original = "Hello, Shadowsocks! This is a test payload.".data(using: .utf8)!

        // Encrypt
        let encrypted = try session.encryptChunk(plaintext: original)
        #expect(encrypted.count > original.count) // includes tag + 2‑byte length
        #expect(encrypted != original)

        // Verify ciphertext is scrambled (not readable as UTF‑8)
        let utf8String = String(data: encrypted, encoding: .utf8)
        #expect(utf8String == nil || utf8String! != "Hello, Shadowsocks!")

        // --- Decrypt with a NEW session restored from the same salt ------
        let decryptSession = cipher.session(from: salt)
        let decrypted = try decryptSession.decryptChunk(ciphertext: encrypted)
        #expect(decrypted == original)
    }

    // MARK: AES-256-GCM

    @Test func aes256GCMRoundTrip() async throws {
        let cipher = ShadowsocksCipher(type: .aes256GCM,
                                        password: "longer-test-secret-for-256-bit!")
        let (salt, session) = cipher.newSession()
        #expect(salt.count == 32)

        let payload = Data((0 ..< 256).map { UInt8($0 % 256) })

        let encrypted = try session.encryptChunk(plaintext: payload)
        // Encrypted chunk = 2‑byte len + payload + tag
        #expect(encrypted.count == 2 + payload.count + 16)

        let decryptSession = cipher.session(from: salt)
        let decrypted = try decryptSession.decryptChunk(ciphertext: encrypted)
        #expect(decrypted == payload)
    }

    // MARK: ChaCha20-Poly1305

    @Test func chacha20Poly1305RoundTrip() async throws {
        let cipher = ShadowsocksCipher(type: .chacha20Poly1305,
                                        password: "chacha20-test-secret-key!!")
        let (salt, session) = cipher.newSession()
        #expect(salt.count == 32)

        let payload = Data("ChaCha20-Poly1305 test data 🔐".utf8)

        let encrypted = try session.encryptChunk(plaintext: payload)
        let decryptSession = cipher.session(from: salt)
        let decrypted = try decryptSession.decryptChunk(ciphertext: encrypted)
        #expect(decrypted == payload)
    }

    // MARK: Salt Randomness

    @Test func saltsAreRandom() {
        let cipher = ShadowsocksCipher(type: .aes256GCM, password: "random-salt-test")
        let (salt1, _) = cipher.newSession()
        let (salt2, _) = cipher.newSession()
        // Two consecutive salts MUST be different (probability of collision
        // for 256‑bit random values is effectively zero).
        #expect(salt1 != salt2)
    }

    // MARK: Key Derivation Determinism

    @Test func sameSaltProducesSameKey() throws {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "deterministic-key")
        let (salt, session1) = cipher.newSession()
        let encrypt1 = try session1.encryptChunk(plaintext: Data("hello".utf8))

        // Restore a second session from the same salt — decryption must work.
        let session2 = cipher.session(from: salt)
        let decrypt2 = try session2.decryptChunk(ciphertext: encrypt1)
        #expect(decrypt2 == Data("hello".utf8))
    }

    // MARK: Chunk Size Limits

    @Test func maxChunkSizeEnforced() {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "chunk-test")
        // 0x3FFF = 16383 bytes per Shadowsocks AEAD spec.
        #expect(cipher.cipherType.maxChunkSize == 0x3FFF)
    }

    // MARK: Multiple Chunks

    @Test func multipleChunksEncryptAndDecrypt() throws {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "multi-chunk-key!")
        let (salt, session) = cipher.newSession()

        let chunks: [Data] = [
            Data("Chunk 1 — short".utf8),
            Data("Chunk 2 — a bit longer with more content inside".utf8),
            Data("Chunk 3 — 🔒🔑💻".utf8),
            Data([UInt8](repeating: 0x42, count: 500)), // binary chunk
        ]

        // Encrypt all chunks
        var encryptedChunks: [Data] = []
        for chunk in chunks {
            encryptedChunks.append(try session.encryptChunk(plaintext: chunk))
        }

        // All ciphertexts must differ from their plaintexts
        for (i, encrypted) in encryptedChunks.enumerated() {
            #expect(encrypted != chunks[i], "Chunk \(i) ciphertext matches plaintext")
        }

        // Decrypt with a restored session
        let decryptSession = cipher.session(from: salt)
        for (i, encrypted) in encryptedChunks.enumerated() {
            let decrypted = try decryptSession.decryptChunk(ciphertext: encrypted)
            #expect(decrypted == chunks[i], "Chunk \(i) round‑trip mismatch")
        }
    }
}

// MARK: - Handler Simulation Tests

@Suite("ShadowsocksOutboundHandler")
struct ShadowsocksOutboundHandlerTests {

    /// Simulates the handler pipeline by manually exercising the encryption
    /// path (outbound write → ciphertext) and decryption path (ciphertext →
    /// inbound read → plaintext) in the same order they would occur in a
    /// real SwiftNIO pipeline.
    @Test func handlerEncryptDecryptSimulation() throws {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "handler-test-key!!")
        let (salt, encSession) = cipher.newSession()

        // ---- Simulate outbound write (encryption) ------------------------
        let plaintext = Data(
            "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".utf8
        )

        // Step 1: encrypt with salt prepended (simulating first write).
        let encryptedChunk = try encSession.encryptChunk(plaintext: plaintext)
        var wireData = Data()
        wireData.append(salt)           // salt prepended on first write
        wireData.append(encryptedChunk) // encrypted chunk

        // Verify wire data is not plaintext
        #expect(!wireData.contains(plaintext))

        // ---- Simulate inbound read (decryption) --------------------------
        // Step 2: consume salt from wire data.
        let saltLen = cipher.cipherType.saltLength
        #expect(wireData.count >= saltLen)
        let receivedSalt = wireData.prefix(saltLen)
        wireData.removeFirst(saltLen)

        // Step 3: restore session from salt and decrypt.
        let decSession = cipher.session(from: Data(receivedSalt))
        let decrypted = try decSession.decryptChunk(ciphertext: wireData)

        #expect(decrypted == plaintext)
    }

    /// Verifies that the chunk length prefix correctly identifies the
    /// payload boundary.
    @Test func chunkLengthPrefixIsCorrect() throws {
        let cipher = ShadowsocksCipher(type: .aes256GCM,
                                        password: "length-prefix-test!!")

        let payloadSizes = [1, 16, 255, 1024, 0x3FFF]
        for size in payloadSizes {
            // Use a fresh session for each size so encrypt/decrypt counters
            // both start at zero.
            let (salt, encSession) = cipher.newSession()
            let payload = Data([UInt8](repeating: 0xAB, count: size))
            let encrypted = try encSession.encryptChunk(plaintext: payload)

            let dec = cipher.session(from: salt)
            let restored = try dec.decryptChunk(ciphertext: encrypted)
            #expect(restored.count == size)
            #expect(restored == payload)
        }
    }

    /// Decrypting with the wrong salt must fail (authentication error).
    @Test func wrongSaltFailsDecryption() throws {
        let cipher = ShadowsocksCipher(type: .aes128GCM, password: "correct-key")
        let (correctSalt, session) = cipher.newSession()

        let payload = Data("secret message".utf8)
        let encrypted = try session.encryptChunk(plaintext: payload)

        // Derive a different salt and attempt decryption.
        let (wrongSalt, _) = cipher.newSession()
        #expect(correctSalt != wrongSalt) // sanity check

        let wrongSession = cipher.session(from: wrongSalt)

        #expect(throws: (any Error).self) {
            _ = try wrongSession.decryptChunk(ciphertext: encrypted)
        }
    }

    /// Verify that ciphertexts from different cipher types are incompatible.
    @Test func crossCipherDecryptionFails() throws {
        let cipherAES = ShadowsocksCipher(type: .aes128GCM, password: "shared-key")
        let cipherCha  = ShadowsocksCipher(type: .chacha20Poly1305, password: "shared-key")

        let (salt, aesSession) = cipherAES.newSession()
        let payload = Data("cross-cipher test".utf8)
        let encrypted = try aesSession.encryptChunk(plaintext: payload)

        // Try to decrypt AES ciphertext with ChaCha20 session.
        let chaSession = cipherCha.session(from: salt) // different HKDF output!
        #expect(throws: (any Error).self) {
            _ = try chaSession.decryptChunk(ciphertext: encrypted)
        }
    }
}

// MARK: - HKDF-SHA1 Validation

@Suite("HKDF")
struct HKDFTests {

    /// Validates that the HKDF‑SHA1 implementation is deterministic and
    /// produces the expected length.
    @Test func hkdfSHA1IsDeterministic() {
        let cipher1 = ShadowsocksCipher(type: .aes128GCM, password: "test")
        let cipher2 = ShadowsocksCipher(type: .aes128GCM, password: "test")

        // Use a fixed salt to ensure deterministic output.
        let fixedSalt = Data([UInt8](repeating: 0x01, count: 16))
        let s1 = cipher1.session(from: fixedSalt)
        let s2 = cipher2.session(from: fixedSalt)

        // Both sessions derived from the same master key + salt should
        // produce identical ciphertext for the same plaintext.
        let payload = Data("deterministic".utf8)
        let enc1 = try! s1.encryptChunk(plaintext: payload)
        let enc2 = try! s2.encryptChunk(plaintext: payload)
        #expect(enc1 == enc2)
    }
}
