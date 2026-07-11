//===----------------------------------------------------------------------===//
//
//  ShadowsocksCipher.swift
//  SwiftletCore — Shadowsocks AEAD Cipher (CryptoKit)
//
//  Implements the Shadowsocks AEAD-2017 cipher suite using Apple's native
//  `CryptoKit` for hardware‑accelerated AES‑GCM and ChaCha20‑Poly1305
//  encryption.  Key derivation follows HKDF‑SHA1 per the Shadowsocks spec.
//
//  Supported ciphers
//  -----------------
//  •  aes-128-gcm        (16‑byte key, 16‑byte salt)
//  •  aes-256-gcm        (32‑byte key, 32‑byte salt)
//  •  chacha20-poly1305  (32‑byte key, 32‑byte salt)
//
//  Nonce construction
//  ------------------
//  For each connection, a random salt is generated.  The session sub‑key is
//  derived via HKDF‑SHA1(master_key, salt, info="ss-subkey").  Per‑chunk
//  nonces are formed by XOR‑ing a little‑endian counter into the last bytes
//  of the base nonce (first 12 bytes of the salt).
//
//===----------------------------------------------------------------------===//

import CryptoKit
import Foundation

// MARK: - Cipher Identifier

/// Supported Shadowsocks AEAD cipher algorithms.
public enum ShadowsocksCipherType: String, Sendable, CaseIterable {
    case aes128GCM        = "aes-128-gcm"
    case aes256GCM        = "aes-256-gcm"
    case chacha20Poly1305 = "chacha20-poly1305"

    /// Key length in bytes.
    public var keyLength: Int {
        switch self {
        case .aes128GCM:        return 16
        case .aes256GCM:        return 32
        case .chacha20Poly1305: return 32
        }
    }

    /// Salt length in bytes.
    public var saltLength: Int { keyLength }

    /// AEAD authentication tag length in bytes.
    public var tagLength: Int { 16 }

    /// Maximum plaintext payload per chunk (0x3FFF per spec).
    public var maxChunkSize: Int { 0x3FFF }
}

// MARK: - Session Key & Nonce

/// Holds the derived session key and base nonce for a single TCP connection.
private struct SessionMaterial: Sendable {
    let key: SymmetricKey
    let salt: Data
    let nonceLen: Int
}

// MARK: - Cipher

/// A stateless Shadowsocks AEAD cipher engine.
///
/// Each instance is configured with a master key and cipher type.  Call
/// `newSession()` to generate a per‑connection salt and derive the session
/// sub‑key; then use `encryptChunk` / `decryptChunk` with that session.
public final class ShadowsocksCipher: Sendable {

    // MARK: - Configuration

    public let cipherType: ShadowsocksCipherType
    private let masterKey: SymmetricKey

    // MARK: - Initialisation

    /// - Parameters:
    ///   - type: The AEAD cipher to use.
    ///   - password: The master password (arbitrary length; the raw UTF‑8
    ///     bytes are used directly as the IKM for HKDF‑SHA1).
    public init(type: ShadowsocksCipherType, password: String) {
        self.cipherType = type
        // The master key is the password bytes, truncated/padded to key length
        // per many Shadowsocks implementations.
        var keyBytes = Array(password.utf8)
        if keyBytes.count > type.keyLength {
            keyBytes = Array(keyBytes.prefix(type.keyLength))
        } else if keyBytes.count < type.keyLength {
            keyBytes.append(contentsOf: [UInt8](
                repeating: 0, count: type.keyLength - keyBytes.count
            ))
        }
        self.masterKey = SymmetricKey(data: keyBytes)
    }

    /// Convenience initialiser with raw Data key.
    public init(type: ShadowsocksCipherType, keyData: Data) {
        self.cipherType = type
        let keyBytes: [UInt8]
        if keyData.count > type.keyLength {
            keyBytes = Array(keyData.prefix(type.keyLength))
        } else if keyData.count < type.keyLength {
            keyBytes = Array(keyData) + [UInt8](
                repeating: 0, count: type.keyLength - keyData.count
            )
        } else {
            keyBytes = Array(keyData)
        }
        self.masterKey = SymmetricKey(data: keyBytes)
    }

    // MARK: - Session Management

    /// Creates a new per‑connection session, generating a random salt and
    /// returning the salt (which must be sent to the peer) together with a
    /// session handle.
    ///
    /// - Returns: A tuple of `(salt, session)` where `salt` is prepended to
    ///   the first outbound chunk and `session` is an opaque token for
    ///   subsequent `encryptChunk` / `decryptChunk` calls.
    public func newSession() -> (salt: Data, session: ShadowsocksSession) {
        let salt = generateSalt(length: cipherType.saltLength)
        let sessionKey = deriveSessionKey(salt: salt)
        let material = SessionMaterial(
            key: sessionKey,
            salt: salt,
            nonceLen: 12
        )
        return (salt, ShadowsocksSession(material: material, cipherType: cipherType))
    }

    /// Restores a session from a received salt (server side / decryption path).
    public func session(from salt: Data) -> ShadowsocksSession {
        let sessionKey = deriveSessionKey(salt: salt)
        let material = SessionMaterial(
            key: sessionKey,
            salt: salt,
            nonceLen: 12
        )
        return ShadowsocksSession(material: material, cipherType: cipherType)
    }

    // MARK: - Key Derivation (HKDF‑SHA1)

    /// Derives the per‑session sub‑key using HKDF‑SHA1.
    ///
    ///   PRK = HMAC‑SHA1(salt, masterKey)
    ///   OKM = HKDF‑Expand(PRK, "ss-subkey", keyLength)
    private func deriveSessionKey(salt: Data) -> SymmetricKey {
        let info = "ss-subkey".data(using: .utf8)!
        return hkdfSHA1(
            ikm: masterKey,
            salt: salt,
            info: info,
            outputLength: cipherType.keyLength
        )
    }

    // MARK: - Helpers

    private func generateSalt(length: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: length)
        _ = SecRandomCopyBytes(kSecRandomDefault, length, &bytes)
        return Data(bytes)
    }
}

// MARK: - Session (Opaque Handle)

/// An opaque handle to a per‑connection Shadowsocks session.
///
/// Carries the derived key, salt, and chunk counter.  Not `Sendable` because
/// the mutable counter is updated on each chunk operation.
public final class ShadowsocksSession: @unchecked Sendable {

    fileprivate let material: SessionMaterial
    fileprivate let cipherType: ShadowsocksCipherType

    /// Monotonically increasing chunk counter (starts at 0, increments per
    /// AEAD chunk).  Used for nonce construction.
    fileprivate var encryptCounter: UInt64 = 0
    fileprivate var decryptCounter: UInt64 = 0

    fileprivate init(material: SessionMaterial, cipherType: ShadowsocksCipherType) {
        self.material = material
        self.cipherType = cipherType
    }

    // MARK: - Public API

    /// The salt bytes that were used when creating this session.
    public var salt: Data { material.salt }

    // MARK: Encryption

    /// Encrypts a plaintext chunk (length + payload) into an AEAD ciphertext
    /// that includes the authentication tag.
    ///
    /// The returned `Data` is `encrypted(length || plaintext) || tag` and is
    /// ready to be written to the wire.
    public func encryptChunk(plaintext: Data) throws -> Data {
        // Prepend 2‑byte big‑endian length.
        let payloadLength = UInt16(plaintext.count)
        var chunk = Data()
        chunk.append(UInt8(payloadLength >> 8))
        chunk.append(UInt8(payloadLength & 0xFF))
        chunk.append(plaintext)

        let nonce = makeNonce(counter: encryptCounter)
        encryptCounter &+= 1

        switch cipherType {
        case .aes128GCM, .aes256GCM:
            let aesNonce = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.seal(chunk, using: material.key, nonce: aesNonce)
            return sealed.ciphertext + sealed.tag

        case .chacha20Poly1305:
            let chaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.seal(chunk, using: material.key, nonce: chaNonce)
            return sealed.ciphertext + sealed.tag
        }
    }

    // MARK: Decryption

    /// Decrypts an AEAD ciphertext (ciphertext + tag) back into plaintext.
    ///
    /// The returned `Data` contains the plaintext **without** the 2‑byte
    /// length prefix (which is stripped automatically).
    public func decryptChunk(ciphertext: Data) throws -> Data {
        let nonce = makeNonce(counter: decryptCounter)
        decryptCounter &+= 1

        let tagLength = cipherType.tagLength
        guard ciphertext.count >= tagLength else {
            throw CipherError.invalidChunkLength(ciphertext.count)
        }

        let rawCiphertext = ciphertext.prefix(ciphertext.count - tagLength)
        let tag = ciphertext.suffix(tagLength)

        let decrypted: Data
        switch cipherType {
        case .aes128GCM, .aes256GCM:
            let aesNonce = try AES.GCM.Nonce(data: nonce)
            let sealed = try AES.GCM.SealedBox(
                nonce: aesNonce,
                ciphertext: rawCiphertext,
                tag: tag
            )
            decrypted = try AES.GCM.open(sealed, using: material.key)

        case .chacha20Poly1305:
            let chaNonce = try ChaChaPoly.Nonce(data: nonce)
            let sealed = try ChaChaPoly.SealedBox(
                nonce: chaNonce,
                ciphertext: rawCiphertext,
                tag: tag
            )
            decrypted = try ChaChaPoly.open(sealed, using: material.key)
        }

        // Strip the 2‑byte length prefix.
        guard decrypted.count >= 2 else {
            throw CipherError.invalidPlaintextLength(decrypted.count)
        }
        let payloadLength = (UInt16(decrypted[0]) << 8) | UInt16(decrypted[1])
        let payload = decrypted.suffix(from: 2)
        guard payload.count == payloadLength else {
            throw CipherError.lengthMismatch(declared: Int(payloadLength), actual: payload.count)
        }
        return payload
    }

    /// Skips the initial salt bytes from a peer's first message and
    /// returns a session ready for decryption.
    public static func consumeSalt(
        from data: inout Data,
        cipherType: ShadowsocksCipherType,
        cipher: ShadowsocksCipher
    ) -> ShadowsocksSession? {
        let saltLen = cipherType.saltLength
        guard data.count >= saltLen else { return nil }
        let salt = data.prefix(saltLen)
        data.removeFirst(saltLen)
        return cipher.session(from: Data(salt))
    }

    // MARK: - Nonce Construction

    /// Builds a 12‑byte AEAD nonce from the base nonce and chunk counter.
    ///
    /// The counter is XOR'd as a little‑endian 8‑byte integer into bytes
    /// 4–11 of the base nonce.
    private func makeNonce(counter: UInt64) -> Data {
        var bytes = Array(material.salt.prefix(material.nonceLen))
        // Pad to 12 bytes if the salt is shorter.
        while bytes.count < 12 { bytes.append(0) }

        var ctr = counter.littleEndian
        withUnsafeBytes(of: &ctr) { ctrBytes in
            for i in 0 ..< min(8, bytes.count - 4) {
                bytes[4 + i] ^= ctrBytes[i]
            }
        }
        return Data(bytes)
    }
}

// MARK: - HKDF-SHA1 Implementation

/// Derives a `SymmetricKey` using HKDF with SHA1 as the hash function.
///
/// CryptoKit exposes `HKDF<Insecure.SHA1>` on iOS 15+/macOS 12+, but the
/// exact API surface varies across SDK versions.  For maximum compatibility
/// this function implements HKDF‑SHA1 manually using only the HMAC primitive
/// (which is universally available).
private func hkdfSHA1(
    ikm: SymmetricKey,
    salt: Data,
    info: Data,
    outputLength: Int
) -> SymmetricKey {

    // ---- HKDF-Extract: PRK = HMAC-SHA1(salt, IKM) -----------------------
    let saltKey = SymmetricKey(data: salt)
    let prk = HMAC<Insecure.SHA1>.authenticationCode(
        for: ikm.withUnsafeBytes { Data($0) },
        using: saltKey
    )
    let prkData = Data(prk)
    let prkKey  = SymmetricKey(data: prkData)

    // ---- HKDF-Expand: T(i) = HMAC-SHA1(PRK, T(i-1) || info || i) --------
    // SHA1 produces 20‑byte blocks; the loop naturally stops at outputLength.
    var output  = Data()
    var counter: UInt8 = 1
    var lastT   = Data() // T(0) = empty

    while output.count < outputLength {
        var message = lastT
        message.append(info)
        message.append(counter)
        let authCode = HMAC<Insecure.SHA1>.authenticationCode(
            for: message,
            using: prkKey
        )
        lastT = Data(authCode)
        output.append(lastT)
        counter &+= 1
    }

    return SymmetricKey(data: output.prefix(outputLength))
}

// MARK: - Errors

public enum CipherError: Error, Sendable, Equatable {
    case invalidChunkLength(Int)
    case invalidPlaintextLength(Int)
    case lengthMismatch(declared: Int, actual: Int)
    case invalidSalt(Int)
}
