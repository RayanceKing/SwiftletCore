//===----------------------------------------------------------------------===//
//
//  SnellCryptoEngine.swift
//  SwiftletCore — Snell v4 Session Key Derivation & Encryption
//
//  Implements the Snell v4 cryptographic handshake: ephemeral nonce
//  generation, HKDF‑SHA256 session key derivation, and AES‑128‑GCM
//  encrypt/decrypt for the metadata and stream payloads.
//
//  Snell v4 Cryptography Specification
//  -----------------------------------
//  ```
//  1. Client generates a random 16‑byte Nonce.
//  2. SessionKey = HKDF‑SHA256(PSK, Salt=Nonce, Info="snell-key")
//  3. Request meta (host type + address + port + command) is encrypted
//     with AES‑128‑GCM using SessionKey and a fixed 12‑byte nonce.
//  4. Server decrypts, verifies tag, and derives the same SessionKey.
//  5. Subsequent streaming data is encrypted/decrypted with the same
//     SessionKey and incrementing per‑chunk nonces.
//  ```
//
//  Thread Safety
//  -------------
//  All methods are synchronous and stateless.  `SnellCryptoEngine` is a
//  value‑type namespace (no instances, all static methods).  The per‑
//  session `SnellSession` class holds the derived key and mutable
//  counters and is marked `@unchecked Sendable`.
//
//===----------------------------------------------------------------------===//

import CryptoKit
import Foundation

// MARK: - Constants

/// Snell v4 nonce length in bytes.
public let snellNonceLength = 16

/// Snell v4 session key length in bytes (AES‑128).
public let snellKeyLength = 16

/// AEAD authentication tag length in bytes.
public let snellTagLength = 16

/// Fixed AEAD nonce for the handshake metadata frame (12 bytes, all zero).
private let handshakeNonceData = Data(repeating: 0, count: 12)

/// HKDF info string for session key derivation.
private let hkdfInfo = "snell-key".data(using: .utf8)!

/// Snell v4 address type indicators.
private let snellAddrTypeIPv4   = UInt8(0x01)
private let snellAddrTypeDomain = UInt8(0x03)
private let snellAddrTypeIPv6   = UInt8(0x04)

/// Snell v4 command verbs.
public let snellCommandConnect = UInt8(0x01)
public let snellCommandUDP     = UInt8(0x03)

// MARK: - Per‑Session State

/// Holds the derived session key and per‑chunk counters for a single
/// Snell v4 connection.
public final class SnellSession: @unchecked Sendable {

    /// The derived AES‑128 session key (16 bytes).
    public let sessionKey: SymmetricKey

    /// The connection nonce (16 bytes, sent in cleartext to the server).
    public let nonce: Data

    /// Monotonic encrypt counter (starts at 0, increments per chunk).
    fileprivate var encryptCounter: UInt64 = 0

    /// Monotonic decrypt counter (starts at 0, increments per chunk).
    fileprivate var decryptCounter: UInt64 = 0

    /// Creates a new Snell session from a derived key and nonce.
    fileprivate init(sessionKey: SymmetricKey, nonce: Data) {
        self.sessionKey = sessionKey
        self.nonce = nonce
    }

    // MARK: - AEAD Nonce Construction

    /// Builds a 12‑byte AEAD nonce for the given counter value.
    ///
    /// The nonce is the first 12 bytes of the HMAC‑SHA256(key, counter)
    /// output, following the Snell v4 convention.
    private func makeAEADNonce(counter: UInt64) throws -> AES.GCM.Nonce {
        var ctrData = Data()
        ctrData.reserveCapacity(8)
        withUnsafeBytes(of: counter.littleEndian) { ctrData.append(contentsOf: $0) }

        let mac = HMAC<SHA256>.authenticationCode(for: ctrData, using: sessionKey)
        let nonceBytes = Data(mac).prefix(12)
        return try AES.GCM.Nonce(data: nonceBytes)
    }

    // MARK: - Encrypt

    /// Encrypts a plaintext chunk for outbound transmission.
    ///
    /// - Parameter plaintext: The raw payload bytes.
    /// - Returns: `ciphertext || tag` (ready for the wire).
    public func encrypt(plaintext: Data) throws -> Data {
        let nonce = try makeAEADNonce(counter: encryptCounter)
        encryptCounter &+= 1

        let sealed = try AES.GCM.seal(plaintext, using: sessionKey, nonce: nonce)
        return sealed.ciphertext + sealed.tag
    }

    /// Encrypts a `ByteBuffer` chunk, returning a new `ByteBuffer` with
    /// ciphertext + tag appended.
    public func encrypt(buffer: inout ByteBuffer, allocator: ByteBufferAllocator) throws -> ByteBuffer {
        let plaintext = buffer.readBytes(length: buffer.readableBytes) ?? []
        let ciphertext = try encrypt(plaintext: Data(plaintext))
        var result = allocator.buffer(capacity: ciphertext.count)
        result.writeBytes(ciphertext)
        return result
    }

    // MARK: - Decrypt

    /// Decrypts a ciphertext + tag chunk from the inbound stream.
    ///
    /// - Parameter ciphertext: `ciphertext || tag` received from the wire.
    /// - Returns: The decrypted plaintext bytes.
    public func decrypt(ciphertext: Data) throws -> Data {
        let nonce = try makeAEADNonce(counter: decryptCounter)
        decryptCounter &+= 1

        guard ciphertext.count >= snellTagLength else {
            throw SnellCryptoError.invalidChunkLength(ciphertext.count)
        }

        let rawCiphertext = ciphertext.prefix(ciphertext.count - snellTagLength)
        let tag = ciphertext.suffix(snellTagLength)

        let sealed = try AES.GCM.SealedBox(
            nonce: nonce,
            ciphertext: rawCiphertext,
            tag: tag
        )
        return try AES.GCM.open(sealed, using: sessionKey)
    }
}

// MARK: - Crypto Engine

/// Stateless Snell v4 cryptographic operations.
///
/// All methods are `static` — no instance state is ever created.
/// This namespace exists solely for organisational grouping.
public enum SnellCryptoEngine {

    // MARK: - Nonce Generation

    /// Generates a cryptographically secure random 16‑byte nonce.
    public static func generateNonce() -> Data {
        var bytes = [UInt8](repeating: 0, count: snellNonceLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, snellNonceLength, &bytes)
        return Data(bytes)
    }

    // MARK: - Session Key Derivation

    /// Derives the AES‑128 session key from the PSK and connection nonce.
    ///
    /// Uses HKDF‑SHA256:
    ///   PRK = HMAC‑SHA256(salt=nonce, IKM=PSK)
    ///   OKM = HKDF‑Expand(PRK, info="snell-key", length=16)
    public static func deriveSessionKey(psk: String, nonce: Data) -> SymmetricKey {
        // ---- HKDF-Extract ------------------------------------------------
        let pskData = Data(psk.utf8)
        let saltKey = SymmetricKey(data: nonce)
        let prk = HMAC<SHA256>.authenticationCode(
            for: pskData,
            using: saltKey
        )

        // ---- HKDF-Expand ------------------------------------------------
        let prkKey = SymmetricKey(data: Data(prk))
        let authCode = HMAC<SHA256>.authenticationCode(
            for: hkdfInfo + Data([0x01]),
            using: prkKey
        )
        return SymmetricKey(data: Data(authCode).prefix(snellKeyLength))
    }

    /// Creates a new Snell session: generates a nonce, derives the key,
    /// and returns the session + nonce (which must be prepended to the
    /// first outbound wire frame).
    public static func newSession(psk: String) -> (nonce: Data, session: SnellSession) {
        let nonce = generateNonce()
        let key = deriveSessionKey(psk: psk, nonce: nonce)
        let session = SnellSession(sessionKey: key, nonce: nonce)
        return (nonce, session)
    }

    /// Restores a Snell session from a received nonce (server‑side path).
    public static func session(from nonce: Data, psk: String) -> SnellSession {
        let key = deriveSessionKey(psk: psk, nonce: nonce)
        return SnellSession(sessionKey: key, nonce: nonce)
    }

    // MARK: - Handshake Meta Encryption

    /// Builds and encrypts the Snell v4 request metadata frame.
    ///
    /// The metadata layout is:
    /// ```
    /// [0x01] [addrLen?] [address…] [port BE] [command]
    /// ```
    /// where `0x01` signals an IPv4 address, `0x03` signals a domain, and
    /// `0x04` signals an IPv6 address.
    public static func buildEncryptedMetadata(
        host: String,
        port: UInt16,
        command: UInt8,
        session: SnellSession
    ) throws -> Data {
        // ---- 1. Serialise the metadata payload ---------------------------
        var meta = Data()

        // Determine address type and serialise.
        if let ipv4 = parseIPv4(host) {
            meta.append(snellAddrTypeIPv4)
            meta.append(contentsOf: ipv4)
        } else if let ipv6 = parseIPv6(host) {
            meta.append(snellAddrTypeIPv6)
            meta.append(contentsOf: ipv6)
        } else {
            // Domain name.
            let domainBytes = Array(host.utf8)
            guard domainBytes.count <= 255 else {
                throw SnellCryptoError.domainTooLong(domainBytes.count)
            }
            meta.append(snellAddrTypeDomain)
            meta.append(UInt8(domainBytes.count))
            meta.append(contentsOf: domainBytes)
        }

        // Port (big‑endian UInt16).
        var portBE = port.bigEndian
        withUnsafeBytes(of: &portBE) { meta.append(contentsOf: $0) }

        // Command verb.
        meta.append(command)

        // ---- 2. Encrypt with the handshake nonce -------------------------
        let handshakeNonce = try AES.GCM.Nonce(data: handshakeNonceData)
        let sealed = try AES.GCM.seal(meta, using: session.sessionKey, nonce: handshakeNonce)

        // ---- 3. Return nonce + ciphertext + tag --------------------------
        var frame = Data(capacity: snellNonceLength + sealed.ciphertext.count + sealed.tag.count)
        frame.append(session.nonce)
        frame.append(sealed.ciphertext)
        frame.append(sealed.tag)
        return frame
    }

    /// Decrypts and parses server handshake response metadata.
    ///
    /// Returns `true` if the server accepted the connection.
    public static func verifyHandshakeResponse(
        data: Data,
        session: SnellSession
    ) throws -> Bool {
        guard data.count >= snellTagLength else {
            throw SnellCryptoError.invalidResponseLength(data.count)
        }

        let handshakeNonce = try AES.GCM.Nonce(data: handshakeNonceData)
        let rawCiphertext = data.prefix(data.count - snellTagLength)
        let tag = data.suffix(snellTagLength)

        let sealed = try AES.GCM.SealedBox(
            nonce: handshakeNonce,
            ciphertext: rawCiphertext,
            tag: tag
        )
        let plaintext = try AES.GCM.open(sealed, using: session.sessionKey)

        // The server response is a single byte: 0x00 = success, others = error.
        return plaintext.first == 0x00
    }

    // MARK: - Address Helpers

    /// Attempts to parse a string as an IPv4 address, returning 4 raw bytes.
    private static func parseIPv4(_ host: String) -> [UInt8]? {
        let parts = host.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var bytes = [UInt8]()
        for part in parts {
            guard let b = UInt8(part), String(b) == String(part) else { return nil }
            bytes.append(b)
        }
        return bytes.count == 4 ? bytes : nil
    }

    /// Attempts to parse a string as an IPv6 address, returning 16 raw bytes.
    private static func parseIPv6(_ host: String) -> [UInt8]? {
        // IPv6 addresses may contain brackets; strip them.
        let stripped = host.trimmingCharacters(
            in: CharacterSet(charactersIn: "[]")
        )
        let groups = stripped.split(separator: ":", omittingEmptySubsequences: false)
        // Must have 8 groups for a full IPv6 address.
        guard groups.count == 8 else { return nil }
        var bytes = [UInt8]()
        for group in groups {
            guard let val = UInt16(group, radix: 16) else { return nil }
            var be = val.bigEndian
            withUnsafeBytes(of: &be) { bytes.append(contentsOf: $0) }
        }
        return bytes.count == 16 ? bytes : nil
    }
}

// MARK: - Errors

public enum SnellCryptoError: Error, Sendable {
    case invalidChunkLength(Int)
    case invalidResponseLength(Int)
    case domainTooLong(Int)
}

extension SnellCryptoError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidChunkLength(let len):
            return "Snell chunk too short for AEAD tag: \(len) bytes"
        case .invalidResponseLength(let len):
            return "Snell handshake response too short: \(len) bytes"
        case .domainTooLong(let len):
            return "Domain name too long for Snell metadata: \(len) bytes"
        }
    }
}
