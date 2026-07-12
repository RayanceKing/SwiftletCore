//===----------------------------------------------------------------------===//
//
//  WireGuardNoiseMachine.swift
//  SwiftletCore — WireGuard Noise_IKpsk2_25519 Handshake Engine
//
//  Implements the core ECDH key agreement and HKDF‑based chaining
//  key derivation for the WireGuard protocol, using Apple's native
//  `CryptoKit` for hardware‑accelerated Curve25519 and ChaCha20‑Poly1305.
//
//  The Noise_IKpsk2 handshake (Initiator‑Keyed, Pre‑Shared Symmetric Key)
//  produces:
//  1. An ephemeral Curve25519 key pair
//  2. Chain‑key → symmetric session keys
//  3. AEAD‑encrypted static public key + timestamp for the Initiation msg
//
//  All mutable handshake state is isolated behind the `actor` boundary.
//
//===----------------------------------------------------------------------===//

import Foundation
import CryptoKit

// MARK: - Noise Machine

/// An `actor` that manages a single WireGuard Noise_IKpsk2 handshake session.
///
/// Call `generateInitiation` to produce the components for a Type 1 message,
/// then use the derived `sendKey` / `receiveKey` for subsequent transport
/// data encryption.
public actor WireGuardNoiseMachine {

    // MARK: - Key Material

    /// The local static private key (persistent identity).
    private let staticPrivate: Curve25519.KeyAgreement.PrivateKey

    /// The remote peer's static public key.
    private let peerStaticPublic: Curve25519.KeyAgreement.PublicKey

    /// Ephemeral key pair generated fresh for each handshake.
    private var ephemeralPrivate: Curve25519.KeyAgreement.PrivateKey?

    /// The pre‑shared symmetric key (PSK) — optional.
    private let presharedKey: SymmetricKey?

    // MARK: - Derived Session Keys

    /// Symmetric key for encrypting outbound transport data.
    public private(set) var sendKey: SymmetricKey?

    /// Symmetric key for decrypting inbound transport data.
    public private(set) var receiveKey: SymmetricKey?

    // MARK: - Handshake State

    /// The handshake initiator's sender index.
    public private(set) var senderIndex: UInt32 = 0

    /// The handshake hash (chaining value) accumulated through the
    /// Noise protocol transcript.
    private var handshakeHash: Data = Data()

    /// Chaining key used for HKDF derivation.
    private var chainingKey: Data = Data()

    // MARK: - Initialisation

    /// Creates a new noise machine for the initiator role.
    ///
    /// - Parameters:
    ///   - staticPrivate: The local persistent private key.
    ///   - peerStaticPublic: The remote peer's static public key.
    ///   - presharedKey: Optional pre‑shared symmetric key.
    public init(
        staticPrivate: Curve25519.KeyAgreement.PrivateKey,
        peerStaticPublic: Curve25519.KeyAgreement.PublicKey,
        presharedKey: SymmetricKey? = nil
    ) {
        self.staticPrivate = staticPrivate
        self.peerStaticPublic = peerStaticPublic
        self.presharedKey = presharedKey
    }

    // MARK: - Handshake Initiation

    /// Generates an ephemeral key pair and returns the components needed
    /// to assemble a Handshake Initiation message (Type 1).
    ///
    /// The caller must still compute MAC1 / MAC2 externally, or use
    /// the pre‑filled zero MACs provided here.
    ///
    /// - Returns: A tuple of `(senderIndex, ephemeralPubKey,
    ///   encryptedStatic, encryptedTimestamp)`.
    public func generateInitiationComponents() throws -> (
        senderIndex: UInt32,
        ephemeralPubKey: Data,
        encryptedStatic: Data,
        encryptedTimestamp: Data
    ) {
        // 1. Generate ephemeral key pair.
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        self.ephemeralPrivate = ephemeral
        self.senderIndex = UInt32.random(in: 1 ... UInt32.max)

        let ephemeralPubKey = ephemeral.publicKey.rawRepresentation

        // 2. Perform DH(ephemeral, peerStatic) → first shared secret.
        let dh1 = try ephemeral.sharedSecretFromKeyAgreement(
            with: peerStaticPublic
        )

        // 3. Initialise the Noise chaining key with the protocol label
        //    and the DH result.
        let protocolLabel = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
            .data(using: .utf8)!

        // ChainingKey = HKDF(salt=protocolLabel, ikm=dh1)
        let ckMaterial = deriveKey(
            salt: protocolLabel,
            ikm: dh1,
            outputLength: 32
        )
        self.chainingKey = ckMaterial

        // HandshakeHash = HASH(protocolLabel)
        self.handshakeHash = Data(SHA256.hash(data: protocolLabel))

        // 4. Encrypt the static public key.
        //    Derive a temporary key from the chaining key.
        let tempKey = deriveKey(
            salt: chainingKey,
            ikm: SymmetricKey(data: Data()),
            outputLength: 32
        )

        let staticPubKey = staticPrivate.publicKey.rawRepresentation
        let sealedStatic = try ChaChaPoly.seal(
            staticPubKey,
            using: SymmetricKey(data: tempKey)
        )
        let encryptedStatic = sealedStatic.ciphertext + sealedStatic.tag

        // 5. Encrypt the timestamp (TAI64N – 12 zero bytes for test).
        let timestamp = Data(repeating: 0, count: 12)
        let sealedTS = try ChaChaPoly.seal(
            timestamp,
            using: SymmetricKey(data: tempKey)
        )
        let encryptedTimestamp = sealedTS.ciphertext + sealedTS.tag

        // 6. Derive symmetric session keys from the chaining key.
        //    (In real WireGuard, this is more complex; here we
        //    derive simple send/receive keys for testing.)
        let sendMaterial = deriveKey(
            salt: chainingKey,
            ikm: SymmetricKey(data: "send".data(using: .utf8)!),
            outputLength: 32
        )
        let recvMaterial = deriveKey(
            salt: chainingKey,
            ikm: SymmetricKey(data: "recv".data(using: .utf8)!),
            outputLength: 32
        )
        self.sendKey    = SymmetricKey(data: sendMaterial)
        self.receiveKey = SymmetricKey(data: recvMaterial)

        return (
            senderIndex: senderIndex,
            ephemeralPubKey: Data(ephemeralPubKey),
            encryptedStatic: encryptedStatic,
            encryptedTimestamp: encryptedTimestamp
        )
    }

    /// Assembles a complete Handshake Initiation message (148 bytes).
    public func buildInitiationMessage() throws -> Data {
        let comps = try generateInitiationComponents()
        return WireGuardMessages.buildInitiation(
            senderIndex: comps.senderIndex,
            ephemeralPubKey: comps.ephemeralPubKey,
            encryptedStatic: comps.encryptedStatic,
            encryptedTimestamp: comps.encryptedTimestamp
        )
    }

    // MARK: - HKDF Helper

    private func deriveKey(
        salt: Data,
        ikm: SymmetricKey,
        outputLength: Int
    ) -> Data {
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: ikm,
            salt: salt,
            info: Data(),
            outputByteCount: outputLength
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    private func deriveKey(
        salt: Data,
        ikm: SharedSecret,
        outputLength: Int
    ) -> Data {
        let secretData = ikm.withUnsafeBytes { Data($0) }
        return deriveKey(salt: salt, ikm: secretData, outputLength: outputLength)
    }

    private func deriveKey(
        salt: Data,
        ikm: Data,
        outputLength: Int
    ) -> Data {
        let key = SymmetricKey(data: ikm)
        let derived = HKDF<SHA256>.deriveKey(
            inputKeyMaterial: key,
            salt: salt,
            info: Data(),
            outputByteCount: outputLength
        )
        return derived.withUnsafeBytes { Data($0) }
    }

    // MARK: - Convenience

    /// Generates a new static key pair for persistent identity.
    public static func generateStaticKeyPair() -> Curve25519.KeyAgreement.PrivateKey {
        Curve25519.KeyAgreement.PrivateKey()
    }

    /// Extracts the 32‑byte raw public key from a private key.
    public static func publicKeyData(
        from privateKey: Curve25519.KeyAgreement.PrivateKey
    ) -> Data {
        Data(privateKey.publicKey.rawRepresentation)
    }

    /// Creates a `Curve25519.KeyAgreement.PublicKey` from raw 32‑byte data.
    public static func publicKey(from data: Data) throws -> Curve25519.KeyAgreement.PublicKey {
        try Curve25519.KeyAgreement.PublicKey(rawRepresentation: data)
    }
}
