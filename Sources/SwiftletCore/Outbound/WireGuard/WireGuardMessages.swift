//===----------------------------------------------------------------------===//
//
//  WireGuardMessages.swift
//  SwiftletCore — WireGuard Handshake Message Serialization
//
//  Implements precision‑aligned binary builders for the WireGuard
//  Noise_IKpsk2_25519 handshake protocol.
//
//  Message Layouts
//  ---------------
//  **Type 1 — Handshake Initiation (148 bytes)**:
//  ```
//  [4]  Type       = 0x01_000000 (little‑endian UInt32)
//  [4]  Sender     = random index
//  [32] Ephemeral  = sender's Curve25519 public key
//  [48] Static     = AEAD(sender's static public key)  (32 + 16 tag)
//  [28] Timestamp  = AEAD(TAI64N)                       (12 + 16 tag)
//  [16] MAC1       = keyed hash for DoS protection
//  [16] MAC2       = optional cookie MAC
//  ```
//
//  **Type 2 — Handshake Response (92 bytes)**:
//  ```
//  [4]  Type       = 0x02_000000
//  [4]  Sender     = server's index
//  [4]  Receiver   = copied from initiation sender
//  [32] Ephemeral  = server's Curve25519 public key
//  [16] Nothing    = AEAD(empty)  (0 + 16 tag)
//  [16] MAC1
//  [16] MAC2
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation
import CryptoKit

// MARK: - Message Type

public enum WireGuardMessageType: UInt32, Sendable {
    case initiation = 1
    case response   = 2
    case cookieReply = 3
    case transport   = 4
}

// MARK: - WireGuard Messages

/// Builders and parsers for WireGuard handshake messages.
public enum WireGuardMessages {

    // MARK: - Sizes

    public static let initiationSize = 148
    public static let responseSize   = 92
    public static let keySize        = 32
    public static let macSize        = 16
    public static let aeadTagSize    = 16

    /// The TAI64N timestamp (12 bytes) AEAD‑encrypted with a 16‑byte tag.
    public static let encryptedTimestampSize = 28
    /// The static public key (32 bytes) AEAD‑encrypted.
    public static let encryptedStaticSize    = 48
    /// An empty payload AEAD‑encrypted (0 bytes + 16‑byte tag).
    public static let encryptedNothingSize   = 16

    /// Fixed header overhead for Type 4 Transport Data messages.
    ///  [4] Type  |  [4] Receiver Index  |  [8] Counter
    public static let transportHeaderSize    = 16

    // MARK: - Build Initiation (Type 1)

    /// Builds a Handshake Initiation message (148 bytes).
    ///
    /// Fields that require AEAD encryption (static key, timestamp) and
    /// MAC computation are provided pre‑computed by the caller (typically
    /// the `WireGuardNoiseMachine`).
    ///
    /// - Parameters:
    ///   - senderIndex: Random 4‑byte sender identifier.
    ///   - ephemeralPubKey: 32‑byte unencrypted Curve25519 public key.
    ///   - encryptedStatic: 48‑byte AEAD(sender static public key).
    ///   - encryptedTimestamp: 28‑byte AEAD(TAI64N timestamp).
    ///   - mac1: 16‑byte keyed hash for DoS protection.
    ///   - mac2: 16‑byte optional cookie MAC (may be all‑zeros).
    /// - Returns: Exactly 148 bytes.
    public static func buildInitiation(
        senderIndex: UInt32,
        ephemeralPubKey: Data,
        encryptedStatic: Data,
        encryptedTimestamp: Data,
        mac1: Data = Data(repeating: 0, count: macSize),
        mac2: Data = Data(repeating: 0, count: macSize)
    ) -> Data {
        var data = Data(capacity: initiationSize)

        // [4] Type = 1 (little‑endian)
        var type = WireGuardMessageType.initiation.rawValue.littleEndian
        data.append(withUnsafeBytes(of: &type) { Data($0) })

        // [4] Sender Index
        var sender = senderIndex.littleEndian
        data.append(withUnsafeBytes(of: &sender) { Data($0) })

        // [32] Ephemeral Public Key
        data.append(ephemeralPubKey.prefix(keySize).padded(to: keySize))

        // [48] Encrypted Static
        data.append(encryptedStatic.prefix(encryptedStaticSize).padded(to: encryptedStaticSize))

        // [28] Encrypted Timestamp
        data.append(encryptedTimestamp.prefix(encryptedTimestampSize).padded(to: encryptedTimestampSize))

        // [16] MAC1 + [16] MAC2
        data.append(mac1.prefix(macSize).padded(to: macSize))
        data.append(mac2.prefix(macSize).padded(to: macSize))

        precondition(data.count == initiationSize,
                     "Initiation must be \(initiationSize) bytes, got \(data.count)")
        return data
    }

    // MARK: - Build Response (Type 2)

    /// Builds a Handshake Response message (92 bytes).
    public static func buildResponse(
        senderIndex: UInt32,
        receiverIndex: UInt32,
        ephemeralPubKey: Data,
        encryptedNothing: Data,
        mac1: Data = Data(repeating: 0, count: macSize),
        mac2: Data = Data(repeating: 0, count: macSize)
    ) -> Data {
        var data = Data(capacity: responseSize)

        // [4] Type = 2
        var type = WireGuardMessageType.response.rawValue.littleEndian
        data.append(withUnsafeBytes(of: &type) { Data($0) })

        // [4] Sender Index
        var sender = senderIndex.littleEndian
        data.append(withUnsafeBytes(of: &sender) { Data($0) })

        // [4] Receiver Index
        var receiver = receiverIndex.littleEndian
        data.append(withUnsafeBytes(of: &receiver) { Data($0) })

        // [32] Ephemeral Public Key
        data.append(ephemeralPubKey.prefix(keySize).padded(to: keySize))

        // [16] Encrypted Empty Payload (16‑byte AEAD tag)
        data.append(encryptedNothing.prefix(encryptedNothingSize).padded(to: encryptedNothingSize))

        // [16] MAC1 + [16] MAC2
        data.append(mac1.prefix(macSize).padded(to: macSize))
        data.append(mac2.prefix(macSize).padded(to: macSize))

        precondition(data.count == responseSize,
                     "Response must be \(responseSize) bytes, got \(data.count)")
        return data
    }

    // MARK: - Parse

    /// Parsed Initiation message fields.
    public struct ParsedInitiation: Sendable {
        public let senderIndex: UInt32
        public let ephemeralPubKey: Data
        public let encryptedStatic: Data
        public let encryptedTimestamp: Data
        public let mac1: Data
        public let mac2: Data
    }

    /// Parsed Response message fields.
    public struct ParsedResponse: Sendable {
        public let senderIndex: UInt32
        public let receiverIndex: UInt32
        public let ephemeralPubKey: Data
        public let encryptedNothing: Data
        public let mac1: Data
        public let mac2: Data
    }

    /// Extracts the message type from the first 4 bytes.
    public static func messageType(from data: Data) -> WireGuardMessageType? {
        guard data.count >= 4 else { return nil }
        let raw = UInt32(littleEndian: data.withUnsafeBytes { $0.load(as: UInt32.self) })
        return WireGuardMessageType(rawValue: raw)
    }

    /// Parses a Handshake Initiation message.
    public static func parseInitiation(_ data: Data) -> ParsedInitiation? {
        guard data.count >= initiationSize else { return nil }
        var offset = 4 // skip type

        let senderIndex = data.readUInt32LE(at: offset); offset += 4
        let ephemeral   = data.subdata(in: offset ..< offset + keySize); offset += keySize
        let encStatic   = data.subdata(in: offset ..< offset + encryptedStaticSize); offset += encryptedStaticSize
        let encTS       = data.subdata(in: offset ..< offset + encryptedTimestampSize); offset += encryptedTimestampSize
        let mac1        = data.subdata(in: offset ..< offset + macSize); offset += macSize
        let mac2        = data.subdata(in: offset ..< offset + macSize)

        return ParsedInitiation(
            senderIndex: senderIndex,
            ephemeralPubKey: ephemeral,
            encryptedStatic: encStatic,
            encryptedTimestamp: encTS,
            mac1: mac1,
            mac2: mac2
        )
    }

    /// Parses a Handshake Response message.
    public static func parseResponse(_ data: Data) -> ParsedResponse? {
        guard data.count >= responseSize else { return nil }
        var offset = 4

        let sender   = data.readUInt32LE(at: offset); offset += 4
        let receiver = data.readUInt32LE(at: offset); offset += 4
        let ephemeral = data.subdata(in: offset ..< offset + keySize); offset += keySize
        let encNothing = data.subdata(in: offset ..< offset + encryptedNothingSize); offset += encryptedNothingSize
        let mac1 = data.subdata(in: offset ..< offset + macSize); offset += macSize
        let mac2 = data.subdata(in: offset ..< offset + macSize)

        return ParsedResponse(
            senderIndex: sender,
            receiverIndex: receiver,
            ephemeralPubKey: ephemeral,
            encryptedNothing: encNothing,
            mac1: mac1,
            mac2: mac2
        )
    }

    // MARK: - Build Transport Data (Type 4)

    /// Parsed Transport Data message fields.
    public struct ParsedTransport: Sendable {
        public let receiverIndex: UInt32
        public let counter: UInt64
        public let encryptedPayload: Data
    }

    /// Builds a Transport Data message (Type 4) for carrying encrypted
    /// inner‑tunnel IP packets over UDP.
    ///
    /// Wire format (16‑byte header + encrypted payload):
    /// ```
    /// [4]  Type           = 0x04_000000  (little‑endian UInt32)
    /// [4]  Receiver Index
    /// [8]  Counter        (little‑endian UInt64)
    /// [N]  Encrypted      = ChaCha20‑Poly1305(inner IP packet)
    /// ```
    ///
    /// - Parameters:
    ///   - receiverIndex: The remote peer's sender index acquired during
    ///     the Type 2 Handshake Response.
    ///   - counter: Strictly‑increasing 64‑bit counter used for nonce
    ///     derivation and replay defence.
    ///   - encryptedPayload: `ChaChaPoly.seal()` ciphertext + 16‑byte tag.
    /// - Returns: A complete Type 4 datagram ready for UDP transmission.
    public static func buildTransportData(
        receiverIndex: UInt32,
        counter: UInt64,
        encryptedPayload: Data
    ) -> Data {
        var data = Data(capacity: transportHeaderSize + encryptedPayload.count)

        // [4] Type = 4 (little‑endian)
        var type = WireGuardMessageType.transport.rawValue.littleEndian
        data.append(withUnsafeBytes(of: &type) { Data($0) })

        // [4] Receiver Index (little‑endian)
        var receiver = receiverIndex.littleEndian
        data.append(withUnsafeBytes(of: &receiver) { Data($0) })

        // [8] Counter (little‑endian)
        var counterLE = counter.littleEndian
        data.append(withUnsafeBytes(of: &counterLE) { Data($0) })

        // [N] Encrypted Payload (ciphertext + AEAD tag)
        data.append(encryptedPayload)

        return data
    }

    /// Parses a Transport Data message (Type 4), extracting the header
    /// fields and leaving the encrypted payload as an opaque `Data` slice.
    ///
    /// - Parameter data: Raw UDP datagram received from the WireGuard peer.
    /// - Returns: `ParsedTransport` on success, `nil` if the datagram is
    ///   too short or has an incorrect type byte.
    public static func parseTransportData(_ data: Data) -> ParsedTransport? {
        guard data.count >= transportHeaderSize else { return nil }

        // Verify the type byte is 0x04.
        guard data[0] == WireGuardMessageType.transport.rawValue,
              data[1] == 0x00, data[2] == 0x00, data[3] == 0x00 else {
            return nil
        }

        let receiverIndex = data.readUInt32LE(at: 4)
        let counter       = data.readUInt64LE(at: 8)
        let encryptedPayload = data.subdata(in: transportHeaderSize ..< data.count)

        return ParsedTransport(
            receiverIndex: receiverIndex,
            counter: counter,
            encryptedPayload: encryptedPayload
        )
    }
}

// MARK: - Data Helpers

extension Data {
    fileprivate func readUInt32LE(at offset: Int) -> UInt32 {
        subdata(in: offset ..< offset + 4).withUnsafeBytes {
            $0.load(as: UInt32.self)
        }
    }

    fileprivate func readUInt64LE(at offset: Int) -> UInt64 {
        subdata(in: offset ..< offset + 8).withUnsafeBytes {
            $0.load(as: UInt64.self)
        }
    }

    fileprivate func padded(to length: Int, with pad: UInt8 = 0) -> Data {
        if count >= length { return prefix(length) }
        var copy = self
        copy.append(contentsOf: [UInt8](repeating: pad, count: length - count))
        return copy
    }
}
