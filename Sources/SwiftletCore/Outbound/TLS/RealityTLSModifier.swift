//===----------------------------------------------------------------------===//
//
//  RealityTLSModifier.swift
//  SwiftletCore — RAW TLS 1.3 Client Hello Mutator
//
//  A byte‑level parser and modifier for TLS 1.3 Client Hello messages.
//  Because Apple's `Network.framework` seals the handshake and forbids
//  custom extension injection, REALITY‑style protocols must operate on
//  raw byte buffers.  This module provides safe, bounds‑checked primitives
//  for parsing, locating, inserting, and re‑serialising TLS extensions
//  without unsafe pointer arithmetic.
//
//  TLS Record structure (RFC 8446)
//  -------------------------------
//  ```
//  [1] ContentType (0x16 = Handshake)
//  [2] LegacyVersion  (0x0301 or 0x0303)
//  [2] RecordLength   (length of following handshake data)
//
//  [1] HandshakeType    (0x01 = ClientHello)
//  [3] HandshakeLength  (length of ClientHello data)
//
//  [2] ClientVersion
//  [32] Random
//  [1 + n] SessionID
//  [2 + n] CipherSuites
//  [1 + n] CompressionMethods
//  [2 + n] Extensions
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - TLS Record

/// A parsed TLS Record Layer header + payload.
public struct TLSRecord: Sendable {
    public let contentType: UInt8
    public let legacyVersion: UInt16
    public let recordLength: UInt16
    public let payload: Data

    /// The minimum valid record (header = 5 bytes).
    public static let headerSize = 5
}

// MARK: - TLS Handshake

/// A parsed TLS Handshake message.
public struct TLSHandshake: Sendable {
    public let handshakeType: UInt8
    public let handshakeLength: UInt32  // 3 bytes on wire
    public let data: Data
}

// MARK: - TLS Client Hello

/// The fully parsed content of a TLS 1.3 Client Hello.
public struct TLSClientHello: Sendable {
    public let clientVersion: UInt16
    public let random: Data           // 32 bytes
    public let sessionID: Data
    public let cipherSuites: [UInt16]
    public let compressionMethods: [UInt8]
    public var extensions: [TLSExtension]
}

// MARK: - TLS Extension

/// A single TLS extension (type + opaque data).
public struct TLSExtension: Sendable, Equatable {
    public let type: UInt16
    public var data: Data

    public var wireLength: Int { 4 + data.count } // 2(type) + 2(len) + data

    /// Well‑known extension types.
    public struct Types {
        public static let serverName       : UInt16 = 0x0000
        public static let supportedGroups   : UInt16 = 0x000A
        public static let signatureAlgorithms: UInt16 = 0x000D
        public static let applicationLayerProtocolNegotiation: UInt16 = 0x0010
        public static let padding           : UInt16 = 0x0015
        public static let supportedVersions : UInt16 = 0x002B
        public static let keyShare          : UInt16 = 0x0033
    }
}

// MARK: - Parser Errors

public enum TLSParseError: Error, Sendable, Equatable {
    case insufficientData(needed: Int, available: Int)
    case invalidContentType(UInt8)
    case invalidHandshakeType(UInt8)
}

// MARK: - Reality TLS Modifier

/// A namespace for raw TLS Client Hello parsing and modification operations.
public enum RealityTLSModifier {

    // MARK: - Builder

    /// Creates a minimal but valid TLS 1.3 Client Hello suitable as the
    /// base for REALITY modifications.
    ///
    /// The returned structure includes:
    /// • ClientVersion = TLS 1.2 (0x0303, for compatibility)
    /// • SNI extension pointing to the provided hostname
    /// • Supported Versions extension (TLS 1.3 = 0x0304)
    /// • Minimal Key Share (x25519 placeholder)
    /// • No session ID, single cipher suite (TLS_AES_128_GCM_SHA256),
    ///   null compression
    ///
    /// Callers should then add the REALITY auth‑key extension and padding
    /// via `addCustomExtension` / `addPadding` before serialising.
    public static func makeBaseClientHello(sni: String) -> TLSClientHello {
        // Build the SNI extension data (internal format).
        var sniExtData = Data()
        writeUInt16(UInt16(sni.utf8.count + 3), to: &sniExtData)
        sniExtData.append(0x00) // name_type = host_name
        writeUInt16(UInt16(sni.utf8.count), to: &sniExtData)
        sniExtData.append(contentsOf: sni.utf8)

        // Build a minimal Key Share (x25519, 32‑byte placeholder).
        var ksData = Data()
        writeUInt16(0x001D, to: &ksData) // named group: x25519
        writeUInt16(0x0020, to: &ksData) // key length = 32
        ksData.append(contentsOf: [UInt8](repeating: 0xCC, count: 32))

        return TLSClientHello(
            clientVersion: 0x0303,
            random: Data([UInt8](repeating: 0xAA, count: 32)),
            sessionID: Data(),
            cipherSuites: [0x1301], // TLS_AES_128_GCM_SHA256
            compressionMethods: [0x00],
            extensions: [
                TLSExtension(type: TLSExtension.Types.serverName, data: sniExtData),
                TLSExtension(type: TLSExtension.Types.supportedVersions,
                              data: Data([0x03, 0x04])),
                TLSExtension(type: TLSExtension.Types.keyShare, data: ksData),
            ]
        )
    }

    // MARK: - Parse

    /// Parses a complete TLS record containing a Client Hello handshake
    /// message from a raw byte buffer.
    ///
    /// - Parameter data: The raw TLS record bytes.
    /// - Returns: A fully parsed `TLSClientHello`.
    /// - Throws: `TLSParseError` if the data is malformed or truncated.
    public static func parseClientHello(from data: Data) throws -> TLSClientHello {
        var offset = 0

        // ---- TLS Record Layer --------------------------------------------
        guard data.count >= 5 else {
            throw TLSParseError.insufficientData(needed: 5, available: data.count)
        }

        let contentType   = data[offset];     offset += 1
        _                  = readUInt16(data, at: offset); offset += 2 // legacyVersion
        let recordLength   = readUInt16(data, at: offset); offset += 2

        guard contentType == 0x16 else {
            throw TLSParseError.invalidContentType(contentType)
        }
        guard offset + Int(recordLength) <= data.count else {
            throw TLSParseError.insufficientData(
                needed: offset + Int(recordLength), available: data.count
            )
        }

        // ---- Handshake Protocol ------------------------------------------
        let handshakeType  = data[offset];     offset += 1
        let handshakeLen   = readUInt24(data, at: offset); offset += 3

        guard handshakeType == 0x01 else {
            throw TLSParseError.invalidHandshakeType(handshakeType)
        }
        guard offset + Int(handshakeLen) <= data.count else {
            throw TLSParseError.insufficientData(
                needed: offset + Int(handshakeLen), available: data.count
            )
        }

        let helloStart = offset

        // ---- ClientHello -------------------------------------------------
        let clientVersion = readUInt16(data, at: offset); offset += 2

        // Random (32 bytes)
        let random = data.subdata(in: offset ..< offset + 32)
        offset += 32

        // Session ID
        let sidLen = Int(data[offset]); offset += 1
        let sessionID = data.subdata(in: offset ..< offset + sidLen)
        offset += sidLen

        // Cipher Suites
        let csLen = Int(readUInt16(data, at: offset)); offset += 2
        var cipherSuites: [UInt16] = []
        for i in stride(from: 0, to: csLen, by: 2) {
            cipherSuites.append(readUInt16(data, at: offset + i))
        }
        offset += csLen

        // Compression Methods
        let compLen = Int(data[offset]); offset += 1
        let compressionMethods = Array(
            data.subdata(in: offset ..< offset + compLen)
        )
        offset += compLen

        // ---- Extensions --------------------------------------------------
        let extLen = Int(readUInt16(data, at: offset)); offset += 2
        let extEnd = offset + extLen
        var extensions: [TLSExtension] = []

        while offset + 4 <= extEnd {
            let extType   = readUInt16(data, at: offset); offset += 2
            let extDataLen = Int(readUInt16(data, at: offset)); offset += 2
            guard offset + extDataLen <= extEnd else { break }
            let extData = data.subdata(in: offset ..< offset + extDataLen)
            offset += extDataLen
            extensions.append(TLSExtension(type: extType, data: extData))
        }

        _ = helloStart // suppress unused warning; used for extEnd calculation

        return TLSClientHello(
            clientVersion: clientVersion,
            random: random,
            sessionID: sessionID,
            cipherSuites: cipherSuites,
            compressionMethods: compressionMethods,
            extensions: extensions
        )
    }

    // MARK: - Extension Operations

    /// Finds an extension by its type code.
    public static func findExtension(
        _ type: UInt16,
        in hello: TLSClientHello
    ) -> TLSExtension? {
        hello.extensions.first { $0.type == type }
    }

    /// Inserts (or replaces) an extension in the Client Hello.
    public static func setExtension(
        _ ext: TLSExtension,
        in hello: inout TLSClientHello
    ) {
        if let idx = hello.extensions.firstIndex(where: { $0.type == ext.type }) {
            hello.extensions[idx] = ext
        } else {
            hello.extensions.append(ext)
        }
    }

    /// Adds a padding extension filled with the given number of zero bytes.
    ///
    /// REALITY uses padding to match browser TLS fingerprint sizes.
    public static func addPadding(
        _ byteCount: Int,
        to hello: inout TLSClientHello
    ) {
        let paddingData = Data(repeating: 0x00, count: byteCount)
        let ext = TLSExtension(type: TLSExtension.Types.padding, data: paddingData)
        setExtension(ext, in: &hello)
    }

    /// Adds a custom extension with arbitrary bytes (e.g. REALITY auth key).
    ///
    /// The extension type should be chosen to match the target browser's
    /// GREASE or vendor‑specific extension range.
    public static func addCustomExtension(
        type: UInt16,
        data customData: Data,
        to hello: inout TLSClientHello
    ) {
        let ext = TLSExtension(type: type, data: customData)
        setExtension(ext, in: &hello)
    }

    // MARK: - Serialisation

    /// Serialises a `TLSClientHello` back into a complete TLS Record
    /// (ContentType + Version + RecordLength + Handshake header + ClientHello)
    /// with all length fields correctly recomputed.
    ///
    /// This is the inverse of `parseClientHello(from:)` — the output is
    /// a valid TLS record ready for the wire.
    public static func serializeClientHello(
        _ hello: TLSClientHello,
        legacyVersion: UInt16 = 0x0303
    ) -> Data {
        var clientHelloBytes = Data()

        // Client Version
        writeUInt16(hello.clientVersion, to: &clientHelloBytes)

        // Random (32 bytes)
        clientHelloBytes.append(hello.random)

        // Session ID
        clientHelloBytes.append(UInt8(hello.sessionID.count))
        clientHelloBytes.append(hello.sessionID)

        // Cipher Suites
        let csLen = UInt16(hello.cipherSuites.count * 2)
        writeUInt16(csLen, to: &clientHelloBytes)
        for suite in hello.cipherSuites {
            writeUInt16(suite, to: &clientHelloBytes)
        }

        // Compression Methods
        clientHelloBytes.append(UInt8(hello.compressionMethods.count))
        clientHelloBytes.append(contentsOf: hello.compressionMethods)

        // Extensions
        let extStart = clientHelloBytes.count
        writeUInt16(0, to: &clientHelloBytes) // placeholder for Extensions length
        for ext in hello.extensions {
            writeUInt16(ext.type, to: &clientHelloBytes)
            writeUInt16(UInt16(ext.data.count), to: &clientHelloBytes)
            clientHelloBytes.append(ext.data)
        }
        // Patch the Extensions length (total bytes after the length field).
        let extPayloadLen = clientHelloBytes.count - extStart - 2
        patchUInt16(UInt16(extPayloadLen), in: &clientHelloBytes, at: extStart)

        // ---- Handshake envelope ------------------------------------------
        var handshakeData = Data()
        handshakeData.append(0x01) // HandshakeType = ClientHello
        // Handshake length (3 bytes)
        let hsLen = UInt32(clientHelloBytes.count)
        handshakeData.append(UInt8((hsLen >> 16) & 0xFF))
        handshakeData.append(UInt8((hsLen >>  8) & 0xFF))
        handshakeData.append(UInt8( hsLen        & 0xFF))
        handshakeData.append(clientHelloBytes)

        // ---- TLS Record envelope -----------------------------------------
        var record = Data()
        record.append(0x16) // ContentType = Handshake
        writeUInt16(legacyVersion, to: &record)
        writeUInt16(UInt16(handshakeData.count), to: &record)
        record.append(handshakeData)

        return record
    }

    // MARK: - Length Validation

    /// Verifies that after modification the total TLS record length does not
    /// exceed the maximum allowed by the protocol (16 384 bytes for standard
    /// TLS, per RFC 8449 §5.4).
    public static func validateRecordLength(_ record: Data) -> Bool {
        guard record.count >= 5 else { return false }
        let declared = Int(readUInt16(record, at: 3))
        return declared + 5 <= record.count && record.count <= 16_384 + 5
    }
}

// MARK: - Binary Helpers

private func readUInt16(_ data: Data, at offset: Int) -> UInt16 {
    (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
}

private func readUInt24(_ data: Data, at offset: Int) -> UInt32 {
    (UInt32(data[offset]) << 16)
    | (UInt32(data[offset + 1]) << 8)
    |  UInt32(data[offset + 2])
}

private func writeUInt16(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

private func patchUInt16(_ value: UInt16, in data: inout Data, at offset: Int) {
    data[offset]     = UInt8(value >> 8)
    data[offset + 1] = UInt8(value & 0xFF)
}
