//===----------------------------------------------------------------------===//
//
//  RealityTLSTests.swift
//  SwiftletCore — REALITY TLS Modifier Unit Tests
//
//  Validates:
//  • Correct parsing of a hand‑built TLS 1.3 Client Hello
//  • Extension insertion, replacement, and removal
//  • Accurate length recalculation after mutation
//  • Round‑trip parse → serialise fidelity
//  • Padding injection without memory corruption
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - Helpers

/// Builds a minimal but valid TLS 1.3 Client Hello record for testing.
private func buildMockClientHello(
    sni: String = "www.example.com",
    extraExtensions: [TLSExtension] = []
) -> Data {
    var hello = Data()

    // ---- ClientHello ----------------------------------------------------
    // ClientVersion (TLS 1.2 = 0x0303 for compatibility)
    writeUInt16(0x0303, to: &hello)

    // Random (32 bytes of 0xAA)
    hello.append(contentsOf: [UInt8](repeating: 0xAA, count: 32))

    // Session ID (empty)
    hello.append(0x00)

    // Cipher Suites: [TLS_AES_128_GCM_SHA256 = 0x1301]
    writeUInt16(2, to: &hello) // length = 2 bytes
    writeUInt16(0x1301, to: &hello)

    // Compression Methods: [null = 0x00]
    hello.append(0x01) // length
    hello.append(0x00)

    // ---- Extensions -----------------------------------------------------
    var extensions = Data()

    // SNI: server_name = 0x0000
    var sniExt = Data()
    // SNI list length
    writeUInt16(UInt16(sni.utf8.count + 3), to: &sniExt)
    sniExt.append(0x00) // name_type = host_name
    writeUInt16(UInt16(sni.utf8.count), to: &sniExt)
    sniExt.append(contentsOf: sni.utf8)
    // Encode as a TLS extension
    writeUInt16(0x0000, to: &extensions) // type = server_name
    writeUInt16(UInt16(sniExt.count), to: &extensions)
    extensions.append(sniExt)

    // Supported Versions: 0x002B → TLS 1.3 (0x0304)
    writeUInt16(0x002B, to: &extensions)
    writeUInt16(2, to: &extensions) // length
    writeUInt16(0x0304, to: &extensions)

    // Key Share: 0x0033 (minimal placeholder)
    writeUInt16(0x0033, to: &extensions)
    let ksData = Data([0x00, 0x1D, // named group: x25519
                        0x00, 0x20]) + Data([UInt8](repeating: 0xCC, count: 32))
    writeUInt16(UInt16(ksData.count), to: &extensions)
    extensions.append(ksData)

    // Add any extra extensions
    for ext in extraExtensions {
        writeUInt16(ext.type, to: &extensions)
        writeUInt16(UInt16(ext.data.count), to: &extensions)
        extensions.append(ext.data)
    }

    // Write Extensions length + data
    writeUInt16(UInt16(extensions.count), to: &hello)
    hello.append(extensions)

    // ---- Handshake envelope ---------------------------------------------
    var handshake = Data()
    handshake.append(0x01) // HandshakeType = ClientHello
    let hsLen = UInt32(hello.count)
    handshake.append(UInt8((hsLen >> 16) & 0xFF))
    handshake.append(UInt8((hsLen >>  8) & 0xFF))
    handshake.append(UInt8( hsLen        & 0xFF))
    handshake.append(hello)

    // ---- TLS Record envelope --------------------------------------------
    var record = Data()
    record.append(0x16) // ContentType = Handshake
    writeUInt16(0x0303, to: &record) // legacy version
    writeUInt16(UInt16(handshake.count), to: &record)
    record.append(handshake)

    return record
}

private func writeUInt16(_ value: UInt16, to data: inout Data) {
    data.append(UInt8(value >> 8))
    data.append(UInt8(value & 0xFF))
}

// MARK: - Parse Tests

@Suite("RealityTLSModifier — Parse")
struct RealityTLSParseTests {

    @Test func parseValidClientHello() throws {
        let record = buildMockClientHello()
        let hello = try RealityTLSModifier.parseClientHello(from: record)

        #expect(hello.clientVersion == 0x0303)
        #expect(hello.random.count == 32)
        #expect(hello.sessionID.isEmpty)
        #expect(hello.cipherSuites.contains(0x1301))
        #expect(hello.compressionMethods == [0x00])
        #expect(hello.extensions.count == 3) // SNI, supported_versions, key_share
    }

    @Test func parseRejectsNonHandshakeRecord() {
        var record = buildMockClientHello()
        record[0] = 0x17 // Application Data, not Handshake
        #expect(throws: TLSParseError.invalidContentType(0x17)) {
            _ = try RealityTLSModifier.parseClientHello(from: record)
        }
    }

    @Test func parseRejectsTruncatedRecord() {
        let truncated = Data([0x16, 0x03, 0x03, 0xFF, 0xFF]) // claims 65535 bytes
        #expect(throws: TLSParseError.insufficientData(needed: 5 + 65535, available: 5)) {
            _ = try RealityTLSModifier.parseClientHello(from: truncated)
        }
    }
}

// MARK: - Modification Tests

@Suite("RealityTLSModifier — Modify")
struct RealityTLSModifyTests {

    @Test func addCustomExtension() throws {
        let record = buildMockClientHello()
        var hello = try RealityTLSModifier.parseClientHello(from: record)

        let initialExtCount = hello.extensions.count

        // Insert a custom "REALITY auth key" extension.
        let authKey = Data([UInt8](repeating: 0xAB, count: 32))
        RealityTLSModifier.addCustomExtension(
            type: 0xF001, // GREASE range
            data: authKey,
            to: &hello
        )

        #expect(hello.extensions.count == initialExtCount + 1)
        let inserted = RealityTLSModifier.findExtension(0xF001, in: hello)
        #expect(inserted != nil)
        #expect(inserted?.data == authKey)
    }

    @Test func addPaddingExtension() throws {
        let record = buildMockClientHello()
        var hello = try RealityTLSModifier.parseClientHello(from: record)

        RealityTLSModifier.addPadding(64, to: &hello)

        let padding = RealityTLSModifier.findExtension(
            TLSExtension.Types.padding, in: hello
        )
        #expect(padding != nil)
        #expect(padding?.data.count == 64)
        #expect(padding?.data.allSatisfy { $0 == 0x00 } ?? false)
    }

    @Test func replaceExistingExtension() throws {
        let record = buildMockClientHello()
        var hello = try RealityTLSModifier.parseClientHello(from: record)

        // The SNI extension is present — replace it.
        let originalSNI = RealityTLSModifier.findExtension(
            TLSExtension.Types.serverName, in: hello
        )
        #expect(originalSNI != nil)

        let newSNI = TLSExtension(
            type: TLSExtension.Types.serverName,
            data: "replaced-host.com".data(using: .utf8)!
        )
        RealityTLSModifier.setExtension(newSNI, in: &hello)

        let updated = RealityTLSModifier.findExtension(
            TLSExtension.Types.serverName, in: hello
        )
        // Count should be the same (replaced, not added)
        #expect(hello.extensions.count == 3)
        #expect(updated?.data != originalSNI?.data)
    }
}

// MARK: - Serialisation Tests

@Suite("RealityTLSModifier — Serialise")
struct RealityTLSSerializeTests {

    @Test func serialiseProducesValidRecord() throws {
        let original = buildMockClientHello()
        let hello = try RealityTLSModifier.parseClientHello(from: original)

        let reserialised = RealityTLSModifier.serializeClientHello(hello)
        #expect(reserialised.count > 0)

        // Must parse again without errors.
        let reparsed = try RealityTLSModifier.parseClientHello(from: reserialised)
        #expect(reparsed.clientVersion == hello.clientVersion)
        #expect(reparsed.cipherSuites == hello.cipherSuites)
        #expect(reparsed.extensions.count == hello.extensions.count)
    }

    @Test func serialiseAfterModificationHasCorrectLengths() throws {
        let record = buildMockClientHello()
        var hello = try RealityTLSModifier.parseClientHello(from: record)

        // Add a 128‑byte custom extension.
        RealityTLSModifier.addCustomExtension(
            type: 0xABCD,
            data: Data([UInt8](repeating: 0xCC, count: 128)),
            to: &hello
        )

        let serialised = RealityTLSModifier.serializeClientHello(hello)

        // The TLS Record length field (bytes 3–4) must match the payload.
        #expect(RealityTLSModifier.validateRecordLength(serialised))

        let declaredLength = Int(
            (UInt16(serialised[3]) << 8) | UInt16(serialised[4])
        )
        #expect(declaredLength + 5 == serialised.count)
    }

    @Test func serialiseAfterPaddingHasCorrectLengths() throws {
        let record = buildMockClientHello()
        var hello = try RealityTLSModifier.parseClientHello(from: record)

        RealityTLSModifier.addPadding(256, to: &hello)

        let serialised = RealityTLSModifier.serializeClientHello(hello)
        #expect(RealityTLSModifier.validateRecordLength(serialised))

        // Parse back and verify the padding extension is present.
        let reparsed = try RealityTLSModifier.parseClientHello(from: serialised)
        let padding = RealityTLSModifier.findExtension(
            TLSExtension.Types.padding, in: reparsed
        )
        #expect(padding?.data.count == 256)
    }

    @Test func validateRejectsOversizedRecord() {
        // A record claiming a length beyond 16 384 bytes should fail validation.
        var data = Data([0x16, 0x03, 0x03, 0x40, 0x01]) // claims 16385
        data.append(contentsOf: [UInt8](repeating: 0, count: 16385))
        #expect(RealityTLSModifier.validateRecordLength(data) == false)
    }
}
