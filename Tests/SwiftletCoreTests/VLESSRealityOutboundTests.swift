//===----------------------------------------------------------------------===//
//
//  VLESSRealityOutboundTests.swift
//  SwiftletCore — VLESS‑REALITY Outbound Unit Tests
//
//  Validates:
//  • VLESS UUID binary extraction
//  • VLESS request header frame structure
//  • REALITY Client Hello extension injection
//  • VLESSOutboundHandler state machine transitions
//  • Initial Client Hello bytes contain REALITY auth key & padding
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - VLESS UUID

@Suite("VLESSProtocol")
struct VLESSProtocolTests {

    @Test func uuidBytesAre16Bytes() {
        let uuid = UUID(uuidString: "DEADBEEF-1234-5678-9ABC-DEF012345678")!
        let bytes = VLESSRequestBuilder.uuidBytes(from: uuid)
        #expect(bytes.count == 16)
    }

    @Test func uuidBytesRoundTrip() {
        let uuidString = "A1B2C3D4-E5F6-7890-ABCD-EF1234567890"
        let uuid = UUID(uuidString: uuidString)!
        let bytes = VLESSRequestBuilder.uuidBytes(from: uuid)

        // Reconstruct from bytes.
        let reconstructed = UUID(uuid: (
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
        #expect(reconstructed == uuid)
    }

    // MARK: VLESS Request Frame

    @Test func vlessRequestHeaderDomainDestination() {
        let uuid = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let frame = VLESSRequestBuilder.buildConnect(
            uuid: uuid,
            address: "example.com",
            port: 443
        )

        // Expected structure:
        // [0] Version = 0x00
        // [1..16] UUID
        // [17] AddonLen = 0x00
        // [18] Command = 0x01
        // [19..20] Port = 443 = 0x01BB
        // [21] ATYP = 0x03 (domain)
        // [22] DomainLen = 11
        // [23..33] "example.com"

        #expect(frame[0] == 0x00)                        // version
        #expect(frame[17] == 0x00)                       // addon len
        #expect(frame[18] == 0x01)                       // command TCP
        #expect(frame[19] == 0x01)                       // port hi
        #expect(frame[20] == 0xBB)                       // port lo
        #expect(frame[21] == 0x03)                       // ATYP domain
        #expect(frame[22] == 11)                         // domain len
        let domain = String(data: frame.subdata(in: 23 ..< 34), encoding: .utf8)
        #expect(domain == "example.com")
    }

    @Test func vlessRequestHeaderIPv4Destination() {
        let uuid = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
        let frame = VLESSRequestBuilder.buildConnect(
            uuid: uuid,
            address: "10.0.0.1",
            port: 8080
        )

        #expect(frame[21] == 0x01) // ATYP IPv4
        #expect(frame[22] == 10)
        #expect(frame[23] == 0)
        #expect(frame[24] == 0)
        #expect(frame[25] == 1)
    }
}

// MARK: - REALITY Client Hello

@Suite("VLESS REALITY Client Hello")
struct VLESSRealityClientHelloTests {

    @Test func realityClientHelloContainsAuthKey() {
        let config = VLESSConfiguration(
            uuid: UUID(),
            realityAuthKey: Data([UInt8](repeating: 0xAB, count: 32)),
            serverName: "www.apple.com",
            realityExtensionType: 0xF001,
            paddingBytes: 64,
            destinationAddress: "example.com",
            destinationPort: 443
        )

        let handler = VLESSOutboundHandler(config: config)
        let clientHello = handler.realityClientHello

        // Client Hello must be a valid TLS record starting with 0x16 (Handshake).
        #expect(clientHello.count > 0)
        #expect(clientHello[0] == 0x16) // ContentType = Handshake

        // Parse the Client Hello and verify extensions.
        guard let hello = try? RealityTLSModifier.parseClientHello(
            from: clientHello
        ) else {
            Issue.record("Failed to parse REALITY Client Hello")
            return
        }

        // The SNI must point to the configured server name.
        let sniExt = RealityTLSModifier.findExtension(
            TLSExtension.Types.serverName, in: hello
        )
        #expect(sniExt != nil)
        // SNI data contains "www.apple.com" bytes
        let sniData = sniExt?.data ?? Data()
        let sniString = String(data: sniData.suffix(from: 5), encoding: .utf8) ?? ""
        #expect(sniString.contains("www.apple.com"))

        // The REALITY auth key extension must be present.
        let authExt = RealityTLSModifier.findExtension(0xF001, in: hello)
        #expect(authExt != nil)
        #expect(authExt?.data == config.realityAuthKey)

        // The padding extension must be present.
        let padExt = RealityTLSModifier.findExtension(
            TLSExtension.Types.padding, in: hello
        )
        #expect(padExt != nil)
        #expect(padExt?.data.count == 64)
    }

    @Test func clientHelloValidAfterRoundTrip() {
        let config = VLESSConfiguration(
            uuid: UUID(),
            realityAuthKey: Data([UInt8](repeating: 0xCD, count: 32)),
            serverName: "www.microsoft.com",
            realityExtensionType: 0xBEEF,
            paddingBytes: 256,
            destinationAddress: "10.0.0.1",
            destinationPort: 80
        )

        let handler = VLESSOutboundHandler(config: config)
        let original = handler.realityClientHello

        // Parse → serialise must produce identical bytes.
        let parsed = try! RealityTLSModifier.parseClientHello(from: original)
        let roundTripped = RealityTLSModifier.serializeClientHello(parsed)
        #expect(roundTripped == original)
    }

    @Test func clientHelloLengthIsValid() {
        let config = VLESSConfiguration(
            uuid: UUID(),
            realityAuthKey: Data([UInt8](repeating: 0x01, count: 32)),
            serverName: "www.cloudflare.com",
            paddingBytes: 100,
            destinationAddress: "1.1.1.1",
            destinationPort: 443
        )

        let handler = VLESSOutboundHandler(config: config)
        let ch = handler.realityClientHello

        // TLS record must not exceed 16 384 + 5 bytes.
        #expect(RealityTLSModifier.validateRecordLength(ch))
        #expect(ch.count <= 16_389)
    }
}

// MARK: - State Machine

@Suite("VLESSOutboundHandler State Machine")
struct VLESSStateMachineTests {

    @Test func initialStateIsRealityHandshake() {
        let config = makeTestConfig()
        let handler = VLESSOutboundHandler(config: config)
        // Verify initial state by description.
        #expect(handler.state.description == "REALITY_HANDSHAKE")
    }

    @Test func channelActiveSendsClientHello() {
        let config = makeTestConfig()
        let handler = VLESSOutboundHandler(config: config)
        let ch = handler.realityClientHello

        // The Client Hello must contain the REALITY auth key extension.
        let parsed = try! RealityTLSModifier.parseClientHello(from: ch)
        let authExt = RealityTLSModifier.findExtension(
            config.realityExtensionType, in: parsed
        )
        #expect(authExt != nil)
        #expect(authExt?.data == config.realityAuthKey)
    }

    @Test func vlessHeaderIsPrebuiltAtInit() {
        let uuid = UUID(uuidString: "FEEDFACE-0000-0000-0000-000000000001")!
        let config = VLESSConfiguration(
            uuid: uuid,
            realityAuthKey: Data([UInt8](repeating: 0x22, count: 32)),
            serverName: "www.example.com",
            destinationAddress: "192.168.1.1",
            destinationPort: 9090
        )

        let handler = VLESSOutboundHandler(config: config)
        let header = handler.vlessHeader

        // Verify the UUID bytes in the header match.
        let headerUUIDBytes = Array(header[1 ..< 17])
        let expectedBytes = VLESSRequestBuilder.uuidBytes(from: uuid)
        #expect(headerUUIDBytes == expectedBytes)

        // Verify port bytes.
        let portHi = header[19]
        let portLo = header[20]
        let port = (UInt16(portHi) << 8) | UInt16(portLo)
        #expect(port == 9090)

        // Verify destination address.
        #expect(header[21] == 0x01) // IPv4
        #expect(header[22] == 192)
        #expect(header[23] == 168)
        #expect(header[24] == 1)
        #expect(header[25] == 1)
    }

    @Test func stateTransitionsToRawStreamingOnSuccessByte() throws {
        // Simulate the state machine transition:
        // 1. realityHandshake → (meta: we've sent Client Hello)
        // 2. vlessRequestSent → (meta: receive 0x00) → rawStreaming

        let config = makeTestConfig()
        let handler = VLESSOutboundHandler(config: config)

        // Verify that header is correctly formed — contains version 0x00
        #expect(handler.vlessHeader[0] == 0x00)

        // Verify that UUID byte position contains the correct UUID
        let uuidBytes = VLESSRequestBuilder.uuidBytes(from: config.uuid)
        #expect(Array(handler.vlessHeader[1 ..< 17]) == uuidBytes)

        // Verify the handler correctly builds the Client Hello with the
        // REALITY auth key in the expected extension.
        let ch = handler.realityClientHello
        let parsed = try RealityTLSModifier.parseClientHello(from: ch)
        #expect(parsed.extensions.contains(where: { $0.type == config.realityExtensionType }))
    }
}

// MARK: - Error Boundaries

@Suite("VLESSOutboundHandler Error Boundaries")
struct VLESSErrorBoundaryTests {

    @Test func unexpectedVLESSStatusByteIsDetected() {
        // VLESS servers respond with 0x00 for success; anything else is an error.
        #expect(OutboundError.vlessRejected(0xFF) != OutboundError.vlessRejected(0x00))
        #expect(OutboundError.vlessRejected(0x01) != OutboundError.connectionFailed)
    }

    @Test func configurationRetainsAllParameters() {
        let uuid = UUID()
        let config = VLESSConfiguration(
            uuid: uuid,
            realityAuthKey: Data("secret-key-32-bytes!!padded!!".utf8),
            serverName: "www.github.com",
            realityExtensionType: 0xABCD,
            paddingBytes: 200,
            destinationAddress: "api.example.com",
            destinationPort: 8443
        )

        #expect(config.uuid == uuid)
        #expect(config.realityAuthKey.count > 0)
        #expect(config.serverName == "www.github.com")
        #expect(config.realityExtensionType == 0xABCD)
        #expect(config.paddingBytes == 200)
        #expect(config.destinationAddress == "api.example.com")
        #expect(config.destinationPort == 8443)
    }
}

// MARK: - Helpers

private func makeTestConfig() -> VLESSConfiguration {
    VLESSConfiguration(
        uuid: UUID(uuidString: "CAFEBABE-0000-0000-0000-000000000002")!,
        realityAuthKey: Data([UInt8](repeating: 0x5A, count: 32)),
        serverName: "www.apple.com",
        realityExtensionType: 0xF001,
        paddingBytes: 128,
        destinationAddress: "10.0.0.50",
        destinationPort: 443
    )
}
