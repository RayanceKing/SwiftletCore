//===----------------------------------------------------------------------===//
//
//  gRPCTransportTests.swift
//  SwiftletCoreTests — gRPC Stream Framing & Transport Tests
//
//  Verifies the gRPC 5‑byte header codec, frame marshalling, segmented
//  data reassembly, and transport lifecycle.
//
//  Test Coverage
//  -------------
//  ┌─────────────────────────────────────────┬────────────────────────────┐
//  │ Test                                    │ What it verifies           │
//  ├─────────────────────────────────────────┼────────────────────────────┤
//  │ testFrameEncoder_producesCorrectHeader  │ 5‑byte header (0x00 + BE)  │
//  │ testFrameEncoder_emptyPayload           │ Zero‑length payload frame  │
//  │ testFrameDecoder_completeFrame          │ Single complete frame      │
//  │ testFrameDecoder_segmentedData          │ TCP segmentation recovery  │
//  │ testFrameDecoder_multipleFrames         │ Back‑to‑back frames        │
//  │ testFrameDecoder_partialHeader_thenMore │ Split header reassembly    │
//  │ testFrameEncoderDecoder_roundTrip       │ Encode → decode loop       │
//  │ testFrameDecoder_inactive_discards      │ Partial data on close      │
//  │ testTransportConfig_defaults            │ gRPC transport config      │
//  │ testGRPCNodeConfig_vmess_grpc           │ VMess gRPC config creation │
//  │ testGRPCNodeConfig_vless_grpc           │ VLESS gRPC config creation │
//  │ testGRPCNodeConfig_trojan_grpc          │ Trojan gRPC config creation│
//  │ testSubscriptionParser_vless_grpc       │ VLESS gRPC URI parsing     │
//  │ testSubscriptionParser_trojan_grpc      │ Trojan gRPC URI parsing    │
//  │ testSubscriptionParser_vmess_grpc       │ VMess gRPC URI parsing     │
//  └─────────────────────────────────────────┴────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
@preconcurrency import NIOCore
import NIOEmbedded

// MARK: - gRPC Frame Codec Tests

final class gRPCFrameCodecTests: XCTestCase {

    // MARK: - Encoder Tests

    /// Verifies that the encoder prepends the correct 5‑byte header:
    /// `0x00` (uncompressed) + 4‑byte big‑endian payload length.
    func testFrameEncoder_producesCorrectHeader() throws {
        let encoder = gRPCFrameEncoder()
        let channel = EmbeddedChannel(handler: encoder)

        let payload = ByteBuffer(string: "Hello, gRPC!")
        try channel.writeOutbound(payload)

        var output = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)

        // Read the 5‑byte header.
        let compressionFlag = output?.readInteger(endianness: .big, as: UInt8.self)
        XCTAssertEqual(compressionFlag, 0x00, "Compression flag must be 0x00 for uncompressed")

        let length = output?.readInteger(endianness: .big, as: UInt32.self)
        XCTAssertEqual(length, 12, "Payload length must be 12 bytes for 'Hello, gRPC!'")

        // Read the payload.
        let decoded = output?.readString(length: 12)
        XCTAssertEqual(decoded, "Hello, gRPC!")

        // No trailing data.
        XCTAssertEqual(output?.readableBytes, 0)

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that encoding an empty payload produces a header with
    /// length 0 and no payload body.
    func testFrameEncoder_emptyPayload() throws {
        let encoder = gRPCFrameEncoder()
        let channel = EmbeddedChannel(handler: encoder)

        let payload = ByteBuffer()
        try channel.writeOutbound(payload)

        var output = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)

        let compressionFlag = output?.readInteger(endianness: .big, as: UInt8.self)
        XCTAssertEqual(compressionFlag, 0x00)

        let length = output?.readInteger(endianness: .big, as: UInt32.self)
        XCTAssertEqual(length, 0, "Empty payload must encode length 0")

        XCTAssertEqual(output?.readableBytes, 0)

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that the encoder uses a custom compression flag when
    /// configured.
    func testFrameEncoder_customCompressionFlag() throws {
        let encoder = gRPCFrameEncoder(compressionFlag: 0x01)
        let channel = EmbeddedChannel(handler: encoder)

        let payload = ByteBuffer(string: "compressed!")
        try channel.writeOutbound(payload)

        var output = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)

        let compressionFlag = output?.readInteger(endianness: .big, as: UInt8.self)
        XCTAssertEqual(compressionFlag, 0x01, "Custom compression flag must be preserved")

        let length = output?.readInteger(endianness: .big, as: UInt32.self)
        XCTAssertEqual(length, 10)

        XCTAssertNoThrow(try channel.finish())
    }

    // MARK: - Decoder Tests

    /// Verifies that the decoder correctly processes a single complete
    /// gRPC frame and fires the payload up the pipeline.
    func testFrameDecoder_completeFrame() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Build a frame: 0x00 + length(5) + "Hello"
        var frame = ByteBuffer()
        frame.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame.writeInteger(UInt32(5), endianness: .big, as: UInt32.self)
        frame.writeString("Hello")

        try channel.writeInbound(frame)

        let output = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        XCTAssertEqual(output?.readableBytes, 5)
        XCTAssertEqual(output?.readString(length: 5), "Hello")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that the decoder correctly reassembles a frame delivered
    /// in two TCP segments (head‑of‑line blocking recovery).
    func testFrameDecoder_segmentedData() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Build a frame with payload "SegmentedDataTest" (16 bytes).
        var frame = ByteBuffer()
        frame.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame.writeInteger(UInt32(16), endianness: .big, as: UInt32.self)
        frame.writeString("SegmentedDataTest")

        // Deliver the first 7 bytes (partial header + some of length field).
        let segment1 = frame.getSlice(at: 0, length: 7)!
        try channel.writeInbound(segment1)

        // No complete frame yet — decoder should not fire anything.
        var partial = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNil(partial, "Decoder must not fire incomplete frames")

        // Deliver the remaining bytes.
        let segment2 = frame.getSlice(at: 7, length: frame.readableBytes - 7)!
        try channel.writeInbound(segment2)

        // Now the complete frame should be emitted.
        let output = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        XCTAssertEqual(output?.readString(length: 16), "SegmentedDataTest")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that the decoder handles multiple back‑to‑back frames
    /// delivered in a single `channelRead`.
    func testFrameDecoder_multipleFrames() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Build frame 1: "AAA" (3 bytes)
        var frame1 = ByteBuffer()
        frame1.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame1.writeInteger(UInt32(3), endianness: .big, as: UInt32.self)
        frame1.writeString("AAA")

        // Build frame 2: "BB" (2 bytes)
        var frame2 = ByteBuffer()
        frame2.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame2.writeInteger(UInt32(2), endianness: .big, as: UInt32.self)
        frame2.writeString("BB")

        // Concatenate and deliver at once.
        var combined = frame1
        combined.writeBuffer(&frame2)
        try channel.writeInbound(combined)

        // Read first frame.
        let first = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(first)
        XCTAssertEqual(first?.readString(length: 3), "AAA")

        // Read second frame.
        let second = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(second)
        XCTAssertEqual(second?.readString(length: 2), "BB")

        // No more frames.
        let third = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNil(third)

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that the decoder handles a split 5‑byte header — the
    /// header itself arrives in two pieces.
    func testFrameDecoder_partialHeader_thenMore() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Build a frame with payload "Partial" (7 bytes).
        var frame = ByteBuffer()
        frame.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame.writeInteger(UInt32(7), endianness: .big, as: UInt32.self)
        frame.writeString("Partial")

        // Deliver only the first 2 bytes of the header.
        let headerPart = frame.getSlice(at: 0, length: 2)!
        try channel.writeInbound(headerPart)

        var result = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNil(result, "No frame should fire with partial header")

        // Deliver the remaining 3 header bytes + payload.
        let rest = frame.getSlice(at: 2, length: frame.readableBytes - 2)!
        try channel.writeInbound(rest)

        result = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(result)
        XCTAssertEqual(result?.readString(length: 7), "Partial")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that large payloads (larger than 1 buffer) are correctly
    /// framed and deframed.
    func testFrameDecoder_largePayload() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Build a 64 KiB payload.
        let largeString = String(repeating: "A", count: 65536)
        var frame = ByteBuffer()
        frame.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        frame.writeInteger(UInt32(65536), endianness: .big, as: UInt32.self)
        frame.writeString(largeString)

        try channel.writeInbound(frame)

        let output = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        XCTAssertEqual(output?.readableBytes, 65536)

        XCTAssertNoThrow(try channel.finish())
    }

    // MARK: - Round‑Trip Tests

    /// Verifies that encoding then decoding a payload returns the original
    /// bytes exactly.
    func testFrameEncoderDecoder_roundTrip() throws {
        let encoder = gRPCFrameEncoder()
        let decoder = gRPCFrameDecoder()

        // Chain encoder → decoder in an EmbeddedChannel.
        let channel = EmbeddedChannel()
        XCTAssertNoThrow(try channel.pipeline.addHandler(decoder).wait())
        XCTAssertNoThrow(try channel.pipeline.addHandler(encoder).wait())

        let original = ByteBuffer(string: "Round-trip verification payload!")

        // Write outbound through encoder.
        XCTAssertNoThrow(try channel.writeOutbound(original))

        // Read the encoded frame from the outbound side.
        var encoded = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(encoded)

        // Feed the encoded frame into the inbound side (decoder).
        // We need to write it to the channel directly since EmbeddedChannel
        // separates inbound/outbound.
        XCTAssertNoThrow(try channel.writeInbound(encoded!))

        // Read the decoded payload from inbound.
        let decoded = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(decoded)
        XCTAssertEqual(decoded?.readString(length: decoded!.readableBytes),
                       "Round-trip verification payload!")

        XCTAssertNoThrow(try channel.finish())
    }

    // MARK: - Lifecycle Tests

    /// Verifies that partial data on channel inactive is discarded
    /// without firing.
    func testFrameDecoder_inactive_discards() throws {
        let decoder = gRPCFrameDecoder()
        let channel = EmbeddedChannel(handler: decoder)

        // Deliver only the header (5 bytes), no payload.
        var partial = ByteBuffer()
        partial.writeInteger(UInt8(0x00), endianness: .big, as: UInt8.self)
        partial.writeInteger(UInt32(100), endianness: .big, as: UInt32.self)
        // No payload delivered!

        try channel.writeInbound(partial)

        // No frame should fire — payload never arrived.
        let result = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNil(result, "No frame should fire for incomplete data")

        // Simulate channel close.
        try channel.close().wait()

        // After close, nothing should fire.
        let afterClose = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNil(afterClose)

        XCTAssertNoThrow(try channel.finish())
    }
}

// MARK: - gRPC Configuration Tests

final class gRPCConfigurationTests: XCTestCase {

    /// Verifies default gRPC transport configuration.
    func testTransportConfig_defaults() {
        let config = gRPCTransportConfiguration(
            serviceName: "TunService"
        )
        XCTAssertEqual(config.serviceName, "TunService")
        XCTAssertNil(config.authority)
        XCTAssertTrue(config.tlsEnabled)
        XCTAssertNil(config.sni)
    }

    /// Verifies full gRPC transport configuration.
    func testTransportConfig_full() {
        let config = gRPCTransportConfiguration(
            serviceName: "CustomService",
            authority: "proxy.example.com:443",
            tlsEnabled: true,
            sni: "sni.example.com"
        )
        XCTAssertEqual(config.serviceName, "CustomService")
        XCTAssertEqual(config.authority, "proxy.example.com:443")
        XCTAssertTrue(config.tlsEnabled)
        XCTAssertEqual(config.sni, "sni.example.com")
    }
}

// MARK: - gRPC Node Configuration Tests

final class gRPCNodeConfigurationTests: XCTestCase {

    /// Verifies creating a VMess node with gRPC transport.
    func testGRPCNodeConfig_vmess_grpc() {
        let config = ProxyNodeConfiguration.vmess(
            host: "grpc.example.com",
            port: 443,
            uuid: "550e8400-e29b-41d4-a716-446655440000",
            alterId: 0,
            transport: "grpc",
            tlsEnabled: true,
            sni: nil,
            wsPath: nil,
            wsHost: nil,
            serviceName: "TunService",
            authority: "grpc.example.com:443"
        )

        XCTAssertEqual(config.host, "grpc.example.com")
        XCTAssertEqual(config.port, 443)
        XCTAssertEqual(config.label, "VMess")

        if case .vmess(_, _, _, _, let transport, _, _, _, _, let svc, let auth) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(svc, "TunService")
            XCTAssertEqual(auth, "grpc.example.com:443")
        } else {
            XCTFail("Expected .vmess case")
        }
    }

    /// Verifies creating a VLESS node with gRPC transport.
    func testGRPCNodeConfig_vless_grpc() {
        let config = ProxyNodeConfiguration.vless(
            host: "vless-grpc.example.com",
            port: 443,
            uuid: "550e8400-e29b-41d4-a716-446655440001",
            flow: nil,
            xtls: false,
            sni: nil,
            pbk: nil,
            transport: "grpc",
            wsPath: nil,
            wsHost: nil,
            fingerprint: nil,
            shortId: nil,
            spiderX: nil,
            serviceName: "TunService",
            authority: nil
        )

        XCTAssertEqual(config.host, "vless-grpc.example.com")
        XCTAssertEqual(config.port, 443)
        XCTAssertEqual(config.label, "VLESS")

        if case .vless(_, _, _, _, _, _, _, let transport, _, _, _, _, _, let svc, _) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(svc, "TunService")
        } else {
            XCTFail("Expected .vless case")
        }
    }

    /// Verifies creating a Trojan node with gRPC transport.
    func testGRPCNodeConfig_trojan_grpc() {
        let config = ProxyNodeConfiguration.trojan(
            host: "trojan-grpc.example.com",
            port: 443,
            password: "trojan-password",
            transport: "grpc",
            sni: nil,
            wsPath: nil,
            wsHost: nil,
            fingerprint: nil,
            serviceName: "TunService",
            authority: "custom-authority:443"
        )

        XCTAssertEqual(config.host, "trojan-grpc.example.com")
        XCTAssertEqual(config.port, 443)
        XCTAssertEqual(config.label, "Trojan")

        if case .trojan(_, _, _, let transport, _, _, _, _, let svc, let auth) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(svc, "TunService")
            XCTAssertEqual(auth, "custom-authority:443")
        } else {
            XCTFail("Expected .trojan case")
        }
    }
}

// MARK: - Subscription Parser gRPC Tests

final class gRPCSubscriptionParserTests: XCTestCase {

    /// Verifies that a VLESS URI with gRPC transport parameters is
    /// correctly parsed.
    func testSubscriptionParser_vless_grpc() throws {
        let uri = "vless://550e8400-e29b-41d4-a716-446655440001@grpc.example.com:443?type=grpc&security=reality&sni=example.com&fp=chrome&pbk=testpubkey&sid=1234&spx=/&serviceName=TunService&authority=grpc.example.com:443"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse VLESS gRPC URI")
            return
        }

        XCTAssertEqual(config.host, "grpc.example.com")
        XCTAssertEqual(config.port, 443)

        if case .vless(_, _, _, _, _, let sni, _, let transport, _, _, let fp, _, _, let svc, let auth) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(sni, "example.com")
            XCTAssertEqual(fp, "chrome")
            XCTAssertEqual(svc, "TunService")
            XCTAssertEqual(auth, "grpc.example.com:443")
        } else {
            XCTFail("Expected .vless case")
        }
    }

    /// Verifies that a Trojan URI with gRPC transport parameters is
    /// correctly parsed.
    func testSubscriptionParser_trojan_grpc() throws {
        let uri = "trojan://password123@grpc.example.com:443?type=grpc&sni=example.com&fp=chrome&serviceName=TunService&authority=grpc.example.com:443"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse Trojan gRPC URI")
            return
        }

        XCTAssertEqual(config.host, "grpc.example.com")
        XCTAssertEqual(config.port, 443)

        if case .trojan(_, _, _, let transport, let sni, _, _, let fp, let svc, let auth) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(sni, "example.com")
            XCTAssertEqual(fp, "chrome")
            XCTAssertEqual(svc, "TunService")
            XCTAssertEqual(auth, "grpc.example.com:443")
        } else {
            XCTFail("Expected .trojan case")
        }
    }

    /// Verifies that a VMess JSON with gRPC parameters is correctly parsed.
    func testSubscriptionParser_vmess_grpc() throws {
        // Build a VMess JSON payload with gRPC fields.
        let vmessDict: [String: Any] = [
            "add": "grpc.example.com",
            "port": 443,
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": 0,
            "net": "grpc",
            "tls": "tls",
            "sni": "example.com",
            "serviceName": "TunService",
            "authority": "grpc.example.com:443"
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: vmessDict, options: [])
        let base64 = jsonData.base64EncodedString()
            .replacingOccurrences(of: "=", with: "") // strip padding
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")

        let uri = "vmess://\(base64)"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse VMess gRPC URI")
            return
        }

        XCTAssertEqual(config.host, "grpc.example.com")
        XCTAssertEqual(config.port, 443)

        if case .vmess(_, _, _, _, let transport, _, let sni, _, _, let svc, let auth) = config {
            XCTAssertEqual(transport, "grpc")
            XCTAssertEqual(sni, "example.com")
            XCTAssertEqual(svc, "TunService")
            XCTAssertEqual(auth, "grpc.example.com:443")
        } else {
            XCTFail("Expected .vmess case")
        }
    }

    /// Verifies that a VLESS URI without gRPC parameters defaults
    /// serviceName and authority to nil.
    func testSubscriptionParser_vless_noGrpc() throws {
        let uri = "vless://550e8400-e29b-41d4-a716-446655440001@tcp.example.com:443?type=tcp&security=none"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse VLESS TCP URI")
            return
        }

        if case .vless(_, _, _, _, _, _, _, let transport, _, _, _, _, _, let svc, let auth) = config {
            XCTAssertEqual(transport, "tcp")
            XCTAssertNil(svc, "serviceName must be nil when not specified")
            XCTAssertNil(auth, "authority must be nil when not specified")
        } else {
            XCTFail("Expected .vless case")
        }
    }
}

// MARK: - Outbound Protocol gRPC Variants Tests

final class gRPCProtocolVariantTests: XCTestCase {

    /// Verifies that the gRPC protocol variants are correctly configured.
    func testGRPCProtocolVariant_labels() {
        let trojanGRPC = OutboundProtocol.trojanGRPC(
            host: "host.example.com",
            port: 443,
            password: "pass",
            serviceName: "TunService",
            authority: nil
        )
        XCTAssertEqual(trojanGRPC.label, "Trojan+gRPC")
        XCTAssertTrue(trojanGRPC.isGRPC)
        XCTAssertTrue(trojanGRPC.isTLS)
        XCTAssertFalse(trojanGRPC.isHTTPWrapped)

        let vlessGRPC = OutboundProtocol.vlessGRPC(
            uuid: "550e8400-e29b-41d4-a716-446655440000",
            serviceName: "TunService",
            authority: "custom:443"
        )
        XCTAssertEqual(vlessGRPC.label, "VLESS+gRPC")
        XCTAssertTrue(vlessGRPC.isGRPC)

        let vmessGRPC = OutboundProtocol.vmessGRPC(
            uuid: "550e8400-e29b-41d4-a716-446655440000",
            alterId: 0,
            serviceName: "TunService",
            authority: nil
        )
        XCTAssertEqual(vmessGRPC.label, "VMess+gRPC")
        XCTAssertTrue(vmessGRPC.isGRPC)
    }
}
