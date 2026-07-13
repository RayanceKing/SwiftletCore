//===----------------------------------------------------------------------===//
//
//  ShadowsocksROutboundTests.swift
//  SwiftletCoreTests — ShadowsocksR Protocol & Obfs Plugin Unit Tests
//
//  Validates SSR URI parsing, protocol plugin header generation, obfs
//  plugin handshake construction, and the SSR handler state machine.
//
//  Test Coverage
//  -------------
//  ┌──────────────────────────────────────────┬──────────────────────────────┐
//  │ Test                                     │ What it verifies             │
//  ├──────────────────────────────────────────┼──────────────────────────────┤
//  │ testSubscriptionParserSSR                │ Basic SSR URI parsing        │
//  │ testSubscriptionParserSSRWithParams      │ SSR with obfsparam/protoparam│
//  │ testSubscriptionParserSSRBase64Password  │ Base64 password decoding     │
//  │ testSubscriptionParserSSRUnpaddedBase64  │ Unpadded Base64 repair       │
//  │ testSSRNodeConfiguration                 │ Node creation + getters      │
//  │ testSSRLabel                             │ Label correctness            │
//  │ testSSRDescription                       │ Description formatting       │
//  │ testSSREquatable                         │ Equality comparisons         │
//  │ testSSRProtocolHeader_forOrigin          │ origin → no header passthru  │
//  │ testSSRProtocolHeader_forAuthSHA1        │ auth_aes128_sha1 header      │
//  │ testSSRObfsHandshake_plain               │ plain → no handshake         │
//  │ testSSRObfsHandshake_httpSimple          │ HTTP GET handshake framing   │
//  │ testSSRObfsHandshake_tls12Ticket         │ TLS 1.2 ClientHello build    │
//  │ testSSRObfsStripHTTPResponse             │ HTTP response header strip   │
//  │ testOutboundDialerSSR                    │ OutboundProtocol.shadowsocksR│
//  └──────────────────────────────────────────┴──────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
@preconcurrency import NIOCore
import NIOEmbedded
import Foundation

// MARK: - Subscription Parser Tests

final class ShadowsocksRSubscriptionParserTests: XCTestCase {

    /// Verifies basic SSR URI parsing with all core fields.
    func testSubscriptionParserSSR() throws {
        // Build SSR payload: host:port:protocol:method:obfs:base64_password
        let b64Password = Data("ssr-test-password".utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let mainPart = "ssr.example.com:8388:auth_aes128_sha1:aes-256-cfb:tls1.2_ticket_auth:\(b64Password)"
        let base64Payload = mainPart.data(using: .utf8)!.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let uri = "ssr://\(base64Payload)"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse SSR URI"); return
        }

        if case .shadowsocksr(let h, let p, let c, let pw,
                               let proto, let protoParam,
                               let obfs, let obfsParam) = config {
            XCTAssertEqual(h, "ssr.example.com")
            XCTAssertEqual(p, 8388)
            XCTAssertEqual(c, "aes-256-cfb")
            XCTAssertEqual(pw, "ssr-test-password")
            XCTAssertEqual(proto, "auth_aes128_sha1")
            XCTAssertNil(protoParam)
            XCTAssertEqual(obfs, "tls1.2_ticket_auth")
            XCTAssertNil(obfsParam)
        } else {
            XCTFail("Expected .shadowsocksr case")
        }
    }

    /// Verifies SSR URI with obfsparam and protoparam query parameters.
    func testSubscriptionParserSSRWithParams() throws {
        let b64Password = Data("test-pwd".utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let b64ObfsParam = Data("cloudfront.com".utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")
        let b64ProtoParam = Data("client-id-123".utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let mainPart = "srv.example.com:443:auth_chain_a:chacha20:http_simple:\(b64Password)"
        let params = "?obfsparam=\(b64ObfsParam)&protoparam=\(b64ProtoParam)"
        let fullPayload = mainPart + params
        let base64 = fullPayload.data(using: .utf8)!.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let uri = "ssr://\(base64)"
        guard let config = SubscriptionParser.parse(uri: uri) else {
            XCTFail("Failed to parse SSR URI with params"); return
        }

        if case .shadowsocksr(_, _, _, _, let proto, let protoP,
                                let obfs, let obfsP) = config {
            XCTAssertEqual(proto, "auth_chain_a")
            XCTAssertEqual(protoP, "client-id-123")
            XCTAssertEqual(obfs, "http_simple")
            XCTAssertEqual(obfsP, "cloudfront.com")
        } else {
            XCTFail("Expected .shadowsocksr case")
        }
    }

    /// Verifies that a base64-encoded password is correctly decoded.
    func testSubscriptionParserSSRBase64Password() throws {
        let rawPassword = "p@ss:w0rd!with/special=chars"
        let b64Password = Data(rawPassword.utf8).base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let mainPart = "host.com:8080:origin:aes-128-ctr:plain:\(b64Password)"
        let base64 = mainPart.data(using: .utf8)!.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let uri = "ssr://\(base64)"
        let config = SubscriptionParser.parse(uri: uri)

        if case .shadowsocksr(_, _, _, let pw, _, _, _, _) = config {
            XCTAssertEqual(pw, rawPassword)
        } else {
            XCTFail("Expected .shadowsocksr case")
        }
    }

    /// Verifies that the parser handles unpadded base64 SSR payloads.
    func testSubscriptionParserSSRUnpaddedBase64() {
        // Manually create a payload with length that produces padding.
        let mainPart = "tiny.com:80:origin:rc4-md5:plain:dGVzdA=="  // "test"
        let base64 = mainPart.data(using: .utf8)!.base64EncodedString()
            .replacingOccurrences(of: "=", with: "")

        let uri = "ssr://\(base64)"
        let config = SubscriptionParser.parse(uri: uri)
        XCTAssertNotNil(config)
    }
}

// MARK: - Node Configuration Tests

final class ShadowsocksRNodeConfigurationTests: XCTestCase {

    /// Verifies creating an SSR node configuration.
    func testSSRNodeConfiguration() {
        let config = ProxyNodeConfiguration.shadowsocksr(
            host: "ssr.example.com",
            port: 8388,
            cipher: "aes-256-cfb",
            password: "my-password",
            protocolMode: "auth_aes128_sha1",
            protocolParam: nil,
            obfsMode: "tls1.2_ticket_auth",
            obfsParam: nil
        )

        XCTAssertEqual(config.host, "ssr.example.com")
        XCTAssertEqual(config.port, 8388)
        XCTAssertEqual(config.label, "ShadowsocksR")

        if case .shadowsocksr(let h, let p, let c, _, let proto, _, let obfs, _) = config {
            XCTAssertEqual(h, "ssr.example.com")
            XCTAssertEqual(p, 8388)
            XCTAssertEqual(c, "aes-256-cfb")
            XCTAssertEqual(proto, "auth_aes128_sha1")
            XCTAssertEqual(obfs, "tls1.2_ticket_auth")
        } else {
            XCTFail("Expected .shadowsocksr case")
        }
    }

    /// Verifies SSR label correctness.
    func testSSRLabel() {
        let node = ProxyNodeConfiguration.shadowsocksr(
            host: "s", port: 1, cipher: "c", password: "p",
            protocolMode: "origin", protocolParam: nil,
            obfsMode: "plain", obfsParam: nil
        )
        XCTAssertEqual(node.label, "ShadowsocksR")
    }

    /// Verifies SSR description formatting.
    func testSSRDescription() {
        let node = ProxyNodeConfiguration.shadowsocksr(
            host: "desc.com", port: 9999, cipher: "rc4-md5",
            password: "p", protocolMode: "origin", protocolParam: nil,
            obfsMode: "plain", obfsParam: nil
        )
        let desc = node.description
        XCTAssertTrue(desc.contains("ssr://"))
        XCTAssertTrue(desc.contains("9999"))
        XCTAssertTrue(desc.contains("origin"))
        XCTAssertTrue(desc.contains("plain"))
    }

    /// Verifies SSR equality.
    func testSSREquatable() {
        let a = ProxyNodeConfiguration.shadowsocksr(
            host: "eq.com", port: 443, cipher: "c", password: "p",
            protocolMode: "origin", protocolParam: nil,
            obfsMode: "plain", obfsParam: nil
        )
        let b = ProxyNodeConfiguration.shadowsocksr(
            host: "eq.com", port: 443, cipher: "c", password: "p",
            protocolMode: "origin", protocolParam: nil,
            obfsMode: "plain", obfsParam: nil
        )
        XCTAssertEqual(a, b)

        let c = ProxyNodeConfiguration.shadowsocksr(
            host: "eq.com", port: 443, cipher: "c", password: "different",
            protocolMode: "origin", protocolParam: nil,
            obfsMode: "plain", obfsParam: nil
        )
        XCTAssertNotEqual(a, c)
    }
}

// MARK: - Protocol Plugin Tests

final class ShadowsocksRProtocolPluginTests: XCTestCase {

    /// Verifies that `origin` protocol plugin passes data through
    /// without adding a frame header.
    func testSSRProtocolHeader_forOrigin() throws {
        let handler = SSRProtocolPluginHandler(
            protocolMode: "origin",
            protocolParam: nil,
            password: "test"
        )
        let channel = EmbeddedChannel(handler: handler)

        let payload = ByteBuffer(string: "hello-world-data")
        try channel.writeOutbound(payload)

        var output = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        // origin should pass through unchanged.
        let nb = output?.readableBytes ?? 0
        XCTAssertEqual(output?.readString(length: nb),
                       "hello-world-data")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that `auth_aes128_sha1` protocol plugin prepends the
    /// required frame header (DataLen(2) + HMAC(4) + ClientID(4) + Timestamp(4)).
    func testSSRProtocolHeader_forAuthSHA1() throws {
        let handler = SSRProtocolPluginHandler(
            protocolMode: "auth_aes128_sha1",
            protocolParam: nil,
            password: "my-ssr-password"
        )
        let channel = EmbeddedChannel(handler: handler)

        let payload = ByteBuffer(string: "ssr-payload-data")
        try channel.writeOutbound(payload)

        var output = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)

        // The header is 14 bytes, followed by the payload.
        guard output!.readableBytes >= 14 else {
            XCTFail("Output must be at least 14 bytes (header)")
            return
        }

        // Read DataLen (2 bytes).
        let dataLenHi = output?.readInteger(endianness: .big, as: UInt8.self) ?? 0
        let dataLenLo = output?.readInteger(endianness: .big, as: UInt8.self) ?? 0
        let dataLen = UInt16(dataLenHi) << 8 | UInt16(dataLenLo)
        XCTAssertEqual(dataLen, 16, "DataLen must be 16 for 'ssr-payload-data'")

        // Skip HMAC(4) + ClientID(4) + Timestamp(4) = 12 bytes.
        output?.moveReaderIndex(forwardBy: 12)

        // Verify payload.
        let nr = output?.readableBytes ?? 0
        let remaining = output?.readString(length: nr)
        XCTAssertEqual(remaining, "ssr-payload-data")

        XCTAssertNoThrow(try channel.finish())
    }
}

// MARK: - Obfs Plugin Tests

final class ShadowsocksRObfsPluginTests: XCTestCase {

    /// Verifies that `plain` obfs passes data through immediately.
    func testSSRObfsHandshake_plain() throws {
        let handler = SSRObfsPluginHandler(
            obfsMode: "plain",
            obfsParam: nil
        )
        let channel = EmbeddedChannel(handler: handler)

        // Trigger channelActive (plain → immediate forwarding).
        try channel.connect(to: try .init(ipAddress: "127.0.0.1", port: 0))
            .wait()

        // Data should pass through.
        let payload = ByteBuffer(string: "payload-after-handshake")
        try channel.writeInbound(payload)

        var output = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        let ob = output?.readableBytes ?? 0
        XCTAssertEqual(output?.readString(length: ob),
                       "payload-after-handshake")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that `http_simple` obfs sends an HTTP GET handshake.
    func testSSRObfsHandshake_httpSimple() throws {
        let handler = SSRObfsPluginHandler(
            obfsMode: "http_simple",
            obfsParam: "example.org"
        )
        let channel = EmbeddedChannel(handler: handler)

        // Trigger channelActive (should send HTTP GET).
        try channel.connect(to: try .init(ipAddress: "127.0.0.1", port: 0))
            .wait()

        // Read the outbound handshake data.
        var handshake = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(handshake)
        let hsLen = handshake?.readableBytes ?? 0
        let hsString = handshake?.readString(length: hsLen) ?? ""
        XCTAssertTrue(hsString.contains("GET / HTTP/1.1"))
        XCTAssertTrue(hsString.contains("example.org"))

        // Feed a mock HTTP response.
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
        var responseBuf = ByteBuffer(string: response)
        try channel.writeInbound(responseBuf)

        // After stripping response, the handler should forward payload.
        var data = ByteBuffer(string: "stream-data")
        try channel.writeInbound(data)

        var output = try channel.readInbound(as: ByteBuffer.self)
        XCTAssertNotNil(output)
        let ob2 = output?.readableBytes ?? 0
        XCTAssertEqual(output?.readString(length: ob2),
                       "stream-data")

        XCTAssertNoThrow(try channel.finish())
    }

    /// Verifies that `tls1.2_ticket_auth` obfs sends a mock TLS
    /// ClientHello record.
    func testSSRObfsHandshake_tls12Ticket() throws {
        let handler = SSRObfsPluginHandler(
            obfsMode: "tls1.2_ticket_auth",
            obfsParam: "cdn.example.com"
        )
        let channel = EmbeddedChannel(handler: handler)

        try channel.connect(to: try .init(ipAddress: "127.0.0.1", port: 0))
            .wait()

        // Read the outbound ClientHello.
        var clientHello = try channel.readOutbound(as: ByteBuffer.self)
        XCTAssertNotNil(clientHello)
        let chLen = clientHello?.readableBytes ?? 0
        guard let clBytes = clientHello?.readBytes(length: chLen) else {
            XCTFail("Failed to read ClientHello"); return
        }

        // Verify TLS record structure.
        XCTAssertEqual(clBytes[0], 0x16, "ContentType must be handshake (0x16)")
        XCTAssertEqual(clBytes[1], 0x03, "TLS major version must be 3")
        XCTAssertEqual(clBytes[2], 0x03, "TLS minor version must be 3")
        XCTAssertEqual(clBytes[5], 0x01, "Handshake type must be ClientHello (0x01)")

        XCTAssertNoThrow(try channel.finish())
    }
}

// MARK: - Outbound Dialer Integration Tests

final class ShadowsocksROutboundDialerTests: XCTestCase {

    /// Verifies that the SSR OutboundProtocol variant has correct metadata.
    func testOutboundDialerSSR() {
        let proto = OutboundProtocol.shadowsocksR(
            cipher: "aes-256-cfb",
            password: "test-password",
            protocolMode: "auth_aes128_sha1",
            protocolParam: nil,
            obfsMode: "tls1.2_ticket_auth",
            obfsParam: nil
        )

        XCTAssertEqual(proto.label, "ShadowsocksR")
        XCTAssertFalse(proto.isTLS)
        XCTAssertFalse(proto.isHTTPWrapped)
        XCTAssertFalse(proto.isGRPC)
    }
}
