//===----------------------------------------------------------------------===//
//
//  Hysteria2ProtocolTests.swift
//  SwiftletCore — Hysteria 2 Protocol Unit Tests
//
//  Validates:
//  • Frame build → parse round‑trip for all four frame types
//  • Data frame header field correctness (stream ID, payload length)
//  • Auth/Ping frame length‑prefixed parsing
//  • Parser error paths (truncation, invalid type byte)
//  • Obfuscation padding injection and boundary safety
//  • Handler frame construction
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - Frame Build → Parse Round‑Trip

@Suite("Hysteria2Frame — Round‑Trip")
struct Hysteria2FrameRoundTripTests {

    @Test func tcpDataFrameRoundTrip() throws {
        let payload = Data("Hello Hysteria2 TCP stream!".utf8)
        let frame = Hysteria2Frame.tcpData(streamID: 42, payload: payload)

        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .tcpData(let sid, let pld) = parsed else {
            Issue.record("Expected .tcpData, got \(parsed)")
            return
        }
        #expect(sid == 42)
        #expect(pld == payload)
    }

    @Test func udpDataFrameRoundTrip() throws {
        let payload = Data([UInt8](repeating: 0xAB, count: 256))
        let frame = Hysteria2Frame.udpData(sessionID: 7, payload: payload)

        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .udpData(let sid, let pld) = parsed else {
            Issue.record("Expected .udpData, got \(parsed)")
            return
        }
        #expect(sid == 7)
        #expect(pld == payload)
    }

    @Test func authFrameRoundTrip() throws {
        let secret = Data("pre-shared-secret-key!!".utf8)
        let frame = Hysteria2Frame.auth(secret: secret)

        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .auth(let s) = parsed else {
            Issue.record("Expected .auth, got \(parsed)")
            return
        }
        #expect(s == secret)
    }

    @Test func pingFrameRoundTrip() throws {
        let pingData = Data([0x01, 0x02, 0x03])
        let frame = Hysteria2Frame.ping(data: pingData)

        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .ping(let d) = parsed else {
            Issue.record("Expected .ping, got \(parsed)")
            return
        }
        #expect(d == pingData)
    }

    @Test func emptyPingFrameRoundTrip() throws {
        let frame = Hysteria2Frame.ping(data: Data())
        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .ping(let d) = parsed else {
            Issue.record("Expected .ping, got \(parsed)")
            return
        }
        #expect(d.isEmpty)
    }

    @Test func emptyAuthFrameRoundTrip() throws {
        let frame = Hysteria2Frame.auth(secret: Data())
        let wireData = Hysteria2FrameBuilder.build(frame)
        let parsed   = try Hysteria2FrameParser.parse(wireData)

        guard case .auth(let s) = parsed else {
            Issue.record("Expected .auth, got \(parsed)")
            return
        }
        #expect(s.isEmpty)
    }
}

// MARK: - Frame Header Fields

@Suite("Hysteria2Frame — Header Fields")
struct Hysteria2FrameHeaderTests {

    @Test func dataFrameHeaderSize() {
        let frame = Hysteria2Frame.tcpData(
            streamID: 1,
            payload: Data([0x42])
        )
        let wireData = Hysteria2FrameBuilder.build(frame)
        // 1 (type) + 2 (streamID) + 2 (length) + 1 (payload) = 6
        #expect(wireData.count == 6)
        #expect(Hysteria2FrameBuilder.dataHeaderSize == 5)
    }

    @Test func dataFrameTypeBytePosition() {
        let frame = Hysteria2Frame.tcpData(
            streamID: 0x1234,
            payload: Data("test".utf8)
        )
        let wireData = Hysteria2FrameBuilder.build(frame)

        // Byte 0: type
        #expect(wireData[0] == 0x00) // TCP
        // Bytes 1–2: stream ID
        #expect(wireData[1] == 0x12)
        #expect(wireData[2] == 0x34)
        // Bytes 3–4: payload length
        #expect(wireData[3] == 0x00)
        #expect(wireData[4] == 0x04)
    }

    @Test func udpDataFrameTypeByte() {
        let frame = Hysteria2Frame.udpData(
            sessionID: 1,
            payload: Data("u".utf8)
        )
        let wireData = Hysteria2FrameBuilder.build(frame)
        #expect(wireData[0] == 0x01) // UDP
    }

    @Test func authFrameTypeByte() {
        let frame = Hysteria2Frame.auth(secret: Data("key".utf8))
        let wireData = Hysteria2FrameBuilder.build(frame)
        #expect(wireData[0] == 0x02)
        #expect(wireData[1] == 3) // "key".utf8.count = 3
    }

    @Test func pingFrameTypeByte() {
        let frame = Hysteria2Frame.ping(data: Data())
        let wireData = Hysteria2FrameBuilder.build(frame)
        #expect(wireData[0] == 0x03)
        #expect(wireData[1] == 0) // data len = 0
    }

    @Test func streamIDBoundaries() {
        // StreamID = 0xFFFF (max UInt16)
        let frame = Hysteria2Frame.tcpData(
            streamID: 0xFFFF,
            payload: Data()
        )
        let wireData = Hysteria2FrameBuilder.build(frame)
        #expect(wireData[1] == 0xFF)
        #expect(wireData[2] == 0xFF)
    }
}

// MARK: - Parser Error Paths

@Suite("Hysteria2Frame — Error Paths")
struct Hysteria2FrameErrorTests {

    @Test func emptyDataThrows() {
        #expect(throws: Hysteria2FrameParser.ParseError.insufficientData(
            needed: 1, available: 0
        )) {
            _ = try Hysteria2FrameParser.parse(Data())
        }
    }

    @Test func invalidTypeByteThrows() {
        let data = Data([0xFF]) // unknown type
        #expect(throws: Hysteria2FrameParser.ParseError.invalidFrameType(0xFF)) {
            _ = try Hysteria2FrameParser.parse(data)
        }
    }

    @Test func truncatedDataFrameThrows() {
        // Only 3 bytes — need at least 5 for a data frame.
        let data = Data([0x00, 0x00, 0x01]) // type + partial stream ID
        #expect(throws: Hysteria2FrameParser.ParseError.insufficientData(
            needed: 5, available: 3
        )) {
            _ = try Hysteria2FrameParser.parse(data)
        }
    }

    @Test func dataFrameWithMissingPayloadThrows() {
        // Declares 10 bytes of payload but provides none.
        var data = Data([0x00, 0x00, 0x01, 0x00, 0x0A]) // len=10
        data.append(contentsOf: [0x42, 0x42]) // only 2 bytes
        #expect(throws: Hysteria2FrameParser.ParseError.insufficientData(
            needed: 15, available: 7
        )) {
            _ = try Hysteria2FrameParser.parse(data)
        }
    }

    @Test func truncatedAuthFrameThrows() {
        let data = Data([0x02, 0x10]) // declares 16 secret bytes, none provided
        #expect(throws: Hysteria2FrameParser.ParseError.insufficientData(
            needed: 18, available: 2
        )) {
            _ = try Hysteria2FrameParser.parse(data)
        }
    }

    @Test func truncatedPingFrameThrows() {
        let data = Data([0x03, 0x08]) // declares 8 ping bytes, none provided
        #expect(throws: Hysteria2FrameParser.ParseError.insufficientData(
            needed: 10, available: 2
        )) {
            _ = try Hysteria2FrameParser.parse(data)
        }
    }
}

// MARK: - Obfuscation

@Suite("Hysteria2 — Obfuscation")
struct Hysteria2ObfuscationTests {

    @Test func obfuscationAddsPadding() {
        var buffer = ByteBuffer(bytes: Data([0x01, 0x02, 0x03]))
        let originalLen = buffer.readableBytes

        Hysteria2Obfuscator.obfuscatePayload(&buffer, maxPadding: 32)
        #expect(buffer.readableBytes >= originalLen)
    }

    @Test func obfuscationDisabledWhenMaxPaddingIsZero() {
        var buffer = ByteBuffer(bytes: Data([0x01, 0x02]))
        let originalLen = buffer.readableBytes

        Hysteria2Obfuscator.obfuscatePayload(&buffer, maxPadding: 0)
        #expect(buffer.readableBytes == originalLen)
    }

    @Test func stripPaddingPreservesKnownLength() {
        var data = Data("PAYLOAD_DATA_EXTRA".utf8) // 19 bytes
        let knownLen = 7 // "PAYLOAD"
        Hysteria2Obfuscator.stripPadding(&data, knownPayloadLength: knownLen)
        #expect(data.count == 7)
        #expect(String(data: data, encoding: .utf8) == "PAYLOAD")
    }
}

// MARK: - Handler Frame Construction

@Suite("Hysteria2ClientHandler")
struct Hysteria2ClientHandlerTests {

    @Test func buildTcpDataFrame() throws {
        let handler = Hysteria2ClientHandler(sessionID: 100)
        let allocator = ByteBufferAllocator()

        let payload = Data("TCP stream payload".utf8)
        let buffer = handler.buildFrame(
            allocator: allocator,
            payload: payload,
            frameType: .tcpData
        )

        let rawBytes = buffer.getBytes(at: 0, length: buffer.readableBytes)!
        let frame = try Hysteria2FrameParser.parse(Data(rawBytes))

        guard case .tcpData(let sid, let pld) = frame else {
            Issue.record("Expected .tcpData")
            return
        }
        #expect(sid == 100)
        #expect(pld == payload)
    }

    @Test func buildUdpDataFrame() throws {
        let handler = Hysteria2ClientHandler(sessionID: 200)
        let allocator = ByteBufferAllocator()

        let payload = Data([UInt8](repeating: 0xDD, count: 64))
        let buffer = handler.buildFrame(
            allocator: allocator,
            payload: payload,
            frameType: .udpData
        )

        let rawBytes = buffer.getBytes(at: 0, length: buffer.readableBytes)!
        let frame = try Hysteria2FrameParser.parse(Data(rawBytes))

        guard case .udpData(let sid, let pld) = frame else {
            Issue.record("Expected .udpData")
            return
        }
        #expect(sid == 200)
        #expect(pld == payload)
    }

    @Test func buildAuthFrame() throws {
        let handler = Hysteria2ClientHandler(sessionID: 1)
        let allocator = ByteBufferAllocator()

        let secret = Data("auth-secret-32-bytes!!padded!!".utf8)
        let buffer = handler.buildAuthFrame(
            allocator: allocator,
            secret: secret
        )

        let rawBytes = buffer.getBytes(at: 0, length: buffer.readableBytes)!
        let frame = try Hysteria2FrameParser.parse(Data(rawBytes))

        guard case .auth(let s) = frame else {
            Issue.record("Expected .auth")
            return
        }
        #expect(s == secret)
    }

    @Test func obfuscationCanBeToggled() {
        let handler = Hysteria2ClientHandler(sessionID: 1)
        #expect(handler.obfuscationEnabled == true)

        handler.obfuscationEnabled = false
        #expect(handler.obfuscationEnabled == false)

        // Frame built with obfuscation disabled should have exact size.
        let allocator = ByteBufferAllocator()
        let payload = Data("test".utf8)
        let buffer = handler.buildFrame(
            allocator: allocator,
            payload: payload
        )
        // 5 (header) + 4 (payload) = 9 bytes exactly.
        #expect(buffer.readableBytes == 9)
    }

    @Test func errorEquatability() {
        #expect(Hysteria2Error.noRemoteAddress == Hysteria2Error.noRemoteAddress)
    }
}

// MARK: - Frame Type Enum

@Suite("Hysteria2FrameType")
struct Hysteria2FrameTypeTests {

    @Test func rawValuesAreCorrect() {
        #expect(Hysteria2FrameType.tcpData.rawValue == 0x00)
        #expect(Hysteria2FrameType.udpData.rawValue == 0x01)
        #expect(Hysteria2FrameType.auth.rawValue == 0x02)
        #expect(Hysteria2FrameType.ping.rawValue == 0x03)
    }

    @Test func frameTypeProperty() {
        let tcpFrame  = Hysteria2Frame.tcpData(streamID: 0, payload: Data())
        let udpFrame  = Hysteria2Frame.udpData(sessionID: 0, payload: Data())
        let authFrame = Hysteria2Frame.auth(secret: Data())
        let pingFrame = Hysteria2Frame.ping(data: Data())

        #expect(tcpFrame.type == .tcpData)
        #expect(udpFrame.type == .udpData)
        #expect(authFrame.type == .auth)
        #expect(pingFrame.type == .ping)
    }
}
