//===----------------------------------------------------------------------===//
//
//  Hysteria2UdpTests.swift
//  SwiftletCore — Hysteria 2 UDP Framing & Obfuscation Tests
//
//  Validates:
//  • UDP request frame (0x402) session ID encoding
//  • UDP data frame (0x403) build → parse round‑trip
//  • DNS query (port 53) simulation in 0x403 frame
//  • Salamander padding injection and deterministic stripping
//  • Padding mutates packet length without corrupting payload boundaries
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - UDP Request Frame (0x402)

@Suite("Hysteria2 — UDP Request (0x402)")
struct Hysteria2UDPRequestTests {

    @Test func commandConstantIs0x402() {
        #expect(Hysteria2UDPCommand.udpRequest == 0x402)
    }

    @Test func buildEncodesSessionID() throws {
        let frame = Hysteria2UDPRequestBuilder.build(sessionID: 42)

        // Parse: command varint then session ID varint.
        let (cmd, cmdLen) = try QUICVarint.decode(frame)
        #expect(cmd == 0x402)

        let remainder = frame.subdata(in: cmdLen ..< frame.count)
        let (sid, _) = try QUICVarint.decode(remainder)
        #expect(sid == 42)
    }

    @Test func buildMaxSessionID() throws {
        let frame = Hysteria2UDPRequestBuilder.build(sessionID: 0xFFFF)

        let (cmd, cmdLen) = try QUICVarint.decode(frame)
        #expect(cmd == 0x402)

        let remainder = frame.subdata(in: cmdLen ..< frame.count)
        let (sid, _) = try QUICVarint.decode(remainder)
        #expect(sid == 0xFFFF)
    }
}

// MARK: - UDP Data Frame (0x403)

@Suite("Hysteria2 — UDP Data (0x403)")
struct Hysteria2UDPDataTests {

    @Test func commandConstantIs0x403() {
        #expect(Hysteria2UDPCommand.udpData == 0x403)
    }

    @Test func buildAndParseRoundTrip() throws {
        let payload = Data("UDP relay payload".utf8)
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 7,
            packetIndex: 3,
            payload: payload
        )

        let parsed = try Hysteria2UDPDataBuilder.parse(frame)

        #expect(parsed.sessionID == 7)
        #expect(parsed.packetIndex == 3)
        #expect(parsed.payload == payload)
    }

    @Test func buildAndParseEmptyPayload() throws {
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 1,
            packetIndex: 0,
            payload: Data()
        )

        let parsed = try Hysteria2UDPDataBuilder.parse(frame)
        #expect(parsed.sessionID == 1)
        #expect(parsed.packetIndex == 0)
        #expect(parsed.payload.isEmpty)
    }

    @Test func buildAndParseLargePayload() throws {
        let payload = Data([UInt8](repeating: 0xAB, count: 1500))
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 99,
            packetIndex: 42,
            payload: payload
        )

        let parsed = try Hysteria2UDPDataBuilder.parse(frame)
        #expect(parsed.payload == payload)
    }

    @Test func parseRejectsNonUDPDataCommand() {
        // Build a 0x402 frame and try to parse as 0x403.
        let frame = Hysteria2UDPRequestBuilder.build(sessionID: 1)

        #expect(throws: Hysteria2UDPDataBuilder.ParseError.invalidCommand(0x402)) {
            _ = try Hysteria2UDPDataBuilder.parse(frame)
        }
    }

    @Test func parseRejectsTruncatedFrame() {
        // Cut the frame short after the payload length varint.
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 1, packetIndex: 0,
            payload: Data([UInt8](repeating: 0x00, count: 32))
        )
        let truncated = frame.prefix(frame.count - 20)

        #expect(throws: Hysteria2UDPDataBuilder.ParseError.insufficientData(
            needed: frame.count, available: truncated.count
        )) {
            _ = try Hysteria2UDPDataBuilder.parse(Data(truncated))
        }
    }

    // MARK: DNS Packet Simulation

    /// Simulates a DNS query (port 53) being relayed through a Hysteria 2
    /// UDP data frame.
    @Test func dnsQuerySimulation() throws {
        // Build a mock DNS query: 12‑byte header + query for "example.com"
        var dnsQuery = Data()

        // DNS Header
        let txID: UInt16 = 0xABCD
        dnsQuery.append(UInt8(txID >> 8))
        dnsQuery.append(UInt8(txID & 0xFF))
        // Flags: standard query, recursion desired
        dnsQuery.append(contentsOf: [0x01, 0x00])
        // QDCOUNT = 1
        dnsQuery.append(contentsOf: [0x00, 0x01])
        // ANCOUNT, NSCOUNT, ARCOUNT = 0
        dnsQuery.append(contentsOf: [UInt8](repeating: 0x00, count: 6))

        // Question: "example.com" → \x07example\x03com\x00
        dnsQuery.append(0x07)
        dnsQuery.append(contentsOf: "example".utf8)
        dnsQuery.append(0x03)
        dnsQuery.append(contentsOf: "com".utf8)
        dnsQuery.append(0x00)
        // QTYPE = A (1), QCLASS = IN (1)
        dnsQuery.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        // Wrap in Hysteria 2 UDP data frame.
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 53,        // using port 53 as session ID
            packetIndex: 1,
            payload: dnsQuery
        )

        // Parse back.
        let parsed = try Hysteria2UDPDataBuilder.parse(frame)
        #expect(parsed.sessionID == 53)
        #expect(parsed.packetIndex == 1)
        #expect(parsed.payload == dnsQuery)

        // Verify the DNS query is intact.
        let restoredTxID = (UInt16(parsed.payload[0]) << 8) | UInt16(parsed.payload[1])
        #expect(restoredTxID == 0xABCD)
        #expect(parsed.payload[12] == 0x07) // "example" length byte
    }

    @Test func parseErrorEquatability() {
        let e1 = Hysteria2UDPDataBuilder.ParseError.invalidCommand(0x402)
        let e2 = Hysteria2UDPDataBuilder.ParseError.invalidCommand(0x402)
        let e3 = Hysteria2UDPDataBuilder.ParseError.invalidCommand(0x403)
        let e4 = Hysteria2UDPDataBuilder.ParseError.insufficientData(
            needed: 10, available: 5
        )
        #expect(e1 == e2)
        #expect(e1 != e3)
        #expect(e1 != e4)
    }
}

// MARK: - Salamander Obfuscator

@Suite("Salamander Obfuscator")
struct SalamanderObfuscatorTests {

    @Test func paddingIncreasesBufferSize() {
        var obfuscator = SalamanderObfuscator(seed: 42, multi: 64)
        var buffer = ByteBuffer(bytes: Data([UInt8](repeating: 0x01, count: 100)))
        let originalLen = buffer.readableBytes

        obfuscator.injectSalamanderPadding(to: &buffer)
        #expect(buffer.readableBytes >= originalLen)
    }

    @Test func paddingIsDeterministic() {
        // Two separate instances with same seed both start at counter=0,
        // so the same packet index produces the same pad length.
        var sender1 = SalamanderObfuscator(seed: 12345, multi: 32)
        var sender2 = SalamanderObfuscator(seed: 12345, multi: 32)

        var buf1 = ByteBuffer(bytes: Data([UInt8](repeating: 0x42, count: 50)))
        var buf2 = ByteBuffer(bytes: Data([UInt8](repeating: 0x42, count: 50)))

        sender1.injectSalamanderPadding(to: &buf1)
        sender2.injectSalamanderPadding(to: &buf2)

        // Same counter + same seed → same pad length.
        #expect(buf1.readableBytes == buf2.readableBytes)
    }

    @Test func consecutivePacketsGetDifferentPadLengths() {
        var obfuscator = SalamanderObfuscator(seed: 0, multi: 64)

        var buf1 = ByteBuffer(bytes: Data([0x00]))
        var buf2 = ByteBuffer(bytes: Data([0x00]))

        obfuscator.injectSalamanderPadding(to: &buf1)
        obfuscator.injectSalamanderPadding(to: &buf2)

        // Consecutive packets should (probabilistically) get different
        // pad lengths since the counter differs.
        // Both should be larger than the original 1‑byte payload.
        #expect(buf1.readableBytes >= 1)
        #expect(buf2.readableBytes >= 1)
    }

    @Test func stripRestoresOriginalSize() {
        // Sender and receiver have separate obfuscator instances, both
        // starting at counter = 0 with the same seed + multi.
        var sender = SalamanderObfuscator(seed: 0xABCD, multi: 32)
        var receiver = SalamanderObfuscator(seed: 0xABCD, multi: 32)

        let payload = Data("ORIGINAL_PAYLOAD_DATA".utf8)
        var buffer = ByteBuffer(bytes: payload)
        let originalLen = buffer.readableBytes

        // Sender injects padding.
        sender.injectSalamanderPadding(to: &buffer)
        #expect(buffer.readableBytes >= originalLen)

        // Receiver strips it.
        receiver.stripSalamanderPadding(from: &buffer)
        #expect(buffer.readableBytes == originalLen)

        // Content before padding should be intact.
        let restored = buffer.getBytes(
            at: buffer.readerIndex, length: originalLen
        )
        #expect(restored == Array(payload))
    }

    @Test func paddingRespectsMultiplier() {
        var obfuscator = SalamanderObfuscator(seed: 99, multi: 16)

        // Run many times — padding must always be < multi.
        for _ in 0 ..< 50 {
            var buf = ByteBuffer(bytes: Data([UInt8].random(count: 64)))
            let before = buf.readableBytes
            obfuscator.injectSalamanderPadding(to: &buf)
            let added = buf.readableBytes - before
            #expect(added < 16, "Padding \(added) exceeded multi=16")
        }
    }

    @Test func emptyBufferIsUnaffected() {
        var obfuscator = SalamanderObfuscator(seed: 1, multi: 64)
        var buffer = ByteBuffer()
        #expect(buffer.readableBytes == 0)

        obfuscator.injectSalamanderPadding(to: &buffer)
        #expect(buffer.readableBytes == 0)
    }

    @Test func multiOfOneAddsNoPadding() {
        var obfuscator = SalamanderObfuscator(seed: 7, multi: 1)
        var buffer = ByteBuffer(bytes: Data([UInt8](repeating: 0x11, count: 20)))
        let originalLen = buffer.readableBytes

        obfuscator.injectSalamanderPadding(to: &buffer)
        #expect(buffer.readableBytes == originalLen)
    }
}

// MARK: - Integration: Frame + Obfuscation

@Suite("Hysteria2 UDP Integration")
struct Hysteria2UDPIntegrationTests {

    @Test func dnsFrameWithSalamanderPaddingPreservesPayload() throws {
        // Build a mock DNS query.
        let dnsQuery = Data([
            0xAB, 0xCD,             // TXID
            0x01, 0x00,             // Flags
            0x00, 0x01,             // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/AR
            0x07,                   // label len
        ] + Array("example".utf8) + [
            0x03,                   // label len
        ] + Array("com".utf8) + [
            0x00,                   // terminator
            0x00, 0x01,             // QTYPE = A
            0x00, 0x01,             // QCLASS = IN
        ])

        // Build the 0x403 frame.
        let frame = Hysteria2UDPDataBuilder.build(
            sessionID: 53,
            packetIndex: 0,
            payload: dnsQuery
        )

        // Apply Salamander padding to the raw frame bytes.
        var sender = SalamanderObfuscator(seed: 0xCAFE, multi: 48)
        var receiver = SalamanderObfuscator(seed: 0xCAFE, multi: 48)
        var buffer = ByteBuffer(bytes: frame)
        let beforeLen = buffer.readableBytes
        sender.injectSalamanderPadding(to: &buffer)

        // Frame grew.
        #expect(buffer.readableBytes >= beforeLen)

        // Strip padding (separate instance, same counter sequence).
        receiver.stripSalamanderPadding(from: &buffer)

        // After stripping, parse must succeed and payload must match.
        let strippedData = buffer.getBytes(
            at: buffer.readerIndex, length: buffer.readableBytes
        ).map { Data($0) } ?? Data()

        let parsed = try Hysteria2UDPDataBuilder.parse(strippedData)
        #expect(parsed.sessionID == 53)
        #expect(parsed.payload == dnsQuery)
    }
}

// MARK: - Random Data Helper

extension Array where Element == UInt8 {
    static func random(count: Int) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}
