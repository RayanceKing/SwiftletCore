//===----------------------------------------------------------------------===//
//
//  TUN2UdpBridgeTests.swift
//  SwiftletCore — TUN→UDP Bridge Unit Tests
//
//  Validates:
//  • UDP header parsing (8‑byte layout, field extraction)
//  • UDP checksum over IPv4 pseudo‑header
//  • UDP session key hashing, equality, reverse lookup
//  • Session registry register / lookup / remove / count
//  • TUN2UdpBridge: IPv4 UDP → ProcessResult.forward
//  • TUN2UdpBridge: non‑UDP (TCP) → ProcessResult.none
//  • Reply packet assembly: correct IPv4 header, UDP header,
//    address swap, checksum, byte‑exact payload
//  • Full round‑trip: mock DNS query → parse → build reply → parse back
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - Packet Builders

private func buildIPv4UDPPacket(
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    payload: Data
) -> Data {
    let udpLen = 8 + payload.count
    let totalLen = 20 + udpLen
    var pkt = [UInt8](repeating: 0, count: totalLen)

    // IPv4 header.
    pkt[0] = 0x45; pkt[1] = 0x00
    pkt[2] = UInt8(totalLen >> 8); pkt[3] = UInt8(totalLen & 0xFF)
    pkt[4] = 0x00; pkt[5] = 0x00; pkt[6] = 0x00; pkt[7] = 0x00
    pkt[8] = 0x40; pkt[9] = 17
    pkt[10] = 0x00; pkt[11] = 0x00
    pkt[12] = srcIP.octet0; pkt[13] = srcIP.octet1
    pkt[14] = srcIP.octet2; pkt[15] = srcIP.octet3
    pkt[16] = dstIP.octet0; pkt[17] = dstIP.octet1
    pkt[18] = dstIP.octet2; pkt[19] = dstIP.octet3

    // UDP header.
    pkt[20] = UInt8(srcPort >> 8); pkt[21] = UInt8(srcPort & 0xFF)
    pkt[22] = UInt8(dstPort >> 8); pkt[23] = UInt8(dstPort & 0xFF)
    pkt[24] = UInt8(udpLen >> 8); pkt[25] = UInt8(udpLen & 0xFF)
    pkt[26] = 0x00; pkt[27] = 0x00
    for (i, b) in payload.enumerated() { pkt[28 + i] = b }

    // Compute and write UDP checksum.
    let segment = Array(pkt[20...])
    let cksum = UDPChecksum.computeIPv4(
        sourceAddr: srcIP, destAddr: dstIP, udpSegment: segment
    )
    pkt[26] = UInt8(cksum >> 8); pkt[27] = UInt8(cksum & 0xFF)

    return Data(pkt)
}

private func buildIPv4TCPPacket() -> Data {
    var pkt = [UInt8](repeating: 0, count: 40)
    pkt[0] = 0x45; pkt[1] = 0x00
    pkt[2] = 0x00; pkt[3] = 40  // Total Length = 40
    pkt[9] = 6                 // Protocol = TCP
    pkt[20] = 0x00; pkt[21] = 0x50
    pkt[22] = 0x04; pkt[23] = 0x00
    pkt[32] = 0x50; pkt[33] = 0x02
    return Data(pkt)
}

private let testSrcIP  = IPv4Address(10, 0, 0, 1)
private let testDstIP  = IPv4Address(10, 0, 0, 2)
private let testSrcPort: UInt16 = 12345
private let testDstPort: UInt16 = 53

// MARK: - UDP Header Parsing

@Suite("UDPHeader — Parsing")
struct UDPHeaderParsingTests {

    @Test func parsesValidUDPHeader() throws {
        let payload = Data("dns-query".utf8)
        let udpLen = 8 + payload.count
        var raw = Data([UInt8](repeating: 0, count: udpLen))
        raw[0] = UInt8(testSrcPort >> 8); raw[1] = UInt8(testSrcPort & 0xFF)
        raw[2] = UInt8(testDstPort >> 8); raw[3] = UInt8(testDstPort & 0xFF)
        raw[4] = UInt8(udpLen >> 8); raw[5] = UInt8(udpLen & 0xFF)
        for (i, b) in payload.enumerated() { raw[8 + i] = b }

        let udp = try UDPParser.parse(raw)
        #expect(udp.sourcePort == testSrcPort)
        #expect(udp.destinationPort == testDstPort)
        #expect(udp.length == UInt16(udpLen))
        #expect(udp.payload == payload)
    }

    @Test func headerSizeConstant() {
        #expect(UDPHeader.headerSize == 8)
    }

    @Test func parseRejectsTooShort() {
        let short = Data([0x00, 0x01, 0x02])
        #expect(throws: UDPParser.ParseError.insufficientData(
            needed: 8, available: 3
        )) { _ = try UDPParser.parse(short) }
    }

    @Test func parseRejectsLengthMismatch() {
        var raw = Data([UInt8](repeating: 0, count: 10))
        raw[4] = 0x00; raw[5] = 0x50
        #expect(throws: UDPParser.ParseError.self) {
            _ = try UDPParser.parse(raw)
        }
    }

    @Test func parseErrorEquatability() {
        let e1 = UDPParser.ParseError.insufficientData(needed: 8, available: 3)
        let e2 = UDPParser.ParseError.insufficientData(needed: 8, available: 3)
        #expect(e1 == e2)
    }
}

// MARK: - UDP Checksum

@Suite("UDPChecksum — IPv4")
struct UDPChecksumTests {

    @Test func computesNonZeroChecksum() {
        let payload = Data("test".utf8)
        let seg = buildUDPSegment(srcPort: testSrcPort, dstPort: testDstPort, payload: payload)
        let checksum = UDPChecksum.computeIPv4(
            sourceAddr: testSrcIP, destAddr: testDstIP, udpSegment: seg
        )
        #expect(checksum != 0)
    }

    @Test func identicalInputsProduceIdenticalChecksums() {
        let payload = Data([0xAA, 0xBB])
        let s1 = buildUDPSegment(srcPort: 1, dstPort: 2, payload: payload)
        let s2 = buildUDPSegment(srcPort: 1, dstPort: 2, payload: payload)
        let c1 = UDPChecksum.computeIPv4(
            sourceAddr: testSrcIP, destAddr: testDstIP, udpSegment: s1
        )
        let c2 = UDPChecksum.computeIPv4(
            sourceAddr: testSrcIP, destAddr: testDstIP, udpSegment: s2
        )
        #expect(c1 == c2)
    }

    private func buildUDPSegment(
        srcPort: UInt16, dstPort: UInt16, payload: Data
    ) -> [UInt8] {
        let len = 8 + payload.count
        var s = [UInt8](repeating: 0, count: len)
        s[0] = UInt8(srcPort >> 8); s[1] = UInt8(srcPort & 0xFF)
        s[2] = UInt8(dstPort >> 8); s[3] = UInt8(dstPort & 0xFF)
        s[4] = UInt8(len >> 8); s[5] = UInt8(len & 0xFF)
        for (i, b) in payload.enumerated() { s[8 + i] = b }
        return s
    }
}

// MARK: - Session Key & Registry

@Suite("UdpBridgeSessionKey & Registry")
struct UdpBridgeKeyRegistryTests {

    @Test func keyIsHashable() {
        let a = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        )
        let b = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        )
        #expect(a == b)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func reversedKeySwapsCoordinates() {
        let key = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 100,
            destinationIP: testDstIP, destinationPort: 200
        )
        let rev = key.reversed
        #expect(rev.sourceIP == testDstIP)
        #expect(rev.sourcePort == 200)
        #expect(rev.destinationIP == testSrcIP)
        #expect(rev.destinationPort == 100)
    }

    @Test func registryRegisterAndLookup() {
        let reg = UdpBridgeSessionRegistry()
        let key = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        )
        reg.register(UdpBridgeSession(key: key))
        #expect(reg.lookup(key) != nil)
        #expect(reg.count == 1)
    }

    @Test func registryLookupReverse() {
        let reg = UdpBridgeSessionRegistry()
        let key = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        )
        reg.register(UdpBridgeSession(key: key))

        // A reply packet has swapped coordinates (dst→src).  Look up
        // the reverse of the reply's 4‑tuple to find the session.
        let replyKey = UdpBridgeSessionKey(
            sourceIP: testDstIP, sourcePort: 2,
            destinationIP: testSrcIP, destinationPort: 1
        )
        // reverseOf(replyKey) = (testSrcIP:1 → testDstIP:2) = original key.
        #expect(reg.lookup(reverseOf: replyKey) != nil)
    }

    @Test func registryRemove() {
        let reg = UdpBridgeSessionRegistry()
        let key = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        )
        reg.register(UdpBridgeSession(key: key))
        reg.remove(key)
        #expect(reg.count == 0)
        #expect(reg.isEmpty)
    }

    @Test func registryRemoveAll() {
        let reg = UdpBridgeSessionRegistry()
        for i in 0..<5 {
            reg.register(UdpBridgeSession(key: UdpBridgeSessionKey(
                sourceIP: testSrcIP, sourcePort: UInt16(i),
                destinationIP: testDstIP, destinationPort: 53
            )))
        }
        #expect(reg.count == 5)
        reg.removeAll()
        #expect(reg.count == 0)
    }
}

// MARK: - TUN2UdpBridge Inbound

@Suite("TUN2UdpBridge — Inbound")
struct TUN2UdpBridgeInboundTests {

    @Test func udpPacketReturnsForwardResult() throws {
        let bridge = TUN2UdpBridge()
        let payload = Data([0xAB, 0xCD, 0xEF])
        let pkt = buildIPv4UDPPacket(
            srcIP: testSrcIP, dstIP: testDstIP,
            srcPort: testSrcPort, dstPort: testDstPort,
            payload: payload
        )
        let result = try bridge.processInbound(pkt)
        guard case .forward(let session, let fwdPayload) = result else {
            Issue.record("Expected .forward"); return
        }
        #expect(session.sourceIP == testSrcIP)
        #expect(session.sourcePort == testSrcPort)
        #expect(session.destinationIP == testDstIP)
        #expect(session.destinationPort == testDstPort)
        #expect(fwdPayload == payload)
    }

    @Test func tcpPacketReturnsNone() throws {
        let bridge = TUN2UdpBridge()
        let result = try bridge.processInbound(buildIPv4TCPPacket())
        guard case .none = result else {
            Issue.record("Expected .none"); return
        }
    }

    @Test func sessionRegisteredOnFirstPacket() throws {
        let bridge = TUN2UdpBridge()
        try bridge.processInbound(buildIPv4UDPPacket(
            srcIP: testSrcIP, dstIP: testDstIP,
            srcPort: testSrcPort, dstPort: testDstPort,
            payload: Data([0x01])
        ))
        #expect(bridge.registry.count == 1)
    }

    @Test func sessionReusedOnSubsequentPacket() throws {
        let bridge = TUN2UdpBridge()
        let makePkt = { (p: Data) in buildIPv4UDPPacket(
            srcIP: testSrcIP, dstIP: testDstIP,
            srcPort: testSrcPort, dstPort: testDstPort, payload: p
        )}
        try bridge.processInbound(makePkt(Data([0x01])))
        try bridge.processInbound(makePkt(Data([0x02])))
        #expect(bridge.registry.count == 1)
    }

    @Test func differentPortsCreateDifferentSessions() throws {
        let bridge = TUN2UdpBridge()
        try bridge.processInbound(buildIPv4UDPPacket(
            srcIP: testSrcIP, dstIP: testDstIP,
            srcPort: 1000, dstPort: 53, payload: Data([0x01])
        ))
        try bridge.processInbound(buildIPv4UDPPacket(
            srcIP: testSrcIP, dstIP: testDstIP,
            srcPort: 1001, dstPort: 53, payload: Data([0x02])
        ))
        #expect(bridge.registry.count == 2)
    }
}

// MARK: - Reply Packet Assembly

@Suite("TUN2UdpBridge — Reply Assembly")
struct TUN2UdpBridgeReplyTests {

    @Test func producesValidIPv4() {
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: Data("r".utf8)
        )
        #expect(pkt[0] == 0x45)
        #expect(pkt[9] == 17)
    }

    @Test func correctTotalLength() {
        let payload = Data([UInt8](repeating: 0, count: 32))
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: payload
        )
        let totalLen = (Int(pkt[2]) << 8) | Int(pkt[3])
        #expect(totalLen == 20 + 8 + 32)
    }

    @Test func addressesSwapped() {
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: Data([0x01])
        )
        #expect([pkt[12], pkt[13], pkt[14], pkt[15]]
            == [testDstIP.octet0, testDstIP.octet1, testDstIP.octet2, testDstIP.octet3])
        #expect([pkt[16], pkt[17], pkt[18], pkt[19]]
            == [testSrcIP.octet0, testSrcIP.octet1, testSrcIP.octet2, testSrcIP.octet3])
    }

    @Test func portsCorrect() {
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: 53,
            dstIP: testSrcIP, dstPort: 12345,
            payload: Data([0x01])
        )
        let udpSrc = (UInt16(pkt[20]) << 8) | UInt16(pkt[21])
        let udpDst = (UInt16(pkt[22]) << 8) | UInt16(pkt[23])
        #expect(udpSrc == 53)
        #expect(udpDst == 12345)
    }

    @Test func payloadPreserved() {
        let payload = Data("exact match".utf8)
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: payload
        )
        #expect(pkt.subdata(in: 28..<pkt.count) == payload)
    }

    @Test func checksumValidates() {
        let payload = Data("validate".utf8)
        let pkt = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: payload
        )
        let segment = Array(pkt[20...])
        let verify = UDPChecksum.computeIPv4(
            sourceAddr: testDstIP, destAddr: testSrcIP, udpSegment: segment
        )
        #expect(verify == 0)
    }

    @Test func bridgeBuildReplyMatchesStatic() {
        let bridge = TUN2UdpBridge()
        let key = UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: testSrcPort,
            destinationIP: testDstIP, destinationPort: testDstPort
        )
        let payload = Data([0x01, 0x02])
        let fromBridge = bridge.buildReply(for: key, payload: payload)
        let fromStatic = TUN2UdpBridge.buildInboundUdpPacket(
            srcIP: testDstIP, srcPort: testDstPort,
            dstIP: testSrcIP, dstPort: testSrcPort,
            payload: payload
        )
        #expect(fromBridge == fromStatic)
    }
}

// MARK: - Full Round‑Trip

@Suite("TUN2UdpBridge — Round‑Trip")
struct TUN2UdpBridgeRoundTripTests {

    @Test func dnsQueryRoundTrip() throws {
        let clientIP = IPv4Address(192, 168, 1, 100)
        let serverIP = IPv4Address(8, 8, 8, 8)
        let clientPort: UInt16 = 54321
        let serverPort: UInt16 = 53

        let dnsQuery = Data([
            0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x07,
        ] + Array("example".utf8) + [
            0x03,
        ] + Array("com".utf8) + [
            0x00, 0x00, 0x01, 0x00, 0x01,
        ])

        let bridge = TUN2UdpBridge()
        let queryPkt = buildIPv4UDPPacket(
            srcIP: clientIP, dstIP: serverIP,
            srcPort: clientPort, dstPort: serverPort,
            payload: dnsQuery
        )
        let result = try bridge.processInbound(queryPkt)

        guard case .forward(let session, let fwdPayload) = result else {
            Issue.record("Expected .forward"); return
        }
        #expect(fwdPayload == dnsQuery)

        // Build reply.
        let dnsResponse = Data([0xAB, 0xCD, 0x81, 0x80, 0x00, 0x01,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
            0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01,
            0x00, 0x00, 0x00, 0x3C, 0x00, 0x04,
            0x5D, 0xB8, 0xD8, 0x22])
        let replyPkt = bridge.buildReply(for: session, payload: dnsResponse)

        // Verify structure.
        #expect(replyPkt[0] == 0x45)
        #expect(replyPkt[9] == 17)
        #expect([replyPkt[12], replyPkt[13], replyPkt[14], replyPkt[15]]
            == [serverIP.octet0, serverIP.octet1, serverIP.octet2, serverIP.octet3])
        #expect([replyPkt[16], replyPkt[17], replyPkt[18], replyPkt[19]]
            == [clientIP.octet0, clientIP.octet1, clientIP.octet2, clientIP.octet3])

        let udpSrc = (UInt16(replyPkt[20]) << 8) | UInt16(replyPkt[21])
        #expect(udpSrc == serverPort)

        #expect(replyPkt.subdata(in: 28..<replyPkt.count) == dnsResponse)

        // Checksum must be valid.
        let segment = Array(replyPkt[20...])
        let verify = UDPChecksum.computeIPv4(
            sourceAddr: serverIP, destAddr: clientIP, udpSegment: segment
        )
        #expect(verify == 0)
    }
}

// MARK: - Session Metadata

@Suite("UdpBridgeSession — Metadata")
struct UdpBridgeSessionTests {

    @Test func sessionStoresCreationTime() {
        let session = UdpBridgeSession(key: UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        ))
        #expect(abs(session.createdAt.timeIntervalSinceNow) < 1)
    }

    @Test func markActivityUpdatesTimestamp() {
        let session = UdpBridgeSession(key: UdpBridgeSessionKey(
            sourceIP: testSrcIP, sourcePort: 1,
            destinationIP: testDstIP, destinationPort: 2
        ))
        let before = session.lastActivity
        Thread.sleep(forTimeInterval: 0.001)
        session.markActivity()
        #expect(session.lastActivity > before)
    }
}
