//===----------------------------------------------------------------------===//
//
//  TUN2SocksBridgeTests.swift
//  SwiftletCore — TUN2Socks Bridge Unit Tests
//
//  Verifies the end‑to‑end virtual TCP handshake: feeds a raw IPv4 TCP
//  SYN packet into the bridge, asserts that a session is registered, and
//  validates the structure and checksum of the returned SYN‑ACK.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - SYN → SYN‑ACK Handshake Test

/// Feeds a raw IPv4 TCP SYN packet into the bridge and verifies that:
/// 1. A session is registered in the registry.
/// 2. The bridge returns a `.reply` containing a valid SYN‑ACK.
/// 3. The SYN‑ACK has correct addresses, ports, flags, and checksum.
@Test func synPacketGeneratesValidSynAckAndRegistersSession() async throws {

    // ---- 1. Build the mock IPv4 TCP SYN packet ---------------------------
    //
    //  IPv4 header:
    //    Src: 10.0.0.1
    //    Dst: 93.184.216.34
    //    Protocol: TCP (6), TTL: 64
    //
    //  TCP header (20 bytes, Data Offset = 5, no options):
    //    Src Port: 50318
    //    Dst Port: 80
    //    Seq:      0x12345678
    //    Ack:      0 (not valid for SYN)
    //    Flags:    SYN (0x02)
    //    Window:   65535
    //
    //  Payload: none (pure SYN)

    var packetBytes: [UInt8] = []

    // --- IPv4 header (20 bytes) -------------------------------------------
    packetBytes.append(contentsOf: [
        0x45,                   // Version=4, IHL=5
        0x00,                   // ToS
        0x00, 0x28,             // Total Length = 40 (20 IP + 20 TCP)
        0x00, 0x00,             // Identification
        0x00, 0x00,             // Flags + Fragment Offset
        0x40,                   // TTL = 64
        0x06,                   // Protocol = TCP
        0x00, 0x00,             // Header Checksum (placeholder)
        0x0A, 0x00, 0x00, 0x01, // Source: 10.0.0.1
        0x5D, 0xB8, 0xD8, 0x22, // Dest: 93.184.216.34
    ])

    // --- TCP header (20 bytes) --------------------------------------------
    packetBytes.append(contentsOf: [
        0xC4, 0x8E,             // Source Port = 50318
        0x00, 0x50,             // Dest Port = 80
        0x12, 0x34, 0x56, 0x78, // Sequence = 0x12345678
        0x00, 0x00, 0x00, 0x00, // Ack = 0
        0x50,                   // Data Offset = 5 (top nibble)
        0x02,                   // Flags = SYN
        0xFF, 0xFF,             // Window = 65535
        0x00, 0x00,             // Checksum (placeholder)
        0x00, 0x00,             // Urgent Pointer
    ])

    let synPacket = Data(packetBytes)

    // ---- 2. Process the packet through the bridge ------------------------
    let bridge = TUN2SocksBridge()

    let result = try bridge.processInbound(synPacket)

    // ---- 3. Assert: reply type -------------------------------------------
    guard case .reply(let synAckData) = result else {
        Issue.record("Expected .reply, got \(result)")
        return
    }

    // ---- 4. Assert: session registered -----------------------------------
    #expect(bridge.registry.count == 1)

    let expectedKey = TCPSessionKey(
        sourceIP: IPv4Address(10, 0, 0, 1),
        sourcePort: 50318,
        destinationIP: IPv4Address(93, 184, 216, 34),
        destinationPort: 80
    )

    guard let session = bridge.registry.lookup(expectedKey) else {
        Issue.record("Session not found for key \(expectedKey)")
        return
    }

    #expect(session.state == .synReceived)
    #expect(session.clientISN == 0x12345678)
    #expect(session.serverISN != 0) // must be a random non‑zero ISN
    #expect(session.clientNextSeq == 0x12345679)
    #expect(session.serverNextSeq == session.serverISN + 1)

    // ---- 5. Parse the SYN‑ACK reply --------------------------------------
    let replyPacket = try IPPacketParser.parse(synAckData)

    guard case .ipv4(let ipHeader) = replyPacket else {
        Issue.record("SYN‑ACK reply is not IPv4")
        return
    }

    // ---- 6. Assert: IP header fields -------------------------------------
    #expect(ipHeader.sourceAddress == IPv4Address(93, 184, 216, 34))
    #expect(ipHeader.destinationAddress == IPv4Address(10, 0, 0, 1))
    #expect(ipHeader.protocol == 6)             // TCP
    #expect(ipHeader.totalLength > 20)           // has payload

    // ---- 7. Parse the TCP header inside the SYN‑ACK ----------------------
    var tcpBuffer = ipHeader.payload
    let tcpReply = try TCPParser.parse(buffer: &tcpBuffer)

    // ---- 8. Assert: TCP header fields ------------------------------------
    #expect(tcpReply.sourcePort == 80)             // reversed
    #expect(tcpReply.destinationPort == 50318)     // reversed

    // Flags: SYN | ACK
    #expect(tcpReply.flags.contains(.syn))
    #expect(tcpReply.flags.contains(.ack))
    #expect(!tcpReply.flags.contains(.rst))
    #expect(!tcpReply.flags.contains(.fin))
    #expect(tcpReply.isSYNACK)

    // Ack = client ISN + 1
    #expect(tcpReply.acknowledgmentNumber == 0x12345679)
    // Server seq = session.serverISN
    #expect(tcpReply.sequenceNumber == session.serverISN)

    // Data Offset = 5 (20‑byte header)
    #expect(tcpReply.dataOffset == 5)

    // Window > 0
    #expect(tcpReply.windowSize > 0)

    // No payload in SYN‑ACK
    #expect(tcpReply.payloadLength == 0)

    // ---- 9. Validate TCP checksum ----------------------------------------
    //
    // Reconstruct the TCP segment from the raw reply data (header bytes
    // with checksum zeroed) and verify the checksum matches.
    let rawTCPBytes = synAckData.subdata(in: 20 ..< synAckData.count)
    var checksumBytes = Array(rawTCPBytes)
    // Zero out the checksum field (bytes 16–17 of TCP header)
    checksumBytes[16] = 0x00
    checksumBytes[17] = 0x00

    let computed = TCPChecksum.computeIPv4(
        sourceAddr: IPv4Address(93, 184, 216, 34),
        destAddr: IPv4Address(10, 0, 0, 1),
        tcpSegment: checksumBytes
    )

    #expect(computed == tcpReply.checksum)
    #expect(computed != 0) // a valid checksum should be non‑zero

    // ---- 10. Verify no unexpected registry side effects ------------------
    #expect(bridge.registry.count == 1)
}

// MARK: - RST Generation Test

/// An unknown session (no SYN preceding it) should trigger a RST reply.
@Test func unknownSessionTriggersRST() async throws {

    // Build a TCP ACK packet that does not match any registered session.
    var bytes: [UInt8] = []
    // IPv4 header: 10.0.0.1 → 10.0.0.2, proto=TCP
    bytes.append(contentsOf: [
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    ])
    // TCP header: port 12345 → 80, ACK flag, random seq
    bytes.append(contentsOf: [
        0x30, 0x39,             // Src Port = 12345
        0x00, 0x50,             // Dst Port = 80
        0x00, 0x00, 0x00, 0x99, // Seq
        0x00, 0x00, 0x00, 0x00, // Ack
        0x50,                   // Data Offset = 5
        0x10,                   // Flags = ACK
        0xFF, 0xFF,
        0x00, 0x00,
        0x00, 0x00,
    ])

    let bridge = TUN2SocksBridge()
    let result = try bridge.processInbound(Data(bytes))

    guard case .reply(let rstData) = result else {
        Issue.record("Expected .reply (RST), got \(result)")
        return
    }

    // Parse the RST and verify it is indeed an RST.
    let rstPacket = try IPPacketParser.parse(rstData)
    guard case .ipv4(let ipHdr) = rstPacket else {
        Issue.record("RST is not IPv4")
        return
    }

    var tcpBuf = ipHdr.payload
    let tcp = try TCPParser.parse(buffer: &tcpBuf)

    #expect(tcp.flags.contains(.rst))
    #expect(bridge.registry.isEmpty) // no session should have been created
}

// MARK: - Session Lifecycle Test

/// A SYN followed by a matching ACK should transition the session to
/// `.established`.
@Test func synThenAckCompletesHandshake() async throws {

    let bridge = TUN2SocksBridge()

    // ---- Step 1: send SYN ------------------------------------------------
    let synData = buildMockSYN(
        srcIP: IPv4Address(10, 0, 0, 1),
        dstIP: IPv4Address(10, 0, 0, 2),
        srcPort: 40000,
        dstPort: 8080,
        seq: 0x1000
    )

    let synResult = try bridge.processInbound(synData)
    guard case .reply(let synAckData) = synResult else {
        Issue.record("Expected SYN‑ACK reply")
        return
    }

    // Extract the server ISN from the SYN‑ACK.
    let synAckPacket = try IPPacketParser.parse(synAckData)
    guard case .ipv4(let saIP) = synAckPacket else { return }
    var saBuf = saIP.payload
    let synAckTCP = try TCPParser.parse(buffer: &saBuf)
    let serverISN = synAckTCP.sequenceNumber

    #expect(bridge.registry.count == 1)

    // ---- Step 2: send matching ACK ---------------------------------------
    let ackData = buildMockACK(
        srcIP: IPv4Address(10, 0, 0, 1),
        dstIP: IPv4Address(10, 0, 0, 2),
        srcPort: 40000,
        dstPort: 8080,
        seq: 0x1000 + 1,                   // client seq after SYN
        ack: serverISN + 1                 // acknowledging server's SYN‑ACK
    )

    let ackResult = try bridge.processInbound(ackData)

    // ACK by itself should produce no reply.
    guard case .none = ackResult else {
        Issue.record("Expected .none after ACK, got \(ackResult)")
        return
    }

    // Session should now be established.
    let key = TCPSessionKey(
        sourceIP: IPv4Address(10, 0, 0, 1),
        sourcePort: 40000,
        destinationIP: IPv4Address(10, 0, 0, 2),
        destinationPort: 8080
    )
    guard let session = bridge.registry.lookup(key) else {
        Issue.record("Session not found")
        return
    }
    #expect(session.state == .established)
}

// MARK: - Non‑TCP Packet Test

/// Non‑TCP packets (e.g. UDP, ICMP) should be silently ignored.
@Test func nonTCPPacketIsIgnored() async throws {
    // Build a minimal IPv4 UDP packet.
    var bytes: [UInt8] = []
    bytes.append(contentsOf: [
        0x45, 0x00, 0x00, 0x1C, // Ver=4, IHL=5, Total Length = 28
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00, // Proto = UDP (0x11)
        0x0A, 0x00, 0x00, 0x01,
        0x0A, 0x00, 0x00, 0x02,
    ])
    // 8 bytes of mock UDP header
    bytes.append(contentsOf: [UInt8](repeating: 0x00, count: 8))

    let bridge = TUN2SocksBridge()
    let result = try bridge.processInbound(Data(bytes))

    guard case .none = result else {
        Issue.record("Expected .none for UDP, got \(result)")
        return
    }
    #expect(bridge.registry.isEmpty)
}

// MARK: - Test Helpers

/// Builds a raw IPv4 TCP SYN packet.
private func buildMockSYN(
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    seq: UInt32
) -> Data {
    var bytes: [UInt8] = []

    // IPv4 header
    bytes.append(contentsOf: [
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        srcIP.octet0, srcIP.octet1, srcIP.octet2, srcIP.octet3,
        dstIP.octet0, dstIP.octet1, dstIP.octet2, dstIP.octet3,
    ])

    // TCP header (SYN)
    bytes.append(contentsOf: [
        UInt8(truncatingIfNeeded: srcPort >> 8),
        UInt8(truncatingIfNeeded: srcPort),
        UInt8(truncatingIfNeeded: dstPort >> 8),
        UInt8(truncatingIfNeeded: dstPort),
        UInt8(truncatingIfNeeded: seq >> 24),
        UInt8(truncatingIfNeeded: seq >> 16),
        UInt8(truncatingIfNeeded: seq >> 8),
        UInt8(truncatingIfNeeded: seq),
        0x00, 0x00, 0x00, 0x00,  // Ack = 0
        0x50,                     // Data Offset = 5
        0x02,                     // SYN
        0xFF, 0xFF,               // Window
        0x00, 0x00,               // Checksum
        0x00, 0x00,               // Urgent
    ])

    return Data(bytes)
}

/// Builds a raw IPv4 TCP ACK packet (no payload).
private func buildMockACK(
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    seq: UInt32,
    ack: UInt32
) -> Data {
    var bytes: [UInt8] = []

    // IPv4 header
    bytes.append(contentsOf: [
        0x45, 0x00, 0x00, 0x28,
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        srcIP.octet0, srcIP.octet1, srcIP.octet2, srcIP.octet3,
        dstIP.octet0, dstIP.octet1, dstIP.octet2, dstIP.octet3,
    ])

    // TCP header (ACK)
    bytes.append(contentsOf: [
        UInt8(truncatingIfNeeded: srcPort >> 8),
        UInt8(truncatingIfNeeded: srcPort),
        UInt8(truncatingIfNeeded: dstPort >> 8),
        UInt8(truncatingIfNeeded: dstPort),
        UInt8(truncatingIfNeeded: seq >> 24),
        UInt8(truncatingIfNeeded: seq >> 16),
        UInt8(truncatingIfNeeded: seq >> 8),
        UInt8(truncatingIfNeeded: seq),
        UInt8(truncatingIfNeeded: ack >> 24),
        UInt8(truncatingIfNeeded: ack >> 16),
        UInt8(truncatingIfNeeded: ack >> 8),
        UInt8(truncatingIfNeeded: ack),
        0x50,                     // Data Offset = 5
        0x10,                     // ACK
        0xFF, 0xFF,               // Window
        0x00, 0x00,               // Checksum
        0x00, 0x00,               // Urgent
    ])

    return Data(bytes)
}
