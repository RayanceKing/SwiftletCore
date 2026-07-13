//===----------------------------------------------------------------------===//
//
//  TUN2UdpBridgeFullConeTests.swift
//  SwiftletCoreTests — Full Cone NAT (Type A) Unit Tests
//
//  Validates RFC 4787 Endpoint‑Independent Mapping (EIM), Endpoint‑
//  Independent Filtering (EIF), session reuse across destinations,
//  unsolicited inbound packet punching, and idle session eviction.
//
//  Test Coverage
//  -------------
//  ┌──────────────────────────────────────────┬──────────────────────────────┐
//  │ Test                                     │ What it verifies             │
//  ├──────────────────────────────────────────┼──────────────────────────────┤
//  │ testEIM_reuseAcrossDestinations          │ Same endpoint → 1 session    │
//  │ testEIM_differentSourcePortCreatesNew    │ Different ports → 2 sessions │
//  │ testEIM_isNewMappingFlag                 │ New vs existing EIM flag     │
//  │ testEIF_unsolicitedAccepted              │ Unknown remote can punch in  │
//  │ testEIF_unsolicitedRejectedIfNoMatch     │ Drop if no EIM session       │
//  │ testEIF_biDirectionalActivityRefresh     │ Activity refreshed on inbound │
//  │ testFullCone_multipleRemotePeers         │ Many remotes → 1 session     │
//  │ testIdlePurge_removesStaleSessions       │ 30s idle → eviction          │
//  │ testIdlePurge_doesNotRemoveActive        │ Active sessions survive       │
//  │ testBuildReply_swapsCoordinates          │ Reply swaps src/dst          │
//  │ testUnsolicitedInbound_preservesPayload  │ Payload integrity in EIF     │
//  │ testRegistry_totalFlows                  │ Flow count tracking          │
//  │ testEIMEndpoint_hashable                 │ EIM endpoint equality         │
//  │ testSessionKey_eimProperty               │ 4‑tuple → 2‑tuple derivation  │
//  └──────────────────────────────────────────┴──────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
import Foundation

// MARK: - Helpers

private let clientIP  = IPv4Address(192, 168, 1, 100)
private let serverA   = IPv4Address(8, 8, 8, 8)
private let serverB   = IPv4Address(1, 1, 1, 1)
private let clientPort: UInt16 = 54321
private let dnsPort: UInt16    = 53
private let httpPort: UInt16   = 443

private func buildMockIPPacket(
    srcIP: IPv4Address,
    dstIP: IPv4Address,
    srcPort: UInt16,
    dstPort: UInt16,
    payload: Data
) -> Data {
    let udpLen = 8 + payload.count
    let totalLen = 20 + udpLen
    var pkt = [UInt8](repeating: 0, count: totalLen)
    pkt[0] = 0x45; pkt[1] = 0x00
    pkt[2] = UInt8(totalLen >> 8); pkt[3] = UInt8(totalLen & 0xFF)
    pkt[9] = 17
    pkt[12] = srcIP.octet0; pkt[13] = srcIP.octet1
    pkt[14] = srcIP.octet2; pkt[15] = srcIP.octet3
    pkt[16] = dstIP.octet0; pkt[17] = dstIP.octet1
    pkt[18] = dstIP.octet2; pkt[19] = dstIP.octet3
    pkt[20] = UInt8(srcPort >> 8); pkt[21] = UInt8(srcPort & 0xFF)
    pkt[22] = UInt8(dstPort >> 8); pkt[23] = UInt8(dstPort & 0xFF)
    pkt[24] = UInt8(udpLen >> 8); pkt[25] = UInt8(udpLen & 0xFF)
    for (i, b) in payload.enumerated() { pkt[28 + i] = b }
    return Data(pkt)
}

// MARK: - EIM Endpoint Tests

final class EIMEndpointTests: XCTestCase {

    /// Verifies EIM endpoint equality and hashing.
    func testEIMEndpoint_hashable() {
        let a = UdpEIMEndpoint(sourceIP: clientIP, sourcePort: 100)
        let b = UdpEIMEndpoint(sourceIP: clientIP, sourcePort: 100)
        let c = UdpEIMEndpoint(sourceIP: clientIP, sourcePort: 200)

        XCTAssertEqual(a, b)
        XCTAssertNotEqual(a, c)
        XCTAssertEqual(a.hashValue, b.hashValue)
    }

    /// Verifies that the 4‑tuple key correctly derives its EIM endpoint.
    func testSessionKey_eimProperty() {
        let key = UdpBridgeSessionKey(
            sourceIP: clientIP, sourcePort: 100,
            destinationIP: serverA, destinationPort: dnsPort
        )
        let eim = key.eim
        XCTAssertEqual(eim.sourceIP, clientIP)
        XCTAssertEqual(eim.sourcePort, 100)
    }
}

// MARK: - Endpoint‑Independent Mapping (EIM) Tests

final class EIMMappingTests: XCTestCase {

    /// Verifies that the same client endpoint reuses its EIM session
    /// when sending to different remote destinations (core EIM behavior).
    func testEIM_reuseAcrossDestinations() throws {
        let bridge = TUN2UdpBridge()

        // Client sends to server A.
        let pkt1 = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        let result1 = try bridge.processInbound(pkt1)

        guard case .forward(_, _, _, let isNew1) = result1 else {
            XCTFail("Expected .forward"); return
        }
        XCTAssertTrue(isNew1, "First packet must create a new EIM mapping")
        XCTAssertEqual(bridge.registry.count, 1)

        // Client sends to server B from the same source port.
        let pkt2 = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverB,
            srcPort: clientPort, dstPort: httpPort,
            payload: Data([0x02])
        )
        let result2 = try bridge.processInbound(pkt2)

        guard case .forward(_, _, _, let isNew2) = result2 else {
            XCTFail("Expected .forward"); return
        }
        XCTAssertFalse(isNew2, "Second packet must reuse existing EIM mapping")
        // Still only one EIM endpoint in the registry.
        XCTAssertEqual(bridge.registry.count, 1)
        // But now two flows.
        XCTAssertEqual(bridge.registry.totalFlows, 2)
    }

    /// Verifies that different source ports create separate EIM sessions.
    func testEIM_differentSourcePortCreatesNew() throws {
        let bridge = TUN2UdpBridge()

        let pkt1 = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: 1000, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt1)

        let pkt2 = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: 1001, dstPort: dnsPort,
            payload: Data([0x02])
        )
        _ = try bridge.processInbound(pkt2)

        // Two different source ports → two EIM sessions.
        XCTAssertEqual(bridge.registry.count, 2)
    }

    /// Verifies that the isNewMapping flag is correct for first vs
    /// subsequent packets from the same endpoint.
    func testEIM_isNewMappingFlag() throws {
        let bridge = TUN2UdpBridge()
        let makePkt = { (d: UInt16) in buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: d,
            payload: Data([0x01])
        )}

        let r1 = try bridge.processInbound(makePkt(53))
        guard case .forward(_, _, _, let new1) = r1 else { XCTFail(); return }
        XCTAssertTrue(new1)

        let r2 = try bridge.processInbound(makePkt(443))
        guard case .forward(_, _, _, let new2) = r2 else { XCTFail(); return }
        XCTAssertFalse(new2)
    }

    /// Verifies that many remote peers all share the same EIM session.
    func testFullCone_multipleRemotePeers() throws {
        let bridge = TUN2UdpBridge()
        let remotes: [(IPv4Address, UInt16)] = [
            (IPv4Address(1, 1, 1, 1), 53),
            (IPv4Address(2, 2, 2, 2), 443),
            (IPv4Address(3, 3, 3, 3), 8080),
            (IPv4Address(4, 4, 4, 4), 123),
            (IPv4Address(5, 5, 5, 5), 9999),
        ]

        for (remote, port) in remotes {
            let pkt = buildMockIPPacket(
                srcIP: clientIP, dstIP: remote,
                srcPort: clientPort, dstPort: port,
                payload: Data([0x01])
            )
            _ = try bridge.processInbound(pkt)
        }

        // All 5 flows share 1 EIM session.
        XCTAssertEqual(bridge.registry.count, 1)
        XCTAssertEqual(bridge.registry.totalFlows, 5)
    }
}

// MARK: - Endpoint‑Independent Filtering (EIF) Tests

final class EIFUnsolicitedInboundTests: XCTestCase {

    /// Verifies that an unsolicited inbound packet from an unknown
    /// remote host targeting an active EIM session is accepted (EIF).
    func testEIF_unsolicitedAccepted() throws {
        let bridge = TUN2UdpBridge()

        // First, register a session via a client outbound packet.
        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt)

        // Now simulate an unsolicited inbound packet from a
        // completely NEW remote host (serverB) targeting our
        // allocated endpoint (serverA:dnsPort → the "proxy" side).
        // In EIF, this should be accepted and forwarded to the client.
        let unsolicitedResult = bridge.processUnsolicitedInbound(
            fromRemoteIP: serverB,    // never‑before‑seen remote
            fromRemotePort: 9999,
            toProxyIP: serverA,       // original destination of the client outbound
            toProxyPort: dnsPort,
            payload: Data("unsolicited response".utf8)
        )

        guard case .reply(let replyData) = unsolicitedResult else {
            XCTFail("Expected .reply for unsolicited EIF packet"); return
        }
        XCTAssertFalse(replyData.isEmpty)

        // Verify the reply is addressed to the internal client.
        let dstIPOctets = [replyData[16], replyData[17], replyData[18], replyData[19]]
        XCTAssertEqual(dstIPOctets, [
            clientIP.octet0, clientIP.octet1, clientIP.octet2, clientIP.octet3
        ])
    }

    /// Verifies that an unsolicited packet is dropped when no EIM
    /// session matches the target endpoint.
    func testEIF_unsolicitedRejectedIfNoMatch() {
        let bridge = TUN2UdpBridge()

        // No sessions registered — unsolicited packet should be dropped.
        let result = bridge.processUnsolicitedInbound(
            fromRemoteIP: serverB,
            fromRemotePort: 9999,
            toProxyIP: serverA,
            toProxyPort: dnsPort,
            payload: Data("ghost packet".utf8)
        )

        guard case .none = result else {
            XCTFail("Expected .none for unmatched unsolicited packet"); return
        }
    }

    /// Verifies that bi‑directional activity refreshes the session TTL.
    func testEIF_biDirectionalActivityRefresh() throws {
        let bridge = TUN2UdpBridge()

        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt)

        // Get the initial activity timestamp.
        let eim = UdpEIMEndpoint(sourceIP: clientIP, sourcePort: clientPort)
        guard let session = bridge.registry.lookup(eim: eim) else {
            XCTFail("Session not found"); return
        }
        let initialActivity = session.lastActivity

        // Small wait.
        Thread.sleep(forTimeInterval: 0.01)

        // Send unsolicited inbound — this should refresh activity.
        _ = bridge.processUnsolicitedInbound(
            fromRemoteIP: serverB,
            fromRemotePort: 9999,
            toProxyIP: serverA,
            toProxyPort: dnsPort,
            payload: Data("refresh".utf8)
        )

        XCTAssertTrue(
            session.lastActivity > initialActivity,
            "Activity must be refreshed on unsolicited inbound"
        )
    }

    /// Verifies payload integrity through the unsolicited inbound path.
    func testUnsolicitedInbound_preservesPayload() throws {
        let bridge = TUN2UdpBridge()

        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt)

        let testPayload = Data("exact-unsolicited-payload".utf8)
        let result = bridge.processUnsolicitedInbound(
            fromRemoteIP: serverB,
            fromRemotePort: 9999,
            toProxyIP: serverA,
            toProxyPort: dnsPort,
            payload: testPayload
        )

        guard case .reply(let replyData) = result else {
            XCTFail("Expected .reply"); return
        }
        // The UDP payload starts at offset 28 in the IPv4 packet.
        let embeddedPayload = replyData.subdata(in: 28 ..< replyData.count)
        XCTAssertEqual(embeddedPayload, testPayload)
    }
}

// MARK: - Idle Purge Tests

final class IdlePurgeTests: XCTestCase {

    /// Verifies that idle sessions are evicted after the timeout.
    func testIdlePurge_removesStaleSessions() throws {
        let bridge = TUN2UdpBridge()
        bridge.idleTimeout = 0.001  // 1ms for fast test

        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt)
        XCTAssertEqual(bridge.registry.count, 1)

        // Wait longer than the idle timeout.
        Thread.sleep(forTimeInterval: 0.05)

        let purged = bridge.purgeIdle()
        XCTAssertGreaterThanOrEqual(purged, 1)
        XCTAssertEqual(bridge.registry.count, 0)
    }

    /// Verifies that active sessions survive the purge.
    func testIdlePurge_doesNotRemoveActive() throws {
        let bridge = TUN2UdpBridge()
        bridge.idleTimeout = 0.2  // 200ms

        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data([0x01])
        )
        _ = try bridge.processInbound(pkt)
        XCTAssertEqual(bridge.registry.count, 1)

        // Send another packet immediately — this refreshes activity.
        let pkt2 = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverB,
            srcPort: clientPort, dstPort: httpPort,
            payload: Data([0x02])
        )
        _ = try bridge.processInbound(pkt2)

        // Purge with a timeout that should NOT catch our active session.
        let purged = bridge.purgeIdle()
        // The session was just refreshed — it should survive.
        // But the cutoff uses `Date().addingTimeInterval(-idleTimeout)`,
        // which is 200ms ago. Our packets were sent <200ms ago, so
        // the session should survive.
        XCTAssertEqual(purged, 0)
        XCTAssertEqual(bridge.registry.count, 1)
    }
}

// MARK: - Registry Statistics Tests

final class FullConeRegistryTests: XCTestCase {

    /// Verifies that totalFlows tracks the cumulative flow count.
    func testRegistry_totalFlows() throws {
        let bridge = TUN2UdpBridge()

        for port in [53, 443, 8080] as [UInt16] {
            let pkt = buildMockIPPacket(
                srcIP: clientIP, dstIP: serverA,
                srcPort: clientPort, dstPort: port,
                payload: Data([0x01])
            )
            _ = try bridge.processInbound(pkt)
        }

        XCTAssertEqual(bridge.registry.count, 1)       // 1 EIM endpoint
        XCTAssertEqual(bridge.registry.totalFlows, 3)   // 3 flows
    }

    /// Verifies that drainAll clears everything.
    func testRegistry_removeAll() throws {
        let bridge = TUN2UdpBridge()

        _ = try bridge.processInbound(buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: 1000, dstPort: dnsPort,
            payload: Data([0x01])
        ))
        _ = try bridge.processInbound(buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: 1001, dstPort: dnsPort,
            payload: Data([0x02])
        ))

        XCTAssertEqual(bridge.registry.count, 2)
        bridge.registry.removeAll()
        XCTAssertEqual(bridge.registry.count, 0)
        XCTAssertEqual(bridge.registry.totalFlows, 0)
        XCTAssertTrue(bridge.registry.isEmpty)
    }
}

// MARK: - Reply Assembly Compatibility Tests

final class ReplyAssemblyCompatibilityTests: XCTestCase {

    /// Verifies that buildReply still works with the 4‑tuple session key.
    func testBuildReply_swapsCoordinates() throws {
        let bridge = TUN2UdpBridge()

        let pkt = buildMockIPPacket(
            srcIP: clientIP, dstIP: serverA,
            srcPort: clientPort, dstPort: dnsPort,
            payload: Data("query".utf8)
        )
        let result = try bridge.processInbound(pkt)

        guard case .forward(_, let session, _, _) = result else {
            XCTFail("Expected .forward"); return
        }

        let replyPayload = Data("response".utf8)
        let replyPkt = bridge.buildReply(for: session, payload: replyPayload)

        // Source of reply = original destination (serverA).
        let replySrc = [replyPkt[12], replyPkt[13], replyPkt[14], replyPkt[15]]
        XCTAssertEqual(replySrc, [serverA.octet0, serverA.octet1, serverA.octet2, serverA.octet3])
        // Destination of reply = original source (clientIP).
        let replyDst = [replyPkt[16], replyPkt[17], replyPkt[18], replyPkt[19]]
        XCTAssertEqual(replyDst, [clientIP.octet0, clientIP.octet1, clientIP.octet2, clientIP.octet3])
    }
}
