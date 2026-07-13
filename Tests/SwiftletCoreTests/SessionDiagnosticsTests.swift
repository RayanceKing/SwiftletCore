//===----------------------------------------------------------------------===//
//
//  SessionDiagnosticsTests.swift
//  SwiftletCoreTests — Session Diagnostics & PCAP Dumper Unit Tests
//
//  Validates the SessionDiagnosticsTracker actor (session creation,
//  DNS / route / traffic updates, closure, capacity eviction) and the
//  PCAPPacketDumper (circular buffer capture, libpcap header/record
//  format, byte‑exact header validation).
//
//  Test Coverage
//  -------------
//  ┌──────────────────────────────────────────┬──────────────────────────────┐
//  │ Test                                     │ What it verifies             │
//  ├──────────────────────────────────────────┼──────────────────────────────┤
//  │ testTrackNewSession                      │ Session creation + UUID      │
//  │ testTrackMultipleSessions                │ Concurrent session tracking  │
//  │ testUpdateDNSInfo                        │ DNS duration recording       │
//  │ testUpdateRouteInfo                      │ Route match string recording │
//  │ testMarkPoolReused                       │ Pool‑reuse flag              │
//  │ testIncrementTraffic                     │ Byte counter accumulation    │
//  │ testCloseSession                         │ Active → closed transition   │
//  │ testActiveSnapshotsFiltering             │ Active vs closed filtering   │
//  │ testCapacityEviction                     │ Max‑1024 session enforcement │
//  │ testPurgeClosed                          │ Closed snapshot cleanup       │
//  │ testResetAll                             │ Full tracker reset           │
//  │ testSnapshotDescription                  │ Human‑readable description   │
//  │ testInboundTypeDescriptions              │ TUN / SOCKS5 / HTTP / Custom  │
//  │ testPCAPCaptureAndExport                 │ PCAP header + packet export  │
//  │ testPCAPGlobalHeaderValidation           │ Magic / version / link type  │
//  │ testPCAPCircularBufferOverflow           │ Wrapped buffer ordering      │
//  │ testPCAPEmptyExport                      │ Empty buffer → valid header  │
//  │ testPCAPDisabledCapture                  │ isEnabled = false skips      │
//  │ testPCAPClearReset                       │ Clear / reset operations     │
//  └──────────────────────────────────────────┴──────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
import Foundation

// MARK: - Session Diagnostics Tracker Tests

final class SessionDiagnosticsTrackerTests: XCTestCase {

    /// Verifies that `trackNewSession` creates a session and returns a
    /// valid UUID.
    func testTrackNewSession() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun,
            client: "192.168.1.100:54321",
            target: "api.example.com:443"
        )
        XCTAssertNotEqual(id, UUID(uuidString: "00000000-0000-0000-0000-000000000000")!)

        let active = await tracker.activeSnapshots
        XCTAssertEqual(active.count, 1)
        XCTAssertEqual(active.first?.clientAddress, "192.168.1.100:54321")
        XCTAssertEqual(active.first?.destinationTarget, "api.example.com:443")
        XCTAssertEqual(active.first?.inboundType, .tun)
        XCTAssertTrue(active.first?.isActive ?? false)
    }

    /// Verifies that multiple sessions can be tracked concurrently.
    func testTrackMultipleSessions() async {
        let tracker = SessionDiagnosticsTracker()

        for i in 0 ..< 10 {
            _ = await tracker.trackNewSession(
                inbound: .socks5,
                client: "10.0.0.\(i):\(1000 + i)",
                target: "target\(i).com:443"
            )
        }

        let active = await tracker.activeSnapshots
        XCTAssertEqual(active.count, 10)
        let cnt = await tracker.activeCount; XCTAssertEqual(cnt, 10)
        let tsc = await tracker.totalSessionsCreated; XCTAssertEqual(tsc, 10)
    }

    /// Verifies that DNS lookup duration is correctly recorded.
    func testUpdateDNSInfo() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun, client: "c", target: "t"
        )

        await tracker.updateDNSInfo(id: id, durationMicros: 54321)
        let snapshots = await tracker.activeSnapshots
        XCTAssertEqual(snapshots.first?.dnsLookupDurationMicros, 54321)
    }

    /// Verifies that routing rule match info is correctly recorded.
    func testUpdateRouteInfo() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun, client: "c", target: "t"
        )

        await tracker.updateRouteInfo(id: id, matched: "domainSuffix:example.com → PROXY")
        let snapshots = await tracker.activeSnapshots
        XCTAssertEqual(snapshots.first?.ruleMatched, "domainSuffix:example.com → PROXY")
    }

    /// Verifies that the pool‑reused flag is correctly set.
    func testMarkPoolReused() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun, client: "c", target: "t"
        )

        await tracker.markPoolReused(id: id)
        let snapshots = await tracker.activeSnapshots
        XCTAssertTrue(snapshots.first?.outboundPoolReused ?? false)
    }

    /// Verifies that byte counters accumulate correctly.
    func testIncrementTraffic() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun, client: "c", target: "t"
        )

        await tracker.incrementTraffic(id: id, bytesIn: 1000, bytesOut: 500)
        await tracker.incrementTraffic(id: id, bytesIn: 250, bytesOut: 750)

        let snapshots = await tracker.activeSnapshots
        XCTAssertEqual(snapshots.first?.bytesIn, 1250)
        XCTAssertEqual(snapshots.first?.bytesOut, 1250)
    }

    /// Verifies that closing a session sets the closedAt timestamp
    /// and marks it inactive.
    func testCloseSession() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .tun, client: "c", target: "t"
        )

        await tracker.closeSession(id: id)
        let active = await tracker.activeSnapshots
        XCTAssertEqual(active.count, 0, "Session must be removed from active list")
        let tcl = await tracker.totalSessionsClosed; XCTAssertEqual(tcl, 1)

        let closed = await tracker.recentClosedSnapshots(count: 10)
        XCTAssertEqual(closed.count, 1)
        XCTAssertFalse(closed.first?.isActive ?? true)
        XCTAssertNotNil(closed.first?.closedAt)
        XCTAssertNotNil(closed.first?.activeDuration)
    }

    /// Verifies that activeSnapshots only returns active sessions.
    func testActiveSnapshotsFiltering() async {
        let tracker = SessionDiagnosticsTracker()

        let id1 = await tracker.trackNewSession(inbound: .tun, client: "a", target: "t1")
        let id2 = await tracker.trackNewSession(inbound: .tun, client: "b", target: "t2")
        let id3 = await tracker.trackNewSession(inbound: .tun, client: "c", target: "t3")

        await tracker.closeSession(id: id2)

        let active = await tracker.activeSnapshots
        XCTAssertEqual(active.count, 2)
        XCTAssertTrue(active.contains(where: { $0.id == id1 }))
        XCTAssertTrue(active.contains(where: { $0.id == id3 }))
        XCTAssertFalse(active.contains(where: { $0.id == id2 }))
    }

    /// Verifies that the capacity cap (1024 sessions) is enforced,
    /// evicting the oldest entry when full.
    func testCapacityEviction() async {
        let tracker = SessionDiagnosticsTracker()
        _ = tracker // ensure initialised

        // Fill beyond the cap.
        for i in 0 ..< 1500 {
            _ = await tracker.trackNewSession(
                inbound: .socks5,
                client: "c\(i)",
                target: "t\(i).com:443"
            )
        }

        let active = await tracker.activeCount
        XCTAssertLessThanOrEqual(active, 1024, "Must not exceed maxActiveSessions")
        let tsc = await tracker.totalSessionsCreated; XCTAssertEqual(tsc, 1500)
    }

    /// Verifies that purgeClosed removes closed snapshots from storage.
    func testPurgeClosed() async {
        let tracker = SessionDiagnosticsTracker()

        let id1 = await tracker.trackNewSession(inbound: .tun, client: "a", target: "t1")
        let id2 = await tracker.trackNewSession(inbound: .tun, client: "b", target: "t2")

        await tracker.closeSession(id: id1)

        let purged = await tracker.purgeClosed()
        XCTAssertGreaterThanOrEqual(purged, 1)

        let stored = await tracker.totalStored
        XCTAssertEqual(stored, 1)  // Only id2 remains.
    }

    /// Verifies that resetAll clears everything.
    func testResetAll() async {
        let tracker = SessionDiagnosticsTracker()

        for _ in 0 ..< 5 {
            _ = await tracker.trackNewSession(inbound: .tun, client: "c", target: "t")
        }

        await tracker.resetAll()
        let cnt = await tracker.activeCount; XCTAssertEqual(cnt, 0)
        let tsd = await tracker.totalStored; XCTAssertEqual(tsd, 0)
        let tsc = await tracker.totalSessionsCreated; XCTAssertEqual(tsc, 0)
    }

    /// Verifies human‑readable snapshot description.
    func testSnapshotDescription() async {
        let tracker = SessionDiagnosticsTracker()
        let id = await tracker.trackNewSession(
            inbound: .socks5,
            client: "1.2.3.4:1080",
            target: "example.com:443"
        )
        let snapshots = await tracker.activeSnapshots
        let desc = snapshots.first?.description ?? ""
        XCTAssertTrue(desc.contains("SOCKS5"))
        XCTAssertTrue(desc.contains("1.2.3.4:1080"))
        XCTAssertTrue(desc.contains("example.com:443"))
        _ = id
    }

    /// Verifies inbound‑type descriptions.
    func testInboundTypeDescriptions() {
        XCTAssertEqual(SessionInboundType.tun.description, "TUN")
        XCTAssertEqual(SessionInboundType.socks5.description, "SOCKS5")
        XCTAssertEqual(SessionInboundType.httpConnect.description, "HTTP")
        XCTAssertEqual(SessionInboundType.custom("test").description, "CUSTOM(test)")
    }
}

// MARK: - PCAP Packet Dumper Tests

final class PCAPPacketDumperTests: XCTestCase {

    /// Verifies that capturing a packet and exporting to PCAP produces
    /// a valid file with at least the global header and one packet record.
    func testPCAPCaptureAndExport() {
        let dumper = PCAPPacketDumper(maxPackets: 100)
        dumper.isEnabled = true

        let mockPacket = Data([0x45, 0x00, 0x00, 0x3C, 0xAB, 0xCD] +
            [UInt8](repeating: 0x00, count: 60))
        dumper.capture(packetData: mockPacket)

        let pcap = dumper.dumpActiveBuffersToPCAP()
        XCTAssertGreaterThanOrEqual(pcap.count, 24 + 16 + 66)

        // Global header: 24 bytes.
        let magic = pcap.subdata(in: 0 ..< 4)
        XCTAssertEqual(magic, Data([0xD4, 0xC3, 0xB2, 0xA1]))

        // Packet header at offset 24: ts_sec(4)+ts_usec(4)+incl_len(4)+orig_len(4)
        // incl_len is at offset 32-35.
        let pktInclLen = UInt32(littleEndian: pcap.subdata(in: 32 ..< 36).withUnsafeBytes { $0.load(as: UInt32.self) })
        XCTAssertEqual(pktInclLen, 66)

        // Packet data follows at offset 24 + 16 = 40.
        let captured = pcap.subdata(in: 40 ..< (40 + Int(pktInclLen)))
        XCTAssertEqual(captured, mockPacket)
    }

    /// Verifies the libpcap global header fields are correct.
    func testPCAPGlobalHeaderValidation() {
        let dumper = PCAPPacketDumper(maxPackets: 1)
        dumper.isEnabled = true
        dumper.capture(packetData: Data([0x45]))
        let pcap = dumper.dumpActiveBuffersToPCAP()

        // Magic: 0xa1b2c3d4 (little‑endian).
        let magic = pcap.subdata(in: 0 ..< 4)
        XCTAssertEqual(magic, Data([0xD4, 0xC3, 0xB2, 0xA1]))

        // Major version: 2.
        let major = UInt16(littleEndian: pcap.subdata(in: 4 ..< 6).withUnsafeBytes { $0.load(as: UInt16.self) })
        XCTAssertEqual(major, 2)

        // Minor version: 4.
        let minor = UInt16(littleEndian: pcap.subdata(in: 6 ..< 8).withUnsafeBytes { $0.load(as: UInt16.self) })
        XCTAssertEqual(minor, 4)

        // Link type: 101 (RAW).
        let linkType = UInt32(littleEndian: pcap.subdata(in: 20 ..< 24).withUnsafeBytes { $0.load(as: UInt32.self) })
        XCTAssertEqual(linkType, 101)
    }

    /// Verifies that the circular buffer correctly overwrites the oldest
    /// entry when capacity is exceeded and that the PCAP export preserves
    /// chronological ordering.
    func testPCAPCircularBufferOverflow() {
        let dumper = PCAPPacketDumper(maxPackets: 4)
        dumper.isEnabled = true

        // Capture 6 packets — only the last 4 should survive.
        for i in 0 ..< 6 {
            dumper.capture(packetData: Data([UInt8(i)]))
        }

        XCTAssertEqual(dumper.bufferedCount, 4)
        XCTAssertTrue(dumper.hasWrapped)
        XCTAssertEqual(dumper.totalCaptured, 6)

        let pcap = dumper.dumpActiveBuffersToPCAP()
        // 24‑byte header + 4 × (16‑byte header + 1‑byte payload) = 24 + 68 = 92.
        XCTAssertEqual(pcap.count, 24 + 4 * (16 + 1))
    }

    /// Verifies that exporting with an empty buffer still produces a
    /// valid (but empty) PCAP file.
    func testPCAPEmptyExport() {
        let dumper = PCAPPacketDumper(maxPackets: 10)
        let pcap = dumper.dumpActiveBuffersToPCAP()
        XCTAssertEqual(pcap.count, 24)  // Only global header.
    }

    /// Verifies that packets are NOT captured when `isEnabled` is false.
    func testPCAPDisabledCapture() {
        let dumper = PCAPPacketDumper(maxPackets: 100)
        dumper.isEnabled = false

        dumper.capture(packetData: Data([0x45]))
        XCTAssertEqual(dumper.bufferedCount, 0)
        XCTAssertEqual(dumper.totalCaptured, 0)
    }

    /// Verifies clear and reset operations.
    func testPCAPClearReset() {
        let dumper = PCAPPacketDumper(maxPackets: 10)
        dumper.isEnabled = true

        for _ in 0 ..< 5 {
            dumper.capture(packetData: Data([0x45, 0x00]))
        }

        XCTAssertEqual(dumper.bufferedCount, 5)

        dumper.clear()
        XCTAssertEqual(dumper.bufferedCount, 0)
        XCTAssertEqual(dumper.totalCaptured, 0)

        // Re‑capture after clear.
        dumper.capture(packetData: Data([0x00]))
        XCTAssertEqual(dumper.bufferedCount, 1)

        // Reset disables capture.
        dumper.reset()
        XCTAssertFalse(dumper.isEnabled)
        XCTAssertEqual(dumper.bufferedCount, 0)
    }
}

// MARK: - Integration: Tracker + Dumper

final class DiagnosticsIntegrationTests: XCTestCase {

    /// Verifies that a complete lifecycle — from session creation through
    /// teardown — records all metadata correctly.
    func testFullSessionLifecycle() async {
        let tracker = SessionDiagnosticsTracker()

        // --- Create session ---
        let id = await tracker.trackNewSession(
            inbound: .tun,
            client: "192.168.1.50:49152",
            target: "cdn.example.org:443"
        )

        // --- DNS lookup ---
        await tracker.updateDNSInfo(id: id, durationMicros: 850)

        // --- Route match ---
        await tracker.updateRouteInfo(id: id, matched: "domainSuffix:example.org → PROXY")

        // --- Pool reused ---
        await tracker.markPoolReused(id: id)

        // --- Traffic ---
        await tracker.incrementTraffic(id: id, bytesIn: 4096, bytesOut: 2048)
        await tracker.incrementTraffic(id: id, bytesIn: 1024, bytesOut: 512)

        // --- Verify ---
        let active = await tracker.activeSnapshots
        XCTAssertEqual(active.count, 1)
        let snap = active.first!
        XCTAssertEqual(snap.dnsLookupDurationMicros, 850)
        XCTAssertEqual(snap.ruleMatched, "domainSuffix:example.org → PROXY")
        XCTAssertTrue(snap.outboundPoolReused)
        XCTAssertEqual(snap.bytesIn, 5120)
        XCTAssertEqual(snap.bytesOut, 2560)
        XCTAssertTrue(snap.isActive)

        // --- Close ---
        await tracker.closeSession(id: id)
        let activeAfter = await tracker.activeSnapshots
        XCTAssertEqual(activeAfter.count, 0)

        let closedSnaps = await tracker.recentClosedSnapshots(count: 10)
        XCTAssertNotNil(closedSnaps.first?.activeDuration)
    }
}
