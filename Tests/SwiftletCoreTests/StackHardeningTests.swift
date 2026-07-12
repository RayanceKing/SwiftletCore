//===----------------------------------------------------------------------===//
//
//  StackHardeningTests.swift
//  SwiftletCore — Network Stack Hardening Unit Tests
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - FakeIPPoolManager

@Suite("FakeIPPoolManager")
struct FakeIPPoolManagerTests {

    @Test func allocateIPv4ReturnsFakeAddress() async {
        let pool = FakeIPPoolManager()
        let ip = await pool.allocateIPv4(for: "example.com")
        #expect(ip.hasPrefix("198.18."))
    }

    @Test func sameDomainReturnsSameIP() async {
        let pool = FakeIPPoolManager()
        let ip1 = await pool.allocateIPv4(for: "test.com")
        let ip2 = await pool.allocateIPv4(for: "test.com")
        #expect(ip1 == ip2)
    }

    @Test func differentDomainsGetDifferentIPs() async {
        let pool = FakeIPPoolManager()
        let ip1 = await pool.allocateIPv4(for: "a.com")
        let ip2 = await pool.allocateIPv4(for: "b.com")
        #expect(ip1 != ip2)
    }

    @Test func resolveIPv4ReturnsDomain() async {
        let pool = FakeIPPoolManager()
        let ip = await pool.allocateIPv4(for: "resolve.test")
        let domain = await pool.resolveIPv4(ip)
        #expect(domain == "resolve.test")
    }

    @Test func resolveIPv4ByUInt32() async {
        let pool = FakeIPPoolManager()
        let ipStr = await pool.allocateIPv4(for: "uint32.test")
        let parts = ipStr.split(separator: ".").compactMap { UInt8($0) }
        let ip = (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16)
               | (UInt32(parts[2]) << 8)  |  UInt32(parts[3])
        #expect(pool.resolveIPv4(ip) == "uint32.test")
    }

    @Test func resolveIPv4UnknownReturnsNil() async {
        let pool = FakeIPPoolManager()
        #expect(await pool.resolveIPv4("10.0.0.1") == nil)
    }

    @Test func releaseIPv4RemovesMapping() async {
        let pool = FakeIPPoolManager()
        let ip = await pool.allocateIPv4(for: "release.test")
        #expect(await pool.ipv4MappingCount == 1)
        await pool.releaseIPv4(ip)
        #expect(await pool.ipv4MappingCount == 0)
        #expect(await pool.resolveIPv4(ip) == nil)
    }

    @Test func releaseAllClearsEverything() async {
        let pool = FakeIPPoolManager()
        _ = await pool.allocateIPv4(for: "a.com")
        _ = await pool.allocateIPv4(for: "b.com")
        _ = await pool.allocateIPv6(for: "c.com")
        #expect(await pool.totalMappingCount == 3)
        await pool.releaseAll()
        #expect(await pool.totalMappingCount == 0)
    }

    @Test func allocateDualStack() async {
        let pool = FakeIPPoolManager()
        let (v4, v6) = await pool.allocateDualStack(for: "dual.test")
        #expect(v4.hasPrefix("198.18."))
        #expect(v6.hasPrefix("fc00::"))
    }

    @Test func isFakeIPv4Detection() {
        #expect(FakeIPPoolManager.isFakeIPv4((198 << 24) | (18 << 16) | 5))
        #expect(!FakeIPPoolManager.isFakeIPv4((8 << 24) | (8 << 16) | (8 << 8) | 8))
    }

    @Test func allMappedDomains() async {
        let pool = FakeIPPoolManager()
        _ = await pool.allocateIPv4(for: "alpha.com")
        _ = await pool.allocateIPv4(for: "beta.com")
        let domains = await pool.allMappedDomains
        #expect(domains.contains("alpha.com"))
    }
}

// MARK: - TCPSession Dynamic Window

@Suite("TCPSession — Window & Reassembly")
struct TCPSessionHardeningTests {

    @Test func defaultWindowIsMax() {
        let s = makeSession()
        #expect(s.advertisedWindow == 65535)
    }

    @Test func backpressureScalesWindow() {
        let s = makeSession()
        s.adjustWindow(bufferedBytes: 60000)
        #expect(s.advertisedWindow == 4096)
        s.adjustWindow(bufferedBytes: 0)
        #expect(s.advertisedWindow == 65535)
    }

    @Test func minWindowBoundary() {
        let s = makeSession()
        s.adjustWindow(bufferedBytes: 200_000)
        #expect(s.advertisedWindow == 512)
    }

    @Test func bufferOutOfOrder() {
        let s = makeSession()
        #expect(s.bufferOutOfOrder(seq: 9999, data: Data([0x01])))
        #expect(s.reassemblySlotsUsed == 1)
    }

    @Test func extractContiguousWhenNextMissing() {
        let s = makeSession()
        s.bufferOutOfOrder(seq: s.clientNextSeq + 50, data: Data([0xFF]))
        #expect(s.extractContiguous() == nil)
    }

    @Test func extractContiguousMerges() {
        let s = makeSession()
        let seq1 = s.clientNextSeq
        let d1 = Data("abc".utf8)
        s.bufferOutOfOrder(seq: seq1 + 3, data: Data("def".utf8))
        s.bufferOutOfOrder(seq: seq1, data: d1)
        #expect(s.extractContiguous() == Data("abcdef".utf8))
        #expect(s.reassemblySlotsUsed == 0)
    }

    @Test func reassemblyBufferFull() {
        let s = makeSession()
        for i in 0..<64 { s.bufferOutOfOrder(seq: UInt32(i * 10), data: Data([UInt8(i)])) }
        #expect(s.reassemblySlotsUsed == 64)
        #expect(!s.bufferOutOfOrder(seq: 99999, data: Data([0xFF])))
    }

    @Test func flushReassemblyBuffer() {
        let s = makeSession()
        s.bufferOutOfOrder(seq: 100, data: Data([0x01]))
        s.flushReassemblyBuffer()
        #expect(s.reassemblySlotsUsed == 0)
    }

    private func makeSession() -> TCPSession {
        TCPSession(key: TCPSessionKey(
            sourceIP: IPv4Address(10, 0, 0, 1), sourcePort: 1,
            destinationIP: IPv4Address(10, 0, 0, 2), destinationPort: 2
        ), clientISN: 0, serverISN: 1000)
    }
}

// MARK: - ICMP Unreachable

@Suite("TUN2SocksBridge — ICMP")
struct ICMPHardeningTests {

    @Test func buildsValidICMP() {
        var orig = [UInt8](repeating: 0, count: 40)
        orig[0] = 0x45; orig[2] = 0; orig[3] = 40; orig[9] = 6
        orig[12...15] = [10, 0, 0, 1]; orig[16...19] = [10, 0, 0, 2]

        let icmp = TUN2SocksBridge.buildICMPUnreachable(for: Data(orig), code: 1)
        #expect(icmp[0] == 0x45)
        #expect(icmp[9] == 1)   // ICMP protocol
        #expect(icmp[20] == 3)  // Type 3
        #expect(icmp[21] == 1)  // Code 1
    }

    @Test func icmpContainsOriginalPrefix() {
        var orig = [UInt8](repeating: 0, count: 40)
        orig[0] = 0x45; orig[2] = 0; orig[3] = 40; orig[9] = 6
        orig[12...15] = [192, 168, 1, 100]; orig[16...19] = [8, 8, 8, 8]

        let icmp = TUN2SocksBridge.buildICMPUnreachable(for: Data(orig), code: 1)
        #expect(icmp[28] == 0x45) // original IP header embedded
    }

    @Test func icmpChecksumNonZero() {
        var orig = [UInt8](repeating: 0, count: 40)
        orig[0] = 0x45; orig[2] = 0; orig[3] = 40; orig[9] = 6
        orig[12...15] = [10, 0, 0, 1]; orig[16...19] = [10, 0, 0, 2]

        let icmp = TUN2SocksBridge.buildICMPUnreachable(for: Data(orig), code: 3)
        let cksum = (UInt16(icmp[22]) << 8) | UInt16(icmp[23])
        #expect(cksum != 0)
    }
}

// MARK: - RoutingEngine Fake IP

@Suite("RoutingEngine — Fake IP")
struct RoutingEngineFakeIPTests {

    @Test func fakeIPReverseResolves() async {
        let engine = RoutingEngine()
        let pool = FakeIPPoolManager()
        await engine.add(rule: .domainSuffix("example.com", decision: .direct))
        await engine.setFakeIPManager(pool)

        let ipStr = await pool.allocateIPv4(for: "example.com")
        let parts = ipStr.split(separator: ".").compactMap { UInt8($0) }
        let ip = (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16)
               | (UInt32(parts[2]) << 8)  |  UInt32(parts[3])

        let decision = await engine.route(domain: nil, ip: ip)
        #expect(decision == .direct)
    }

    @Test func fakeIPNoRuleFallsThrough() async {
        let engine = RoutingEngine()
        let pool = FakeIPPoolManager()
        await engine.setFakeIPManager(pool)

        let ipStr = await pool.allocateIPv4(for: "nomatch.com")
        let parts = ipStr.split(separator: ".").compactMap { UInt8($0) }
        let ip = (UInt32(parts[0]) << 24) | (UInt32(parts[1]) << 16)
               | (UInt32(parts[2]) << 8)  |  UInt32(parts[3])

        let decision = await engine.route(domain: nil, ip: ip)
        #expect(decision == .proxy)
    }
}

// MARK: - Zero-Window Squeeze & Resumption

@Suite("TCPSession — Zero-Window & Writability")
struct TCPSessionZeroWindowTests {

    private func makeSession() -> TCPSession {
        TCPSession(key: TCPSessionKey(
            sourceIP: IPv4Address(10, 0, 0, 1), sourcePort: 1,
            destinationIP: IPv4Address(10, 0, 0, 2), destinationPort: 2
        ), clientISN: 0, serverISN: 1000)
    }

    @Test func zeroWindowWhenChannelUnwritable() {
        let s = makeSession()
        s.channelWritabilityChanged(writable: false)
        #expect(s.advertisedWindow == 0)
    }

    @Test func windowStaysZeroWhenUnwritable() {
        let s = makeSession()
        s.channelWritabilityChanged(writable: false)
        s.adjustWindow(bufferedBytes: 0)
        #expect(s.advertisedWindow == 0)
    }

    @Test func resumptionHandshakeRestoresWindow() {
        let s = makeSession()
        s.channelWritabilityChanged(writable: false)
        #expect(s.advertisedWindow == 0)
        s.channelWritabilityChanged(writable: true)
        s.adjustWindow(bufferedBytes: 0)
        #expect(s.advertisedWindow == 65535)
    }

    @Test func gradualWindowRecovery() {
        let s = makeSession()
        // Extreme pressure.
        s.adjustWindow(bufferedBytes: 100_000)
        let squeezed = s.advertisedWindow
        #expect(squeezed == 1024)
        // Moderate recovery.
        s.adjustWindow(bufferedBytes: 30000)
        #expect(s.advertisedWindow == 8192)
        // Full recovery.
        s.adjustWindow(bufferedBytes: 100)
        #expect(s.advertisedWindow == 65535)
    }
}

// MARK: - Reassembly Timeout Eviction

@Suite("TCPSession — Reassembly Timeout Eviction")
struct TCPSessionTimeoutEvictionTests {

    private func makeSession() -> TCPSession {
        TCPSession(key: TCPSessionKey(
            sourceIP: IPv4Address(10, 0, 0, 1), sourcePort: 1,
            destinationIP: IPv4Address(10, 0, 0, 2), destinationPort: 2
        ), clientISN: 0, serverISN: 1000)
    }

    @Test func evictStaleRemovesOldData() {
        let s = makeSession()
        s.bufferOutOfOrder(seq: s.clientNextSeq, data: Data("old".utf8))
        #expect(s.reassemblySlotsUsed == 1)
        let evicted = s.evictStaleSegments(olderThan: -1.0)
        #expect(evicted.count == 1)
        #expect(s.reassemblySlotsUsed == 0)
    }

    @Test func evictStalePreservesFreshData() {
        let s = makeSession()
        s.bufferOutOfOrder(seq: s.clientNextSeq, data: Data("fresh".utf8))
        let evicted = s.evictStaleSegments(olderThan: 5.0)
        #expect(evicted.isEmpty)
        #expect(s.reassemblySlotsUsed == 1)
    }

    @Test func forceEvacuateAllDrainsEverything() {
        let s = makeSession()
        for i in 0..<5 {
            s.bufferOutOfOrder(seq: UInt32(i * 100), data: Data([UInt8(i)]))
        }
        let all = s.forceEvacuateAll()
        #expect(all.count == 5)
        #expect(s.reassemblySlotsUsed == 0)
    }

    @Test func oldestSegmentAgeIsReasonable() {
        let s = makeSession()
        s.bufferOutOfOrder(seq: s.clientNextSeq, data: Data([0x01]))
        #expect(s.oldestSegmentAge < 1.0)
    }

    @Test func firstMissingSeqTracksCorrectly() {
        let s = makeSession()
        let gapSeq = s.clientNextSeq + 50
        s.bufferOutOfOrder(seq: gapSeq, data: Data([0xFF]))
        #expect(s.firstMissingSeq == gapSeq)
        s.evictStaleSegments(olderThan: -1.0)
        #expect(s.firstMissingSeq == nil)
    }

    @Test func evictionAdvancesClientSeq() {
        let s = makeSession()
        let expectedSeq = s.clientNextSeq
        s.bufferOutOfOrder(seq: expectedSeq, data: Data("gap".utf8))
        let evicted = s.evictStaleSegments(olderThan: -1.0)
        #expect(evicted.count == 1)
        #expect(s.clientNextSeq == expectedSeq + UInt32(3))
    }

    @Test func concurrentSegmentEviction() {
        let s = makeSession()
        // Buffer 3 segments: one at nextSeq (gap filler), two ahead.
        s.bufferOutOfOrder(seq: s.clientNextSeq, data: Data("a".utf8))
        let seq2 = s.clientNextSeq + 10
        s.bufferOutOfOrder(seq: seq2, data: Data("b".utf8))
        s.bufferOutOfOrder(seq: seq2 + 10, data: Data("c".utf8))

        // Evict all (negative timeout).
        let evicted = s.evictStaleSegments(olderThan: -1.0)
        #expect(evicted.count == 3)
        #expect(s.reassemblySlotsUsed == 0)
    }
}

// MARK: - Registry-Level Eviction

@Suite("TCPSessionRegistry — Stalled Eviction")
struct TCPSessionRegistryEvictionTests {

    @Test func purgeStalledReassembly() {
        let reg = TCPSessionRegistry()
        let s1 = TCPSession(key: TCPSessionKey(
            sourceIP: IPv4Address(10, 0, 0, 1), sourcePort: 1,
            destinationIP: IPv4Address(10, 0, 0, 2), destinationPort: 2
        ), clientISN: 0, serverISN: 1000)
        reg.register(s1)

        // Insert stale data and evict immediately.
        s1.bufferOutOfOrder(seq: s1.clientNextSeq + 100, data: Data([0xFF]))
        let purged = reg.purgeStalledReassembly(olderThan: -1.0)
        #expect(purged == 1)
        #expect(s1.reassemblySlotsUsed == 0)
    }
}
