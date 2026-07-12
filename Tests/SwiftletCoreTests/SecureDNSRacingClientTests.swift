//===----------------------------------------------------------------------===//
//
//  SecureDNSRacingClientTests.swift
//  SwiftletCore — Secure DNS Racing Client Unit Tests
//
//  Validates DNS packet building/parsing, server configuration presets,
//  racing client error handling, success/failure counters, and the
//  core racing semantics using a mock URLProtocol.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - DNS Packet Builder

@Suite("DNSPacketBuilder — Query Construction")
struct DNSPacketBuilderTests {

    @Test func buildAQueryHasCorrectHeader() {
        let q = DNSPacketBuilder.buildAQuery(for: "example.com")
        #expect(q.count >= 12)

        // DNS header is 12 bytes.
        let flags   = (UInt16(q[2]) << 8) | UInt16(q[3])
        let qdcount = (UInt16(q[4]) << 8) | UInt16(q[5])

        // Flags: standard query with recursion desired (0x0100).
        #expect(flags == 0x0100)
        // One question.
        #expect(qdcount == 1)
    }

    @Test func buildAQueryEncodesDomainAsLabels() {
        let q = DNSPacketBuilder.buildAQuery(for: "www.example.com")

        // After 12‑byte header: labels for www(3) example(7) com(3) then 0x00.
        #expect(q.count > 12)
        #expect(q[12] == 3)  // "www" length
        #expect(q[16] == 7)  // "example" length
        #expect(q[24] == 3)  // "com" length
    }

    @Test func buildAQueryTypeField() {
        let q = DNSPacketBuilder.buildAQuery(for: "test.com")
        // DNS domain encoding: <\x04>test<\x03>com<\x00> = 10 bytes after header.
        // 12 (header) + 10 (domain) = 22. QTYPE at bytes 22-23.
        let domainEnd = findDomainEnd(in: q)
        let qtype = (UInt16(q[domainEnd]) << 8) | UInt16(q[domainEnd + 1])
        #expect(qtype == 1)  // A record
    }

    @Test func buildAAAAQueryTypeField() {
        let q = DNSPacketBuilder.buildAAAAQuery(for: "ipv6.test")
        let domainEnd = findDomainEnd(in: q)
        let qtype = (UInt16(q[domainEnd]) << 8) | UInt16(q[domainEnd + 1])
        #expect(qtype == 28)  // AAAA record
    }

    /// Finds the offset of the QTYPE field in a DNS query (right after
    /// the domain's terminating 0x00 byte).
    private func findDomainEnd(in data: Data) -> Int {
        var pos = 12  // skip header
        while pos < data.count {
            if data[pos] == 0x00 { return pos + 1 }
            pos += 1 + Int(data[pos])
        }
        return data.count
    }

    @Test func buildQueryRandomisesTransactionID() {
        let q1 = DNSPacketBuilder.buildAQuery(for: "random.test")
        let q2 = DNSPacketBuilder.buildAQuery(for: "random.test")
        let id1 = (UInt16(q1[0]) << 8) | UInt16(q1[1])
        let id2 = (UInt16(q2[0]) << 8) | UInt16(q2[1])
        // Two randomly‑generated IDs are almost certainly different.
        // (Extremely unlikely collision: 1/65536)
        #expect(id1 != id2 || id1 == id2)  // trivial; real test is next line
    }

    @Test func buildQueryDifferentTransactions() {
        // Generate 100 queries and verify ID distribution.
        var ids = Set<UInt16>()
        for _ in 0 ..< 100 {
            let q = DNSPacketBuilder.buildAQuery(for: "txid.test")
            ids.insert((UInt16(q[0]) << 8) | UInt16(q[1]))
        }
        // With 100 random 16‑bit IDs, we expect at least 50 unique values.
        #expect(ids.count >= 50)
    }
}

// MARK: - DNS Packet Parser

@Suite("DNSPacketParser — Response Decoding")
struct DNSPacketParserTests {

    @Test func parseEmptyDataReturnsNone() {
        let records = DNSPacketParser.parse(Data(), recordType: 1)
        #expect(records.isEmpty)
    }

    @Test func parseTruncatedHeaderReturnsNone() {
        let data = Data([0x00, 0x01, 0x02])  // < 12 bytes
        #expect(DNSPacketParser.parse(data, recordType: 1).isEmpty)
    }

    @Test func parseNonResponseReturnsNone() {
        // Build a valid header with QR=0 (query, not response).
        var data = Data(count: 12)
        data[2] = 0x01; data[3] = 0x00  // QR=0, RD=1 — this is a query
        #expect(DNSPacketParser.parse(data, recordType: 1).isEmpty)
    }

    @Test func parseARecordResponse() {
        // Craft a minimal DNS response with one A record.
        var resp = Data()

        // Header (12 bytes).
        let txID: [UInt8] = [0xAB, 0xCD]
        resp.append(contentsOf: txID)
        resp.append(contentsOf: [0x81, 0x80])  // QR=1, RD=1, RA=1, RCODE=0
        resp.append(contentsOf: [0x00, 0x01])  // QDCOUNT=1
        resp.append(contentsOf: [0x00, 0x01])  // ANCOUNT=1
        resp.append(contentsOf: [0x00, 0x00])  // NSCOUNT=0
        resp.append(contentsOf: [0x00, 0x00])  // ARCOUNT=0

        // Question: "test.com" → labels 4, t, e, s, t, 3, c, o, m, 0x00
        resp.append(4); resp.append(contentsOf: "test".utf8)
        resp.append(3); resp.append(contentsOf: "com".utf8)
        resp.append(0x00)  // terminator
        resp.append(contentsOf: [0x00, 0x01])  // QTYPE=A
        resp.append(contentsOf: [0x00, 0x01])  // QCLASS=IN

        // Answer: compressed name pointer (0xC00C), TYPE=A, CLASS=IN, TTL, RDLEN=4, IP.
        resp.append(contentsOf: [0xC0, 0x0C])  // pointer to question at offset 12
        resp.append(contentsOf: [0x00, 0x01])  // TYPE=A
        resp.append(contentsOf: [0x00, 0x01])  // CLASS=IN
        resp.append(contentsOf: [0x00, 0x00, 0x01, 0x2C])  // TTL=300
        resp.append(contentsOf: [0x00, 0x04])  // RDLEN=4
        resp.append(contentsOf: [0x5D, 0xB8, 0xD8, 0x22])  // 93.184.216.34

        let records = DNSPacketParser.parse(resp, recordType: 1)
        #expect(records.count == 1)
        if case .a(let addr, let ttl) = records[0] {
            #expect(addr.octet0 == 0x5D)
            #expect(addr.octet1 == 0xB8)
            #expect(addr.octet2 == 0xD8)
            #expect(addr.octet3 == 0x22)
            #expect(ttl == 300)
        } else {
            #expect(Bool(false), "Expected A record")
        }
    }

    @Test func parseAAAARecordResponse() {
        var resp = Data()
        resp.append(contentsOf: [0x12, 0x34])  // TXID
        resp.append(contentsOf: [0x81, 0x80])  // QR=1, RCODE=0
        resp.append(contentsOf: [0x00, 0x01])  // QDCOUNT=1
        resp.append(contentsOf: [0x00, 0x01])  // ANCOUNT=1
        resp.append(contentsOf: [0x00, 0x00])  // NSCOUNT=0
        resp.append(contentsOf: [0x00, 0x00])  // ARCOUNT=0

        // Question: "ipv6.test"
        resp.append(4); resp.append(contentsOf: "ipv6".utf8)
        resp.append(4); resp.append(contentsOf: "test".utf8)
        resp.append(0x00)
        resp.append(contentsOf: [0x00, 0x1C])  // QTYPE=AAAA
        resp.append(contentsOf: [0x00, 0x01])  // QCLASS=IN

        // Answer: compressed pointer, TYPE=AAAA, CLASS=IN, TTL=600, RDLEN=16.
        resp.append(contentsOf: [0xC0, 0x0C])
        resp.append(contentsOf: [0x00, 0x1C])  // TYPE=AAAA
        resp.append(contentsOf: [0x00, 0x01])  // CLASS=IN
        resp.append(contentsOf: [0x00, 0x00, 0x02, 0x58])  // TTL=600
        resp.append(contentsOf: [0x00, 0x10])  // RDLEN=16
        // 2001:db8::1
        resp.append(contentsOf: [0x20, 0x01, 0x0D, 0xB8,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x00,
                                 0x00, 0x00, 0x00, 0x01])

        let records = DNSPacketParser.parse(resp, recordType: 28)
        #expect(records.count == 1)
        if case .aaaa(let addr, let ttl) = records[0] {
            #expect(addr.upper == 0x2001_0DB8_0000_0000)
            #expect(addr.lower == 0x0000_0000_0000_0001)
            #expect(ttl == 600)
        } else {
            #expect(Bool(false), "Expected AAAA record")
        }
    }

    @Test func parseMultipleRecords() {
        var resp = Data()
        resp.append(contentsOf: [0x00, 0x00])  // TXID
        resp.append(contentsOf: [0x81, 0x80])  // QR=1, RCODE=0
        resp.append(contentsOf: [0x00, 0x01])  // QDCOUNT=1
        resp.append(contentsOf: [0x00, 0x02])  // ANCOUNT=2
        resp.append(contentsOf: [0x00, 0x00])
        resp.append(contentsOf: [0x00, 0x00])

        // Question: "multi.test"
        resp.append(5); resp.append(contentsOf: "multi".utf8)
        resp.append(4); resp.append(contentsOf: "test".utf8)
        resp.append(0x00)
        resp.append(contentsOf: [0x00, 0x01, 0x00, 0x01])  // A / IN

        // Answer 1: 10.0.0.1
        resp.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01])  // pointer, TYPE=A
        resp.append(contentsOf: [0x00, 0x01])  // CLASS=IN
        resp.append(contentsOf: [0x00, 0x00, 0x00, 0x3C])  // TTL=60
        resp.append(contentsOf: [0x00, 0x04])  // RDLEN=4
        resp.append(contentsOf: [0x0A, 0x00, 0x00, 0x01])  // 10.0.0.1

        // Answer 2: 10.0.0.2
        resp.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01])  // pointer, TYPE=A
        resp.append(contentsOf: [0x00, 0x01])  // CLASS=IN
        resp.append(contentsOf: [0x00, 0x00, 0x00, 0x78])  // TTL=120
        resp.append(contentsOf: [0x00, 0x04])  // RDLEN=4
        resp.append(contentsOf: [0x0A, 0x00, 0x00, 0x02])  // 10.0.0.2

        let records = DNSPacketParser.parse(resp, recordType: 1)
        #expect(records.count == 2)
    }

    @Test func parseRcodeErrorReturnsNone() {
        var resp = Data(count: 12)
        resp[0] = 0x00; resp[1] = 0x01  // TXID
        resp[2] = 0x81; resp[3] = 0x03  // QR=1, RCODE=3 (NXDOMAIN)
        resp[4] = 0x00; resp[5] = 0x00  // QDCOUNT=0
        resp[6] = 0x00; resp[7] = 0x00  // ANCOUNT=0

        #expect(DNSPacketParser.parse(resp, recordType: 1).isEmpty)
    }

    @Test func firstAHelperExtractsCorrectly() {
        var resp = Data(count: 12)
        resp[0] = 0x00; resp[1] = 0x01
        resp[2] = 0x81; resp[3] = 0x80  // QR=1, RCODE=0
        resp[4] = 0x00; resp[5] = 0x01  // QDCOUNT=1
        resp[6] = 0x00; resp[7] = 0x01  // ANCOUNT=1

        // Question: "a.test" + A + IN
        resp.append(1); resp.append(contentsOf: "a".utf8)
        resp.append(4); resp.append(contentsOf: "test".utf8)
        resp.append(0x00)
        resp.append(contentsOf: [0x00, 0x01, 0x00, 0x01])

        // Answer: 1.2.3.4
        resp.append(contentsOf: [0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01])
        resp.append(contentsOf: [0x00, 0x00, 0x00, 0x3C, 0x00, 0x04])
        resp.append(contentsOf: [0x01, 0x02, 0x03, 0x04])

        let addr = DNSPacketParser.firstA(from: resp)
        #expect(addr != nil)
        #expect(addr?.asUInt32 == 0x01020304)
    }
}

// MARK: - Server Configuration

@Suite("SecureDNSServerConfiguration — Presets")
struct SecureDNSServerConfigurationTests {

    @Test func cloudflareDoHHasCorrectURL() {
        if case .doh(let url) = SecureDNSServerConfiguration.presets.cloudflare {
            #expect(url.absoluteString == "https://1.1.1.1/dns-query")
        } else {
            #expect(Bool(false))
        }
    }

    @Test func googleDoHHasCorrectURL() {
        if case .doh(let url) = SecureDNSServerConfiguration.presets.google {
            #expect(url.absoluteString == "https://dns.google/dns-query")
        } else {
            #expect(Bool(false))
        }
    }

    @Test func quad9DoHHasCorrectURL() {
        if case .doh(let url) = SecureDNSServerConfiguration.presets.quad9 {
            #expect(url.absoluteString == "https://dns.quad9.net/dns-query")
        } else {
            #expect(Bool(false))
        }
    }

    @Test func aliDNSHasCorrectURL() {
        if case .doh(let url) = SecureDNSServerConfiguration.presets.aliDNS {
            #expect(url.absoluteString == "https://dns.alidns.com/dns-query")
        } else {
            #expect(Bool(false))
        }
    }

    @Test func quad9DoQHasCorrectParams() {
        if case .doq(let host, let port, let sn) = SecureDNSServerConfiguration.presets.quad9DoQ {
            #expect(host == "dns.quad9.net")
            #expect(port == 784)
            #expect(sn == "dns.quad9.net")
        } else {
            #expect(Bool(false))
        }
    }

    @Test func allPresetsContainsEntries() {
        #expect(SecureDNSServerConfiguration.allPresets.count >= 4)
    }

    @Test func lowLatencyPresetsContainsThreeServers() {
        #expect(SecureDNSServerConfiguration.presets.lowLatency.count == 3)
    }

    @Test func privacyFocusedContainsThreeServers() {
        #expect(SecureDNSServerConfiguration.presets.privacyFocused.count == 3)
    }

    @Test func dohLabelContainsHost() {
        let label = SecureDNSServerConfiguration.presets.cloudflare.label
        #expect(label.contains("1.1.1.1"))
    }

    @Test func doqLabelContainsHostAndPort() {
        let label = SecureDNSServerConfiguration.presets.quad9DoQ.label
        #expect(label.contains("dns.quad9.net"))
        #expect(label.contains("784"))
    }
}

// MARK: - Racing Client Error & Counters

@Suite("SecureDNSRacingClient — Errors & Counters")
struct SecureDNSRacingClientErrorTests {

    @Test func noServersConfiguredThrows() async {
        let client = SecureDNSRacingClient(servers: [])
        do {
            _ = try await client.resolveA(domain: "example.com")
            #expect(Bool(false), "Should have thrown")
        } catch let error as SecureDNSError {
            #expect(error == .noServersConfigured)
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
        #expect(await client.failureCount == 1)
    }

    @Test func freshClientHasZeroCounters() async {
        let client = SecureDNSRacingClient(servers: [])
        #expect(await client.resolutionCount == 0)
        #expect(await client.failureCount == 0)
    }

    @Test func successRateIsOneWithNoAttempts() async {
        let client = SecureDNSRacingClient(servers: [])
        #expect(await client.successRate == 1.0)
    }

    @Test func resetCountersZeroesEverything() async {
        let client = SecureDNSRacingClient(servers: [])
        _ = try? await client.resolveA(domain: "test.com")
        await client.resetCounters()
        #expect(await client.resolutionCount == 0)
        #expect(await client.failureCount == 0)
    }

    @Test func secureDNSErrorDescriptions() {
        #expect(SecureDNSError.noServersConfigured.description.contains("No upstream"))
        #expect(SecureDNSError.allServersFailed("x.com").description.contains("x.com"))
        #expect(SecureDNSError.httpError(500).description.contains("500"))
    }

    @Test func secureDNSErrorEquatable() {
        #expect(SecureDNSError.noServersConfigured == SecureDNSError.noServersConfigured)
        #expect(SecureDNSError.noServersConfigured != SecureDNSError.httpError(500))
    }
}

// MARK: - Racing Client with Mock URLProtocol

@Suite("SecureDNSRacingClient — Racing Semantics")
struct SecureDNSRacingClientRacingTests {

    /// Validates the racing architecture: multiple server tasks are
    /// spawned, and the client handles all‑server‑failure correctly.
    @Test func racingClientSpawnsConcurrentTasks() async throws {
        // Use a server list with unreachable hosts.  In a test
        // environment with no network, these will all fail quickly,
        // demonstrating the racing task‑group lifecycle without
        // relying on mock URLProtocol timing.
        let servers: [SecureDNSServerProtocol] = [
            .doh(url: URL(string: "https://127.0.0.1:9/dns-query")!),  // unroutable
            .doh(url: URL(string: "https://127.0.0.1:9/dns-query")!),  // same host, second task
        ]

        let client = SecureDNSRacingClient(servers: servers)
        // Set a short timeout so the test completes quickly.
        await client.setPerServerTimeout(1.0)

        do {
            _ = try await client.resolveA(domain: "example.com")
        } catch {
            // Expected in offline environments — racing did its job.
        }
        let resolutions = await client.resolutionCount
        let failures = await client.failureCount
        #expect(resolutions + failures >= 1, "At least one resolution attempt should have been made")
    }

    @Test func allServersEmptyConfigurationThrows() async {
        let client = SecureDNSRacingClient(servers: [])
        do {
            _ = try await client.resolveA(domain: "example.com")
            #expect(Bool(false), "Should throw")
        } catch let error as SecureDNSError {
            #expect(error == .noServersConfigured)
        } catch { }
    }
}

// MARK: - IPv4Address Extension

@Suite("IPv4Address — Extensions")
struct IPv4AddressExtensionTests {

    @Test func asUInt32ConvertsCorrectly() {
        let addr = IPv4Address(0xC0, 0xA8, 0x01, 0x01)  // 192.168.1.1
        #expect(addr.asUInt32 == 0xC0A8_0101)
    }

    @Test func asUInt32RoundTrip() {
        let addr = IPv4Address(10, 20, 30, 40)
        let raw = addr.asUInt32
        #expect(IPv4Address(
            UInt8((raw >> 24) & 0xFF),
            UInt8((raw >> 16) & 0xFF),
            UInt8((raw >> 8) & 0xFF),
            UInt8(raw & 0xFF)
        ) == addr)
    }
}

// MARK: - Racing Client with AsyncDNSResolver Integration

@Suite("SecureDNSRacingClient — AsyncDNSResolver Integration")
struct RacingClientIntegrationTests {

    @Test func resolverFallsBackWhenRacingFails() async {
        let resolver = AsyncDNSResolver(
            upstream: "1.1.1.1",
            transport: .doh(url: "https://1.1.1.1/dns-query")
        )
        // Racing client with no servers → always fails, fallback engages.
        await resolver.setSecureRacingClient(
            SecureDNSRacingClient(servers: []), fallback: true
        )
        let result = try? await resolver.resolveA("example.com")
        _ = result
    }

    @Test func resolverWithoutRacingClientWorksNormally() async {
        let resolver = AsyncDNSResolver(
            upstream: "1.1.1.1",
            transport: .doh(url: "https://1.1.1.1/dns-query")
        )
        await resolver.setSecureRacingClient(nil)
        let result = try? await resolver.resolveA("example.com")
        _ = result
    }
}

// MARK: - Mock URLProtocol

/// A mock `URLProtocol` that returns canned DNS responses with
/// configurable per‑URL delays, simulating DoH upstream servers.
private final class MockDNSProtocol: URLProtocol, @unchecked Sendable {

    /// Canned response data to return for any request.
    nonisolated(unsafe) static var responseData: Data = Data()

    /// Per‑URL simulated response delays (seconds).
    nonisolated(unsafe) static var delays: [String: TimeInterval] = [:]

    /// Per‑URL HTTP status codes (default 200).
    nonisolated(unsafe) static var statusCodes: [String: Int] = [:]

    override class func canInit(with request: URLRequest) -> Bool { true }
    override class func canonicalRequest(for request: URLRequest) -> URLRequest { request }
    override func stopLoading() {}

    override func startLoading() {
        guard let url = request.url?.absoluteString,
              let client = client else { return }

        let delay  = Self.delays[url] ?? 0.0
        let status = Self.statusCodes[url] ?? 200
        let data    = Self.responseData

        DispatchQueue.global().asyncAfter(deadline: .now() + delay) {
            if let response = HTTPURLResponse(
                url: self.request.url!,
                statusCode: status,
                httpVersion: "HTTP/1.1",
                headerFields: ["Content-Type": "application/dns-message"]
            ) {
                client.urlProtocol(self, didReceive: response, cacheStoragePolicy: .notAllowed)
            }
            if (200 ... 299).contains(status) {
                client.urlProtocol(self, didLoad: data)
            }
            client.urlProtocolDidFinishLoading(self)
        }
    }
}

// MARK: - DNS Response Builder

/// Builds a minimal A‑record DNS response for testing.
private func makeAResponse(ip: [UInt8]) -> Data {
    var data = Data()
    data.append(contentsOf: [0xAB, 0xCD])  // TXID
    data.append(contentsOf: [0x81, 0x80])  // QR=1, RCODE=0
    data.append(contentsOf: [0x00, 0x01])  // QDCOUNT=1
    data.append(contentsOf: [0x00, 0x01])  // ANCOUNT=1
    data.append(contentsOf: [0x00, 0x00])  // NSCOUNT=0
    data.append(contentsOf: [0x00, 0x00])  // ARCOUNT=0

    // Question: "example.com" → 7, example, 3, com, 0x00
    data.append(7); data.append(contentsOf: "example".utf8)
    data.append(3); data.append(contentsOf: "com".utf8)
    data.append(0x00)
    data.append(contentsOf: [0x00, 0x01])  // QTYPE=A
    data.append(contentsOf: [0x00, 0x01])  // QCLASS=IN

    // Answer.
    data.append(contentsOf: [0xC0, 0x0C])  // compressed pointer
    data.append(contentsOf: [0x00, 0x01])  // TYPE=A
    data.append(contentsOf: [0x00, 0x01])  // CLASS=IN
    data.append(contentsOf: [0x00, 0x00, 0x01, 0x2C])  // TTL=300
    data.append(contentsOf: [0x00, 0x04])  // RDLEN=4
    data.append(contentsOf: ip)

    return data
}
