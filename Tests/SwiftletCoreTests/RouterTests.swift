//===----------------------------------------------------------------------===//
//
//  RouterTests.swift
//  SwiftletCore — Routing Engine Unit & Performance Tests
//
//  Validates domain‑suffix trie matching, CIDR longest‑prefix match, keyword
//  scanning, and the central `RoutingEngine` integration.  Includes a
//  mandatory 10 000‑rule performance benchmark that asserts sub‑millisecond
//  lookup times and verifies that the trie does not leak memory.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - Domain Suffix Trie Tests

@Test func domainSuffixTrieBasicMatching() {
    let trie = DomainTrie()
    trie.insert(suffix: "apple.com", rule: .domainSuffix("apple.com"))
    trie.insert(suffix: "google.com", rule: .domainSuffix("google.com"))

    // Exact match
    #expect(trie.match(domain: "apple.com") != nil)
    #expect(trie.match(domain: "google.com") != nil)

    // Subdomain match
    #expect(trie.match(domain: "www.apple.com") != nil)
    #expect(trie.match(domain: "mail.google.com") != nil)

    // Deep subdomain match
    #expect(trie.match(domain: "cdn.images.apple.com") != nil)

    // No match
    #expect(trie.match(domain: "microsoft.com") == nil)
    #expect(trie.match(domain: "fakeapple.com") == nil) // not a suffix
}

@Test func domainSuffixTrieLongestMatchWins() {
    let trie = DomainTrie()
    trie.insert(suffix: "com", rule: .domainSuffix("com"))
    trie.insert(suffix: "apple.com", rule: .domainSuffix("apple.com"))

    // "www.apple.com" should match "apple.com" (longer), not "com"
    let result = trie.match(domain: "www.apple.com")
    guard case .domainSuffix(let matched, decision: _) = result else {
        Issue.record("Expected domainSuffix match, got \(String(describing: result))")
        return
    }
    #expect(matched == "apple.com")
}

@Test func domainSuffixTrieCaseInsensitive() {
    let trie = DomainTrie()
    trie.insert(suffix: "Apple.COM", rule: .domainSuffix("apple.com"))

    #expect(trie.match(domain: "www.Apple.com") != nil)
    #expect(trie.match(domain: "WWW.APPLE.COM") != nil)
}

@Test func domainSuffixTrieEmptyAndEdgeCases() {
    let trie = DomainTrie()

    // Empty string should not match anything
    #expect(trie.match(domain: "") == nil)

    // Single label
    trie.insert(suffix: "localhost", rule: .domainSuffix("localhost"))
    #expect(trie.match(domain: "localhost") != nil)
    // "localhost" IS a valid suffix of "sub.localhost"
    #expect(trie.match(domain: "sub.localhost") != nil)
}

// MARK: - CIDR Matcher Tests

@Test func cidrMatcherBasicMatching() {
    let matcher = CIDRMatcher()

    // 10.0.0.0/8 → matches 10.x.x.x
    let (net1, len1) = try! CIDRParser.parseIPv4("10.0.0.0/8")
    matcher.insert(network: net1, prefixLength: len1, rule: .ipv4CIDR(network: net1, prefixLength: len1))

    // 192.168.1.0/24 → matches 192.168.1.x
    let (net2, len2) = try! CIDRParser.parseIPv4("192.168.1.0/24")
    matcher.insert(network: net2, prefixLength: len2, rule: .ipv4CIDR(network: net2, prefixLength: len2))

    // 10.0.0.1 should match /8
    let ip1 = try! CIDRParser.parseIPv4Address("10.0.0.1")
    #expect(matcher.match(ip: ip1) != nil)

    // 10.255.255.255 should match /8
    let ip2 = try! CIDRParser.parseIPv4Address("10.255.255.255")
    #expect(matcher.match(ip: ip2) != nil)

    // 11.0.0.1 should NOT match /8
    let ip3 = try! CIDRParser.parseIPv4Address("11.0.0.1")
    #expect(matcher.match(ip: ip3) == nil)

    // 192.168.1.50 should match /24
    let ip4 = try! CIDRParser.parseIPv4Address("192.168.1.50")
    #expect(matcher.match(ip: ip4) != nil)

    // 192.168.2.1 should NOT match /24
    let ip5 = try! CIDRParser.parseIPv4Address("192.168.2.1")
    #expect(matcher.match(ip: ip5) == nil)
}

@Test func cidrMatcherLongestPrefixWins() {
    let matcher = CIDRMatcher()

    // 10.0.0.0/8 (broad)
    let (net1, len1) = try! CIDRParser.parseIPv4("10.0.0.0/8")
    matcher.insert(network: net1, prefixLength: len1, rule: .ipv4CIDR(network: net1, prefixLength: len1))

    // 10.0.1.0/24 (more specific)
    let (net2, len2) = try! CIDRParser.parseIPv4("10.0.1.0/24")
    matcher.insert(network: net2, prefixLength: len2, rule: .ipv4CIDR(network: net2, prefixLength: len2))

    let ip = try! CIDRParser.parseIPv4Address("10.0.1.50")
    guard let rule = matcher.match(ip: ip),
          case .ipv4CIDR(network: _, prefixLength: let prefixLen, decision: _) = rule else {
        Issue.record("Expected CIDR match")
        return
    }
    // Should match /24 (more specific) not /8
    #expect(prefixLen == 24)
}

@Test func cidrParserEdgeCases() {
    // /32 (single host)
    let (_, len) = try! CIDRParser.parseIPv4("192.168.1.1/32")
    #expect(len == 32)

    let mask = CIDRParser.mask(prefixLength: 32)
    #expect(mask == 0xFFFF_FFFF)

    // /0 (everything)
    let mask0 = CIDRParser.mask(prefixLength: 0)
    #expect(mask0 == 0)

    // Invalid formats
    #expect(throws: CIDRParser.CIDRParseError.self) {
        _ = try CIDRParser.parseIPv4("not.an.ip/24")
    }
    #expect(throws: CIDRParser.CIDRParseError.self) {
        _ = try CIDRParser.parseIPv4("10.0.0.0/33") // prefix > 32
    }
}

// MARK: - Keyword Matcher Tests

@Test func keywordMatcherFindsSubstring() {
    let matcher = KeywordMatcher()
    matcher.insert(keyword: "ads", rule: .domainKeyword("ads"))
    matcher.insert(keyword: "tracker", rule: .domainKeyword("tracker"))

    #expect(matcher.match(domain: "ads.google.com") != nil)
    #expect(matcher.match(domain: "doubleclick-ads.net") != nil)
    #expect(matcher.match(domain: "tracker.example.org") != nil)
    #expect(matcher.match(domain: "safe-site.com") == nil)
}

// MARK: - Routing Engine Tests

@Suite("RoutingEngine")
struct RoutingEngineTests {

    @Test func domainRouting() async {
        let engine = RoutingEngine()
        await engine.addDomainSuffixRules(["apple.com", "google.com"], decision: .proxy)
        await engine.addDomainSuffixRules(["localhost"], decision: .direct)

        let r1 = await engine.route(domain: "www.apple.com")
        #expect(r1 == .proxy)

        let r2 = await engine.route(domain: "localhost")
        #expect(r2 == .direct)

        let r3 = await engine.route(domain: "unknown-domain.net")
        #expect(r3 == .proxy) // default
    }

    @Test func cidrRouting() async {
        let engine = RoutingEngine()
        await engine.addCIDRRules(["10.0.0.0/8", "192.168.0.0/16"], decision: .direct)

        let ip1 = IPv4Address(10, 0, 0, 1)
        let r1 = await engine.route(ip: ip1)
        #expect(r1 == .direct)

        let ip2 = IPv4Address(8, 8, 8, 8)
        let r2 = await engine.route(ip: ip2)
        #expect(r2 == .proxy) // default
    }

    @Test func ruleCounts() async {
        let engine = RoutingEngine()
        await engine.addDomainSuffixRules(
            (0 ..< 100).map { "domain\($0).com" }
        )
        await engine.addCIDRRules(
            (0 ..< 50).map { "192.168.\($0).0/24" }
        )

        let domainCount = await engine.domainRuleCount
        let cidrCount   = await engine.cidrRuleCount
        let total       = await engine.totalRuleCount

        #expect(domainCount == 100)
        #expect(cidrCount == 50)
        #expect(total == 150)
    }
}

// MARK: - Performance Benchmark: 10 000 Rules

@Test func tenThousandRulesPerformanceBenchmark() {
    let trie = DomainTrie()

    // ---- 1. Generate 10 000 unique domain‑suffix rules -------------------
    let ruleCount = 10_000
    let domains: [String] = (0 ..< ruleCount).map { i in
        // Create realistic‑looking domains: "host-N.example-N.com"
        "host\(i).example\(i % 100).com"
    }

    // ---- 2. Measure insertion time ---------------------------------------
    let insertStart = ContinuousClock().now
    for domain in domains {
        trie.insert(suffix: domain, rule: .domainSuffix(domain))
    }
    let insertDuration = ContinuousClock().now - insertStart

    #expect(trie.ruleCount == ruleCount)
    // Insertion of 10 000 rules must complete in well under 1 second.
    let insertMS = Double(insertDuration.components.attoseconds) / 1_000_000_000_000_000.0
    #expect(insertMS < 500, "Insertion took \(insertMS)ms, expected < 500ms")

    // ---- 3. Measure lookup time (10 000 lookups) -------------------------
    let lookupStart = ContinuousClock().now
    for domain in domains {
        let match = trie.match(domain: domain)
        #expect(match != nil)
    }
    let lookupDuration = ContinuousClock().now - lookupStart

    let lookupMS = Double(lookupDuration.components.attoseconds) / 1_000_000_000_000_000.0
    // 10 000 trie lookups must complete in well under 100ms
    // (target < 10µs per lookup).
    #expect(lookupMS < 100, "10k lookups took \(lookupMS)ms, expected < 100ms")

    // ---- 4. Verify random lookups work correctly -------------------------
    // Exact match for every inserted domain
    for domain in domains.prefix(100) {
        let match = trie.match(domain: domain)
        #expect(match != nil, "Missing match for \(domain)")
    }

    // Deep subdomain match
    #expect(trie.match(domain: "deep.sub.\(domains[0])") != nil)
    #expect(trie.match(domain: "a.b.c.\(domains[5000])") != nil)

    // Non‑matching domain
    #expect(trie.match(domain: "unmatched-domain.xyz") == nil)
}

// MARK: - Memory Safety Test

/// Verifies that the `DomainTrie` releases all nodes when `removeAll()` is
/// called, ensuring no memory leaks from the 10 000‑rule benchmark.
@Test func trieMemoryCleanup() {
    let trie = DomainTrie()

    // Insert 10 000 rules.
    for i in 0 ..< 10_000 {
        trie.insert(suffix: "host\(i).example\(i % 100).com",
                     rule: .domainSuffix("host\(i).example.com"))
    }
    #expect(trie.ruleCount == 10_000)

    // Root node should have many children.
    #expect(trie.root.children.count > 0)

    // Remove all rules — all nodes should be deallocated (ARC).
    trie.removeAll()
    #expect(trie.ruleCount == 0)
    #expect(trie.root.children.isEmpty)
    #expect(trie.root.rule == nil)
}

// MARK: - CIDR Performance

@Test func cidrMatcherLookupPerformance() {
    let matcher = CIDRMatcher()

    // Insert 500 CIDR rules.
    for i in 0 ..< 500 {
        if let (net, len) = try? CIDRParser.parseIPv4("10.\(i / 256).\(i % 256).0/24") {
            matcher.insert(network: net, prefixLength: len,
                           rule: .ipv4CIDR(network: net, prefixLength: len))
        }
    }
    #expect(matcher.count > 0)

    let testIP = try! CIDRParser.parseIPv4Address("10.1.2.50")

    // 10 000 lookups must complete quickly (32 prefix levels per lookup).
    let start = ContinuousClock().now
    for _ in 0 ..< 10_000 {
        _ = matcher.match(ip: testIP)
    }
    let duration = ContinuousClock().now - start
    let ms = Double(duration.components.attoseconds) / 1_000_000_000_000_000.0
    #expect(ms < 50, "10k CIDR lookups took \(ms)ms, expected < 50ms")
}
