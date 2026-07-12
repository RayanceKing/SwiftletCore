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
    #expect(ms < 100, "10k CIDR lookups took \(ms)ms, expected < 100ms")
}

// MARK: - IPRadixTree — Correctness

@Suite("IPRadixTree — Correctness")
struct IPRadixTreeCorrectnessTests {

    @Test func basicInsertAndMatch() {
        let tree = IPRadixTree()
        // 192.168.0.0/16
        let network: UInt32 = (192 << 24) | (168 << 16)
        let rule = RoutingRule.ipv4CIDR(
            network: network, prefixLength: 16, decision: .direct
        )
        tree.insert(network: network, prefixLength: 16, rule: rule)

        // 192.168.1.1 should match.
        let ip: UInt32 = (192 << 24) | (168 << 16) | (1 << 8) | 1
        let match = tree.match(ip: ip)
        #expect(match != nil)
        #expect(match?.decision == .direct)
    }

    @Test func longestPrefixWins() {
        let tree = IPRadixTree()

        // /8 rule.
        let net8: UInt32 = 10 << 24
        tree.insert(network: net8, prefixLength: 8,
                    rule: .ipv4CIDR(network: net8, prefixLength: 8, decision: .proxy))

        // /16 rule.
        let net16: UInt32 = (10 << 24) | (1 << 16)
        tree.insert(network: net16, prefixLength: 16,
                    rule: .ipv4CIDR(network: net16, prefixLength: 16, decision: .direct))

        // 10.1.2.3 → should match /16 (longer prefix).
        let ip: UInt32 = (10 << 24) | (1 << 16) | (2 << 8) | 3
        let match = tree.match(ip: ip)
        #expect(match?.decision == .direct)
    }

    @Test func noMatchReturnsNil() {
        let tree = IPRadixTree()
        tree.insert(network: 0xC0A80000, prefixLength: 24,
                    rule: .ipv4CIDR(network: 0xC0A80000, prefixLength: 24))
        // 10.0.0.1 doesn't match 192.168.0.0/24.
        #expect(tree.match(ip: 0x0A000001) == nil)
    }

    @Test func exactMatch() {
        let tree = IPRadixTree()
        let net: UInt32 = 0xAC100001 // 172.16.0.1/32
        tree.insert(network: net, prefixLength: 32,
                    rule: .ipv4CIDR(network: net, prefixLength: 32, decision: .block))
        #expect(tree.match(ip: net)?.decision == .block)
        #expect(tree.match(ip: net + 1) == nil)
    }

    @Test func defaultRouteMatchesAll() {
        let tree = IPRadixTree()
        tree.insert(network: 0, prefixLength: 0,
                    rule: .ipv4CIDR(network: 0, prefixLength: 0, decision: .proxy))
        #expect(tree.match(ip: 0xFFFFFFFF)?.decision == .proxy)
        #expect(tree.match(ip: 0)?.decision == .proxy)
    }

    @Test func countTracksCorrectly() {
        let tree = IPRadixTree()
        #expect(tree.count == 0)
        tree.insert(network: 0x0A000000, prefixLength: 8,
                    rule: .ipv4CIDR(network: 0x0A000000, prefixLength: 8))
        #expect(tree.count == 1)
        // Re‑insert at same prefix — count should not increase.
        tree.insert(network: 0x0A000000, prefixLength: 8,
                    rule: .ipv4CIDR(network: 0x0A000000, prefixLength: 8))
        #expect(tree.count == 1)
    }

    @Test func removeAllClears() {
        let tree = IPRadixTree()
        tree.insert(network: 0x0A000000, prefixLength: 8,
                    rule: .ipv4CIDR(network: 0x0A000000, prefixLength: 8))
        tree.removeAll()
        #expect(tree.count == 0)
        #expect(tree.match(ip: 0x0A000001) == nil)
    }
}

// MARK: - IPRadixTree — 10k Performance

@Suite("IPRadixTree — 10k Rules Performance")
struct IPRadixTreePerformanceTests {

    @Test func tenThousandInsertsAndLookups() {
        let tree = IPRadixTree()

        // Insert 10 000 random /24 rules.
        let ruleCount = 10_000
        for i in 0 ..< ruleCount {
            let a = UInt32((i >> 16) & 0xFF)
            let b = UInt32((i >> 8) & 0xFF)
            let c = UInt32(i & 0xFF)
            let network: UInt32 = (a << 24) | (b << 16) | (c << 8)
            tree.insert(network: network, prefixLength: 24,
                        rule: .ipv4CIDR(network: network, prefixLength: 24,
                                        decision: .proxy))
        }
        #expect(tree.count == ruleCount)

        // Time 10 000 lookups.
        let start = ContinuousClock().now
        for i in 0 ..< ruleCount {
            let a = UInt32((i >> 16) & 0xFF)
            let b = UInt32((i >> 8) & 0xFF)
            let c = UInt32(i & 0xFF)
            let ip: UInt32 = (a << 24) | (b << 16) | (c << 8) | 1
            _ = tree.match(ip: ip)
        }
        let duration = ContinuousClock().now - start
        let ms = Double(duration.components.attoseconds) / 1_000_000_000_000_000.0
        #expect(ms < 100, "10k radix-tree lookups took \(ms)ms, expected < 100ms")
    }
}

// MARK: - IPv6 Radix Tree

@Suite("IPv6RadixTree")
struct IPv6RadixTreeTests {

    @Test func basicIPv6Match() {
        let tree = IPv6RadixTree()
        // fd00:a:b:c::/64
        let upper: UInt64 = 0xFD00_000A_000B_000C
        tree.insert(upper: upper, lower: 0, prefixLength: 64,
                    rule: .ipv4CIDR(network: 0, prefixLength: 0, decision: .direct))

        let match = tree.match(upper: upper, lower: 1)
        #expect(match?.decision == .direct)
    }

    @Test func noMatchBeyondPrefix() {
        let tree = IPv6RadixTree()
        tree.insert(upper: 0xFD00_000A_000B_000C, lower: 0, prefixLength: 64,
                    rule: .ipv4CIDR(network: 0, prefixLength: 0, decision: .direct))
        // Different /64 subnet.
        let match = tree.match(upper: 0xFD00_000A_000B_000D, lower: 0)
        #expect(match == nil)
    }
}

// MARK: - RoutingRule — UserAgent

@Suite("RoutingRule — UserAgent")
struct RoutingRuleUserAgentTests {

    @Test func userAgentMatches() {
        let rule = RoutingRule.userAgent(pattern: "Safari", decision: .direct)
        let ctx = RoutingContext(userAgent: "Mozilla/5.0 Safari/605.1.15")
        #expect(rule.evaluate(context: ctx) == true)
    }

    @Test func userAgentCaseInsensitive() {
        let rule = RoutingRule.userAgent(pattern: "chrome", decision: .proxy)
        let ctx = RoutingContext(userAgent: "Mozilla Chrome/120.0")
        #expect(rule.evaluate(context: ctx) == true)
    }

    @Test func userAgentNoMatch() {
        let rule = RoutingRule.userAgent(pattern: "Firefox", decision: .proxy)
        let ctx = RoutingContext(userAgent: "Safari/605.1.15")
        #expect(rule.evaluate(context: ctx) == false)
    }

    @Test func userAgentNoContext() {
        let rule = RoutingRule.userAgent(pattern: "Safari")
        #expect(rule.evaluate(context: .empty) == false)
    }
}

// MARK: - RoutingRule — Logical AND / NOT

@Suite("RoutingRule — Logical Combinations")
struct RoutingRuleLogicalTests {

    @Test func logicalAndBothMatch() {
        let r1 = RoutingRule.domainSuffix("apple.com")
        let r2 = RoutingRule.domainSuffix("google.com")
        // AND of two different suffixes — a single domain can't match both.
        let andRule = RoutingRule.logicalAnd([r1, r2])
        #expect(andRule.evaluate(domain: "www.apple.com") == false)
    }

    @Test func logicalAndSingleDomain() {
        let r1 = RoutingRule.domainSuffix("apple.com")
        let r2 = RoutingRule.domainKeyword("www")
        let andRule = RoutingRule.logicalAnd([r1, r2])
        // "www.apple.com" matches suffix "apple.com" AND contains "www".
        #expect(andRule.evaluate(domain: "www.apple.com") == true)
        // "store.apple.com" matches suffix but doesn't contain "www".
        #expect(andRule.evaluate(domain: "store.apple.com") == false)
    }

    @Test func logicalAndWithUserAgent() {
        let domainRule = RoutingRule.domainSuffix("apple.com")
        let uaRule = RoutingRule.userAgent(pattern: "Safari")
        let andRule = RoutingRule.logicalAnd([domainRule, uaRule])

        // Domain matches, UA matches.
        #expect(andRule.evaluate(
            domain: "www.apple.com",
            context: RoutingContext(userAgent: "Safari/605.1")
        ) == true)

        // Domain matches, UA doesn't.
        #expect(andRule.evaluate(
            domain: "www.apple.com",
            context: RoutingContext(userAgent: "Chrome/120")
        ) == false)
    }

    @Test func logicalNotInverts() {
        let rule = RoutingRule.domainSuffix("apple.com")
        let notRule = RoutingRule.logicalNot(rule, decision: .direct)
        #expect(notRule.evaluate(domain: "www.apple.com") == false)
        #expect(notRule.evaluate(domain: "google.com") == true)
    }

    @Test func logicalNotWithIP() {
        let cidrRule = RoutingRule.ipv4CIDR(
            network: 0x0A000000, prefixLength: 8
        )
        let notRule = RoutingRule.logicalNot(cidrRule, decision: .block)
        // 10.0.0.1 matches the CIDR → NOT inverts → false.
        #expect(notRule.evaluate(ip: 0x0A000001) == false)
        // 192.168.0.1 doesn't match → NOT inverts → true.
        #expect(notRule.evaluate(ip: 0xC0A80001) == true)
    }
}

// MARK: - RoutingRule — ASN

@Suite("RoutingRule — ASN")
struct RoutingRuleASNTests {

    @Test func asnMatches() {
        let rule = RoutingRule.ipAsn(asn: 15169, decision: .direct) // Google ASN
        let ctx = RoutingContext(targetASN: 15169)
        #expect(rule.evaluate(context: ctx) == true)
    }

    @Test func asnNoMatch() {
        let rule = RoutingRule.ipAsn(asn: 15169)
        let ctx = RoutingContext(targetASN: 714) // Apple ASN
        #expect(rule.evaluate(context: ctx) == false)
    }

    @Test func asnNoContext() {
        let rule = RoutingRule.ipAsn(asn: 15169)
        #expect(rule.evaluate(context: .empty) == false)
    }
}

// MARK: - RoutingEngine — Multi‑Dimension Context

@Suite("RoutingEngine — Multi‑Dimension Context")
struct RoutingEngineContextTests {

    @Test func userAgentRuleViaEngine() async {
        let engine = RoutingEngine()
        await engine.add(rule: .domainSuffix("apple.com", decision: .direct))
        await engine.add(rule: .userAgent(pattern: "Safari", decision: .proxy))

        let ctx = RoutingContext(userAgent: "Mozilla/5.0 Safari/605")
        let decision = await engine.route(
            domain: "google.com",
            context: ctx
        )
        // No domain match, but userAgent matches.
        #expect(decision == .proxy)
    }

    @Test func logicalRuleViaEngine() async {
        let engine = RoutingEngine()
        let andRule = RoutingRule.logicalAnd([
            .domainSuffix("apple.com"),
            .userAgent(pattern: "Safari"),
        ], decision: .direct)
        await engine.add(rule: andRule)

        // Both conditions match.
        let ctx = RoutingContext(userAgent: "Safari/605")
        let d1 = await engine.route(domain: "www.apple.com", context: ctx)
        #expect(d1 == .direct)

        // Only domain matches, UA doesn't.
        let ctx2 = RoutingContext(userAgent: "Chrome/120")
        let d2 = await engine.route(domain: "www.apple.com", context: ctx2)
        #expect(d2 != .direct) // Falls through to default (proxy).
    }

    @Test func generalRuleCount() async {
        let engine = RoutingEngine()
        await engine.add(rule: .userAgent(pattern: "TestUA"))
        await engine.add(rule: .ipAsn(asn: 15169))
        await engine.add(rule: .logicalNot(.domainSuffix("blocked.com")))
        let count = await engine.generalRuleCount
        #expect(count == 3)
    }
}

// MARK: - RoutingContext

@Suite("RoutingContext")
struct RoutingContextTests {

    @Test func emptyContext() {
        let ctx = RoutingContext.empty
        #expect(ctx.userAgent == nil)
        #expect(ctx.targetASN == nil)
    }

    @Test func contextWithValues() {
        let ctx = RoutingContext(userAgent: "Test/1.0", targetASN: 12345)
        #expect(ctx.userAgent == "Test/1.0")
        #expect(ctx.targetASN == 12345)
    }

    @Test func equatability() {
        let a = RoutingContext(userAgent: "A")
        let b = RoutingContext(userAgent: "A")
        let c = RoutingContext(userAgent: "B")
        #expect(a == b)
        #expect(a != c)
    }
}
