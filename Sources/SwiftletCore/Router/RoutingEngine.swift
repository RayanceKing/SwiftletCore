//===----------------------------------------------------------------------===//
//
//  RoutingEngine.swift
//  SwiftletCore — Central Routing Decision Engine
//
//  The "brain" of the proxy: it evaluates domain and IP targets against
//  the domain‑suffix trie, keyword matcher, bitwise IP radix trees, and
//  multi‑dimension context rules, then returns a final `RoutingDecision`.
//  When DNS resolution is required, the engine delegates to the
//  `AsyncDNSResolver` for anti‑DNS‑leak CIDR enforcement.
//
//  Rule priority (first match wins)
//  --------------------------------
//  1. Domain‑suffix trie       (longest suffix match)
//  2. Domain‑keyword scan
//  3. General rules             (userAgent → ASN → logical combinations)
//  4. IPv4 Radix Tree           (O(32) bitwise longest‑prefix match)
//  5. IPv6 Radix Tree           (O(128) bitwise longest‑prefix match)
//  6. Default rule
//
//  IP Lookup — Radix Tree vs Legacy CIDRMatcher
//  --------------------------------------------
//  The engine now uses `IPRadixTree` / `IPv6RadixTree` (bitwise binary
//  tries) instead of the array‑of‑33‑dictionaries `CIDRMatcher`.  This
//  guarantees exactly 32 bit‑tests per IPv4 lookup and 128 per IPv6
//  lookup regardless of how many rules are stored — a substantial win
//  for rule sets exceeding ~10 000 CIDR entries.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Routing Engine

/// The central routing engine that evaluates targets and returns decisions.
///
/// Rules are loaded via `add(rule:)` or the convenience bulk‑load methods.
/// Lookups are synchronous for the trie/radix paths; DNS resolution is
/// asynchronous and cachable.
///
/// This type is an `actor` so that rule updates and DNS cache access are
/// serialised without external locking.
public actor RoutingEngine {

    // MARK: - Rule Stores

    /// Domain‑suffix trie (the primary matching structure).
    public let domainTrie: DomainTrie

    /// Keyword matcher (secondary; typically few rules).
    public let keywordMatcher: KeywordMatcher

    /// Bitwise radix tree for IPv4 CIDR rules — O(32) lookup.
    public let ipv4RadixTree: IPRadixTree

    /// Bitwise radix tree for IPv6 CIDR rules — O(128) lookup.
    public let ipv6RadixTree: IPv6RadixTree

    /// The default decision when no rule matches.
    public var defaultDecision: RoutingDecision = .proxy

    // MARK: - Fake IP (optional)

    /// An optional Fake IP pool manager.  When set, IP targets that fall
    /// within the fake IP pool are instantly reverse‑resolved to their
    /// original domain, bypassing blocking network DNS round‑trips.
    public var fakeIPManager: FakeIPPoolManager?

    /// Convenience setter for the fake IP manager (callable from outside
    /// the actor with `await`).
    public func setFakeIPManager(_ pool: FakeIPPoolManager?) {
        self.fakeIPManager = pool
    }

    // MARK: - DNS (optional)

    /// An optional DNS resolver.  When set, domain targets that do not match
    /// any domain rule can be resolved to IPs and evaluated against CIDR
    /// rules (anti‑DNS‑leak).
    public var dnsResolver: AsyncDNSResolver?

    // MARK: - General‑Purpose Rule Store

    /// Rules that require context beyond domain/IP (userAgent, ASN,
    /// logical combinations).
    private var generalRules: [RoutingRule] = []

    // MARK: - Initialisation

    public init() {
        self.domainTrie     = DomainTrie()
        self.keywordMatcher = KeywordMatcher()
        self.ipv4RadixTree  = IPRadixTree()
        self.ipv6RadixTree  = IPv6RadixTree()
    }

    // MARK: - Rule Management

    /// Adds a single routing rule.
    public func add(rule: RoutingRule, forDomain domain: String? = nil) {
        switch rule {
        case .domainSuffix(let suffix, decision: _):
            let domainToInsert = domain ?? suffix
            domainTrie.insert(suffix: domainToInsert, rule: rule)

        case .domainKeyword(let keyword, decision: _):
            keywordMatcher.insert(keyword: keyword, rule: rule)

        case .ipv4CIDR(let network, let prefixLength, decision: _):
            ipv4RadixTree.insert(
                network: network,
                prefixLength: prefixLength,
                rule: rule
            )

        case .userAgent, .ipAsn, .logicalAnd, .logicalNot:
            generalRules.append(rule)
        }
    }

    /// Bulk‑loads multiple domain‑suffix rules for the same decision.
    public func addDomainSuffixRules(
        _ suffixes: [String],
        decision: RoutingDecision = .proxy
    ) {
        for suffix in suffixes {
            let rule = RoutingRule.domainSuffix(suffix, decision: decision)
            domainTrie.insert(suffix: suffix, rule: rule)
        }
    }

    /// Bulk‑loads CIDR rules into the IPv4 radix tree.
    public func addCIDRRules(
        _ cidrs: [String],
        decision: RoutingDecision = .direct
    ) {
        for cidrString in cidrs {
            guard let (network, prefixLen) = try? CIDRParser.parseIPv4(cidrString)
            else { continue }
            let rule = RoutingRule.ipv4CIDR(
                network: network, prefixLength: prefixLen, decision: decision
            )
            ipv4RadixTree.insert(
                network: network, prefixLength: prefixLen, rule: rule
            )
        }
    }

    /// Removes all rules.
    public func reset() {
        domainTrie.removeAll()
        ipv4RadixTree.removeAll()
        ipv6RadixTree.removeAll()
        keywordMatcher.removeAll()
        generalRules.removeAll()
    }

    // MARK: - Contextual Routing (primary entry point)

    /// Evaluates a target with full multi‑dimensional context.
    ///
    /// Rule priority (first match wins):
    /// 1. Domain‑suffix trie
    /// 2. Domain‑keyword scan
    /// 3. General rules (userAgent → ASN → logical combinations)
    /// 4. IPv4 Radix Tree  (O(32) bitwise longest‑prefix)
    /// 5. Default decision
    ///
    /// - Parameters:
    ///   - domain: Optional domain target.
    ///   - ip: Optional IPv4 address (host byte order UInt32).
    ///   - context: Additional context (User‑Agent, ASN).
    /// - Returns: The routing decision.
    public func route(
        domain: String? = nil,
        ip: UInt32? = nil,
        context: RoutingContext = .empty
    ) -> RoutingDecision {
        // Resolve effective domain: if the IP is a fake IP, reverse‑map it
        // to the original domain so suffix‑trie rules apply transparently.
        let effectiveDomain: String? = {
            if let d = domain { return d }
            if let ip = ip, let fip = fakeIPManager,
               let resolved = fip.resolveIPv4(ip) {
                return resolved
            }
            return nil
        }()

        // 1. Domain‑suffix trie (longest match).
        if let d = effectiveDomain, let rule = domainTrie.match(domain: d) {
            return rule.decision
        }

        // 2. Domain‑keyword scan.
        if let d = effectiveDomain, let rule = keywordMatcher.match(domain: d) {
            return rule.decision
        }

        // 3. General‑purpose rules (userAgent, ASN, logical).
        for rule in generalRules {
            if rule.evaluate(
                domain: effectiveDomain, ip: ip, context: context,
                domainTrie: domainTrie
            ) {
                return rule.decision
            }
        }

        // 4. IPv4 Radix Tree (O(32) bitwise longest‑prefix match).
        if let ip = ip, let rule = ipv4RadixTree.match(ip: ip) {
            return rule.decision
        }

        // 5. Default.
        return defaultDecision
    }

    // MARK: - Domain Routing

    /// Evaluates a domain target against all domain‑type rules.
    ///
    /// - Parameter domain: The fully‑qualified domain name.
    /// - Returns: The routing decision.
    public func route(domain: String) -> RoutingDecision {
        // 1. Domain‑suffix trie (longest match).
        if let rule = domainTrie.match(domain: domain) {
            return rule.decision
        }

        // 2. Domain‑keyword scan.
        if let rule = keywordMatcher.match(domain: domain) {
            return rule.decision
        }

        // 3. Default.
        return defaultDecision
    }

    /// Evaluates a domain target, resolving it via DNS first if a resolver
    /// is configured (enables CIDR matching for domains — anti‑leak).
    ///
    /// - Parameter domain: The fully‑qualified domain name.
    /// - Returns: The routing decision.
    public func routeWithDNS(domain: String) async -> RoutingDecision {
        let domainDecision = route(domain: domain)
        if domainDecision != defaultDecision {
            return domainDecision
        }

        if let resolver = dnsResolver, let ip = try? await resolver.resolveA(domain) {
            return route(ip: ip)
        }

        return domainDecision
    }

    // MARK: - IP Routing

    /// Evaluates an IPv4 address against the radix tree.
    ///
    /// - Parameter ip: The IPv4 address.
    /// - Returns: The routing decision.
    public func route(ip: IPv4Address) -> RoutingDecision {
        let addrUInt32 = (UInt32(ip.octet0) << 24)
                       | (UInt32(ip.octet1) << 16)
                       | (UInt32(ip.octet2) <<  8)
                       |  UInt32(ip.octet3)

        if let rule = ipv4RadixTree.match(ip: addrUInt32) {
            return rule.decision
        }
        return defaultDecision
    }

    // MARK: - IPv6 Routing

    /// Evaluates an IPv6 address against the IPv6 radix tree.
    ///
    /// - Parameters:
    ///   - upper: Upper 64 bits of the address.
    ///   - lower: Lower 64 bits of the address.
    /// - Returns: The routing decision.
    public func routeIPv6(upper: UInt64, lower: UInt64) -> RoutingDecision {
        if let rule = ipv6RadixTree.match(upper: upper, lower: lower) {
            return rule.decision
        }
        return defaultDecision
    }

    // MARK: - Statistics

    /// Total number of domain‑suffix rules.
    public var domainRuleCount: Int { domainTrie.ruleCount }

    /// Total number of CIDR rules (IPv4 + IPv6 radix trees).
    public var cidrRuleCount: Int {
        ipv4RadixTree.count + ipv6RadixTree.count
    }

    /// Total number of keyword rules.
    public var keywordRuleCount: Int { keywordMatcher.count }

    /// Total general‑purpose rules (userAgent, ASN, logical).
    public var generalRuleCount: Int { generalRules.count }

    /// Total rules across all matchers.
    public var totalRuleCount: Int {
        domainRuleCount + cidrRuleCount + keywordRuleCount + generalRuleCount
    }
}
