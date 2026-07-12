//===----------------------------------------------------------------------===//
//
//  RoutingEngine.swift
//  SwiftletCore — Central Routing Decision Engine
//
//  The "brain" of the proxy: it evaluates domain and IP targets against the
//  domain‑suffix trie, keyword matcher, and CIDR tables, then returns a
//  final `RoutingDecision`.  When DNS resolution is required (e.g. a domain
//  needs to be resolved to an IP before CIDR rules can be evaluated), the
//  engine delegates to the `AsyncDNSResolver`.
//
//  Rule priority (first match wins)
//  --------------------------------
//  1. Domain‑suffix trie  (longest suffix match)
//  2. Domain‑keyword scan
//  3. IP‑CIDR table       (longest prefix match)
//  4. Default rule        (`.proxy`)
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Routing Engine

/// The central routing engine that evaluates targets and returns decisions.
///
/// Rules are loaded via `add(rule:)` or the convenience bulk‑load methods.
/// Lookups are synchronous for the trie/CIDR paths; DNS resolution is
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

    /// IPv4 CIDR matcher.
    public let cidrMatcher: CIDRMatcher

    /// The default decision when no rule matches.
    public var defaultDecision: RoutingDecision = .proxy

    // MARK: - DNS (optional)

    /// An optional DNS resolver.  When set, domain targets that do not match
    /// any domain rule can be resolved to IPs and evaluated against CIDR
    /// rules (anti‑DNS‑leak).
    public var dnsResolver: AsyncDNSResolver?

    // MARK: - Initialisation

    public init() {
        self.domainTrie = DomainTrie()
        self.keywordMatcher = KeywordMatcher()
        self.cidrMatcher = CIDRMatcher()
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

        case .ipv4CIDR(network: let network, prefixLength: let prefixLength, decision: _):
            cidrMatcher.insert(network: network, prefixLength: prefixLength, rule: rule)

        case .userAgent, .ipAsn, .logicalAnd, .logicalNot:
            // These rules are stored in the general‑purpose rule list
            // and evaluated via `evaluate(context:)`.
            generalRules.append(rule)
        }
    }

    // MARK: - General‑Purpose Rule Store

    /// Rules that require context beyond domain/IP (userAgent, ASN,
    /// logical combinations).
    private var generalRules: [RoutingRule] = []

    /// Bulk‑loads multiple domain‑suffix rules for the same decision.
    ///
    /// - Parameters:
    ///   - suffixes: Domain suffixes (e.g. `["apple.com", "google.com"]`).
    ///   - decision: The decision to assign (default `.proxy` if the rule
    ///     type doesn't carry its own decision).
    public func addDomainSuffixRules(
        _ suffixes: [String],
        decision: RoutingDecision = .proxy
    ) {
        for suffix in suffixes {
            let rule = RoutingRule.domainSuffix(suffix, decision: decision)
            domainTrie.insert(suffix: suffix, rule: rule)
        }
    }

    /// Bulk‑loads CIDR rules.
    public func addCIDRRules(_ cidrs: [String], decision: RoutingDecision = .direct) {
        for cidrString in cidrs {
            guard let (network, prefixLen) = try? CIDRParser.parseIPv4(cidrString) else {
                continue
            }
            let rule = RoutingRule.ipv4CIDR(network: network, prefixLength: prefixLen, decision: decision)
            cidrMatcher.insert(network: network, prefixLength: prefixLen, rule: rule)
        }
    }

    /// Removes all rules.
    public func reset() {
        domainTrie.removeAll()
        cidrMatcher.removeAll()
        keywordMatcher.removeAll()
        generalRules.removeAll()
    }

    // MARK: - Contextual Routing

    /// Evaluates a target with full multi‑dimensional context.
    ///
    /// Rule priority (first match wins):
    /// 1. Domain‑suffix trie
    /// 2. Domain‑keyword scan
    /// 3. User‑Agent rules (from generalRules)
    /// 4. ASN rules (from generalRules)
    /// 5. Logical combination rules (from generalRules)
    /// 6. IP‑CIDR table
    /// 7. Default decision
    ///
    /// - Parameters:
    ///   - domain: Optional domain target.
    ///   - ip: Optional IPv4 address (host byte order).
    ///   - context: Additional context (User‑Agent, ASN).
    /// - Returns: The routing decision.
    public func route(
        domain: String? = nil,
        ip: UInt32? = nil,
        context: RoutingContext = .empty
    ) -> RoutingDecision {
        // 1. Domain‑suffix trie.
        if let domain = domain, let rule = domainTrie.match(domain: domain) {
            return rule.decision
        }

        // 2. Domain‑keyword scan.
        if let domain = domain, let rule = keywordMatcher.match(domain: domain) {
            return rule.decision
        }

        // 3. General‑purpose rules (userAgent, ASN, logical).
        for rule in generalRules {
            if rule.evaluate(
                domain: domain, ip: ip, context: context,
                domainTrie: domainTrie, cidrMatcher: cidrMatcher
            ) {
                return rule.decision
            }
        }

        // 4. IP‑CIDR.
        if let ip = ip, let rule = cidrMatcher.match(ip: ip) {
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

    /// Evaluates a domain target, resolving it via DNS first if a resolver is
    /// configured (enables CIDR matching for domains).
    ///
    /// - Parameter domain: The fully‑qualified domain name.
    /// - Returns: The routing decision.
    public func routeWithDNS(domain: String) async -> RoutingDecision {
        // First try domain rules.
        let domainDecision = route(domain: domain)
        if domainDecision != defaultDecision {
            return domainDecision
        }

        // If domain rules didn't match and we have a DNS resolver, try to
        // resolve the domain and match against CIDR rules (anti‑leak).
        if let resolver = dnsResolver, let ip = try? await resolver.resolveA(domain) {
            return route(ip: ip)
        }

        return domainDecision
    }

    // MARK: - IP Routing

    /// Evaluates an IPv4 address against CIDR rules.
    ///
    /// - Parameter ip: The IPv4 address.
    /// - Returns: The routing decision.
    public func route(ip: IPv4Address) -> RoutingDecision {
        let addrUInt32 = (UInt32(ip.octet0) << 24)
                       | (UInt32(ip.octet1) << 16)
                       | (UInt32(ip.octet2) <<  8)
                       |  UInt32(ip.octet3)

        if let rule = cidrMatcher.match(ip: addrUInt32) {
            return rule.decision
        }
        return defaultDecision
    }

    // MARK: - Statistics

    /// Total number of domain‑suffix rules.
    public var domainRuleCount: Int { domainTrie.ruleCount }

    /// Total number of CIDR rules.
    public var cidrRuleCount: Int { cidrMatcher.count }

    /// Total number of keyword rules.
    public var keywordRuleCount: Int { keywordMatcher.count }

    /// Total general‑purpose rules.
    public var generalRuleCount: Int { generalRules.count }

    /// Total rules across all matchers.
    public var totalRuleCount: Int {
        domainRuleCount + cidrRuleCount + keywordRuleCount + generalRuleCount
    }
}
