//===----------------------------------------------------------------------===//
//
//  RoutingRule.swift
//  SwiftletCore — Routing Rule Types & Matching Primitives
//
//  Defines the rule taxonomy (domain‑suffix, domain‑keyword, IP‑CIDR) and
//  the corresponding CIDR address‑parsing / mask utilities used by the
//  trie and the central `RoutingEngine`.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Routing Decision

/// The routing verdict returned by the engine for a given target.
public enum RoutingDecision: Sendable, Equatable, CustomStringConvertible {
    /// Connect directly (bypass proxy).
    case direct
    /// Route through the upstream proxy.
    case proxy
    /// Drop the connection immediately.
    case block

    public var description: String {
        switch self {
        case .direct: return "DIRECT"
        case .proxy:  return "PROXY"
        case .block:  return "BLOCK"
        }
    }
}

// MARK: - Routing Rule

/// A single rule that the routing engine evaluates against a target domain
/// or IP address.  Each case carries its own `RoutingDecision` so that
/// callers control the verdict.
public enum RoutingRule: Sendable, Equatable {
    /// Matches when the target domain ends with the given suffix.
    /// E.g. `"apple.com"` matches `"www.apple.com"` and `"apple.com"`.
    case domainSuffix(String, decision: RoutingDecision = .proxy)

    /// Matches when the target domain **contains** the given keyword.
    /// E.g. `"ads"` matches `"ads.google.com"` and `"doubleclick-ads.net"`.
    case domainKeyword(String, decision: RoutingDecision = .proxy)

    /// Matches when the target IPv4 address falls within the given CIDR block.
    /// Format: `"192.168.0.0/16"`.
    case ipv4CIDR(network: UInt32, prefixLength: Int, decision: RoutingDecision = .direct)

    // MARK: - Multi‑Dimension Rules

    /// Matches when the HTTP `User-Agent` header contains the given pattern.
    /// Case‑insensitive substring match.  Useful for per‑application routing
    /// (e.g. route Safari traffic differently from in‑app WebView traffic).
    case userAgent(pattern: String, decision: RoutingDecision = .proxy)

    /// Matches when the target IP address belongs to the given Autonomous
    /// System number (for future BGP / GeoIP ASN database integration).
    case ipAsn(asn: Int, decision: RoutingDecision = .direct)

    /// Logical AND — all sub‑rules must match for this rule to fire.
    /// Each sub‑rule carries its own decision; the container's `decision`
    /// is used when the conjunction evaluates to `true`.
    indirect case logicalAnd([RoutingRule], decision: RoutingDecision = .proxy)

    /// Logical NOT — inverts the match of a single sub‑rule.
    /// When the sub‑rule does **not** match, this rule fires with its
    /// associated `decision`.
    indirect case logicalNot(RoutingRule, decision: RoutingDecision = .proxy)

    // MARK: - Decision Accessor

    /// The verdict to apply when this rule matches.
    public var decision: RoutingDecision {
        switch self {
        case .domainSuffix(_, let d):   return d
        case .domainKeyword(_, let d):  return d
        case .ipv4CIDR(_, _, let d):    return d
        case .userAgent(_, let d):      return d
        case .ipAsn(_, let d):          return d
        case .logicalAnd(_, let d):     return d
        case .logicalNot(_, let d):     return d
        }
    }
}

// MARK: - Routing Rule Evaluation Context

/// Contextual information passed to rule evaluation for multi‑dimension
/// matching (User‑Agent, ASN, etc.).
public struct RoutingContext: Sendable, Equatable {
    /// The HTTP User‑Agent header value (if available).
    public var userAgent: String?

    /// The ASN of the target IP (if available from a GeoIP database).
    public var targetASN: Int?

    public init(userAgent: String? = nil, targetASN: Int? = nil) {
        self.userAgent = userAgent
        self.targetASN = targetASN
    }

    /// An empty context — only domain / IP rules will be evaluated.
    public static let empty = RoutingContext()
}

// MARK: - Contextual Rule Evaluation

extension RoutingRule {

    /// Evaluates this rule against domain, IP, and contextual dimensions.
    ///
    /// - Parameters:
    ///   - domain: Optional domain target.
    ///   - ip: Optional `UInt32` IPv4 address (host byte order).
    ///   - context: Additional context (User‑Agent, ASN, etc.).
    ///   - domainTrie: Domain suffix trie for domain‑based sub‑rules.
    ///   - cidrMatcher: CIDR matcher for IP‑based sub‑rules.
    /// - Returns: `true` if the rule matches.
    public func evaluate(
        domain: String? = nil,
        ip: UInt32? = nil,
        context: RoutingContext = .empty,
        domainTrie: DomainTrie? = nil,
        cidrMatcher: CIDRMatcher? = nil
    ) -> Bool {
        switch self {
        case .domainSuffix(let suffix, decision: _):
            guard let domain = domain else { return false }
            return domain.hasSuffix(suffix) || domain == suffix

        case .domainKeyword(let keyword, decision: _):
            guard let domain = domain else { return false }
            return domain.contains(keyword)

        case .ipv4CIDR(let network, let prefixLength, decision: _):
            guard let ip = ip else { return false }
            let mask = CIDRParser.mask(prefixLength: prefixLength)
            return (ip & mask) == (network & mask)

        case .userAgent(let pattern, decision: _):
            guard let ua = context.userAgent else { return false }
            return ua.localizedCaseInsensitiveContains(pattern)

        case .ipAsn(let asn, decision: _):
            guard let targetASN = context.targetASN else { return false }
            return targetASN == asn

        case .logicalAnd(let rules, decision: _):
            return rules.allSatisfy {
                $0.evaluate(
                    domain: domain, ip: ip, context: context,
                    domainTrie: domainTrie, cidrMatcher: cidrMatcher
                )
            }

        case .logicalNot(let rule, decision: _):
            return !rule.evaluate(
                domain: domain, ip: ip, context: context,
                domainTrie: domainTrie, cidrMatcher: cidrMatcher
            )
        }
    }
}

// MARK: - CIDR Parsing

/// Utilities for parsing CIDR notation strings.
public enum CIDRParser {

    /// Parses an IPv4 CIDR string like `"10.0.0.0/8"` into a
    /// `(network: UInt32, prefixLength: Int)` pair.
    ///
    /// - Parameter cidr: The CIDR string.
    /// - Returns: The network address in host byte order and the prefix length.
    /// - Throws: `CIDRParseError` if the string is malformed.
    public static func parseIPv4(_ cidr: String) throws -> (network: UInt32, prefixLength: Int) {
        let parts = cidr.split(separator: "/", maxSplits: 1)
        guard parts.count == 2,
              let prefixLength = Int(parts[1]),
              (0 ... 32).contains(prefixLength) else {
            throw CIDRParseError.invalidFormat(cidr)
        }

        let network = try parseIPv4Address(String(parts[0]))
        return (network, prefixLength)
    }

    /// Parses a dotted‑decimal IPv4 string into a `UInt32`.
    public static func parseIPv4Address(_ string: String) throws -> UInt32 {
        let octets = string.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else {
            throw CIDRParseError.invalidFormat(string)
        }

        var result: UInt32 = 0
        for (i, octetStr) in octets.enumerated() {
            guard let octet = UInt8(String(octetStr)) else {
                throw CIDRParseError.invalidOctet(string, index: i)
            }
            result = (result << 8) | UInt32(octet)
        }
        return result
    }

    /// Builds a 32‑bit mask from a prefix length.
    @inlinable
    public static func mask(prefixLength: Int) -> UInt32 {
        guard prefixLength > 0 else { return 0 }
        return ~UInt32(0) << (32 - UInt32(prefixLength))
    }

    public enum CIDRParseError: Error, Sendable, Equatable {
        case invalidFormat(String)
        case invalidOctet(String, index: Int)
    }
}

// MARK: - CIDR Matcher

/// A fast, array‑based longest‑prefix‑match engine for IPv4 CIDR rules.
///
/// Instead of a binary trie (which requires up to 32 pointer dereferences
/// per lookup), this matcher uses an array of 33 dictionaries keyed by
/// masked network address — one bucket per prefix length.  Lookup scans
/// from `/32` down to `/0` and returns the first match, giving O(32)
/// worst‑case time with excellent cache locality.
public final class CIDRMatcher: @unchecked Sendable {

    /// `tables[p]` maps a masked network address to the rule for prefix
    /// length `p`.  Index 0 is unused (prefix length 0 means "match
    /// everything", which we handle explicitly).
    private var tables: [[UInt32: RoutingRule]]

    public init() {
        self.tables = .init(repeating: [:], count: 33)
    }

    /// Inserts a CIDR rule.
    public func insert(network: UInt32, prefixLength: Int, rule: RoutingRule) {
        let mask = CIDRParser.mask(prefixLength: prefixLength)
        tables[prefixLength][network & mask] = rule
    }

    /// Returns the rule with the longest matching prefix for the given IP.
    public func match(ip: UInt32) -> RoutingRule? {
        for prefixLen in stride(from: 32, through: 0, by: -1) {
            let mask = CIDRParser.mask(prefixLength: prefixLen)
            if let rule = tables[prefixLen][ip & mask] {
                return rule
            }
        }
        return nil
    }

    /// The total number of rules stored.
    public var count: Int {
        tables.reduce(0) { $0 + $1.count }
    }

    /// Removes all CIDR rules.
    public func removeAll() {
        tables = .init(repeating: [:], count: 33)
    }
}
