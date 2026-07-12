//===----------------------------------------------------------------------===//
//
//  IPRadixTree.swift
//  SwiftletCore — Bitwise Radix Tree for IPv4/IPv6 CIDR Matching
//
//  A compressed binary trie that stores CIDR rules keyed by their
//  network prefix.  Each node represents one bit of the address;
//  the left child encodes bit‑0 and the right child encodes bit‑1.
//  Rules are stored at the node corresponding to the prefix depth.
//
//  Complexity
//  ----------
//  • **Insert**: O(prefixLength) — at most 32 (IPv4) or 128 (IPv6)
//    pointer traversals per insertion.
//  • **Lookup**: O(prefixLength) — walks the tree bit‑by‑bit from
//    MSB to LSB, tracking the deepest matching rule along the path.
//    Returns the longest‑prefix‑match in a single pass.
//  • **Space**: O(N × prefixLength) nodes in the worst case, but
//    shared prefixes compress naturally (nodes are reused for
//    overlapping CIDR blocks).
//
//  This is a substantial improvement over the array‑of‑33‑dictionaries
//  `CIDRMatcher` for rule sets exceeding ~10 000 entries, where
//  the O(32) linear scan per lookup becomes a bottleneck.  The radix
//  tree stays at exactly 32 bit‑tests per IPv4 lookup regardless of
//  rule count.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - IP Radix Tree Node

/// A single node in the bitwise radix tree.
private final class RadixNode: @unchecked Sendable {
    /// The routing rule stored at this node (if this prefix has a rule).
    var rule: RoutingRule?

    /// Child for bit‑0 (left).
    var zero: RadixNode?

    /// Child for bit‑1 (right).
    var one: RadixNode?
}

// MARK: - IP Radix Tree

/// A bitwise radix tree for IPv4 CIDR rules with O(32) lookup time
/// regardless of the number of stored rules.
///
/// ## Usage
/// ```swift
/// let tree = IPRadixTree()
/// tree.insert(network: 0xC0A80000, prefixLength: 16,
///             rule: .ipv4CIDR(network: 0xC0A80000, prefixLength: 16))
/// let match = tree.match(ip: 0xC0A80001) // 192.168.0.1 → matches /16
/// ```
public final class IPRadixTree: @unchecked Sendable {

    /// Root node (prefix depth = 0).
    private let root = RadixNode()

    /// Total number of rules stored.
    public private(set) var count: Int = 0

    // MARK: - Initialisation

    public init() {}

    // MARK: - Insert

    /// Inserts a CIDR rule into the tree.
    ///
    /// - Parameters:
    ///   - network: The network address in host byte order.
    ///   - prefixLength: The CIDR prefix length (0…32 for IPv4).
    ///   - rule: The routing rule to store at this prefix.
    public func insert(
        network: UInt32,
        prefixLength: Int,
        rule: RoutingRule
    ) {
        guard prefixLength >= 0, prefixLength <= 32 else { return }

        var node = root
        for depth in 0 ..< prefixLength {
            // Extract the bit at position (31 - depth) — MSB first.
            let bit = (network >> (31 - UInt32(depth))) & 1

            if bit == 0 {
                if node.zero == nil { node.zero = RadixNode() }
                node = node.zero!
            } else {
                if node.one == nil { node.one = RadixNode() }
                node = node.one!
            }
        }

        if node.rule == nil { count += 1 }
        node.rule = rule
    }

    // MARK: - Bulk Insert

    /// Inserts multiple CIDR rules at once.
    public func insertAll(_ rules: [(network: UInt32, prefixLength: Int, rule: RoutingRule)]) {
        for (net, prefix, rule) in rules {
            insert(network: net, prefixLength: prefix, rule: rule)
        }
    }

    // MARK: - Match (Longest Prefix)

    /// Finds the longest‑prefix‑match for the given IPv4 address.
    ///
    /// Traverses the tree bit‑by‑bit from MSB to LSB, tracking the
    /// deepest rule encountered along the path.  Returns the rule
    /// with the longest matching prefix (i.e. the most specific rule).
    ///
    /// - Parameter ip: The IPv4 address in host byte order.
    /// - Returns: The matching rule with the longest prefix, or `nil`.
    public func match(ip: UInt32) -> RoutingRule? {
        var bestMatch: RoutingRule?
        var node = root

        // Check root-level rule (prefix length 0 = default route).
        if let rule = node.rule { bestMatch = rule }

        for depth in 0 ..< 32 {
            let bit = (ip >> (31 - UInt32(depth))) & 1

            if bit == 0 {
                guard let child = node.zero else { break }
                node = child
            } else {
                guard let child = node.one else { break }
                node = child
            }

            // Track the best (deepest) match.
            if let rule = node.rule { bestMatch = rule }
        }

        return bestMatch
    }

    // MARK: - Match with Decision

    /// Returns the routing decision for the given IP, or `nil` if no
    /// rule matches.
    public func matchDecision(ip: UInt32) -> RoutingDecision? {
        match(ip: ip)?.decision
    }

    // MARK: - Removal

    /// Removes all rules from the tree.
    public func removeAll() {
        root.zero = nil
        root.one = nil
        root.rule = nil
        count = 0
    }
}

// MARK: - IPv6 Radix Tree

/// A bitwise radix tree for IPv6 CIDR rules with O(128) lookup time.
///
/// IPv6 addresses are stored as a pair of `UInt64` values (`upper` and
/// `lower`), each traversed bit‑by‑bit for a combined maximum depth of
/// 128 bits.
public final class IPv6RadixTree: @unchecked Sendable {

    private let root = RadixNode()
    public private(set) var count: Int = 0

    public init() {}

    // MARK: - Insert

    /// Inserts an IPv6 CIDR rule.
    ///
    /// - Parameters:
    ///   - upper: The upper 64 bits of the network address.
    ///   - lower: The lower 64 bits of the network address.
    ///   - prefixLength: The CIDR prefix length (0…128).
    ///   - rule: The routing rule to store.
    public func insert(
        upper: UInt64,
        lower: UInt64,
        prefixLength: Int,
        rule: RoutingRule
    ) {
        guard prefixLength >= 0, prefixLength <= 128 else { return }

        var node = root
        for depth in 0 ..< prefixLength {
            let bit: UInt64
            if depth < 64 {
                bit = (upper >> (63 - UInt64(depth))) & 1
            } else {
                bit = (lower >> (63 - (UInt64(depth) - 64))) & 1
            }

            if bit == 0 {
                if node.zero == nil { node.zero = RadixNode() }
                node = node.zero!
            } else {
                if node.one == nil { node.one = RadixNode() }
                node = node.one!
            }
        }

        if node.rule == nil { count += 1 }
        node.rule = rule
    }

    // MARK: - Match

    /// Finds the longest‑prefix‑match for an IPv6 address.
    public func match(upper: UInt64, lower: UInt64) -> RoutingRule? {
        var bestMatch: RoutingRule?
        var node = root

        if let rule = node.rule { bestMatch = rule }

        for depth in 0 ..< 128 {
            let bit: UInt64
            if depth < 64 {
                bit = (upper >> (63 - UInt64(depth))) & 1
            } else {
                bit = (lower >> (63 - (UInt64(depth) - 64))) & 1
            }

            if bit == 0 {
                guard let child = node.zero else { break }
                node = child
            } else {
                guard let child = node.one else { break }
                node = child
            }

            if let rule = node.rule { bestMatch = rule }
        }

        return bestMatch
    }

    public func removeAll() {
        root.zero = nil
        root.one = nil
        root.rule = nil
        count = 0
    }
}
