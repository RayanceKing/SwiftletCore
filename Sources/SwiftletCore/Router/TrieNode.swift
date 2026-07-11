//===----------------------------------------------------------------------===//
//
//  TrieNode.swift
//  SwiftletCore — Domain Suffix Trie
//
//  A label‑based trie (prefix tree) specialised for high‑performance domain
//  suffix matching.  Domains are reversed so that suffix rules become prefix
//  rules in the trie — e.g. `"apple.com"` → `"com.apple"` — allowing a
//  single O(labels) walk to find the longest matching suffix.
//
//  Performance characteristics (n = number of domain labels):
//    • Insert: O(n)
//    • Lookup: O(n) with at most n dictionary probes
//    • Memory:  proportional to total number of unique labels across all rules
//
//===----------------------------------------------------------------------===//

// MARK: - Domain Trie Node

/// A single node in the domain suffix trie.
///
/// Each node represents one label (the text between dots) of a reversed
/// domain.  Children are keyed by label string for fast hash‑lookup.
public final class DomainTrieNode: @unchecked Sendable {

    /// Child nodes keyed by domain label.
    public var children: [String: DomainTrieNode]

    /// The rule that ends at this node, if any.
    ///
    /// When multiple rules share a domain path (e.g. `"apple.com"` and
    /// `"www.apple.com"`), the deeper (longer) rule takes precedence during
    /// matching.
    public var rule: RoutingRule?

    public init() {
        self.children = [:]
        self.rule = nil
    }
}

// MARK: - Domain Trie

/// A suffix trie for domain‑name routing rules.
///
/// ## How suffix matching works
/// A rule like `"apple.com"` should match `"www.apple.com"` and
/// `"cdn.images.apple.com"`.  By reversing the domain and inserting it as
/// a prefix, the trie naturally handles suffix matching:
///
///   Rule `"apple.com"` → insert `["com", "apple"]`
///   Query `"www.apple.com"` → reverse to `"com.apple.www"` → walk the trie
///
/// During the walk, we record the deepest rule encountered so that the
/// **longest** matching suffix always wins.
public final class DomainTrie: @unchecked Sendable {

    /// Root node (empty label).
    public let root: DomainTrieNode

    /// Total number of rules inserted (for statistics / testing).
    public private(set) var ruleCount: Int = 0

    public init() {
        self.root = DomainTrieNode()
    }

    // MARK: - Insert

    /// Inserts a domain‑suffix rule into the trie.
    ///
    /// The domain is normalised to lowercase and split on `"."`.  Each label
    /// is inserted in **reverse** order so that suffix matching becomes
    /// prefix matching.
    ///
    /// - Parameters:
    ///   - domain: The domain suffix to match (e.g. `"apple.com"`).
    ///   - rule: The rule to associate with this suffix.
    public func insert(suffix domain: String, rule: RoutingRule) {
        let labels = domain
            .lowercased()
            .split(separator: ".", omittingEmptySubsequences: true)
            .map(String.init)
            .reversed()   // ← key transformation

        var node = root
        for label in labels {
            if let child = node.children[label] {
                node = child
            } else {
                let child = DomainTrieNode()
                node.children[label] = child
                node = child
            }
        }

        // Only count the rule if this node did not already carry one.
        if node.rule == nil { ruleCount += 1 }
        node.rule = rule
    }

    // MARK: - Lookup (Longest‑Suffix Match)

    /// Finds the rule with the **longest** matching domain suffix.
    ///
    /// - Parameter domain: The fully‑qualified domain name to test
    ///   (e.g. `"www.apple.com"`).
    /// - Returns: The matching `RoutingRule`, or `nil` if no suffix matches.
    public func match(domain: String) -> RoutingRule? {
        let labels = domain
            .lowercased()
            .split(separator: ".", omittingEmptySubsequences: true)
            .map(String.init)
            .reversed()

        var node = root
        var bestMatch: RoutingRule? = root.rule

        for label in labels {
            guard let child = node.children[label] else {
                break   // no deeper match possible
            }
            node = child
            // A deeper rule overrides a shallower one.
            if let rule = node.rule {
                bestMatch = rule
            }
        }

        return bestMatch
    }

    // MARK: - Bulk Operations

    /// Removes all rules from the trie while keeping the root node.
    public func removeAll() {
        root.children.removeAll()
        root.rule = nil
        ruleCount = 0
    }
}

// MARK: - Keyword Matcher

/// A simple linear keyword scanner for domain keyword rules.
///
/// Keyword rules are typically few in number (dozens, not thousands), so a
/// linear scan over the keywords is sufficient.  For larger keyword sets
/// an Aho‑Corasick automaton should be substituted.
public final class KeywordMatcher: @unchecked Sendable {

    private var keywords: [(keyword: String, rule: RoutingRule)] = []

    public init() {}

    /// Inserts a keyword rule.
    public func insert(keyword: String, rule: RoutingRule) {
        keywords.append((keyword.lowercased(), rule))
    }

    /// Returns the first rule whose keyword appears in the given domain.
    ///
    /// - Parameter domain: The domain to scan.
    /// - Returns: The first matching rule, or `nil`.
    public func match(domain: String) -> RoutingRule? {
        let lower = domain.lowercased()
        for (keyword, rule) in keywords {
            if lower.contains(keyword) {
                return rule
            }
        }
        return nil
    }

    /// Total number of keyword rules.
    public var count: Int { keywords.count }

    /// Removes all keyword rules.
    public func removeAll() {
        keywords.removeAll()
    }
}
