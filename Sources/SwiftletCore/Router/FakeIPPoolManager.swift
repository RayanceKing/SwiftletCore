//===----------------------------------------------------------------------===//
//
//  FakeIPPoolManager.swift
//  SwiftletCore — Atomic Fake‑IP Allocation & Reverse‑Mapping Engine
//
//  Implements a zero‑latency DNS interception pool that returns fake IP
//  addresses from reserved `198.18.0.0/15` (IPv4) and `fc00::/64` (IPv6)
//  blocks the instant a local app triggers a DNS query.  A concurrent
//  bidirectional mapping table allows the routing engine to reverse‑resolve
//  the true domain from a fake IP in O(1) without any synchronous network
//  DNS round‑trips during TCP handshake processing.
//
//  Memory Model
//  ------------
//  • IPv4 pool: 198.18.0.1 … 198.19.255.254  (~131 072 addresses)
//  • IPv6 pool: fc00::1 … fc00::ffff:ffff      (~2⁶⁴ addresses, virtually
//    unlimited — allocated sequentially from a 32‑bit counter)
//  • Mapping table: `[UInt32: String]` for IPv4, `[UInt64: String]` for
//    IPv6 — both O(1) lookups.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Fake IP Pool Manager

/// An `actor` that manages a pool of pseudo IP addresses and their
/// bidirectional mappings to real domain names.
///
/// All state mutations are serialised through the actor's executor,
/// making the manager safe to call from any concurrency domain.
public actor FakeIPPoolManager {

    // MARK: - IPv4 Pool

    /// Base of the fake IPv4 pool (198.18.0.0 — RFC 2544 benchmarking range).
    private static let ipv4Base: UInt32 =
        (198 << 24) | (18 << 16)

    /// Maximum offset within the /15 block (198.18.0.0 … 198.19.255.255).
    /// 198.19.255.255 = base + 0x0001FFFF
    private static let ipv4MaxOffset: UInt32 = 0x0001_FFFF

    /// Next available IPv4 offset.
    private var ipv4NextOffset: UInt32 = 1  // skip .0 (network) and .255 (broadcast)

    /// IPv4 fake → real domain mapping.  Dictionary access is protected
    /// by `ipv4Lock` and marked `nonisolated(unsafe)` so the fast‑path
    /// `resolveIPv4(_:)` can be called synchronously from any context.
    private nonisolated(unsafe) var ipv4ToDomain: [UInt32: String] = [:]
    private let ipv4Lock = NSLock()

    /// Domain → IPv4 fake mapping (for deduplication).
    private var domainToIPv4: [String: UInt32] = [:]

    // MARK: - IPv6 Pool

    /// Upper 64 bits of the fake IPv6 ULA prefix (`fc00::/64`).
    private static let ipv6Prefix: UInt64 = 0xFC00_0000_0000_0000

    /// Next available IPv6 lower 64 bits (treated as a 32‑bit counter for
    /// practical allocation limits — 4 billion addresses is sufficient).
    private var ipv6NextLower: UInt32 = 1

    /// IPv6 fake → real domain mapping (keyed by lower 64 bits).
    private var ipv6ToDomain: [UInt64: String] = [:]

    /// Domain → IPv6 fake mapping.
    private var domainToIPv6: [String: UInt64] = [:]

    // MARK: - Initialisation

    public init() {}

    // MARK: - Allocation

    /// Allocates a fake IPv4 address for the given domain.
    ///
    /// If the domain already has a fake IP, the existing mapping is returned
    /// immediately.  Otherwise, a new address is allocated from the pool.
    ///
    /// - Parameter domain: The real domain name to map.
    /// - Returns: A fake IPv4 address string (e.g. `"198.18.0.1"`).
    public func allocateIPv4(for domain: String) -> String {
        // Return existing mapping if present.
        if let existing = domainToIPv4[domain] {
            return formatIPv4(existing)
        }

        // Allocate next available address.
        let ip = Self.ipv4Base + ipv4NextOffset
        ipv4NextOffset &+= 1

        // Wrap if exhausted.
        if ipv4NextOffset > Self.ipv4MaxOffset {
            ipv4NextOffset = 1
        }

        // Register bidirectional mapping.
        ipv4Lock.lock()
        ipv4ToDomain[ip] = domain
        ipv4Lock.unlock()
        domainToIPv4[domain] = ip

        return formatIPv4(ip)
    }

    /// Allocates a fake IPv6 address for the given domain.
    ///
    /// - Parameter domain: The real domain name to map.
    /// - Returns: A fake IPv6 address string (e.g. `"fc00::1"`).
    public func allocateIPv6(for domain: String) -> String {
        if let existing = domainToIPv6[domain] {
            return formatIPv6(Self.ipv6Prefix, lower: existing)
        }

        let lower = UInt64(ipv6NextLower)
        ipv6NextLower &+= 1

        ipv6ToDomain[lower] = domain
        domainToIPv6[domain] = lower

        return formatIPv6(Self.ipv6Prefix, lower: lower)
    }

    /// Allocates both an IPv4 and IPv6 fake address for the domain.
    ///
    /// - Parameter domain: The real domain name.
    /// - Returns: A tuple of `(ipv4Address, ipv6Address)`.
    public func allocateDualStack(for domain: String) -> (ipv4: String, ipv6: String) {
        let v4 = allocateIPv4(for: domain)
        let v6 = allocateIPv6(for: domain)
        return (v4, v6)
    }

    // MARK: - Reverse Lookup (Fake IP → Real Domain)

    /// Reverse‑resolves a fake IPv4 address to its original domain name.
    ///
    /// - Parameter ip: The fake IPv4 address as a string (e.g. `"198.18.0.5"`).
    /// - Returns: The original domain, or `nil` if the IP is not in the pool.
    public func resolveIPv4(_ ip: String) -> String? {
        guard let addr = parseIPv4(ip) else { return nil }
        return ipv4ToDomain[addr]
    }

    /// Reverse‑resolves a fake IPv6 address to its original domain name.
    public func resolveIPv6(_ ip: String) -> String? {
        guard let (_, lower) = parseIPv6(ip) else { return nil }
        return ipv6ToDomain[lower]
    }

    /// Reverse‑resolves a fake IPv4 `UInt32` address directly (no string
    /// allocation — fast‑path for the routing engine).
    /// Non‑isolated so the `RoutingEngine` actor can call it synchronously.
    public nonisolated func resolveIPv4(_ ip: UInt32) -> String? {
        ipv4Lock.lock(); defer { ipv4Lock.unlock() }
        return ipv4ToDomain[ip]
    }

    // MARK: - Release

    /// Releases a fake IP mapping (e.g. when a session closes).
    public func releaseIPv4(_ ip: String) {
        guard let addr = parseIPv4(ip) else { return }
        ipv4Lock.lock()
        let domain = ipv4ToDomain[addr]
        ipv4ToDomain.removeValue(forKey: addr)
        ipv4Lock.unlock()
        if let domain = domain {
            domainToIPv4.removeValue(forKey: domain)
        }
    }

    /// Releases all mappings (e.g. on tunnel shutdown).
    public func releaseAll() {
        ipv4Lock.lock()
        ipv4ToDomain.removeAll()
        domainToIPv4.removeAll()
        ipv4Lock.unlock()
        ipv6ToDomain.removeAll()
        domainToIPv6.removeAll()
        ipv4NextOffset = 1
        ipv6NextLower = 1
    }

    // MARK: - Statistics

    /// Number of active IPv4 mappings.
    public var ipv4MappingCount: Int { ipv4ToDomain.count }

    /// Number of active IPv6 mappings.
    public var ipv6MappingCount: Int { ipv6ToDomain.count }

    /// Total active mappings.
    public var totalMappingCount: Int { ipv4MappingCount + ipv6MappingCount }

    /// Returns all currently mapped domains.
    public var allMappedDomains: [String] {
        Array(domainToIPv4.keys) + Array(domainToIPv6.keys)
    }

    /// Checks whether the given IPv4 address falls within the fake IP pool.
    public static func isFakeIPv4(_ ip: UInt32) -> Bool {
        let offset = ip &- ipv4Base
        return offset <= ipv4MaxOffset
    }

    /// Checks whether the given IPv6 prefix matches the fake pool.
    public static func isFakeIPv6Prefix(_ upper: UInt64) -> Bool {
        upper == ipv6Prefix
    }

    // MARK: - Formatting

    private func formatIPv4(_ ip: UInt32) -> String {
        "\(ip >> 24).\((ip >> 16) & 0xFF).\((ip >> 8) & 0xFF).\(ip & 0xFF)"
    }

    private func formatIPv6(_ upper: UInt64, lower: UInt64) -> String {
        if lower == 0 { return "fc00::" }
        return String(format: "fc00::%llx", lower)
    }

    private func parseIPv4(_ string: String) -> UInt32? {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var result: UInt32 = 0
        for p in parts {
            guard let val = UInt8(p) else { return nil }
            result = (result << 8) | UInt32(val)
        }
        return result
    }

    private func parseIPv6(_ string: String) -> (upper: UInt64, lower: UInt64)? {
        // Simplified: only handles our own fc00::N format.
        guard string.hasPrefix("fc00::") else { return nil }
        let rest = String(string.dropFirst(6))
        guard let lower = UInt64(rest, radix: 16) else { return nil }
        return (Self.ipv6Prefix, lower)
    }
}
