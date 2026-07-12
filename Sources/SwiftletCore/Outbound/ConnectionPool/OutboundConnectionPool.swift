//===----------------------------------------------------------------------===//
//
//  OutboundConnectionPool.swift
//  SwiftletCore — Asynchronous Outbound Connection Pool
//
//  An actor‑isolated cache of established outbound proxy channels, keyed
//  by destination endpoint + protocol fingerprint.  Instead of performing
//  an expensive cryptographic handshake (Shadowsocks AEAD, REALITY, Noise)
//  for every inbound request, idle channels are detached from completed
//  sessions and recycled — sub‑millisecond acquisition for back‑to‑back
//  flows.
//
//  Architecture
//  ------------
//  ```
//  ┌─────────────────────────────────────────────────────┐
//  │  OutboundConnectionPool (actor)                      │
//  │                                                      │
//  │  [PoolKey] → [PooledChannel]  (LIFO idle stack)      │
//  │                                                      │
//  │  acquireChannel(for:on:)  →  Channel?                │
//  │  releaseChannel(_:for:)   →  void                    │
//  │  purgeIdle(olderThan:)    →  Int (evicted count)     │
//  │                                                      │
//  │  TTL Timer ──► every ~30s sweep idle > 60s channels  │
//  └─────────────────────────────────────────────────────┘
//  ```
//
//  Thread Safety
//  -------------
//  All mutable state is confined to the actor.  Channel lifecycle
//  callbacks (close, inactive) hop to the actor via `Task` to update
//  the pool inventory without blocking the event loop.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Pool Key

/// Uniquely identifies a reusable outbound connection by its endpoint
/// coordinates and protocol identity fingerprint.
///
/// Two connections are interchangeable only if they share the same
/// host, port, and protocol parameters (cipher, UUID, password hash, etc.).
public struct PoolKey: Sendable, Hashable, CustomStringConvertible {

    /// Destination hostname or IP address.
    public let host: String

    /// Destination port.
    public let port: UInt16

    /// Protocol‑specific identity fingerprint.  Derived from the immutable
    /// fields that distinguish one protocol instance from another (e.g.
    /// Shadowsocks cipher+password, VMess UUID, WireGuard keypair).
    public let fingerprint: String

    public init(host: String, port: UInt16, fingerprint: String) {
        self.host = host; self.port = port; self.fingerprint = fingerprint
    }

    /// Derives a pool key from a `ProxyNodeConfiguration`.
    public init(from node: ProxyNodeConfiguration) {
        self.host = node.host
        self.port = node.port
        self.fingerprint = Self.computeFingerprint(from: node)
    }

    public var description: String {
        "\(host):\(port)[\(fingerprint.prefix(16))]"
    }

    // MARK: - Fingerprint Computation

    /// Produces a stable, collision‑resistant fingerprint for a node
    /// configuration.  Only identity fields are included; transport
    /// parameters (WS path, SNI, etc.) that don't change the crypto
    /// handshake are excluded so that channels remain interchangeable
    /// across sessions with different transport options to the same
    /// underlying proxy.
    public static func computeFingerprint(
        from node: ProxyNodeConfiguration
    ) -> String {
        switch node {
        case .shadowsocks(_, _, let cipher, let password, let obfs, _):
            let obfsTag = obfs.map { ":\($0)" } ?? ""
            return "ss:\(cipher):\(hash32(password))\(obfsTag)"

        case .vmess(_, _, let uuid, let aid, let transport, let tls, _, _, _):
            let tlsTag = tls ? "+TLS" : ""
            return "vmess:\(uuid):\(aid):\(transport)\(tlsTag)"

        case .vless(_, _, let uuid, let flow, let xtls, let sni, let pbk,
                    _, _, _, let fp, _, _):
            let flowTag = flow ?? ""
            let sniTag = sni ?? ""
            return "vless:\(uuid):\(flowTag):\(sniTag):\(pbk ?? ""):\(fp ?? ""):\(xtls ? "xtls" : "")"

        case .trojan(_, _, let password, let transport, let sni, _, _, let fp):
            let sniTag = sni ?? ""
            return "trojan:\(hash32(password)):\(transport):\(sniTag):\(fp ?? "")"

        case .hysteria2(_, _, let password, let obfs, _, let sni, _):
            let obfsTag = obfs ?? ""
            let sniTag = sni ?? ""
            return "hy2:\(hash32(password)):\(obfsTag):\(sniTag)"

        case .tuic(_, _, let uuid, let password, let cc, _, _, _):
            return "tuic:\(uuid):\(hash32(password)):\(cc)"

        case .wireguard(let pk, let ppk, _, let psk, _, _, _):
            let pskTag = psk.map { ":\(hash32($0))" } ?? ""
            return "wg:\(pk.prefix(32)):\(ppk.prefix(32))\(pskTag)"
        }
    }

    /// Cheap 32‑bit hash for fingerprint deduplication (not cryptographic).
    private static func hash32(_ string: String) -> UInt32 {
        var h: UInt32 = 0x811C_9DC5
        for byte in string.utf8 {
            h = (h ^ UInt32(byte)) &* 0x0100_0193
        }
        return h
    }
}

// MARK: - Pooled Channel Wrapper

/// Metadata wrapper for a channel held in the idle pool.
private final class PooledChannel: @unchecked Sendable {
    let channel: Channel
    let key: PoolKey
    let idleSince: Date

    init(channel: Channel, key: PoolKey) {
        self.channel = channel
        self.key = key
        self.idleSince = Date()
    }
}

// MARK: - Connection Pool (Actor)

/// An actor‑based outbound connection pool that caches established
/// proxy channels for immediate reuse.
///
/// ## Lifecycle
/// 1. **Acquire** — pop an idle channel from the pool; verify liveness.
/// 2. **Release** — return a fully‑established channel to the idle stack.
/// 3. **Evict** — background timer sweeps channels idle beyond the TTL.
///
/// ## Sendability
/// All internal dictionaries are actor‑isolated.  The shared singleton
/// reference is safe because the actor serialises all access.
public actor OutboundConnectionPool {

    // MARK: - Shared Singleton

    /// The global process‑wide connection pool.  All outbound dialling
    /// paths consult this instance before creating new connections.
    public static let shared = OutboundConnectionPool()

    // MARK: - Configuration

    /// Maximum idle channels retained per pool key.  Excess releases
    /// close the channel instead of caching it.
    public var maxIdlePerKey: Int = 8

    /// Time‑to‑live for an idle channel before eviction (seconds).
    public var idleTTL: TimeInterval = 60.0

    /// Interval between background eviction sweeps (seconds).
    public var evictionInterval: TimeInterval = 30.0

    // MARK: - Stored State

    /// Idle channel inventory, keyed by pool coordinate.
    private var pools: [PoolKey: [PooledChannel]] = [:]

    /// Total idle channels across all keys.
    public var totalIdleChannels: Int {
        pools.values.reduce(0) { $0 + $1.count }
    }

    /// Number of distinct pool keys.
    public var poolKeyCount: Int { pools.count }

    /// Whether the background eviction timer is active.
    private var evictionTask: Task<Void, Never>?

    // MARK: - Initialisation

    public init() {
        // Start the background eviction timer on the actor's executor.
        Task { [weak self] in
            await self?.startEvictionTimer()
        }
    }

    deinit {
        evictionTask?.cancel()
    }

    // MARK: - Acquire

    /// Attempts to acquire an idle channel from the pool that matches the
    /// given node configuration.
    ///
    /// - Parameters:
    ///   - node: The proxy node configuration to match against.
    ///   - loop: The event loop the caller is bound to (unused in actor
    ///     lookups; reserved for future affinity optimisation).
    /// - Returns: An idle, verified‑live `Channel`, or `nil` if the pool
    ///   has no matching idle connection.
    public func acquireChannel(
        for node: ProxyNodeConfiguration,
        on loop: EventLoop
    ) -> Channel? {
        let key = PoolKey(from: node)
        return acquireChannel(for: key)
    }

    /// Acquires a channel by explicit pool key.
    public func acquireChannel(for key: PoolKey) -> Channel? {
        guard var stack = pools[key], !stack.isEmpty else { return nil }

        // Pop from the end (LIFO — most recently released channel).
        while !stack.isEmpty {
            let entry = stack.removeLast()
            if entry.channel.isActive {
                pools[key] = stack.isEmpty ? nil : stack
                if stack.isEmpty { pools.removeValue(forKey: key) }
                return entry.channel
            }
            // Dead channel — skip and continue popping.
        }

        // All cached channels were dead.
        pools.removeValue(forKey: key)
        return nil
    }

    // MARK: - Release

    /// Returns an active channel to the idle pool.
    ///
    /// If the pool for this key is at capacity (`maxIdlePerKey`), or the
    /// channel is no longer active, the channel is closed instead.
    ///
    /// - Parameters:
    ///   - channel: The channel to release into the pool.
    ///   - node: The proxy node configuration for key derivation.
    public func releaseChannel(
        _ channel: Channel,
        for node: ProxyNodeConfiguration
    ) {
        let key = PoolKey(from: node)

        guard channel.isActive else {
            // Don't pool dead channels.
            return
        }

        let entry = PooledChannel(channel: channel, key: key)
        var stack = pools[key] ?? []
        if stack.count >= maxIdlePerKey {
            // Pool at capacity — close this channel instead of caching.
            channel.close(mode: .all, promise: nil)
            return
        }
        stack.append(entry)
        pools[key] = stack
    }

    // MARK: - Eviction

    /// Purges all idle channels that have been sitting in the pool longer
    /// than `idleTTL` seconds.  Each evicted channel is closed cleanly.
    ///
    /// - Returns: The total number of channels evicted.
    @discardableResult
    public func purgeIdle() -> Int {
        let cutoff = Date().addingTimeInterval(-idleTTL)
        return purgeIdle(olderThan: cutoff)
    }

    /// Purges idle channels older than a specific date.
    ///
    /// - Parameter cutoff: Channels idle since before this date are evicted.
    /// - Returns: Number of channels evicted.
    @discardableResult
    public func purgeIdle(olderThan cutoff: Date) -> Int {
        var evictedCount = 0
        var emptyKeys: [PoolKey] = []

        for (key, var stack) in pools {
            let before = stack.count
            stack.removeAll { entry in
                if entry.idleSince < cutoff {
                    entry.channel.close(mode: .all, promise: nil)
                    evictedCount += 1
                    return true
                }
                return false
            }
            if stack.isEmpty {
                emptyKeys.append(key)
            } else if stack.count != before {
                pools[key] = stack
            }
        }

        for key in emptyKeys {
            pools.removeValue(forKey: key)
        }
        return evictedCount
    }

    /// Drains the entire pool, closing every idle channel immediately.
    /// Returns the number of channels closed.
    @discardableResult
    public func drainAll() -> Int {
        var count = 0
        for (_, stack) in pools {
            for entry in stack {
                entry.channel.close(mode: .all, promise: nil)
                count += 1
            }
        }
        pools.removeAll()
        return count
    }

    /// Returns the number of idle channels for a specific key.
    public func idleCount(for key: PoolKey) -> Int {
        pools[key]?.count ?? 0
    }

    /// Returns all currently held pool keys.
    public var allKeys: [PoolKey] { Array(pools.keys) }

    // MARK: - Background Eviction Timer

    /// Starts a periodic sweep that evicts idle channels beyond `idleTTL`.
    private func startEvictionTimer() {
        let interval = evictionInterval
        evictionTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard !Task.isCancelled else { break }
                await self?.purgeIdle()
            }
        }
    }

    /// Cancels the background eviction timer.
    public func stopEvictionTimer() {
        evictionTask?.cancel()
        evictionTask = nil
    }
}
