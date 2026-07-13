//===----------------------------------------------------------------------===//
//
//  SessionDiagnosticsTracker.swift
//  SwiftletCore — Kernel‑Level Live Session Diagnostics Tracker
//
//  A thread‑isolated global actor that audits the complete lifecycle of
//  every socket connection flowing through the proxy kernel.  Provides
//  atomic mutation APIs for tracking session creation, DNS resolution
//  timing, routing decisions, traffic metrics, and session teardown.
//
//  Architecture
//  ------------
//  ```
//  TUN / SOCKS5 / HTTP
//       │
//       ▼  trackNewSession(id:, inbound:, client:, target:)
//  ┌──────────────────────────────┐
//  │  SessionDiagnosticsTracker   │  ← actor (serial executor)
//  │                              │
//  │  ┌────────────────────────┐  │
//  │  │  [0 … 1023] snapshots  │  │  ← bounded ring buffer
//  │  │  activeSessions        │  │
//  │  └────────────────────────┘  │
//  │                              │
//  │  updateDNSInfo / RouteInfo   │
//  │  incrementTraffic            │
//  │  closeSession                │
//  └──────────────────────────────┘
//       │
//       ▼
//  Diagnostic queries (live / active / closed)
//  ```
//
//  Thread Safety
//  -------------
//  `SessionDiagnosticsTracker` is a Swift `actor` — all mutable state
//  is serialised by the actor executor.  Callers from any concurrency
//  domain can safely invoke its methods without explicit locking.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Session Snapshot

/// A type‑safe, Sendable blueprint of a single proxy session's
/// lifecycle metadata — from inbound arrival through to teardown.
public struct SessionSnapshot: Sendable, Identifiable, CustomStringConvertible {

    // MARK: - Identity

    /// Unique trace token assigned at inbound connection arrival.
    public let id: UUID

    /// Wall‑clock time of session creation.
    public let createdAt: Date

    // MARK: - Inbound

    /// The entry point type for this session.
    public let inboundType: SessionInboundType

    /// The client's source address string (e.g. `"192.168.1.100:54321"`).
    public let clientAddress: String

    /// The ultimate destination target (domain or IP:port).
    public let destinationTarget: String

    // MARK: - DNS

    /// Duration of the DNS resolution phase in microseconds, or `nil`
    /// if DNS was bypassed (e.g. direct IP connection).
    public private(set) var dnsLookupDurationMicros: UInt64?

    // MARK: - Routing

    /// The routing rule match description, or `nil` if not yet resolved.
    public private(set) var ruleMatched: String?

    // MARK: - Pool

    /// Whether the outbound connection was acquired from the hot‑path
    /// `OutboundConnectionPool` (as opposed to a fresh TCP connect).
    public private(set) var outboundPoolReused: Bool = false

    // MARK: - Traffic Metrics

    /// Cumulative bytes received from the client (inbound).
    public private(set) var bytesIn: UInt64 = 0

    /// Cumulative bytes sent to the remote (outbound).
    public private(set) var bytesOut: UInt64 = 0

    /// Session active duration in seconds (from `createdAt` to close).
    public private(set) var activeDuration: TimeInterval?

    /// The wall‑clock time when the session was closed, or `nil` if
    /// still active.
    public private(set) var closedAt: Date?

    // MARK: - State

    /// Whether the session is still active.
    public var isActive: Bool { closedAt == nil }

    // MARK: - Initialisation

    public init(
        id: UUID = UUID(),
        createdAt: Date = Date(),
        inboundType: SessionInboundType,
        clientAddress: String,
        destinationTarget: String
    ) {
        self.id = id
        self.createdAt = createdAt
        self.inboundType = inboundType
        self.clientAddress = clientAddress
        self.destinationTarget = destinationTarget
    }

    // MARK: - Description

    public var description: String {
        let status = isActive ? "ACTIVE" : "CLOSED"
        return "[\(status)] \(inboundType) \(clientAddress) → \(destinationTarget)"
    }

    // MARK: - Mutating Helpers (internal to the actor)

    mutating func setDNSLookup(micros: UInt64) {
        dnsLookupDurationMicros = micros
    }

    mutating func setRoute(matched: String) {
        ruleMatched = matched
    }

    mutating func markPoolReused() {
        outboundPoolReused = true
    }

    mutating func addTraffic(bytesIn: UInt64, bytesOut: UInt64) {
        self.bytesIn  &+= bytesIn
        self.bytesOut &+= bytesOut
    }

    mutating func close(at closeTime: Date = Date()) {
        closedAt = closeTime
        activeDuration = closeTime.timeIntervalSince(createdAt)
    }
}

// MARK: - Inbound Type

/// The entry‑point classification for a proxy session.
public enum SessionInboundType: Sendable, CustomStringConvertible, Equatable {

    /// Packet arrived via the TUN virtual interface (IP layer).
    case tun

    /// Connection accepted by the local SOCKS5 proxy.
    case socks5

    /// Connection accepted by the local HTTP CONNECT proxy.
    case httpConnect

    /// A custom / programmatic session source.
    case custom(String)

    // MARK: - Description

    public var description: String {
        switch self {
        case .tun:           return "TUN"
        case .socks5:        return "SOCKS5"
        case .httpConnect:   return "HTTP"
        case .custom(let s): return "CUSTOM(\(s))"
        }
    }
}

// MARK: - Diagnostics Tracker

/// The central actor‑based diagnostic repository.
///
/// ## Usage
/// ```swift
/// let tracker = SessionDiagnosticsTracker.shared
/// let id = await tracker.trackNewSession(
///     inbound: .tun,
///     client: "192.168.1.100:54321",
///     target: "api.example.com:443"
/// )
/// await tracker.updateDNSInfo(id: id, duration: 1234)
/// await tracker.closeSession(id: id)
/// let active = await tracker.activeSnapshots
/// ```
public actor SessionDiagnosticsTracker {

    // MARK: - Shared Instance

    /// The global singleton diagnostics tracker.
    public static let shared = SessionDiagnosticsTracker()

    // MARK: - Storage

    /// Maximum number of concurrent active sessions tracked.
    public let maxActiveSessions = 1024

    /// All snapshots (active + recently closed), keyed by UUID.
    private var snapshots: [UUID: SessionSnapshot] = [:]

    /// Ordered list of active session IDs for quick enumeration.
    private var activeOrder: [UUID] = []

    /// Total sessions ever created by this tracker.
    public private(set) var totalSessionsCreated: UInt64 = 0

    /// Total sessions closed.
    public private(set) var totalSessionsClosed: UInt64 = 0

    // MARK: - Initialisation

    public init() {}

    // MARK: - Session Lifecycle

    /// Creates a new session snapshot and returns its unique ID.
    ///
    /// If the active session count exceeds `maxActiveSessions`, the
    /// oldest idle session is evicted to make room.
    @discardableResult
    public func trackNewSession(
        id: UUID = UUID(),
        inbound: SessionInboundType,
        client: String,
        target: String
    ) -> UUID {
        // Evict if at capacity.
        while activeOrder.count >= maxActiveSessions, let oldest = activeOrder.first {
            snapshots.removeValue(forKey: oldest)
            activeOrder.removeFirst()
        }

        let snapshot = SessionSnapshot(
            id: id,
            inboundType: inbound,
            clientAddress: client,
            destinationTarget: target
        )
        snapshots[id] = snapshot
        activeOrder.append(id)
        totalSessionsCreated &+= 1
        return id
    }

    // MARK: - DNS

    /// Records the DNS resolution duration (in microseconds) for a
    /// session.
    public func updateDNSInfo(id: UUID, durationMicros: UInt64) {
        guard snapshots[id] != nil else { return }
        snapshots[id]?.setDNSLookup(micros: durationMicros)
    }

    // MARK: - Routing

    /// Records the routing rule match outcome for a session.
    public func updateRouteInfo(id: UUID, matched: String) {
        guard snapshots[id] != nil else { return }
        snapshots[id]?.setRoute(matched: matched)
    }

    // MARK: - Connection Pool

    /// Marks that the outbound connection was acquired from the pool
    /// rather than established fresh.
    public func markPoolReused(id: UUID) {
        guard snapshots[id] != nil else { return }
        snapshots[id]?.markPoolReused()
    }

    // MARK: - Traffic

    /// Atomically increments the byte counters for a session.
    public func incrementTraffic(id: UUID, bytesIn: UInt64, bytesOut: UInt64) {
        guard snapshots[id] != nil else { return }
        snapshots[id]?.addTraffic(bytesIn: bytesIn, bytesOut: bytesOut)
    }

    // MARK: - Session Teardown

    /// Closes an active session, recording its final duration.
    public func closeSession(id: UUID) {
        guard snapshots[id] != nil, snapshots[id]?.isActive == true else { return }
        snapshots[id]?.close()
        activeOrder.removeAll { $0 == id }
        totalSessionsClosed &+= 1
    }

    // MARK: - Queries

    /// All currently active snapshots.
    public var activeSnapshots: [SessionSnapshot] {
        activeOrder.compactMap { snapshots[$0] }.filter(\.isActive)
    }

    /// The most recent `count` closed snapshots (for historical audits).
    public func recentClosedSnapshots(count: Int = 100) -> [SessionSnapshot] {
        snapshots.values
            .filter { !$0.isActive }
            .sorted { ($0.closedAt ?? .distantPast) > ($1.closedAt ?? .distantPast) }
            .prefix(count)
            .map { $0 }
    }

    /// The total number of active sessions.
    public var activeCount: Int { activeOrder.count }

    /// The total number of stored snapshots (active + closed).
    public var totalStored: Int { snapshots.count }

    /// Purges all closed snapshots to free memory.
    @discardableResult
    public func purgeClosed() -> Int {
        let before = snapshots.count
        snapshots = snapshots.filter { $0.value.isActive }
        return before - snapshots.count
    }

    /// Resets the tracker to its initial empty state.
    public func resetAll() {
        snapshots.removeAll()
        activeOrder.removeAll()
        totalSessionsCreated = 0
        totalSessionsClosed = 0
    }
}
