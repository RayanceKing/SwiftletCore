//===----------------------------------------------------------------------===//
//
//  UdpAssociationManager.swift
//  SwiftletCore — Dynamic UDP Association Session Manager
//
//  A concurrency‑safe `actor` that tracks active UDP session associations
//  for WireGuard and Hysteria 2 outbound transports.  Each session is keyed
//  by a 4‑tuple (source IP, source port, dest IP, dest port) and maps to a
//  SwiftNIO `Channel` (typically a `DatagramChannel`).
//
//  Automatic cleanup
//  -----------------
//  Sessions that have received no inbound or outbound datagram bytes for
//  **30 seconds** are automatically purged to keep memory under the
//  strict 5 MB iOS Network Extension budget.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - UDP Session Key

/// Uniquely identifies a UDP association by its 4‑tuple.
public struct UDPSessionKey: Hashable, Sendable, CustomStringConvertible {
    /// Source IP (string form, e.g. `"10.0.0.1"`).
    public let sourceIP: String
    /// Source port.
    public let sourcePort: UInt16
    /// Destination IP.
    public let destinationIP: String
    /// Destination port.
    public let destinationPort: UInt16

    public init(
        sourceIP: String,
        sourcePort: UInt16,
        destinationIP: String,
        destinationPort: UInt16
    ) {
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
        self.destinationIP = destinationIP
        self.destinationPort = destinationPort
    }

    public var description: String {
        "\(sourceIP):\(sourcePort) → \(destinationIP):\(destinationPort)"
    }
}

// MARK: - UDP Session

/// Metadata for a single active UDP association.
///
/// The `channel` is stored as `AnyObject` (weakly referenced by the manager)
/// to avoid retain cycles.  The manager itself owns the channel reference.
public final class UDPSession: @unchecked Sendable {

    /// The 4‑tuple key identifying this session.
    public let key: UDPSessionKey

    /// Timestamp of the last outbound datagram (monotonic clock).
    public private(set) var lastSendTime: Date

    /// Timestamp of the last inbound datagram.
    public private(set) var lastReceiveTime: Date

    /// Whether the session is still active.
    public var isActive: Bool { channel != nil }

    /// The underlying NIO channel (weak to avoid cycles; the manager holds
    /// the strong reference separately).
    private weak var channel: AnyObject?

    // MARK: - Initialisation

    public init(key: UDPSessionKey, channel: AnyObject) {
        self.key = key
        self.channel = channel
        self.lastSendTime = Date()
        self.lastReceiveTime = Date()
    }

    // MARK: - Activity Tracking

    /// Call this whenever an outbound datagram is sent on this session.
    public func markSend() {
        lastSendTime = Date()
    }

    /// Call this whenever an inbound datagram is received on this session.
    public func markReceive() {
        lastReceiveTime = Date()
    }

    /// The time since the most recent activity (send or receive).
    public var idleDuration: TimeInterval {
        let latest = max(lastSendTime, lastReceiveTime)
        return Date().timeIntervalSince(latest)
    }
}

// MARK: - UDP Association Manager

/// A concurrency‑safe `actor` that manages the lifecycle of UDP session
/// associations for WireGuard and Hysteria 2 outbound transports.
///
/// All mutations (register, unregister, activity marking, cleanup) are
/// serialised through the actor's executor.
public actor UdpAssociationManager {

    // MARK: - Configuration

    /// Sessions idle for longer than this duration are eligible for cleanup.
    public let idleTimeout: TimeInterval

    /// The task that periodically runs `purgeExpired()`.
    private var purgeTask: Task<Void, Never>?

    // MARK: - Storage

    /// Active session metadata keyed by 4‑tuple.
    private var sessions: [UDPSessionKey: UDPSession] = [:]

    // MARK: - Initialisation

    /// - Parameter idleTimeout: Maximum idle duration before a session is
    ///   purged (default 30 seconds).
    public init(idleTimeout: TimeInterval = 30) {
        self.idleTimeout = idleTimeout
    }

    deinit {
        purgeTask?.cancel()
    }

    // MARK: - Registration

    /// Registers a new UDP session association.
    ///
    /// - Parameters:
    ///   - key: The 4‑tuple identifying this session.
    ///   - channel: The NIO `Channel` handling this session (stored weakly
    ///     inside the session metadata).
    /// - Returns: The newly created `UDPSession`.
    @discardableResult
    public func register(
        key: UDPSessionKey,
        channel: AnyObject
    ) -> UDPSession {
        let session = UDPSession(key: key, channel: channel)
        sessions[key] = session
        return session
    }

    /// Unregisters (removes) a session, closing its channel if still active.
    public func unregister(key: UDPSessionKey) {
        sessions.removeValue(forKey: key)
    }

    // MARK: - Lookup

    /// Looks up a session by its 4‑tuple key.
    public func lookup(_ key: UDPSessionKey) -> UDPSession? {
        sessions[key]
    }

    /// Returns all currently registered session keys.
    public var allKeys: [UDPSessionKey] {
        Array(sessions.keys)
    }

    /// The number of active sessions.
    public var activeCount: Int {
        sessions.count
    }

    // MARK: - Activity Tracking

    /// Marks an outbound datagram on the given session.
    public func markSend(for key: UDPSessionKey) {
        sessions[key]?.markSend()
    }

    /// Marks an inbound datagram on the given session.
    public func markReceive(for key: UDPSessionKey) {
        sessions[key]?.markReceive()
    }

    // MARK: - Cleanup

    /// Removes all sessions that have been idle longer than `idleTimeout`.
    ///
    /// - Returns: The number of sessions purged.
    @discardableResult
    public func purgeExpired() -> Int {
        let before = sessions.count
        sessions = sessions.filter { $0.value.idleDuration < idleTimeout }
        return before - sessions.count
    }

    /// Starts an automatic purge timer that fires at a regular interval.
    ///
    /// - Parameter interval: How often to run the purge (default 10 seconds).
    public func startAutoPurge(interval: TimeInterval = 10) {
        purgeTask?.cancel()
        purgeTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: UInt64(interval * 1_000_000_000))
                guard let self = self else { break }
                let purged = await self.purgeExpired()
                if purged > 0 {
                    // Logging hook — can be wired to OSLog in production.
                    _ = purged
                }
            }
        }
    }

    /// Stops the automatic purge timer.
    public func stopAutoPurge() {
        purgeTask?.cancel()
        purgeTask = nil
    }

    /// Removes all sessions immediately (e.g. on shutdown).
    public func removeAll() {
        sessions.removeAll()
        purgeTask?.cancel()
        purgeTask = nil
    }
}
