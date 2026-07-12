//===----------------------------------------------------------------------===//
//
//  TCPSession.swift
//  SwiftletCore — User‑Space TCP Session Tracker
//
//  Maintains the virtual TCP connection state for every 4‑tuple passing
//  through the TUN2Socks bridge.  Each session tracks sequence numbers,
//  connection state, reactive sliding‑window backpressure (including
//  zero‑window squeeze), and a timeout‑controlled out‑of‑order segment
//  reassembly queue with forced evacuation.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Session Key (4‑Tuple)

public struct TCPSessionKey: Sendable, Hashable, CustomStringConvertible {
    public let sourceIP: IPv4Address
    public let sourcePort: UInt16
    public let destinationIP: IPv4Address
    public let destinationPort: UInt16

    public init(sourceIP: IPv4Address, sourcePort: UInt16,
                destinationIP: IPv4Address, destinationPort: UInt16) {
        self.sourceIP = sourceIP; self.sourcePort = sourcePort
        self.destinationIP = destinationIP; self.destinationPort = destinationPort
    }

    public var reversed: TCPSessionKey {
        TCPSessionKey(sourceIP: destinationIP, sourcePort: destinationPort,
                       destinationIP: sourceIP, destinationPort: sourcePort)
    }
    public var description: String {
        "\(sourceIP):\(sourcePort) → \(destinationIP):\(destinationPort)"
    }
}

// MARK: - Session State

public enum TCPSessionState: Sendable, Equatable, CustomStringConvertible {
    case synReceived
    case established
    case closing
    case closed

    public var description: String {
        switch self {
        case .synReceived: return "SYN_RECEIVED"
        case .established: return "ESTABLISHED"
        case .closing:     return "CLOSING"
        case .closed:      return "CLOSED"
        }
    }
}

// MARK: - Reassembly Slot

/// A single buffered out‑of‑order segment with its arrival timestamp for
/// timeout‑based eviction.
private struct ReassemblySlot {
    let data: Data
    let arrivedAt: Date
}

// MARK: - TCP Session

public final class TCPSession {

    // MARK: Identity

    public let key: TCPSessionKey

    // MARK: Sequence Numbers

    public let clientISN: UInt32
    public let serverISN: UInt32

    // MARK: Mutable State

    public var state: TCPSessionState
    public var clientNextSeq: UInt32
    public var serverNextSeq: UInt32

    // MARK: - Reactive Sliding Window (Backpressure)

    /// Current advertised receive window sent to the client in TCP headers.
    /// Ranges from 0 (zero‑window squeeze — completely halts the sender)
    /// up to `maxWindow` (65535 — full speed).
    public var advertisedWindow: UInt16 = 65535

    /// Minimum window (used when channel is completely unwritable).
    public static let minWindow: UInt16 = 0

    /// Maximum window (used when channel is fully writable).
    public static let maxWindow: UInt16 = 65535

    /// Whether the outbound channel is currently writable.  Set by the
    /// bridge when `channelWritabilityChanged` fires.
    public var isChannelWritable: Bool = true

    /// Timestamp of the last window adjustment (for hysteresis).
    public private(set) var lastWindowAdjustment: Date = Date()

    /// Adjusts the advertised window based on channel writability and
    /// buffered byte count.
    ///
    /// **Zero‑window squeeze**: when `isChannelWritable == false`, the
    /// window immediately drops to 0, forcing the host OS TCP stack to
    /// halt transmission instantly and trap bytes in the app sandbox.
    ///
    /// **Resumption handshake**: when writability is restored, the window
    /// scales back up to full size over successive calls.
    ///
    /// - Parameter bufferedBytes: Bytes waiting in the outbound channel's
    ///   write buffer (0 = empty, >128KB = extreme pressure).
    public func adjustWindow(bufferedBytes: Int) {
        lastWindowAdjustment = Date()

        // Zero-window squeeze: channel unwritable → halt sender NOW.
        guard isChannelWritable else {
            advertisedWindow = Self.minWindow
            return
        }

        // Graduated scaling based on buffer depth.
        switch bufferedBytes {
        case 0 ..< 8192:
            advertisedWindow = Self.maxWindow
        case 8192 ..< 24576:
            advertisedWindow = 32768
        case 24576 ..< 49152:
            advertisedWindow = 8192
        case 49152 ..< 98304:
            advertisedWindow = 4096
        case 98304 ..< 196608:
            advertisedWindow = 1024
        default:
            advertisedWindow = 512  // barely open — extreme pressure
        }
    }

    /// Called when the outbound channel's writability changes.
    /// - When `false`: window is squeezed to 0 immediately.
    /// - When `true`: window recovers to full on the next `adjustWindow` call.
    public func channelWritabilityChanged(writable: Bool) {
        isChannelWritable = writable
        if !writable {
            advertisedWindow = Self.minWindow
        }
        // Don't immediately restore — let adjustWindow() scale up
        // gradually based on actual buffer depth.
    }

    // MARK: - Timeout‑Controlled Reassembly Queue

    /// Maximum out‑of‑order segments that can be buffered.
    private static let maxReassemblySlots = 64

    /// Default eviction timeout for stalled segments.
    public static let reassemblyTimeout: TimeInterval = 0.750  // 750 ms

    /// Buffered out‑of‑order segments, keyed by sequence number.
    private var reassemblyBuffer: [UInt32: ReassemblySlot] = [:]

    /// The sequence number of the first missing segment (for ACK generation).
    public private(set) var firstMissingSeq: UInt32?

    // MARK: Reassembly — Insert

    /// Inserts an out‑of‑order segment.  If the buffer is full, the oldest
    /// segment is evicted to make room.
    ///
    /// - Returns: `true` if buffered, `false` if buffer was full and the
    ///   new segment was dropped.
    @discardableResult
    public func bufferOutOfOrder(seq: UInt32, data: Data) -> Bool {
        guard reassemblyBuffer.count < Self.maxReassemblySlots else {
            return false
        }
        reassemblyBuffer[seq] = ReassemblySlot(data: data, arrivedAt: Date())
        if firstMissingSeq == nil { firstMissingSeq = seq }
        return true
    }

    // MARK: Reassembly — Extract Contiguous

    /// Extracts all contiguous data starting from `clientNextSeq`.
    /// Returns the merged payload and advances `clientNextSeq`.
    public func extractContiguous() -> Data? {
        guard let slot = reassemblyBuffer[clientNextSeq] else { return nil }

        reassemblyBuffer.removeValue(forKey: clientNextSeq)
        var merged = Data()
        merged.append(slot.data)
        advanceClientSeq(by: slot.data.count)

        // Chain subsequent contiguous segments.
        while let next = reassemblyBuffer[clientNextSeq] {
            reassemblyBuffer.removeValue(forKey: clientNextSeq)
            merged.append(next.data)
            advanceClientSeq(by: next.data.count)
        }

        // Update firstMissingSeq.
        firstMissingSeq = reassemblyBuffer.keys.min()

        return merged
    }

    // MARK: Reassembly — Forced Evacuation (Timeout Catcher)

    /// Evicts and returns all buffered segments older than `timeout` seconds.
    /// The caller should forward the evicted data to the outbound tunnel
    /// and send a corrective duplicate ACK to trigger sender recovery.
    ///
    /// - Parameter timeout: Maximum age in seconds (default 750 ms).
    /// - Returns: Array of `(seq, data)` for evicted segments, sorted by
    ///   sequence number.  Empty if nothing is stale.
    public func evictStaleSegments(
        olderThan timeout: TimeInterval = reassemblyTimeout
    ) -> [(seq: UInt32, data: Data)] {
        let now = Date()
        let stale = reassemblyBuffer.filter {
            now.timeIntervalSince($0.value.arrivedAt) > timeout
        }

        guard !stale.isEmpty else { return [] }

        // Remove stale entries and sort by sequence number.
        for (seq, _) in stale { reassemblyBuffer.removeValue(forKey: seq) }

        // Slide `clientNextSeq` forward past the gap if this was the
        // first missing segment.
        let sorted = stale.map { (seq: $0.key, data: $0.value.data) }
            .sorted { $0.seq < $1.seq }

        if let firstStale = sorted.first,
           firstStale.seq == clientNextSeq {
            // This is the oldest missing segment — advance past it.
            advanceClientSeq(by: firstStale.data.count)
            // Also consume any subsequent contiguous evicted segments.
            for entry in sorted.dropFirst() {
                if entry.seq == clientNextSeq {
                    advanceClientSeq(by: entry.data.count)
                }
            }
        }

        firstMissingSeq = reassemblyBuffer.keys.min()
        return sorted
    }

    /// Forces eviction of ALL buffered segments (emergency drain).
    /// Returns all evicted data and resets the reassembly state.
    public func forceEvacuateAll() -> [(seq: UInt32, data: Data)] {
        let all = reassemblyBuffer.map { (seq: $0.key, data: $0.value.data) }
            .sorted { $0.seq < $1.seq }
        reassemblyBuffer.removeAll()
        firstMissingSeq = nil
        return all
    }

    // MARK: Reassembly — Diagnostics

    public var reassemblySlotsUsed: Int { reassemblyBuffer.count }

    /// The age (in seconds) of the oldest buffered segment, or 0 if empty.
    public var oldestSegmentAge: TimeInterval {
        guard let oldest = reassemblyBuffer.values.map({ $0.arrivedAt }).min()
        else { return 0 }
        return Date().timeIntervalSince(oldest)
    }

    public func flushReassemblyBuffer() {
        reassemblyBuffer.removeAll()
        firstMissingSeq = nil
    }

    // MARK: Initialisation

    public init(key: TCPSessionKey, clientISN: UInt32, serverISN: UInt32) {
        self.key = key
        self.clientISN = clientISN
        self.serverISN = serverISN
        self.state = .synReceived
        self.clientNextSeq = clientISN + 1
        self.serverNextSeq = serverISN + 1
    }

    public func advanceClientSeq(by length: Int) {
        clientNextSeq = clientNextSeq &+ UInt32(length)
    }

    public func advanceServerSeq(by length: Int) {
        serverNextSeq = serverNextSeq &+ UInt32(length)
    }
}

// MARK: - Session Registry

public final class TCPSessionRegistry {
    private var storage: [TCPSessionKey: TCPSession] = [:]
    public init() {}

    public func lookup(_ key: TCPSessionKey) -> TCPSession? { storage[key] }
    public func lookup(reverseOf key: TCPSessionKey) -> TCPSession? { storage[key.reversed] }
    public var count: Int { storage.count }
    public var isEmpty: Bool { storage.isEmpty }

    public func register(_ session: TCPSession) { storage[session.key] = session }

    @discardableResult
    public func remove(_ key: TCPSessionKey) -> TCPSession? {
        storage.removeValue(forKey: key)
    }

    @discardableResult
    public func purgeClosed() -> Int {
        let before = storage.count
        storage = storage.filter { $0.value.state != .closed }
        return before - storage.count
    }

    /// Purges sessions whose reassembly buffer has been stalled beyond
    /// the given timeout, forcibly evacuating their buffered data.
    /// Returns the number of sessions that had data evicted.
    @discardableResult
    public func purgeStalledReassembly(
        olderThan timeout: TimeInterval = TCPSession.reassemblyTimeout
    ) -> Int {
        var purged = 0
        for session in storage.values where session.oldestSegmentAge > timeout {
            let evicted = session.evictStaleSegments(olderThan: timeout)
            if !evicted.isEmpty { purged += 1 }
        }
        return purged
    }

    /// Iterates over all active sessions.
    public func forEach(_ body: (TCPSession) -> Void) {
        for session in storage.values { body(session) }
    }

    /// All currently registered sessions.
    public var allSessions: [TCPSession] { Array(storage.values) }

    public func removeAll() { storage.removeAll() }
}
