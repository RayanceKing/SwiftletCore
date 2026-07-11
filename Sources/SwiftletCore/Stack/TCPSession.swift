//===----------------------------------------------------------------------===//
//
//  TCPSession.swift
//  SwiftletCore — User‑Space TCP Session Tracker
//
//  Maintains the virtual TCP connection state for every 4‑tuple
//  (source IP, source port, destination IP, destination port) that passes
//  through the TUN2Socks bridge.  Each session tracks the client and server
//  initial sequence numbers, the connection state, and the outbound SOCKS5
//  channel once the handshake completes.
//
//===----------------------------------------------------------------------===//

// MARK: - Session Key (4‑Tuple)

/// Uniquely identifies a TCP connection in the NAT table by its 4‑tuple.
///
/// For the TUN2Socks bridge, the key is built from the **original** packet
/// addresses (client → server direction) so that reply packets (server →
/// client) can be looked up by swapping source and destination.
public struct TCPSessionKey: Sendable, Hashable, CustomStringConvertible {

    /// Client (source) IPv4 address.
    public let sourceIP: IPv4Address
    /// Client (source) TCP port.
    public let sourcePort: UInt16
    /// Server (destination) IPv4 address.
    public let destinationIP: IPv4Address
    /// Server (destination) TCP port.
    public let destinationPort: UInt16

    public init(
        sourceIP: IPv4Address,
        sourcePort: UInt16,
        destinationIP: IPv4Address,
        destinationPort: UInt16
    ) {
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
        self.destinationIP = destinationIP
        self.destinationPort = destinationPort
    }

    /// Returns the *reverse* key (server → client) for looking up reply
    /// packets in the session table.
    public var reversed: TCPSessionKey {
        TCPSessionKey(
            sourceIP: destinationIP,
            sourcePort: destinationPort,
            destinationIP: sourceIP,
            destinationPort: sourcePort
        )
    }

    public var description: String {
        "\(sourceIP):\(sourcePort) → \(destinationIP):\(destinationPort)"
    }
}

// MARK: - Session State

/// The state of a virtual TCP connection tracked by the TUN2Socks bridge.
public enum TCPSessionState: Sendable, Equatable, CustomStringConvertible {
    /// Client sent SYN; server (bridge) replied with SYN‑ACK.
    /// Waiting for the client's ACK to complete the 3‑way handshake.
    case synReceived

    /// The 3‑way handshake is complete.  The session is ready to relay
    /// payload data to/from the SOCKS5 outbound.
    case established

    /// A FIN has been received from one side; waiting for the other side
    /// to acknowledge.
    case closing

    /// The connection is fully closed; the session is eligible for removal.
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

// MARK: - TCP Session

/// A tracked virtual TCP connection.
///
/// Each session holds the sequence‑number state required to translate between
/// the client's real TCP stack and the SOCKS5 byte stream on the other side.
///
/// - Note: This type is **not** `Sendable` — it is confined to the
///   `TUN2SocksBridge`'s serial dispatch context (event loop or actor).
public final class TCPSession {

    // MARK: Identity

    /// The 4‑tuple that uniquely identifies this connection.
    public let key: TCPSessionKey

    // MARK: Sequence Numbers

    /// The client's initial sequence number (extracted from the SYN segment).
    public let clientISN: UInt32

    /// The server's (bridge's) initial sequence number, randomly generated
    /// when the SYN‑ACK is synthesised.
    public let serverISN: UInt32

    // MARK: Mutable State

    /// Current TCP connection state.
    public var state: TCPSessionState

    /// The next sequence number the client is expected to send.
    /// Advances as data segments are processed.
    public var clientNextSeq: UInt32

    /// The next sequence number the server (bridge) will use when sending
    /// data back to the client.  Advances as outbound segments are produced.
    public var serverNextSeq: UInt32

    // MARK: SOCKS5 Outbound

    /// The SOCKS5 upstream channel, set once the TCP handshake completes and
    /// the bridge initiates a CONNECT to the destination.
    ///
    /// Before this is set, payload data is buffered (or, in the minimal
    /// implementation, data received before the SOCKS5 pipe is ready is
    /// silently dropped — production implementations would buffer it).
//    public var socksChannel: Channel?  // Future: SOCKS5 integration

    // MARK: Initialisation

    public init(
        key: TCPSessionKey,
        clientISN: UInt32,
        serverISN: UInt32
    ) {
        self.key = key
        self.clientISN = clientISN
        self.serverISN = serverISN
        self.state = .synReceived
        // After SYN: clientNextSeq = clientISN + 1 (the SYN consumes one
        // sequence number).  serverNextSeq = serverISN + 1 (the SYN‑ACK
        // consumes one sequence number).
        self.clientNextSeq = clientISN + 1
        self.serverNextSeq = serverISN + 1
    }

    /// Advance the expected client sequence number after successfully
    /// processing a data segment of `length` bytes.
    public func advanceClientSeq(by length: Int) {
        clientNextSeq = clientNextSeq &+ UInt32(length)
    }

    /// Advance the server sequence number after sending a data segment of
    /// `length` bytes to the client.
    public func advanceServerSeq(by length: Int) {
        serverNextSeq = serverNextSeq &+ UInt32(length)
    }
}

// MARK: - Session Registry

/// A thread‑safe (single‑context) registry of active TCP sessions indexed
/// by their 4‑tuple key.
///
/// All mutations must happen on the same serial context (the bridge's event
/// loop or dispatch queue).
public final class TCPSessionRegistry {

    /// The active sessions, keyed by 4‑tuple.
    private var storage: [TCPSessionKey: TCPSession] = [:]

    public init() {}

    // MARK: Queries

    /// Looks up a session by its client‑side key.
    public func lookup(_ key: TCPSessionKey) -> TCPSession? {
        storage[key]
    }

    /// Looks up a session by the *reverse* key (for server→client packets).
    public func lookup(reverseOf key: TCPSessionKey) -> TCPSession? {
        storage[key.reversed]
    }

    /// The number of active sessions.
    public var count: Int { storage.count }

    /// Whether the registry is empty.
    public var isEmpty: Bool { storage.isEmpty }

    // MARK: Mutations

    /// Registers a new session.  Replaces any existing session with the same
    /// key (callers should check for collisions first).
    public func register(_ session: TCPSession) {
        storage[session.key] = session
    }

    /// Removes a session by its key.
    @discardableResult
    public func remove(_ key: TCPSessionKey) -> TCPSession? {
        storage.removeValue(forKey: key)
    }

    /// Removes all sessions in the `.closed` state, returning the number
    /// of entries purged.
    @discardableResult
    public func purgeClosed() -> Int {
        let before = storage.count
        storage = storage.filter { $0.value.state != .closed }
        return before - storage.count
    }

    /// Removes all sessions (e.g. on bridge shutdown).
    public func removeAll() {
        storage.removeAll()
    }
}
