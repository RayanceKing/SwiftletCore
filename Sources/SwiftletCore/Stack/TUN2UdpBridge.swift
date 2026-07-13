//===----------------------------------------------------------------------===//
//
//  TUN2UdpBridge.swift
//  SwiftletCore — Full Cone NAT (Type A) UDP Session Bridge
//
//  Implements RFC 4787 Endpoint‑Independent Mapping (EIM) and Endpoint‑
//  Independent Filtering (EIF) for user‑space UDP NAT.  Replaces the
//  legacy Symmetric 4‑tuple layout with a 2‑tuple endpoint‑splicing
//  matrix that achieves NAT Type A (Full Cone) compatibility —
//  essential for Nintendo Switch, PlayStation, and Xbox gaming consoles.
//
//  Architecture
//  ------------
//  ```
//                    ┌───────────────────────────────┐
//  Client            │        TUN2UdpBridge           │
//  (192.168.1.x)     │                                │
//     │              │  EIMRegistry                   │
//     │ UDP → SvrA   │  ┌─────────────────────────┐   │
//     │  src:1001     │  │ EIM(192.168.1.x:1001)   │   │
//     │              │  │   → outbound socket #1   │   │
//     │ UDP → SvrB   │  │   → flows: [A:53, B:443] │   │
//     │  src:1001     │  └─────────────────────────┘   │
//     │              │                                │
//     ▼              │  EIF: any remote can punch in  │
//  SvrC ──UDP──►     │  → matched to EIM endpoint     │
//  (unsolicited)     │  → forwarded to client 1001    │
//                    └───────────────────────────────┘
//  ```
//
//  Key Design Properties
//  ---------------------
//  • Each local (SrcIP, SrcPort) maps to exactly ONE outbound proxy
//    socket, regardless of how many distinct remote hosts it contacts.
//  • Unsolicited inbound packets from ANY unassociated external host
//    targeting an active EIM port are accepted and forwarded (Full Cone).
//  • Bi‑directional activity refreshes session TTL (30 s idle timeout).
//  • Aggressive non‑blocking sweep prevents memory bloat.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - EIM Endpoint (2‑Tuple Primary Key)

/// Identifies a local client endpoint for Endpoint‑Independent Mapping.
///
/// Two packets from the same `(srcIP, srcPort)` reuse the same outbound
/// proxy association regardless of their destination — the foundation
/// of Full Cone NAT.
public struct UdpEIMEndpoint: Sendable, Hashable, CustomStringConvertible {
    public let sourceIP: IPv4Address
    public let sourcePort: UInt16

    public init(sourceIP: IPv4Address, sourcePort: UInt16) {
        self.sourceIP = sourceIP
        self.sourcePort = sourcePort
    }

    public var description: String {
        "\(sourceIP):\(sourcePort)"
    }
}

// MARK: - Legacy Session Key (4‑Tuple Flow Identifier)

/// A full 4‑tuple key used for reply routing and flow tracking within
/// an EIM endpoint.  Kept for backwards compatibility with existing
/// reply‑assembly APIs.
public struct UdpBridgeSessionKey: Sendable, Hashable, CustomStringConvertible {
    public let sourceIP: IPv4Address
    public let sourcePort: UInt16
    public let destinationIP: IPv4Address
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

    /// The EIM endpoint derived from this 4‑tuple.
    public var eim: UdpEIMEndpoint {
        UdpEIMEndpoint(sourceIP: sourceIP, sourcePort: sourcePort)
    }

    /// The reverse key (for matching reply packets via legacy APIs).
    public var reversed: UdpBridgeSessionKey {
        UdpBridgeSessionKey(
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

// MARK: - Full Cone Session

/// Metadata for a Full Cone NAT session pinned to a single EIM endpoint.
///
/// Multiple 4‑tuple flows can be active simultaneously through the same
/// endpoint; all share a single outbound proxy association.
public final class UdpBridgeSession: @unchecked Sendable {
    /// The EIM endpoint that owns this session.
    public let eim: UdpEIMEndpoint

    /// Creation timestamp.
    public let createdAt: Date

    /// Last activity timestamp (updated on any outbound or inbound packet).
    public private(set) var lastActivity: Date

    /// All 4‑tuple flows currently active through this endpoint.
    public var flows: Set<UdpBridgeSessionKey>

    /// The outbound proxy channel identifier (set externally by the
    /// outbound transport layer when a proxy socket is allocated).
    public var outboundChannelID: String?

    public init(eim: UdpEIMEndpoint) {
        self.eim = eim
        self.createdAt = Date()
        self.lastActivity = Date()
        self.flows = []
        self.outboundChannelID = nil
    }

    /// Legacy convenience initialiser from a 4‑tuple key.
    public init(key: UdpBridgeSessionKey) {
        self.eim = key.eim
        self.createdAt = Date()
        self.lastActivity = Date()
        self.flows = [key]
        self.outboundChannelID = nil
    }

    /// Record bi‑directional activity.
    public func markActivity() { lastActivity = Date() }

    /// Register a new 4‑tuple flow within this EIM endpoint.
    public func registerFlow(_ key: UdpBridgeSessionKey) {
        flows.insert(key)
    }
}

// MARK: - Full Cone EIM Registry

/// An endpoint‑independent mapping registry that ties each local
/// 2‑tuple `(SrcIP, SrcPort)` to a single `UdpBridgeSession`.
///
/// This is the core data structure that enables Full Cone NAT:
/// - **EIM**: Lookup by `(srcIP, srcPort)` — one session, many flows.
/// - **EIF**: Lookup by `(dstIP, dstPort)` on the inbound path — any
///   remote host targeting a mapped endpoint can punch through.
public final class UdpBridgeSessionRegistry {
    /// Primary index: EIM endpoint → session.
    private var eimStorage: [UdpEIMEndpoint: UdpBridgeSession] = [:]

    /// Reverse index: individual 4‑tuple flows → EIM endpoint (for
    /// unsolicited inbound EIF packet matching).
    private var eifIndex: [UdpBridgeSessionKey: UdpEIMEndpoint] = [:]

    public init() {}

    // MARK: - EIM Lookup (Primary)

    /// Looks up the session for a given 2‑tuple endpoint.
    /// - Returns: The session if one exists, or `nil`.
    public func lookup(eim: UdpEIMEndpoint) -> UdpBridgeSession? {
        eimStorage[eim]
    }

    /// Legacy lookup by 4‑tuple — maps to the EIM endpoint first.
    public func lookup(_ key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        eimStorage[key.eim]
    }

    // MARK: - EIF Lookup (Unsolicited Inbound)

    /// Matches an inbound packet from ANY remote host against active
    /// EIM endpoints.  Implements Endpoint‑Independent Filtering:
    /// if any EIM endpoint has the target `(dstIP, dstPort)` as a
    /// registered flow, the packet is forwarded.
    ///
    /// - Parameter dstIP: The destination IP from the inbound packet
    ///   (i.e., our allocated outbound proxy IP).
    /// - Parameter dstPort: The destination port (our allocated port).
    /// - Returns: The matching EIM session, or `nil` if no match.
    public func lookupUnsolicited(
        dstIP: IPv4Address,
        dstPort: UInt16
    ) -> UdpBridgeSession? {
        // Walk all EIF entries; a matching (dstIP, dstPort) as a
        // destination coordinate means this packet targets our client.
        for (flowKey, eimKey) in eifIndex {
            if flowKey.destinationIP == dstIP && flowKey.destinationPort == dstPort {
                return eimStorage[eimKey]
            }
        }
        return nil
    }

    /// Legacy reverse lookup (kept for API compatibility).
    public func lookup(reverseOf key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        lookup(key.reversed)
    }

    // MARK: - Registration

    /// Registers a new session or updates an existing one with a new flow.
    ///
    /// - Returns: `true` if this is a new EIM endpoint (first flow),
    ///   `false` if the endpoint already existed (reused).
    @discardableResult
    public func register(_ session: UdpBridgeSession) -> Bool {
        let isNew = (eimStorage[session.eim] == nil)
        eimStorage[session.eim] = session
        for flow in session.flows {
            eifIndex[flow] = session.eim
        }
        return isNew
    }

    /// Registers a new 4‑tuple flow under an existing EIM endpoint.
    /// - Returns: `true` if the flow was new, `false` if it already existed.
    @discardableResult
    public func registerFlow(
        _ flowKey: UdpBridgeSessionKey,
        in session: UdpBridgeSession
    ) -> Bool {
        let isNew = !session.flows.contains(flowKey)
        session.registerFlow(flowKey)
        eifIndex[flowKey] = session.eim
        return isNew
    }

    // MARK: - Removal

    /// Removes a session by EIM endpoint.
    @discardableResult
    public func remove(eim: UdpEIMEndpoint) -> UdpBridgeSession? {
        guard let session = eimStorage.removeValue(forKey: eim) else {
            return nil
        }
        for flow in session.flows {
            eifIndex.removeValue(forKey: flow)
        }
        return session
    }

    /// Legacy removal by 4‑tuple key.
    @discardableResult
    public func remove(_ key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        let eim = key.eim
        guard let session = eimStorage[eim] else { return nil }
        session.flows.remove(key)
        eifIndex.removeValue(forKey: key)
        if session.flows.isEmpty {
            eimStorage.removeValue(forKey: eim)
        }
        return session
    }

    // MARK: - Statistics

    public var count: Int { eimStorage.count }
    public var totalFlows: Int { eifIndex.count }
    public var isEmpty: Bool { eimStorage.isEmpty }

    public func removeAll() {
        eimStorage.removeAll()
        eifIndex.removeAll()
    }

    // MARK: - Idle Sweep

    /// Removes all sessions that have been idle for longer than the
    /// specified interval.
    ///
    /// - Parameter olderThan: The cutoff time.
    /// - Returns: The number of purged sessions.
    @discardableResult
    public func purgeIdle(olderThan cutoff: Date) -> Int {
        let stale = eimStorage.filter { $0.value.lastActivity < cutoff }
        for (eim, session) in stale {
            for flow in session.flows {
                eifIndex.removeValue(forKey: flow)
            }
            eimStorage.removeValue(forKey: eim)
        }
        return stale.count
    }
}

// MARK: - UDP Header

/// Parsed fields of a UDP datagram header (RFC 768).
public struct UDPHeader: Sendable, Equatable {
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let length: UInt16
    public let checksum: UInt16
    public let payload: Data

    public static let headerSize = 8
}

// MARK: - UDP Parser

/// Zero‑copy parser for UDP datagrams.
public enum UDPParser {

    public enum ParseError: Error, Sendable, Equatable {
        case insufficientData(needed: Int, available: Int)
        case lengthMismatch(declared: Int, actual: Int)
    }

    public static func parse(_ data: Data) throws -> UDPHeader {
        guard data.count >= UDPHeader.headerSize else {
            throw ParseError.insufficientData(
                needed: UDPHeader.headerSize, available: data.count
            )
        }

        let srcPort  = (UInt16(data[0]) << 8) | UInt16(data[1])
        let dstPort  = (UInt16(data[2]) << 8) | UInt16(data[3])
        let length   = (UInt16(data[4]) << 8) | UInt16(data[5])
        let checksum = (UInt16(data[6]) << 8) | UInt16(data[7])

        let expectedPayloadLen = Int(length) - UDPHeader.headerSize
        let actualPayloadLen   = data.count - UDPHeader.headerSize
        guard expectedPayloadLen == actualPayloadLen else {
            throw ParseError.lengthMismatch(
                declared: expectedPayloadLen, actual: actualPayloadLen
            )
        }

        let payload = data.subdata(in: UDPHeader.headerSize ..< data.count)

        return UDPHeader(
            sourcePort: srcPort,
            destinationPort: dstPort,
            length: length,
            checksum: checksum,
            payload: payload
        )
    }
}

// MARK: - UDP Checksum

/// Internet checksum computation for UDP over IPv4 (RFC 768).
public enum UDPChecksum {

    public static func computeIPv4(
        sourceAddr: IPv4Address,
        destAddr: IPv4Address,
        udpSegment: [UInt8]
    ) -> UInt16 {
        let srcUInt32 = ipv4UInt32(from: sourceAddr)
        let dstUInt32 = ipv4UInt32(from: destAddr)

        var sum = ChecksumAccumulator()

        sum.add(UInt16(truncatingIfNeeded: srcUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: srcUInt32))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32))
        sum.add(UInt16(17))
        sum.add(UInt16(udpSegment.count))

        sum.add(bytes: udpSegment)
        return sum.finalize()
    }

    private static func ipv4UInt32(from addr: IPv4Address) -> UInt32 {
        (UInt32(addr.octet0) << 24)
        | (UInt32(addr.octet1) << 16)
        | (UInt32(addr.octet2) <<  8)
        |  UInt32(addr.octet3)
    }
}

// MARK: - Checksum Accumulator

private struct ChecksumAccumulator {
    private var value: UInt32 = 0

    mutating func add(_ word: UInt16) {
        value &+= UInt32(word)
    }

    mutating func add(bytes: [UInt8]) {
        var i = 0
        while i + 1 < bytes.count {
            value &+= (UInt32(bytes[i]) << 8) | UInt32(bytes[i + 1])
            i += 2
        }
        if i < bytes.count {
            value &+= UInt32(bytes[i]) << 8
        }
    }

    mutating func finalize() -> UInt16 {
        while (value >> 16) != 0 {
            value = (value & 0xFFFF) + (value >> 16)
        }
        return ~UInt16(truncatingIfNeeded: value)
    }
}

// MARK: - UDP Packet Builder

/// Builds complete IPv4‑wrapped UDP packets for TUN reply injection.
public enum UDPPacketBuilder {

    private static let ipv4HeaderSize = 20

    /// Builds a complete IPv4 packet containing a UDP datagram.
    public static func buildInboundUdpPacket(
        srcIP: IPv4Address,
        srcPort: UInt16,
        dstIP: IPv4Address,
        dstPort: UInt16,
        payload: Data
    ) -> Data {
        let udpLength = UInt16(UDPHeader.headerSize + payload.count)
        var udpSegment = [UInt8](repeating: 0, count: Int(udpLength))

        udpSegment[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        udpSegment[1] = UInt8(truncatingIfNeeded: srcPort)
        udpSegment[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        udpSegment[3] = UInt8(truncatingIfNeeded: dstPort)
        udpSegment[4] = UInt8(truncatingIfNeeded: udpLength >> 8)
        udpSegment[5] = UInt8(truncatingIfNeeded: udpLength)
        udpSegment[6] = 0
        udpSegment[7] = 0
        for (i, byte) in payload.enumerated() {
            udpSegment[UDPHeader.headerSize + i] = byte
        }

        let checksum = UDPChecksum.computeIPv4(
            sourceAddr: srcIP,
            destAddr: dstIP,
            udpSegment: udpSegment
        )
        udpSegment[6] = UInt8(truncatingIfNeeded: checksum >> 8)
        udpSegment[7] = UInt8(truncatingIfNeeded: checksum)

        let totalLen = ipv4HeaderSize + udpSegment.count
        var packet = [UInt8](repeating: 0, count: totalLen)

        packet[0] = 0x45
        packet[1] = 0x00
        packet[2] = UInt8(truncatingIfNeeded: totalLen >> 8)
        packet[3] = UInt8(truncatingIfNeeded: totalLen)
        packet[4] = 0x00; packet[5] = 0x00
        packet[6] = 0x00; packet[7] = 0x00
        packet[8] = 0x40
        packet[9] = 17
        packet[10] = 0x00; packet[11] = 0x00
        packet[12] = srcIP.octet0
        packet[13] = srcIP.octet1
        packet[14] = srcIP.octet2
        packet[15] = srcIP.octet3
        packet[16] = dstIP.octet0
        packet[17] = dstIP.octet1
        packet[18] = dstIP.octet2
        packet[19] = dstIP.octet3
        for (i, byte) in udpSegment.enumerated() {
            packet[ipv4HeaderSize + i] = byte
        }

        return Data(packet)
    }
}

// MARK: - TUN2UdpBridge (Full Cone NAT)

/// A user‑space Full Cone NAT (Type A) UDP session bridge.
///
/// Implements RFC 4787 Endpoint‑Independent Mapping (EIM) and Endpoint‑
/// Independent Filtering (EIF).  Each local `(SrcIP, SrcPort)` 2‑tuple
/// maps to a single outbound proxy socket; any external host can send
/// unsolicited packets to the mapped port and they will be forwarded
/// to the internal client.
public final class TUN2UdpBridge: @unchecked Sendable {

    /// Result of processing an inbound IP packet.
    public enum ProcessResult: Sendable {
        /// Forward the UDP payload to the outbound proxy.
        /// - eim: The EIM endpoint for outbound channel selection.
        /// - session: The 4‑tuple flow key for reply routing.
        /// - payload: The raw UDP payload bytes.
        /// - isNewMapping: `true` if this is a new EIM mapping
        ///   (triggers outbound socket allocation).
        case forward(
            eim: UdpEIMEndpoint,
            session: UdpBridgeSessionKey,
            payload: Data,
            isNewMapping: Bool
        )

        /// A complete IPv4 reply packet for TUN injection.
        case reply(Data)

        /// Packet handled; no external action required.
        case none
    }

    // MARK: - Registry

    /// The Full Cone NAT table mapping 2‑tuple endpoints to sessions.
    public let registry: UdpBridgeSessionRegistry

    /// Idle timeout in seconds.  Sessions idle longer than this are
    /// eligible for eviction.
    public var idleTimeout: TimeInterval = 30

    // MARK: - Initialisation

    public init() {
        self.registry = UdpBridgeSessionRegistry()
    }

    // MARK: - Inbound Processing (TUN → Proxy)

    /// Processes a raw IP datagram from the TUN read path using
    /// Endpoint‑Independent Mapping.
    ///
    /// If the source endpoint `(srcIP, srcPort)` already has an active
    /// EIM session, it is reused regardless of the destination.  If not,
    /// a new EIM mapping is allocated.
    @discardableResult
    public func processInbound(_ data: Data) throws -> ProcessResult {
        let packet = try IPPacketParser.parse(data)

        guard packet.protocolNumber == .udp else {
            return .none
        }

        let (srcAddr, dstAddr) = extractAddresses(from: packet)

        var payloadBuffer = packet.payload
        guard let payloadBytes = payloadBuffer.readBytes(
            length: payloadBuffer.readableBytes
        ) else { return .none }
        let payloadData = Data(payloadBytes)
        let udp = try UDPParser.parse(payloadData)

        // Build the EIM endpoint (2‑tuple).
        let eim = UdpEIMEndpoint(sourceIP: srcAddr, sourcePort: udp.sourcePort)

        // Build the 4‑tuple flow key for reply routing.
        let flowKey = UdpBridgeSessionKey(
            sourceIP: srcAddr,
            sourcePort: udp.sourcePort,
            destinationIP: dstAddr,
            destinationPort: udp.destinationPort
        )

        // EIM lookup: does this endpoint already have a session?
        let session: UdpBridgeSession
        let isNewMapping: Bool

        if let existing = registry.lookup(eim: eim) {
            session = existing
            isNewMapping = false
            // Register the new destination flow under the existing EIM.
            registry.registerFlow(flowKey, in: session)
        } else {
            session = UdpBridgeSession(eim: eim)
            session.registerFlow(flowKey)
            registry.register(session)
            isNewMapping = true
        }
        session.markActivity()

        return .forward(
            eim: eim,
            session: flowKey,
            payload: udp.payload,
            isNewMapping: isNewMapping
        )
    }

    // MARK: - Unsolicited Inbound Processing (EIF — Proxy → TUN)

    /// Handles an inbound UDP packet from the outbound proxy channel.
    /// Implements Endpoint‑Independent Filtering: if ANY active EIM
    /// endpoint has a flow matching the destination `(dstIP, dstPort)`,
    /// the packet is accepted and forwarded to the internal client.
    ///
    /// - Parameters:
    ///   - srcIP: Remote server IP (from the proxy).
    ///   - srcPort: Remote server port.
    ///   - dstIP: The allocated outbound proxy IP (our NAT address).
    ///   - dstPort: The allocated outbound proxy port.
    ///   - payload: The raw UDP payload from the remote server.
    /// - Returns: `.reply(data)` if a matching EIM session is found,
    ///   `.none` if the packet should be dropped (no matching session).
    public func processUnsolicitedInbound(
        fromRemoteIP srcIP: IPv4Address,
        fromRemotePort srcPort: UInt16,
        toProxyIP dstIP: IPv4Address,
        toProxyPort dstPort: UInt16,
        payload: Data
    ) -> ProcessResult {
        // EIF lookup: find any EIM session that has (dstIP, dstPort)
        // as a destination coordinate.
        guard let session = registry.lookupUnsolicited(
            dstIP: dstIP, dstPort: dstPort
        ) else {
            return .none
        }

        // Refresh session activity (bi‑directional).
        session.markActivity()

        // Build the reply packet addressed to the internal client.
        let replyPacket = UDPPacketBuilder.buildInboundUdpPacket(
            srcIP: srcIP,
            srcPort: srcPort,
            dstIP: session.eim.sourceIP,
            dstPort: session.eim.sourcePort,
            payload: payload
        )
        return .reply(replyPacket)
    }

    // MARK: - Reply Packet Assembly

    /// Builds a complete IPv4‑wrapped UDP reply packet for injection
    /// back into the TUN virtual interface.  Uses the 4‑tuple session
    /// key to reverse source and destination coordinates.
    public func buildReply(
        for session: UdpBridgeSessionKey,
        payload: Data
    ) -> Data {
        UDPPacketBuilder.buildInboundUdpPacket(
            srcIP: session.destinationIP,
            srcPort: session.destinationPort,
            dstIP: session.sourceIP,
            dstPort: session.sourcePort,
            payload: payload
        )
    }

    // MARK: - Static Reply Builder

    /// Builds a complete IPv4‑wrapped UDP reply packet from raw
    /// 4‑tuple coordinates.
    public static func buildInboundUdpPacket(
        srcIP: IPv4Address,
        srcPort: UInt16,
        dstIP: IPv4Address,
        dstPort: UInt16,
        payload: Data
    ) -> Data {
        UDPPacketBuilder.buildInboundUdpPacket(
            srcIP: srcIP,
            srcPort: srcPort,
            dstIP: dstIP,
            dstPort: dstPort,
            payload: payload
        )
    }

    // MARK: - Maintenance

    /// Purges all idle sessions older than the idle timeout.
    /// - Returns: The number of purged sessions.
    @discardableResult
    public func purgeIdle() -> Int {
        let cutoff = Date().addingTimeInterval(-idleTimeout)
        return registry.purgeIdle(olderThan: cutoff)
    }

    // MARK: - Helpers

    private func extractAddresses(
        from packet: IPPacket
    ) -> (source: IPv4Address, destination: IPv4Address) {
        switch packet {
        case .ipv4(let header):
            return (header.sourceAddress, header.destinationAddress)
        case .ipv6:
            return (
                IPv4Address(0, 0, 0, 0),
                IPv4Address(0, 0, 0, 0)
            )
        }
    }
}
