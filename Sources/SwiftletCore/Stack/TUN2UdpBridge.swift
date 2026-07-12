//===----------------------------------------------------------------------===//
//
//  TUN2UdpBridge.swift
//  SwiftletCore — User‑Space UDP Session NAT Bridge
//
//  Expands the TUN‑layer stack to process Layer 3 UDP packets.  It parses
//  raw IP datagrams carrying UDP segments, maintains a 4‑tuple NAT session
//  registry, forwards inner payloads to the outbound proxy pipeline, and
//  assembles reverse‑direction reply packets for injection back into the
//  Apple `packetFlow` virtual channel.
//
//  Architecture
//  ------------
//  ```
//  NEPacketTunnelFlow (TUN read)
//       │
//       ▼
//  TUN2UdpBridge.processInbound(_:)
//       │
//       ├── new session?  → register in NAT table
//       ├── existing?     → lookup, forward payload
//       └── reply?        → buildInboundUdpPacket → TUN write
//       │
//       ▼
//  UdpAssociationManager → Outbound Proxy
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - UDP Session Key

/// Uniquely identifies a virtual UDP session by its 4‑tuple.
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

    /// The reverse key (for matching reply packets).
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

// MARK: - UDP Session

/// Metadata for a single virtual UDP session tracked by the bridge.
public final class UdpBridgeSession: @unchecked Sendable {
    public let key: UdpBridgeSessionKey
    public let createdAt: Date
    public private(set) var lastActivity: Date

    public init(key: UdpBridgeSessionKey) {
        self.key = key
        self.createdAt = Date()
        self.lastActivity = Date()
    }

    public func markActivity() { lastActivity = Date() }
}

// MARK: - UDP Session Registry

/// A thread‑confined registry of active UDP sessions indexed by 4‑tuple.
public final class UdpBridgeSessionRegistry {
    private var storage: [UdpBridgeSessionKey: UdpBridgeSession] = [:]

    public init() {}

    public func lookup(_ key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        storage[key]
    }

    public func lookup(reverseOf key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        storage[key.reversed]
    }

    public func register(_ session: UdpBridgeSession) {
        storage[session.key] = session
    }

    @discardableResult
    public func remove(_ key: UdpBridgeSessionKey) -> UdpBridgeSession? {
        storage.removeValue(forKey: key)
    }

    public var count: Int { storage.count }
    public var isEmpty: Bool { storage.isEmpty }

    public func removeAll() { storage.removeAll() }
}

// MARK: - UDP Header

/// Parsed fields of a UDP datagram header (RFC 768).
///
/// The UDP header is exactly 8 bytes:
/// ```
/// [0…1] Source Port      (big‑endian UInt16)
/// [2…3] Destination Port (big‑endian UInt16)
/// [4…5] Length           (header + payload, big‑endian UInt16)
/// [6…7] Checksum         (big‑endian UInt16)
/// ```
public struct UDPHeader: Sendable, Equatable {
    public let sourcePort: UInt16
    public let destinationPort: UInt16
    public let length: UInt16
    public let checksum: UInt16
    public let payload: Data

    /// Fixed size of the UDP header in bytes.
    public static let headerSize = 8
}

// MARK: - UDP Parser

/// Zero‑copy parser for UDP datagrams.
public enum UDPParser {

    public enum ParseError: Error, Sendable, Equatable {
        case insufficientData(needed: Int, available: Int)
        case lengthMismatch(declared: Int, actual: Int)
    }

    /// Parses a UDP header and payload from raw bytes.
    ///
    /// - Parameter data: The transport‑layer bytes (UDP header + payload).
    /// - Returns: A parsed `UDPHeader`.
    /// - Throws: `ParseError` if the data is too short or the declared
    ///   length does not match.
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
///
/// The pseudo‑header is identical to TCP's, except the protocol field
/// carries 17 (UDP) instead of 6 (TCP).
public enum UDPChecksum {

    /// Computes the UDP checksum for an IPv4 pseudo‑header.
    ///
    /// - Parameters:
    ///   - sourceAddr: IPv4 source address.
    ///   - destAddr: IPv4 destination address.
    ///   - udpSegment: The complete UDP segment (header + payload) with
    ///     the checksum field zeroed.
    /// - Returns: The 16‑bit one's‑complement checksum.
    public static func computeIPv4(
        sourceAddr: IPv4Address,
        destAddr: IPv4Address,
        udpSegment: [UInt8]
    ) -> UInt16 {
        let srcUInt32 = ipv4UInt32(from: sourceAddr)
        let dstUInt32 = ipv4UInt32(from: destAddr)

        var sum = ChecksumAccumulator()

        // IPv4 pseudo‑header.
        sum.add(UInt16(truncatingIfNeeded: srcUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: srcUInt32))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32))
        sum.add(UInt16(17))                      // Protocol = UDP
        sum.add(UInt16(udpSegment.count))        // UDP Length

        // UDP segment (header + payload).
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

/// One's‑complement accumulator with end‑around carry.
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

    /// Fixed IPv4 header size (no options).
    private static let ipv4HeaderSize = 20

    /// Builds a complete IPv4 packet containing a UDP datagram with a
    /// correct checksum.
    ///
    /// - Parameters:
    ///   - srcIP: Source IPv4 address (server side).
    ///   - srcPort: Source UDP port (server side).
    ///   - dstIP: Destination IPv4 address (client side).
    ///   - dstPort: Destination UDP port (client side).
    ///   - payload: The inner UDP payload bytes.
    /// - Returns: A complete IPv4 packet ready for `packetFlow.writePackets`.
    public static func buildInboundUdpPacket(
        srcIP: IPv4Address,
        srcPort: UInt16,
        dstIP: IPv4Address,
        dstPort: UInt16,
        payload: Data
    ) -> Data {
        // ---- Build UDP header (checksum zeroed) -----------------------
        let udpLength = UInt16(UDPHeader.headerSize + payload.count)
        var udpSegment = [UInt8](repeating: 0, count: Int(udpLength))

        // Source Port.
        udpSegment[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        udpSegment[1] = UInt8(truncatingIfNeeded: srcPort)
        // Destination Port.
        udpSegment[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        udpSegment[3] = UInt8(truncatingIfNeeded: dstPort)
        // Length.
        udpSegment[4] = UInt8(truncatingIfNeeded: udpLength >> 8)
        udpSegment[5] = UInt8(truncatingIfNeeded: udpLength)
        // Checksum field zeroed for computation.
        udpSegment[6] = 0
        udpSegment[7] = 0
        // Payload.
        for (i, byte) in payload.enumerated() {
            udpSegment[UDPHeader.headerSize + i] = byte
        }

        // ---- Compute UDP checksum -------------------------------------
        let checksum = UDPChecksum.computeIPv4(
            sourceAddr: srcIP,
            destAddr: dstIP,
            udpSegment: udpSegment
        )
        udpSegment[6] = UInt8(truncatingIfNeeded: checksum >> 8)
        udpSegment[7] = UInt8(truncatingIfNeeded: checksum)

        // ---- Build IPv4 header ----------------------------------------
        let totalLen = ipv4HeaderSize + udpSegment.count
        var packet = [UInt8](repeating: 0, count: totalLen)

        // Version (4) | IHL (5).
        packet[0] = 0x45
        // ToS.
        packet[1] = 0x00
        // Total Length.
        packet[2] = UInt8(truncatingIfNeeded: totalLen >> 8)
        packet[3] = UInt8(truncatingIfNeeded: totalLen)
        // Identification (0).
        packet[4] = 0x00; packet[5] = 0x00
        // Flags + Fragment Offset (0).
        packet[6] = 0x00; packet[7] = 0x00
        // TTL (64).
        packet[8] = 0x40
        // Protocol = UDP (17).
        packet[9] = 17
        // Header Checksum (0 — kernel fills it for TUN).
        packet[10] = 0x00; packet[11] = 0x00
        // Source Address.
        packet[12] = srcIP.octet0
        packet[13] = srcIP.octet1
        packet[14] = srcIP.octet2
        packet[15] = srcIP.octet3
        // Destination Address.
        packet[16] = dstIP.octet0
        packet[17] = dstIP.octet1
        packet[18] = dstIP.octet2
        packet[19] = dstIP.octet3
        // UDP segment.
        for (i, byte) in udpSegment.enumerated() {
            packet[ipv4HeaderSize + i] = byte
        }

        return Data(packet)
    }
}

// MARK: - TUN2UdpBridge

/// A user‑space UDP‑session‑aware bridge between raw IP packets (TUN layer)
/// and outbound proxy transports.
///
/// All session state is guarded by the caller's serial execution context —
/// typically a single SwiftNIO `EventLoop` or a dedicated `DispatchQueue`.
public final class TUN2UdpBridge: @unchecked Sendable {

    /// Result of processing an inbound IP packet.
    public enum ProcessResult: Sendable {
        /// Forward the UDP payload to the outbound proxy for the given session.
        case forward(session: UdpBridgeSessionKey, payload: Data)
        /// A reply IP packet to write back to the TUN interface.
        case reply(Data)
        /// Packet handled internally; no external action required.
        case none
    }

    // MARK: - Session Registry

    /// The NAT table mapping 4‑tuples to virtual UDP sessions.
    public let registry: UdpBridgeSessionRegistry

    // MARK: - Initialisation

    public init() {
        self.registry = UdpBridgeSessionRegistry()
    }

    // MARK: - Inbound Processing

    /// Processes a raw IP datagram from the TUN read path.
    ///
    /// - Parameter data: The raw IP packet (including IP header).
    /// - Returns: A `ProcessResult` indicating the required next action.
    /// - Throws: `IPPacketParser.ParseError` or `UDPParser.ParseError` if
    ///   the packet is malformed.
    @discardableResult
    public func processInbound(_ data: Data) throws -> ProcessResult {
        let packet = try IPPacketParser.parse(data)

        // Only UDP is handled by this bridge.
        guard packet.protocolNumber == .udp else {
            return .none
        }

        // Extract source/destination addresses.
        let (srcAddr, dstAddr) = extractAddresses(from: packet)

        // Parse UDP header + payload.
        var payloadBuffer = packet.payload
        guard let payloadBytes = payloadBuffer.readBytes(
            length: payloadBuffer.readableBytes
        ) else { return .none }
        let payloadData = Data(payloadBytes)
        let udp = try UDPParser.parse(payloadData)

        // Build session key.
        let key = UdpBridgeSessionKey(
            sourceIP: srcAddr,
            sourcePort: udp.sourcePort,
            destinationIP: dstAddr,
            destinationPort: udp.destinationPort
        )

        // Look up or create session.
        let session: UdpBridgeSession
        if let existing = registry.lookup(key) {
            session = existing
        } else {
            session = UdpBridgeSession(key: key)
            registry.register(session)
        }
        session.markActivity()

        return .forward(session: session.key, payload: udp.payload)
    }

    // MARK: - Reply Packet Assembly

    /// Builds a complete IPv4‑wrapped UDP reply packet for injection back
    /// into the TUN virtual interface.
    ///
    /// This reverses the source and destination coordinates: the original
    /// destination becomes the source (as the server is now "sending" to
    /// the client).
    ///
    /// - Parameters:
    ///   - session: The session this reply belongs to.
    ///   - payload: The raw UDP payload from the outbound proxy.
    /// - Returns: A complete IPv4 packet ready for `packetFlow.writePackets`.
    public func buildReply(
        for session: UdpBridgeSessionKey,
        payload: Data
    ) -> Data {
        UDPPacketBuilder.buildInboundUdpPacket(
            srcIP: session.destinationIP,   // reversed
            srcPort: session.destinationPort,
            dstIP: session.sourceIP,
            dstPort: session.sourcePort,
            payload: payload
        )
    }

    // MARK: - Static Reply Builder

    /// Builds a complete IPv4‑wrapped UDP reply packet from raw 4‑tuple
    /// coordinates.  Convenience wrapper around `UDPPacketBuilder`.
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

    // MARK: - Helpers

    /// Extracts source and destination IPv4 addresses from an `IPPacket`.
    private func extractAddresses(
        from packet: IPPacket
    ) -> (source: IPv4Address, destination: IPv4Address) {
        switch packet {
        case .ipv4(let header):
            return (header.sourceAddress, header.destinationAddress)
        case .ipv6:
            // IPv6 UDP is not yet handled; return zero addresses.
            return (
                IPv4Address(0, 0, 0, 0),
                IPv4Address(0, 0, 0, 0)
            )
        }
    }
}
