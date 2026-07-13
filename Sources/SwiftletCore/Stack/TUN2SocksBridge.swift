//===----------------------------------------------------------------------===//
//
//  TUN2SocksBridge.swift
//  SwiftletCore — TUN → SOCKS5 Session Bridge
//
//  The central orchestrator that sits between a TUN virtual interface and
//  the SOCKS5 inbound engine.  It intercepts raw IP packets, tracks TCP
//  sessions by their 4‑tuple, performs a virtual 3‑way handshake (SYN →
//  SYN‑ACK), and pipelines established connection payloads into the SOCKS5
//  outbound while wrapping return traffic back into valid IP/TCP packets.
//
//  Architecture
//  ------------
//  ```
//  NEPacketTunnelFlow (TUN read)
//       │
//       ▼
//  TUN2SocksBridge.processInbound(_:)
//       │
//       ├── SYN  → build SYN‑ACK, register session
//       ├── ACK  → complete handshake
//       ├── DATA → (future) forward to SOCKS5
//       └── RST/FIN → tear down session
//       │
//       ▼
//  Reply Data → NEPacketTunnelFlow (TUN write)
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Bridge

/// A user‑space TCP‑session‑aware bridge that translates between raw IP
/// packets (TUN layer) and TCP byte streams (SOCKS5 layer).
///
/// All session state is guarded by the bridge's serial execution context —
/// callers are responsible for invoking `processInbound` from a single
/// thread or dispatching through a SwiftNIO `EventLoop` / `DispatchQueue`.
public final class TUN2SocksBridge: @unchecked Sendable {

    // MARK: - Public Types

    /// The result of processing an inbound IP packet.
    public enum ProcessResult: Sendable {
        /// A raw IP packet that should be written back to the TUN interface
        /// (e.g. a SYN‑ACK, RST, ICMP unreachable).
        case reply(Data)
        /// Data that should be forwarded to the SOCKS5 outbound for the
        /// identified session (future milestone).
        case forwardToSocks5(session: TCPSessionKey, payload: Data)
        /// Inject an ICMP Destination Unreachable packet (routing block /
        /// connection failure — tells the client app to error immediately).
        case icmpUnreachable(Data)
        /// The packet was handled internally and requires no external action.
        case none
    }

    // MARK: - Backpressure State

    /// Estimated number of bytes buffered in the outbound proxy channel.
    /// Updated by external callers (e.g. the outbound handler's channel
    /// writability listener).  The bridge uses this to dynamically scale
    /// TCP window sizes before building reply packets.
    public var outboundBufferedBytes: Int = 0

    /// Whether the outbound proxy channel is currently writable.
    /// Set to `false` when `channelWritabilityChanged` fires with
    /// unwritable — the bridge immediately squeezes all active session
    /// windows to 0 to halt the host OS TCP stack.
    public var isOutboundWritable: Bool = true

    /// Notifies all active sessions of a channel writability change.
    /// - When `false`: all session windows are squeezed to 0.
    /// - When `true`: sessions will recover on their next `adjustWindow` call.
    public func channelWritabilityChanged(writable: Bool) {
        isOutboundWritable = writable
        for session in registry.allSessions {
            session.channelWritabilityChanged(writable: writable)
        }
    }

    /// Scans all sessions and applies backpressure window adjustments
    /// based on the current `outboundBufferedBytes` and writability state.
    /// Call this periodically or before building reply packets.
    public func applyBackpressureToAllSessions() {
        for session in registry.allSessions {
            session.adjustWindow(bufferedBytes: outboundBufferedBytes)
        }
    }

    /// Evicts stale reassembly data from sessions whose oldest segment
    /// has exceeded the timeout.  Returns evicted data per session for
    /// forwarding to the outbound tunnel.
    public func evictStaleReassemblyData(
        olderThan timeout: TimeInterval = 0.750
    ) -> [(session: TCPSessionKey, data: [(seq: UInt32, payload: Data)])] {
        var results: [(TCPSessionKey, [(UInt32, Data)])] = []
        for session in registry.allSessions {
            let evicted = session.evictStaleSegments(olderThan: timeout)
            if !evicted.isEmpty {
                results.append((session.key, evicted))
            }
        }
        return results
    }

    // MARK: - Stored Properties

    /// The session registry (NAT table).
    public let registry: TCPSessionRegistry

    // MARK: - Initialisation

    public init() {
        self.registry = TCPSessionRegistry()
    }

    // MARK: - Public API

    /// Processes a raw IP datagram from the TUN read path.
    ///
    /// - Parameter data: The raw IP packet (including IP header).
    /// - Returns: A `ProcessResult` indicating the required next action.
    /// - Throws: `IPPacketParser.ParseError` or `TCPParser.ParseError` if
    ///   the packet is malformed.
    @discardableResult
    public func processInbound(_ data: Data) throws -> ProcessResult {
        let packet = try IPPacketParser.parse(data)

        // Only TCP is handled by this bridge.
        guard packet.protocolNumber == .tcp else {
            return .none
        }

        // Extract the transport‑layer segment.
        var tcpBuffer = packet.payload

        // ---- Parse TCP header --------------------------------------------
        let tcpHeader: TCPHeader
        do {
            tcpHeader = try TCPParser.parse(buffer: &tcpBuffer)
        } catch {
            // If we cannot parse the TCP header, drop the packet silently;
            // the client will retransmit.
            return .none
        }

        // ---- Build session key from the *original* packet direction ------
        let (srcAddr, dstAddr) = extractAddresses(from: packet)

        let key = TCPSessionKey(
            sourceIP: srcAddr,
            sourcePort: tcpHeader.sourcePort,
            destinationIP: dstAddr,
            destinationPort: tcpHeader.destinationPort
        )

        // ---- Diagnostic hook: track new TUN session ---------------------
        Task {
            await SessionDiagnosticsTracker.shared.trackNewSession(
                inbound: .tun,
                client: "\(key.sourceIP):\(key.sourcePort)",
                target: "\(key.destinationIP):\(key.destinationPort)"
            )
        }

        // ---- Dispatch based on flags and state ---------------------------
        return try processSegment(
            packet: packet,
            tcp: tcpHeader,
            key: key,
            payload: tcpBuffer
        )
    }

    // MARK: - Segment Processing

    private func processSegment(
        packet: IPPacket,
        tcp: TCPHeader,
        key: TCPSessionKey,
        payload: ByteBuffer
    ) throws -> ProcessResult {

        // --- SYN (no ACK) — connection initiation -------------------------
        if tcp.isSYNOnly {
            return try handleSYN(packet: packet, tcp: tcp, key: key)
        }

        // --- Look up existing session -------------------------------------
        guard let session = registry.lookup(key) ?? registry.lookup(reverseOf: key) else {
            // No session — send RST.
            return buildRST(packet: packet, tcp: tcp, key: key)
        }

        // --- RST — immediate teardown -------------------------------------
        if tcp.isRST {
            session.state = .closed
            registry.remove(session.key)
            return .none
        }

        // --- FIN — graceful close -----------------------------------------
        if tcp.isFIN {
            session.state = .closing
            // Send FIN‑ACK back to the sender.
            return try buildFinAck(
                packet: packet,
                tcp: tcp,
                key: key,
                session: session
            )
        }

        // --- ACK (after SYN‑ACK) — complete handshake ---------------------
        if tcp.flags == .ack && session.state == .synReceived {
            // Verify the ACK number acknowledges our SYN‑ACK.
            // Expected: ack == serverISN + 1
            let expectedAck = session.serverISN + 1
            if tcp.acknowledgmentNumber == expectedAck {
                session.state = .established
            }
            // The client's ACK may also carry data; fall through to data
            // handling.
        }

        // --- Data segments ------------------------------------------------
        if session.state == .established && payload.readableBytes > 0 {
            var dataPayload = payload
            if let bytes = dataPayload.readBytes(length: dataPayload.readableBytes) {
                session.advanceClientSeq(by: bytes.count)
                return .forwardToSocks5(
                    session: session.key,
                    payload: Data(bytes)
                )
            }
        }

        return .none
    }

    // MARK: - SYN Handler (Virtual Handshake)

    /// Processes an inbound TCP SYN segment by synthesising a SYN‑ACK that
    /// mimics a real server response.
    ///
    /// This is the critical "trick" that convinces the iOS kernel's TCP stack
    /// that the remote server has accepted the connection, enabling the local
    /// socket to proceed to the ESTABLISHED state without any actual outbound
    /// TCP handshake at this layer.
    private func handleSYN(
        packet: IPPacket,
        tcp: TCPHeader,
        key: TCPSessionKey
    ) throws -> ProcessResult {

        // Generate the server's initial sequence number (ISN).
        let serverISN = generateISN()

        // Register the session in SYN_RECEIVED state.
        let session = TCPSession(
            key: key,
            clientISN: tcp.sequenceNumber,
            serverISN: serverISN
        )
        registry.register(session)

        // Build the SYN‑ACK reply.
        let synAckData = try buildSYNACKPacket(
            packet: packet,
            tcp: tcp,
            key: key,
            serverISN: serverISN,
            clientISN: tcp.sequenceNumber
        )

        return .reply(synAckData)
    }

    // MARK: - Packet Construction

    /// Builds a raw IPv4 packet containing a TCP SYN‑ACK segment.
    private func buildSYNACKPacket(
        packet: IPPacket,
        tcp: TCPHeader,
        key: TCPSessionKey,
        serverISN: UInt32,
        clientISN: UInt32
    ) throws -> Data {
        // Build the TCP SYN‑ACK segment (20 bytes, no options).
        var tcpSegment = TCPBuilder.synAck(
            srcPort: key.destinationPort,    // server port
            dstPort: key.sourcePort,          // client port
            serverSeq: serverISN,
            clientAck: clientISN + 1
        )

        // Compute the TCP checksum over the reversed pseudo‑header.
        let checksum = TCPChecksum.computeIPv4(
            sourceAddr: key.destinationIP,   // reversed: server is now source
            destAddr: key.sourceIP,           // reversed: client is now dest
            tcpSegment: tcpSegment
        )
        tcpSegment[16] = UInt8(truncatingIfNeeded: checksum >> 8)
        tcpSegment[17] = UInt8(truncatingIfNeeded: checksum)

        // Wrap in an IPv4 header.
        return try assembleIPv4Packet(
            sourceAddr: key.destinationIP,
            destAddr: key.sourceIP,
            protocol: 6,  // TCP
            payload: tcpSegment
        )
    }

    /// Builds a raw IPv4 packet containing a TCP RST segment.
    private func buildRST(
        packet: IPPacket,
        tcp: TCPHeader,
        key: TCPSessionKey
    ) -> ProcessResult {
        let (srcAddr, dstAddr) = extractAddresses(from: packet)

        var rstSegment = TCPBuilder.rst(
            srcPort: key.destinationPort,
            dstPort: key.sourcePort,
            seq: 0,
            ack: tcp.sequenceNumber &+ 1
        )

        let checksum = TCPChecksum.computeIPv4(
            sourceAddr: dstAddr,
            destAddr: srcAddr,
            tcpSegment: rstSegment
        )
        rstSegment[16] = UInt8(truncatingIfNeeded: checksum >> 8)
        rstSegment[17] = UInt8(truncatingIfNeeded: checksum)

        guard let ipPacket = try? assembleIPv4Packet(
            sourceAddr: dstAddr,
            destAddr: srcAddr,
            protocol: 6,
            payload: rstSegment
        ) else {
            return .none
        }

        return .reply(ipPacket)
    }

    /// Builds a FIN‑ACK reply for graceful connection teardown.
    private func buildFinAck(
        packet: IPPacket,
        tcp: TCPHeader,
        key: TCPSessionKey,
        session: TCPSession
    ) throws -> ProcessResult {
        // Build a FIN‑ACK segment.
        var finAck = buildTCPHeaderBytes(
            srcPort: key.destinationPort,
            dstPort: key.sourcePort,
            seq: session.serverNextSeq,
            ack: session.clientNextSeq,
            flags: [.fin, .ack]
        )

        let checksum = TCPChecksum.computeIPv4(
            sourceAddr: key.destinationIP,
            destAddr: key.sourceIP,
            tcpSegment: finAck
        )
        finAck[16] = UInt8(truncatingIfNeeded: checksum >> 8)
        finAck[17] = UInt8(truncatingIfNeeded: checksum)

        session.state = .closed
        registry.remove(session.key)

        let ipPacket = try assembleIPv4Packet(
            sourceAddr: key.destinationIP,
            destAddr: key.sourceIP,
            protocol: 6,
            payload: finAck
        )

        return .reply(ipPacket)
    }

    // MARK: - Helpers

    /// Extracts source and destination IPv4 addresses from an `IPPacket`.
    private func extractAddresses(
        from packet: IPPacket
    ) -> (source: IPv4Address, destination: IPv4Address) {
        switch packet {
        case .ipv4(let h):
            return (h.sourceAddress, h.destinationAddress)
        case .ipv6:
            // Map IPv6 to IPv4 for the session key when possible;
            // for now this path is not exercised in tests.
            // We use a placeholder — production code should handle
            // IPv6‑mapped‑IPv4 or dual‑stack properly.
            return (
                IPv4Address(0, 0, 0, 0),
                IPv4Address(0, 0, 0, 0)
            )
        }
    }

    /// Generates a cryptographically random 32‑bit initial sequence number.
    private func generateISN() -> UInt32 {
        UInt32.random(in: 1 ... UInt32.max)
    }

    /// Assembles a complete IPv4 packet (header + payload) with correct
    /// Total Length and a zeroed checksum (the kernel typically recomputes
    /// the IP header checksum when writing to a TUN interface).
    private func assembleIPv4Packet(
        sourceAddr: IPv4Address,
        destAddr: IPv4Address,
        protocol: UInt8,
        payload: [UInt8]
    ) throws -> Data {
        let headerLength = 20
        let totalLength  = headerLength + payload.count

        var bytes = [UInt8](repeating: 0, count: totalLength)

        // Version (4) | IHL (5)
        bytes[0] = 0x45
        // ToS
        bytes[1] = 0x00
        // Total Length
        bytes[2] = UInt8(truncatingIfNeeded: totalLength >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: totalLength)
        // Identification (0)
        bytes[4] = 0x00; bytes[5] = 0x00
        // Flags + Fragment Offset (0)
        bytes[6] = 0x00; bytes[7] = 0x00
        // TTL (64)
        bytes[8] = 0x40
        // Protocol
        bytes[9] = `protocol`
        // Header Checksum (0 — kernel fills it in)
        bytes[10] = 0x00; bytes[11] = 0x00
        // Source Address
        bytes[12] = sourceAddr.octet0
        bytes[13] = sourceAddr.octet1
        bytes[14] = sourceAddr.octet2
        bytes[15] = sourceAddr.octet3
        // Destination Address
        bytes[16] = destAddr.octet0
        bytes[17] = destAddr.octet1
        bytes[18] = destAddr.octet2
        bytes[19] = destAddr.octet3
        // Payload
        for (i, byte) in payload.enumerated() {
            bytes[headerLength + i] = byte
        }

        return Data(bytes)
    }

    /// Builds a generic 20‑byte TCP header with the given parameters.
    /// The checksum field is set to zero (caller must compute and fill it).
    /// When `session` is provided, its `advertisedWindow` is used for
    /// backpressure‑aware flow control.
    private func buildTCPHeaderBytes(
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        flags: TCPFlags,
        session: TCPSession? = nil
    ) -> [UInt8] {
        var bytes = [UInt8](repeating: 0, count: 20)

        bytes[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        bytes[1] = UInt8(truncatingIfNeeded: srcPort)
        bytes[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: dstPort)
        bytes[4] = UInt8(truncatingIfNeeded: seq >> 24)
        bytes[5] = UInt8(truncatingIfNeeded: seq >> 16)
        bytes[6] = UInt8(truncatingIfNeeded: seq >>  8)
        bytes[7] = UInt8(truncatingIfNeeded: seq)
        bytes[8] = UInt8(truncatingIfNeeded: ack >> 24)
        bytes[9] = UInt8(truncatingIfNeeded: ack >> 16)
        bytes[10] = UInt8(truncatingIfNeeded: ack >>  8)
        bytes[11] = UInt8(truncatingIfNeeded: ack)
        bytes[12] = 0x50  // Data Offset = 5
        bytes[13] = flags.rawValue
        // Dynamic window size — scaled by backpressure.
        let window = session?.advertisedWindow ?? 65535
        bytes[14] = UInt8(truncatingIfNeeded: window >> 8)
        bytes[15] = UInt8(truncatingIfNeeded: window)
        bytes[16] = 0x00; bytes[17] = 0x00  // checksum placeholder
        bytes[18] = 0x00; bytes[19] = 0x00  // urgent pointer

        return bytes
    }

    // MARK: - ICMP Unreachable Injection

    /// Builds a raw IPv4 packet containing an ICMP Destination Unreachable
    /// message (Type 3, Code 1: Host Unreachable), embedding the original
    /// packet's IP header + 8 bytes of transport header as required by
    /// RFC 792.
    ///
    /// This tells the client application (e.g. Safari) to error immediately
    /// instead of hanging on a silent timeout.
    public static func buildICMPUnreachable(
        for originalPacket: Data,
        code: UInt8 = 1,
        srcIP: IPv4Address = IPv4Address(198, 18, 0, 1)
    ) -> Data {
        let ipHeaderLen = Int((originalPacket[0] & 0x0F)) * 4
        let includeLen = min(ipHeaderLen + 8, originalPacket.count)
        let originalSlice = originalPacket.prefix(includeLen)

        let icmpHeaderSize = 8
        let icmpPayloadSize = originalSlice.count
        let icmpTotalLen = icmpHeaderSize + icmpPayloadSize
        let ipTotalLen = 20 + icmpTotalLen

        var pkt = [UInt8](repeating: 0, count: ipTotalLen)

        // IPv4 header.
        pkt[0] = 0x45; pkt[1] = 0x00
        pkt[2] = UInt8(ipTotalLen >> 8); pkt[3] = UInt8(ipTotalLen & 0xFF)
        pkt[4...7] = [0x00, 0x00, 0x00, 0x00]
        pkt[8] = 0x40; pkt[9] = 1  // Protocol=ICMP
        pkt[10...11] = [0x00, 0x00]
        pkt[12...15] = [srcIP.octet0, srcIP.octet1, srcIP.octet2, srcIP.octet3]
        pkt[16] = originalPacket[12]; pkt[17] = originalPacket[13]
        pkt[18] = originalPacket[14]; pkt[19] = originalPacket[15]

        // ICMP header: Type=3, Code=code, Checksum placeholder, Unused=0.
        pkt[20] = 3; pkt[21] = code
        pkt[22...23] = [0x00, 0x00]
        pkt[24...27] = [0x00, 0x00, 0x00, 0x00]

        // ICMP payload = original IP header + 8 bytes.
        for (i, b) in originalSlice.enumerated() {
            pkt[20 + icmpHeaderSize + i] = b
        }

        // ICMP checksum.
        let icmpSegment = Array(pkt[20...])
        let cksum = Self.icmpChecksum(icmpSegment)
        pkt[22] = UInt8(cksum >> 8); pkt[23] = UInt8(cksum & 0xFF)

        return Data(pkt)
    }

    private static func icmpChecksum(_ data: [UInt8]) -> UInt16 {
        var sum: UInt32 = 0; var i = 0
        while i + 1 < data.count {
            sum &+= (UInt32(data[i]) << 8) | UInt32(data[i + 1]); i += 2
        }
        if i < data.count { sum &+= UInt32(data[i]) << 8 }
        while (sum >> 16) != 0 { sum = (sum & 0xFFFF) + (sum >> 16) }
        return ~UInt16(truncatingIfNeeded: sum)
    }

    /// Convenience: builds an ICMP Host Unreachable for a routing `.block`
    /// or connection failure.
    public func buildBlockRejection(for originalPacket: Data) -> Data {
        Self.buildICMPUnreachable(for: originalPacket, code: 1)
    }
}
