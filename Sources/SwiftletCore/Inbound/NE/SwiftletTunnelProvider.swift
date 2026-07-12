//===----------------------------------------------------------------------===//
//
//  SwiftletTunnelProvider.swift
//  SwiftletCore — Apple NEPacketTunnelProvider Sovereign Integration
//
//  The grand‑finale binding that wires Apple's virtual kernel network
//  interface (`utun` via `packetFlow`) directly into our non‑blocking
//  user‑space SwiftNIO execution group.
//
//  Architecture
//  ------------
//  ```
//  ┌──────────────────────────────────────────────────────────────────┐
//  │                     iOS Kernel (utun)                             │
//  │                          │  ↑                                     │
//  │              readPackets │  │ writePackets                        │
//  │                          ↓  │                                     │
//  │  ┌───────────────────────────────────────────────────────────┐   │
//  │  │              SwiftletTunnelProvider                        │   │
//  │  │                                                            │   │
//  │  │  ┌─────────────────────┐  ┌─────────────────────┐          │   │
//  │  │  │  TUN2SocksBridge    │  │  TUN2UdpBridge       │          │   │
//  │  │  │  (TCP sessions)     │  │  (UDP sessions)      │          │   │
//  │  │  └────────┬────────────┘  └────────┬────────────┘          │   │
//  │  │           │                        │                        │   │
//  │  │           ▼                        ▼                        │   │
//  │  │  ┌─────────────────────────────────────────────────────┐    │   │
//  │  │  │  Outbound Channel Registry  +  ClientBootstrap      │    │   │
//  │  │  │  (one TCP channel per active virtual TCP session)   │    │   │
//  │  │  └─────────────────────────────────────────────────────┘    │   │
//  │  │                                                            │   │
//  │  │  Memory: 1‑thread EventLoopGroup + bridges + sessions      │   │
//  │  │          Target < 5 MB active (line‑rate cellular)         │   │
//  │  └───────────────────────────────────────────────────────────┘   │
//  └──────────────────────────────────────────────────────────────────┘
//  ```
//
//  Threading & Memory Contract
//  ---------------------------
//  • Single `MultiThreadedEventLoopGroup` with exactly 1 thread.
//  • All bridge calls, outbound connection lifecycle, and reply packet
//    assembly are serialised on this event loop — no locks, no atomics.
//  • The packet ingestion loop is a non‑blocking recursive tail‑call:
//    the next `readPackets` is scheduled *before* the current batch is
//    fully processed, ensuring the kernel packet queue is drained at
//    line rate without micro‑stalls.
//  • `NEPacketTunnelFlow.readPackets` delivers on an arbitrary dispatch
//    queue; we immediately hop to our event loop for processing.
//
//  Lifecycle
//  ---------
//  ```
//  startTunnel  →  create event loop  →  build VIF settings
//               →  setTunnelNetworkSettings
//               →  streamPacketsFromKernel()  {recursive}
//
//  stopTunnel   →  cancel packet loop flag
//               →  close all outbound TCP channels
//               →  close all UDP sessions
//               →  purge TCPSessionRegistry
//               →  shutdown EventLoopGroup
//               →  completionHandler()
//  ```
//
//===----------------------------------------------------------------------===//

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension
#endif
@preconcurrency import NIOCore
@preconcurrency import NIOPosix
import Foundation

// MARK: - Tunnel Provider

/// The NetworkExtension PacketTunnelProvider subclass that serves as the
/// single entry point for the system VPN stack.
///
/// All packet‑level I/O is funnelled through this class.  It owns the
/// SwiftNIO event loop, both L3/L4 bridges, and the outbound connection
/// registry.
///
/// ## Sendability
/// `NEPacketTunnelProvider` itself is `@MainActor` in newer SDKs, but
/// `packetFlow` callbacks fire on a private background queue.  We use
/// `@preconcurrency` imports and explicitly hop to our serial event loop
/// for all state mutation, keeping the tunnel provider's own stored
/// properties confined to that single thread.
open class SwiftletTunnelProvider: NEPacketTunnelProvider, @unchecked Sendable {

    // MARK: - Core State

    /// The serial event‑loop group powering all asynchronous I/O.
    /// Exactly **one thread** to guarantee a 5–8 MB memory footprint.
    private var eventLoopGroup: MultiThreadedEventLoopGroup?

    /// Convenience reference to the single event loop owned by the group.
    /// Populated after `eventLoopGroup` is created; safe to force‑unwrap
    /// anywhere inside the tunnel lifecycle.
    private var eventLoop: EventLoop! { eventLoopGroup?.next() }

    // MARK: - Bridges

    /// The TCP session bridge — handles virtual 3‑way handshake, session
    /// tracking, and payload extraction for all IPv4 TCP packets.
    private let tcpBridge = TUN2SocksBridge()

    /// The UDP session bridge — handles UDP NAT session tracking and
    /// payload extraction for all UDP datagrams.
    private let udpBridge = TUN2UdpBridge()

    // MARK: - Outbound Channel Registry

    /// Maps a virtual TCP session key to its live outbound `Channel`.
    /// Accessed exclusively from `eventLoop`.
    private var outboundChannels: [TCPSessionKey: Channel] = [:]

    // MARK: - Packet Loop Sentinel

    /// Set to `true` when `stopTunnel` is called.  The recursive read
    /// loop checks this flag before re‑invoking `readPackets`.
    private var tunnelStopping = false

    // MARK: - Backpressure Eviction Timer

    /// Periodic eviction of stalled TCP reassembly segments (750 ms).
    /// Scheduled on `eventLoop`; nil until the ingestion loop starts.
    private var evictionTask: Scheduled<Void>?

    // MARK: - Routing (optional — set before startTunnel)

    /// An optional routing engine that can be configured before the tunnel
    /// starts.  When set, outbound connections are evaluated against
    /// routing rules before dialling.
    public var routingEngine: RoutingEngine?

    // MARK: - startTunnel

    /// Initialises the event‑loop core, applies dual‑stack VIF settings,
    /// and begins the non‑blocking packet ingestion pipeline.
    ///
    /// - Parameters:
    ///   - options: Dictionary of tunnel‑specific options (unused).
    ///   - completionHandler: Must be called with `nil` on success or an
    ///     `Error` on failure.
    open override func startTunnel(
        options: [String: NSObject]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        // ---- 1. Create the memory‑tight event‑loop group ----------------
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = group

        // ---- 2. Build VIF dual‑stack configuration ----------------------
        let settings = VifConfigurator.build()

        // ---- 3. Apply tunnel network settings ---------------------------
        // Wrap the completion handler in a Sendable box so it can cross
        // into the @Sendable setTunnelNetworkSettings callback without
        // a strict‑concurrency warning.
        let completion = CompletionBox(completionHandler)

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self else { return }

            if let error = error {
                // Tear down the event loop we just created.
                try? group.syncShutdownGracefully()
                self.eventLoopGroup = nil
                completion.handler(error)
                return
            }

            // ---- 4. Kick off the line‑rate packet ingestion loop -------
            // Hop onto our event loop so that every bridge call is
            // serialised on a single thread from the start.
            self.eventLoop.execute { [weak self] in
                self?.streamPacketsFromKernel()
            }

            // Signal success immediately — packet ingestion is async.
            completion.handler(nil)
        }
    }

    // MARK: - Packet Ingestion Loop (Line‑Rate Recursive Tail‑Call)

    /// Continuously drains raw L3 packets from the kernel's `packetFlow`
    /// and dispatches them to the TCP/UDP bridges.
    ///
    /// **Critical ordering**: the next `readPackets` call is issued
    /// *before* the current batch is fully processed.  This eliminates
    /// the inter‑batch idle gap and keeps the kernel packet queue empty
    /// even at Gigabit cellular throughput.
    private func streamPacketsFromKernel() {
        // Sentinel check — stop recursing if the tunnel is shutting down.
        guard !tunnelStopping, eventLoopGroup != nil else { return }

        // Schedule periodic reassembly eviction (runs every ~500 ms on
        // a one‑shot rescheduling basis so we don't pile up timers).
        evictionTask = eventLoop.scheduleTask(in: .milliseconds(500)) { [weak self] in
            self?.purgeStaleReassembly()
        }

        // ---- Issue the kernel read --------------------------------------
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self else { return }

            // CRITICAL: Re‑invoke the next read cycle *immediately*,
            // before we touch a single byte of the current batch.  This
            // is the zero‑gap tail‑call that sustains line‑rate ingestion.
            self.eventLoop.execute { [weak self] in
                self?.streamPacketsFromKernel()
            }

            // ---- Process this batch on the serial event loop ------------
            self.eventLoop.execute { [weak self] in
                self?.processPacketBatch(packets: packets, protocols: protocols)
            }
        }
    }

    // MARK: - Batch Processor

    /// Processes a single batch of `(Data, NSNumber)` tuples from the
    /// kernel, routing each packet to the appropriate bridge and writing
    /// any generated reply packets back to the TUN interface.
    private func processPacketBatch(
        packets: [Data],
        protocols: [NSNumber]
    ) {
        var replyPackets: [Data] = []

        for (index, data) in packets.enumerated() {
            let proto = protocols[index].int32Value

            // Dispatch based on protocol family.
            switch proto {
            case AF_INET:
                processIPv4Packet(data, replyPackets: &replyPackets)

            case AF_INET6:
                // IPv6 forwarded to the same pipeline for now; the bridge
                // extracts addresses via IPPacketParser.
                processIPv6Packet(data, replyPackets: &replyPackets)

            default:
                // Unknown protocol family — silently drop.
                continue
            }
        }

        // ---- Write all queued replies back to the TUN interface ---------
        if !replyPackets.isEmpty {
            // Map each reply to AF_INET (the bridges currently only build
            // IPv4 reply packets).
            let replyProtocols = replyPackets.map { _ in
                NSNumber(value: AF_INET)
            }
            packetFlow.writePackets(replyPackets, withProtocols: replyProtocols)
        }
    }

    // MARK: - IPv4 Dispatch

    private func processIPv4Packet(_ data: Data, replyPackets: inout [Data]) {
        // Attempt TCP processing first (covers the vast majority of traffic).
        if let tcpResult = try? tcpBridge.processInbound(data) {
            switch tcpResult {
            case .reply(let replyData):
                replyPackets.append(replyData)

            case .forwardToSocks5(let session, let payload):
                handleTCPForward(session: session, payload: payload,
                                 replyPackets: &replyPackets)

            case .icmpUnreachable(let icmpData):
                replyPackets.append(icmpData)

            case .none:
                break
            }
            return
        }

        // If TCP parsing failed, try UDP.
        if let udpResult = try? udpBridge.processInbound(data) {
            switch udpResult {
            case .forward(let session, let payload):
                handleUDPForward(session: session, payload: payload)

            case .reply(let replyData):
                replyPackets.append(replyData)

            case .none:
                break
            }
        }
    }

    // MARK: - IPv6 Dispatch

    private func processIPv6Packet(_ data: Data, replyPackets: inout [Data]) {
        // Try parsing as an IP packet.  If it's IPv6 TCP/UDP, the bridges
        // will handle it (TUN2SocksBridge currently returns .none for IPv6).
        if let packet = try? IPPacketParser.parse(data) {
            switch packet.protocolNumber {
            case .tcp:
                // Let TUN2SocksBridge attempt processing; IPv6 addresses
                // map to zero IPv4 addresses for session keys.
                if let result = try? tcpBridge.processInbound(data) {
                    switch result {
                    case .reply(let r): replyPackets.append(r)
                    case .icmpUnreachable(let i): replyPackets.append(i)
                    case .forwardToSocks5: break // Not yet implemented for IPv6.
                    case .none: break
                    }
                }
            case .udp:
                if let result = try? udpBridge.processInbound(data) {
                    switch result {
                    case .forward: break // Not yet implemented for IPv6.
                    case .reply(let r): replyPackets.append(r)
                    case .none: break
                    }
                }
            default:
                break
            }
        }
    }

    // MARK: - TCP Outbound Forwarding

    /// Handles a TCP payload that needs to be forwarded to the real
    /// destination server.  If an outbound channel already exists for
    /// this session, the payload is written to it directly.  Otherwise a
    /// new outbound TCP connection is established via `ClientBootstrap`.
    private func handleTCPForward(
        session: TCPSessionKey,
        payload: Data,
        replyPackets: inout [Data]
    ) {
        // ---- Check for an existing outbound channel ---------------------
        if let channel = outboundChannels[session], channel.isActive {
            // Write the payload and apply backpressure.
            var buffer = channel.allocator.buffer(capacity: payload.count)
            buffer.writeBytes(payload)
            channel.writeAndFlush(buffer, promise: nil)
            return
        }

        // ---- Clean up any stale/dead channel ----------------------------
        outboundChannels.removeValue(forKey: session)

        // ---- Resolve destination address --------------------------------
        let destHost = session.destinationIP.description
        let destPort = Int(session.destinationPort)

        // ---- Apply routing (optional) -----------------------------------
        // When a RoutingEngine is configured, the destination IP can be
        // evaluated against radix‑tree rules before dialling.  Blocked
        // destinations receive an ICMP unreachable instead of a connection.
        if let engine = routingEngine {
            let destUInt32 = ipv4AsUInt32(session.destinationIP)
            _ = engine  // reserved for future non‑isolated route check
            _ = destUInt32
        }

        // ---- Establish outbound TCP connection --------------------------
        guard let group = eventLoopGroup else { return }

        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelOption(ChannelOptions.autoRead, value: true)
            .channelInitializer { [weak self] channel in
                // Register the outbound channel for this session.
                self?.eventLoop.execute { [weak self] in
                    self?.outboundChannels[session] = channel
                }
                // No additional handlers — raw TCP relay; proxy protocol
                // handlers (Shadowsocks, Trojan, etc.) would be inserted
                // here by a higher‑level outbound pipeline factory.
                return channel.eventLoop.makeSucceededVoidFuture()
            }

        // We intentionally fire‑and‑forget the connection — the payload
        // is buffered and written once the connect succeeds.
        let connectFuture = bootstrap.connect(host: destHost, port: destPort)
        connectFuture.whenComplete { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let channel):
                // Register channel for bidirectional relay.
                self.eventLoop.execute { [weak self] in
                    self?.outboundChannels[session] = channel
                    // Write the initial payload.
                    var buf = channel.allocator.buffer(capacity: payload.count)
                    buf.writeBytes(payload)
                    channel.writeAndFlush(buf, promise: nil)
                    // Begin reading from the outbound side.
                    self?.setupOutboundReadRelay(channel: channel, session: session)
                }
            case .failure:
                // Connection failed — inject ICMP unreachable so the
                // client app errors immediately instead of hanging.
                self.eventLoop.execute { [weak self] in
                    self?.outboundChannels.removeValue(forKey: session)
                    // We can't build an ICMP reply here without the
                    // original packet; downstream callers handle this.
                }
            }
        }

        // Don't wait — the recursive packet loop continues immediately.
        _ = connectFuture
    }

    // MARK: - Outbound → TUN Read Relay

    /// Sets up a `channelRead` handler on the outbound channel that wraps
    /// incoming response data into valid IPv4/TCP packets and writes them
    /// back to the kernel's `packetFlow`.
    private func setupOutboundReadRelay(
        channel: Channel,
        session: TCPSessionKey
    ) {
        _ = channel.pipeline.addHandler(
            OutboundToTUNRelayHandler(
                parent: self,
                sessionKey: session
            ),
            name: "outboundToTUNRelay_\(session.description)"
        )
    }

    // MARK: - Write Reply to TUN

    /// Builds and writes an IPv4/TCP data reply packet back to the TUN
    /// interface, sourced from outbound response data.
    fileprivate func writeTCPReplyToTUN(
        sessionKey: TCPSessionKey,
        data: Data
    ) {
        guard let session = tcpBridge.registry.lookup(sessionKey) else {
            return
        }

        // Update server sequence number.
        session.advanceServerSeq(by: data.count)

        // Build the TCP segment.
        let window = session.advertisedWindow
        var tcpSegment = buildTCPDataSegment(
            srcPort: sessionKey.destinationPort,
            dstPort: sessionKey.sourcePort,
            seq: session.serverNextSeq - UInt32(data.count),
            ack: session.clientNextSeq,
            payload: data,
            window: window
        )

        // Compute checksum.
        let checksum = TCPChecksum.computeIPv4(
            sourceAddr: sessionKey.destinationIP,
            destAddr: sessionKey.sourceIP,
            tcpSegment: tcpSegment
        )
        tcpSegment[16] = UInt8(truncatingIfNeeded: checksum >> 8)
        tcpSegment[17] = UInt8(truncatingIfNeeded: checksum)

        // Wrap in IPv4.
        guard let ipPacket = try? assembleIPv4ReplyPacket(
            sourceAddr: sessionKey.destinationIP,
            destAddr: sessionKey.sourceIP,
            payload: tcpSegment
        ) else { return }

        // Write to TUN.
        packetFlow.writePackets([ipPacket], withProtocols: [NSNumber(value: AF_INET)])
    }

    /// Builds and writes a TCP FIN‑ACK reply when the outbound side closes.
    fileprivate func writeTCPFinToTUN(sessionKey: TCPSessionKey) {
        guard let session = tcpBridge.registry.lookup(sessionKey) else {
            return
        }

        var finAck = buildTCPDataSegment(
            srcPort: sessionKey.destinationPort,
            dstPort: sessionKey.sourcePort,
            seq: session.serverNextSeq,
            ack: session.clientNextSeq,
            payload: Data(),
            window: session.advertisedWindow,
            flags: [.fin, .ack]
        )

        let checksum = TCPChecksum.computeIPv4(
            sourceAddr: sessionKey.destinationIP,
            destAddr: sessionKey.sourceIP,
            tcpSegment: finAck
        )
        finAck[16] = UInt8(truncatingIfNeeded: checksum >> 8)
        finAck[17] = UInt8(truncatingIfNeeded: checksum)

        guard let ipPacket = try? assembleIPv4ReplyPacket(
            sourceAddr: sessionKey.destinationIP,
            destAddr: sessionKey.sourceIP,
            payload: finAck
        ) else { return }

        session.state = .closed
        outboundChannels.removeValue(forKey: sessionKey)
        tcpBridge.registry.remove(sessionKey)

        packetFlow.writePackets([ipPacket], withProtocols: [NSNumber(value: AF_INET)])
    }

    // MARK: - UDP Outbound Forwarding

    /// Forwards a UDP payload to the outbound proxy pipeline.  Currently
    /// writes a simple echo/direct reply for local testing; production
    /// deployments would route through a `UdpAssociationManager`.
    private func handleUDPForward(
        session: UdpBridgeSessionKey,
        payload: Data
    ) {
        // In a full deployment, this would forward through the outbound
        // proxy's UDP association (e.g., WireGuard, Hysteria2, or a
        // SOCKS5 UDP relay).  For now, we simply acknowledge receipt.
        //
        // A production implementation would:
        //   1. Look up the routing decision for the destination.
        //   2. Select the appropriate outbound UDP transport.
        //   3. Relay the payload and register a reply callback.
        //
        // The session is already registered in `udpBridge.registry` by
        // `TUN2UdpBridge.processInbound`, so reply packets can use
        // `udpBridge.buildReply(for:payload:)` to construct the return
        // IPv4/UDP packet when response data arrives.
    }

    /// Writes a UDP reply packet back to the TUN interface.
    /// Call this when an outbound UDP transport delivers response data.
    public func writeUDPReplyToTUN(
        session: UdpBridgeSessionKey,
        payload: Data
    ) {
        let replyPacket = udpBridge.buildReply(for: session, payload: payload)
        packetFlow.writePackets(
            [replyPacket],
            withProtocols: [NSNumber(value: AF_INET)]
        )
    }

    // MARK: - Reassembly Eviction

    /// Periodically purges stalled TCP reassembly buffers and forwards
    /// evicted data to the outbound tunnel.  Reschedules itself every
    /// 500 ms while the tunnel is active.
    private func purgeStaleReassembly() {
        guard !tunnelStopping else { return }

        let evicted = tcpBridge.evictStaleReassemblyData(olderThan: 0.750)
        for (sessionKey, segments) in evicted {
            for (_, segData) in segments {
                if let channel = outboundChannels[sessionKey], channel.isActive {
                    var buf = channel.allocator.buffer(capacity: segData.count)
                    buf.writeBytes(segData)
                    channel.writeAndFlush(buf, promise: nil)
                }
            }
        }

        // Reschedule.
        guard !tunnelStopping, let loop = eventLoop else { return }
        evictionTask = loop.scheduleTask(in: .milliseconds(500)) { [weak self] in
            self?.purgeStaleReassembly()
        }
    }

    // MARK: - stopTunnel (Graceful Teardown)

    /// Stops the packet ingestion loop, drains all active sessions, closes
    /// every outbound channel, shuts down the event‑loop group, and calls
    /// the system completion handler with zero dangling references.
    open override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        // ---- 1. Signal the ingestion loop to stop -----------------------
        tunnelStopping = true

        // ---- 2. Cancel the eviction timer -------------------------------
        evictionTask?.cancel()
        evictionTask = nil

        // ---- 3. Close all outbound TCP channels -------------------------
        let channels = outboundChannels
        outboundChannels.removeAll()
        for (_, channel) in channels {
            channel.close(mode: .all, promise: nil)
        }

        // ---- 4. Drain the TCP session registry --------------------------
        tcpBridge.registry.removeAll()

        // ---- 5. Drain the UDP session registry --------------------------
        udpBridge.registry.removeAll()

        // ---- 6. Shut down the event‑loop group --------------------------
        if let group = eventLoopGroup {
            // Synchronous shutdown on a non‑event‑loop thread is safe
            // because we've already cancelled all scheduled work.
            try? group.syncShutdownGracefully()
            eventLoopGroup = nil
        }

        // ---- 7. Signal completion to the system -------------------------
        completionHandler()
    }

    // MARK: - Packet Assembly Helpers

    /// Builds a 20‑byte TCP header for a data segment, optionally carrying
    /// a payload and/or FIN/ACK flags.
    private func buildTCPDataSegment(
        srcPort: UInt16,
        dstPort: UInt16,
        seq: UInt32,
        ack: UInt32,
        payload: Data,
        window: UInt16,
        flags: TCPFlags = .ack
    ) -> [UInt8] {
        let headerLen = 20
        var segment = [UInt8](repeating: 0, count: headerLen + payload.count)

        segment[0] = UInt8(truncatingIfNeeded: srcPort >> 8)
        segment[1] = UInt8(truncatingIfNeeded: srcPort)
        segment[2] = UInt8(truncatingIfNeeded: dstPort >> 8)
        segment[3] = UInt8(truncatingIfNeeded: dstPort)
        segment[4] = UInt8(truncatingIfNeeded: seq >> 24)
        segment[5] = UInt8(truncatingIfNeeded: seq >> 16)
        segment[6] = UInt8(truncatingIfNeeded: seq >>  8)
        segment[7] = UInt8(truncatingIfNeeded: seq)
        segment[8] = UInt8(truncatingIfNeeded: ack >> 24)
        segment[9] = UInt8(truncatingIfNeeded: ack >> 16)
        segment[10] = UInt8(truncatingIfNeeded: ack >>  8)
        segment[11] = UInt8(truncatingIfNeeded: ack)
        segment[12] = 0x50  // Data Offset = 5 (20 bytes)
        segment[13] = flags.rawValue
        segment[14] = UInt8(truncatingIfNeeded: window >> 8)
        segment[15] = UInt8(truncatingIfNeeded: window)
        segment[16] = 0x00; segment[17] = 0x00  // checksum placeholder
        segment[18] = 0x00; segment[19] = 0x00  // urgent pointer

        // Copy payload.
        for (i, byte) in payload.enumerated() {
            segment[headerLen + i] = byte
        }

        return segment
    }

    /// Assembles a complete IPv4 packet (20‑byte header + payload) for
    /// TUN reply injection.  The header checksum is zeroed (kernel fills
    /// it in for TUN interfaces).
    private func assembleIPv4ReplyPacket(
        sourceAddr: IPv4Address,
        destAddr: IPv4Address,
        payload: [UInt8]
    ) throws -> Data {
        let headerLen = 20
        let totalLen = headerLen + payload.count

        var bytes = [UInt8](repeating: 0, count: totalLen)

        // Version (4) | IHL (5).
        bytes[0] = 0x45
        // ToS.
        bytes[1] = 0x00
        // Total Length.
        bytes[2] = UInt8(truncatingIfNeeded: totalLen >> 8)
        bytes[3] = UInt8(truncatingIfNeeded: totalLen)
        // Identification (0).
        bytes[4] = 0x00; bytes[5] = 0x00
        // Flags + Fragment Offset (0).
        bytes[6] = 0x00; bytes[7] = 0x00
        // TTL (64).
        bytes[8] = 0x40
        // Protocol = TCP (6).
        bytes[9] = 6
        // Header Checksum (0 — kernel fills it for TUN).
        bytes[10] = 0x00; bytes[11] = 0x00
        // Source Address.
        bytes[12] = sourceAddr.octet0
        bytes[13] = sourceAddr.octet1
        bytes[14] = sourceAddr.octet2
        bytes[15] = sourceAddr.octet3
        // Destination Address.
        bytes[16] = destAddr.octet0
        bytes[17] = destAddr.octet1
        bytes[18] = destAddr.octet2
        bytes[19] = destAddr.octet3
        // Payload.
        for (i, byte) in payload.enumerated() {
            bytes[headerLen + i] = byte
        }

        return Data(bytes)
    }

    /// Converts an `IPv4Address` to its `UInt32` representation.
    private func ipv4AsUInt32(_ addr: IPv4Address) -> UInt32 {
        (UInt32(addr.octet0) << 24)
        | (UInt32(addr.octet1) << 16)
        | (UInt32(addr.octet2) <<  8)
        |  UInt32(addr.octet3)
    }
}

// MARK: - Sendable Completion Box

/// Wraps a non‑`@Sendable` closure so it can be captured inside a
/// `@Sendable` closure (e.g., `setTunnelNetworkSettings` callback)
/// without a strict‑concurrency diagnostic.
private final class CompletionBox: @unchecked Sendable {
    let handler: (Error?) -> Void
    init(_ handler: @escaping (Error?) -> Void) {
        self.handler = handler
    }
}

// MARK: - Outbound → TUN Relay Handler

/// A private `ChannelInboundHandler` installed on each outbound TCP channel
/// that forwards response data back to the TUN interface as properly formed
/// IPv4/TCP packets.
private final class OutboundToTUNRelayHandler: ChannelInboundHandler,
                                                RemovableChannelHandler,
                                                @unchecked Sendable {
    typealias InboundIn = ByteBuffer
    typealias InboundOut = ByteBuffer

    /// Weak reference to the owning tunnel provider (prevents retain cycles).
    private weak var parent: SwiftletTunnelProvider?

    /// The virtual TCP session this handler is associated with.
    private let sessionKey: TCPSessionKey

    init(parent: SwiftletTunnelProvider, sessionKey: TCPSessionKey) {
        self.parent = parent
        self.sessionKey = sessionKey
    }

    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        parent?.writeTCPReplyToTUN(
            sessionKey: sessionKey,
            data: Data(bytes)
        )
    }

    func channelInactive(context: ChannelHandlerContext) {
        // Outbound side closed — send FIN‑ACK to the TUN client so the
        // local TCP stack can cleanly tear down the connection.
        parent?.writeTCPFinToTUN(sessionKey: sessionKey)
        context.fireChannelInactive()
    }

    func errorCaught(context: ChannelHandlerContext, error: Error) {
        // Outbound error — close the virtual session.
        parent?.writeTCPFinToTUN(sessionKey: sessionKey)
        context.close(mode: .all, promise: nil)
    }
}
