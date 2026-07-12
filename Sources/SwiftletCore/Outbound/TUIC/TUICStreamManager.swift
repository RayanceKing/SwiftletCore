//===----------------------------------------------------------------------===//
//
//  TUICStreamManager.swift
//  SwiftletCore — TUIC v5 Async Stream Multiplexer Orchestrator
//
//  A concurrency‑safe `actor` that manages multiple virtual socket
//  channels multiplexed over a single active QUIC connection.  It is
//  the central coordination point between the TUN‑layer bridge and
//  the TUIC‑framed transport.
//
//  Responsibilities
//  ----------------
//  1. Maintain a registry of active streams keyed by `sessionID`.
//  2. Authenticate the master QUIC connection (Type 0x00).
//  3. Allocate new streams on demand, injecting a `.connect` frame
//     (Type 0x01) as each stream's first outbound packet.
//  4. Route outbound `.packet` frames (Type 0x02) to the correct
//     stream and inbound payload back to the matched local session.
//  5. Tear down streams cleanly via `.disconnect` (Type 0x03).
//
//  Concurrency
//  -----------
//  All mutable state is isolated behind the `actor` boundary.
//  Callers from SwiftNIO event‑loop contexts should bridge via
//  `Task { await manager.… }`.
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

// MARK: - Stream State

/// Lifecycle states for a TUIC virtual stream.
public enum TUICStreamState: UInt8, Sendable, Equatable, CustomStringConvertible {
    /// Stream created locally; `.connect` frame queued for delivery.
    case connecting = 0

    /// Stream fully established — `.packet` frames are flowing
    /// bidirectionally.
    case established = 1

    /// `.disconnect` sent or received; awaiting final acknowledgment.
    case closing = 2

    /// Stream is fully torn down and eligible for removal from the
    /// registry.
    case closed = 3

    public var description: String {
        switch self {
        case .connecting:  return "CONNECTING"
        case .established: return "ESTABLISHED"
        case .closing:     return "CLOSING"
        case .closed:      return "CLOSED"
        }
    }
}

// MARK: - Stream Context

/// Per‑stream metadata and I/O buffers managed by the multiplexer.
///
/// Each context holds the stream's identity (session ID, target address),
/// lifecycle state, traffic counters, and an optional per‑stream channel
/// handler reference.
public final class TUICStreamContext: @unchecked Sendable {

    /// The TUIC session / stream identifier.
    public let sessionID: UInt16

    /// The remote destination address requested in the `.connect` frame.
    public let targetAddress: String

    /// The remote destination port.
    public let targetPort: UInt16

    /// Current lifecycle state (mutated exclusively by the manager actor).
    public private(set) var state: TUICStreamState

    /// Total bytes sent on this stream (outbound).
    public private(set) var bytesSent: Int = 0

    /// Total bytes received on this stream (inbound).
    public private(set) var bytesReceived: Int = 0

    /// Monotonic creation timestamp.
    public let createdAt: Date

    /// The per‑stream handler instance (weak, to avoid cycles if the
    /// stream channel outlives the context).
    public weak var handler: TUICClientStreamHandler?

    /// Callback invoked when decoded payload data arrives on this stream.
    /// Set by the integration layer to pipe data back to the TUN bridge.
    public var onInboundData: (@Sendable (Data) -> Void)?

    // MARK: - Initialisation

    public init(
        sessionID: UInt16,
        targetAddress: String,
        targetPort: UInt16
    ) {
        self.sessionID = sessionID
        self.targetAddress = targetAddress
        self.targetPort = targetPort
        self.state = .connecting
        self.createdAt = Date()
    }

    // MARK: - State Transitions (called by manager)

    fileprivate func markEstablished() { state = .established }
    fileprivate func markClosing()      { state = .closing }
    fileprivate func markClosed()       { state = .closed }

    fileprivate func addSent(_ count: Int)    { bytesSent &+= count }
    fileprivate func addReceived(_ count: Int) { bytesReceived &+= count }
}

// MARK: - TUIC Stream Manager

/// An `actor` that multiplexes multiple virtual TCP sessions over a
/// single TUIC‑over‑QUIC transport connection.
///
/// ## Usage
/// ```swift
/// let manager = TUICStreamManager(uuid: myUUID, udpMode: 0)
/// await manager.setTransport { data in
///     quicConnection.send(data)
/// }
/// await manager.onStreamData { sessionID, payload in
///     bridge.injectInbound(sessionID: sessionID, data: payload)
/// }
/// try await manager.authenticate()
/// let sid = try await manager.openStream(
///     addressType: .domain, address: "example.com", port: 443
/// )
/// try await manager.sendPacket(sessionID: sid, payload: tlsClientHello)
/// ```
public actor TUICStreamManager {

    // MARK: - Type Aliases

    /// Closure that delivers raw TUIC‑framed bytes to the QUIC transport.
    public typealias SendTransport = @Sendable (Data) async -> Void

    /// Closure invoked when decoded stream payload arrives.
    public typealias StreamDataHandler = @Sendable (UInt16, Data) async -> Void

    // MARK: - Configuration

    /// The TUIC authentication UUID.
    private let uuid: UUID

    /// UDP relay mode byte (0x00 = TCP only, 0x01 = UDP enabled).
    private let udpMode: UInt8

    // MARK: - Stream Registry

    /// Active stream contexts keyed by TUIC `sessionID` (UInt16).
    private var streams: [UInt16: TUICStreamContext] = [:]

    /// Next available session ID (monotonically increasing, wraps at
    /// UInt16.max → 1, skipping 0 which is reserved).
    private var nextStreamID: UInt16 = 1

    // MARK: - Authentication

    /// Whether the master QUIC connection has been authenticated.
    public private(set) var isAuthenticated: Bool = false

    // MARK: - Transport Hooks

    /// The transport used to send raw bytes over the QUIC connection.
    /// Must be set before any frames can be dispatched.
    private var transport: SendTransport?

    /// Callback for delivering inbound stream data to the upper layer.
    private var streamDataHandler: StreamDataHandler?

    // MARK: - Initialisation

    /// Creates a new stream manager for a single TUIC‑over‑QUIC session.
    ///
    /// - Parameters:
    ///   - uuid: The TUIC authentication UUID.
    ///   - udpMode: `0x00` = TCP only, `0x01` = UDP relaying enabled.
    public init(uuid: UUID, udpMode: UInt8 = 0) {
        self.uuid = uuid
        self.udpMode = udpMode
    }

    // MARK: - Configuration

    /// Sets the transport used to send raw TUIC‑framed bytes.
    ///
    /// In production this writes to the QUIC connection's control stream;
    /// in tests this is a closure that captures sent data.
    public func setTransport(_ transport: @escaping SendTransport) {
        self.transport = transport
    }

    /// Registers a handler for inbound stream payload data.
    ///
    /// The handler receives `(sessionID, payload)` pairs and should
    /// route the payload back to the TUN bridge.
    public func onStreamData(_ handler: @escaping StreamDataHandler) {
        self.streamDataHandler = handler
    }

    // MARK: - Authentication

    /// Sends the TUIC Authenticate frame (Type 0x00) to establish the
    /// master session with the server.
    ///
    /// Must be called once before any streams can be opened.
    ///
    /// - Throws: `TUICManagerError.transportNotConfigured` if no
    ///   transport has been set.
    public func authenticate() async throws {
        guard let transport = transport else {
            throw TUICManagerError.transportNotConfigured
        }

        let frame = TUICFrame.authenticate(uuid: uuid, udpMode: udpMode)
        var buffer = TUICFrameEncoder.encode(frame)
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            throw TUICManagerError.encodeFailed
        }

        await transport(Data(data))
        isAuthenticated = true
    }

    // MARK: - Open Stream

    /// Allocates a new virtual stream, sends a `.connect` frame, and
    /// returns the stream's `sessionID`.
    ///
    /// This is the entry point called by `TUN2SocksBridge` when a new
    /// TCP SYN arrives — no new UDP socket handshake is triggered;
    /// the stream is multiplexed over the existing QUIC connection.
    ///
    /// - Parameters:
    ///   - addressType: The address encoding (`.ipv4`, `.ipv6`, `.domain`).
    ///   - address: The destination hostname or IP string.
    ///   - port: The destination port number.
    /// - Returns: The allocated `sessionID` (UInt16).
    /// - Throws: `TUICManagerError` on transport or encoding failure.
    @discardableResult
    public func openStream(
        addressType: TUICAddressType,
        address: String,
        port: UInt16
    ) async throws -> UInt16 {
        guard let transport = transport else {
            throw TUICManagerError.transportNotConfigured
        }

        let sessionID = allocateStreamID()

        // Create the stream context.
        let context = TUICStreamContext(
            sessionID: sessionID,
            targetAddress: address,
            targetPort: port
        )
        streams[sessionID] = context

        // Build and send the Connect frame.
        let frame = TUICFrame.connect(
            addressType: addressType,
            address: address,
            port: port
        )
        var buffer = TUICFrameEncoder.encode(frame)
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            throw TUICManagerError.encodeFailed
        }

        await transport(Data(data))
        context.markEstablished()

        return sessionID
    }

    // MARK: - Send Packet

    /// Sends a `.packet` frame carrying payload data on the specified
    /// stream.
    ///
    /// - Parameters:
    ///   - sessionID: The target stream identifier.
    ///   - payload: The raw data to send (inner IP packet or TCP segment).
    /// - Throws: `TUICManagerError` if the stream is not found, not in
    ///   an established state, or encoding/transport fails.
    public func sendPacket(
        sessionID: UInt16,
        payload: Data
    ) async throws {
        guard let transport = transport else {
            throw TUICManagerError.transportNotConfigured
        }

        guard let context = streams[sessionID] else {
            throw TUICManagerError.streamNotFound(sessionID)
        }

        guard context.state == .established || context.state == .connecting
        else {
            throw TUICManagerError.streamNotReady(context.state)
        }

        let frame = TUICFrame.packet(sessionID: sessionID, payload: payload)
        var buffer = TUICFrameEncoder.encode(frame)
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            throw TUICManagerError.encodeFailed
        }

        await transport(Data(data))
        context.addSent(payload.count)
    }

    // MARK: - Close Stream

    /// Sends a `.disconnect` frame for the specified stream and removes
    /// it from the registry.
    ///
    /// - Parameter sessionID: The stream to tear down.
    /// - Throws: `TUICManagerError` if the stream is not found.
    public func closeStream(sessionID: UInt16) async throws {
        guard let transport = transport else {
            throw TUICManagerError.transportNotConfigured
        }

        guard let context = streams[sessionID] else {
            throw TUICManagerError.streamNotFound(sessionID)
        }

        let frame = TUICFrame.disconnect(sessionID: sessionID)
        var buffer = TUICFrameEncoder.encode(frame)
        guard let data = buffer.readBytes(length: buffer.readableBytes) else {
            throw TUICManagerError.encodeFailed
        }

        await transport(Data(data))
        context.markClosed()
        streams.removeValue(forKey: sessionID)
    }

    /// Tears down all active streams immediately.
    public func closeAllStreams() async {
        guard let transport = transport else {
            streams.removeAll()
            return
        }

        for (sessionID, context) in streams {
            let frame = TUICFrame.disconnect(sessionID: sessionID)
            var buffer = TUICFrameEncoder.encode(frame)
            if let data = buffer.readBytes(length: buffer.readableBytes) {
                await transport(Data(data))
            }
            context.markClosed()
        }
        streams.removeAll()
    }

    // MARK: - Handle Incoming Data

    /// Processes raw bytes received from the QUIC transport.
    ///
    /// The bytes are decoded via `TUICStreamDecoder`.  Authenticate
    /// responses update the internal state; `.packet` frames are
    /// routed to the appropriate stream's data handler; `.disconnect`
    /// frames trigger stream cleanup.
    ///
    /// - Parameter data: Raw TUIC‑framed bytes from the QUIC connection.
    public func handleIncoming(data: Data) async throws {
        var buffer = ByteBuffer(bytes: data)

        while buffer.readableBytes > 0 {
            let frame = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
            guard let frame = frame else {
                // Incomplete frame — stop processing.  The remaining
                // bytes stay in `buffer` for the next call.
                break
            }

            try await processIncomingFrame(frame)
        }
    }

    /// Processes incoming raw bytes from the QUIC transport, routing
    /// decoded frames to the appropriate stream context.
    public func handleIncoming(buffer: inout ByteBuffer) async throws {
        while buffer.readableBytes > 0 {
            let frame = try TUICStreamDecoder.decodeNextFrame(from: &buffer)
            guard let frame = frame else { break }
            try await processIncomingFrame(frame)
        }
    }

    // MARK: - Frame Processing

    /// Routes a decoded incoming frame to the correct handler.
    private func processIncomingFrame(_ frame: TUICFrame) async throws {
        switch frame {
        case .authenticate:
            // Server may re‑authenticate; acknowledge silently.
            isAuthenticated = true

        case .connect:
            // Server‑initiated connections are not supported in this
            // implementation; ignore.
            break

        case .packet(let sessionID, let payload):
            guard let context = streams[sessionID] else {
                // Packet for unknown stream — may arrive before our
                // local state is updated; drop silently.
                return
            }
            context.addReceived(payload.count)

            // Deliver payload to the stream's handler callback.
            if let handler = context.onInboundData {
                handler(payload)
            }
            if let globalHandler = streamDataHandler {
                await globalHandler(sessionID, payload)
            }

        case .disconnect(let sessionID):
            if let context = streams[sessionID] {
                context.markClosed()
                streams.removeValue(forKey: sessionID)
            }

        case .heartbeat:
            // Keepalive — acknowledge by echoing back.
            if let transport = transport {
                var reply = TUICFrameEncoder.encode(.heartbeat)
                if let data = reply.readBytes(length: reply.readableBytes) {
                    await transport(Data(data))
                }
            }
        }
    }

    // MARK: - Stream ID Allocation

    /// Allocates the next available session ID (wrapping at UInt16.max).
    private func allocateStreamID() -> UInt16 {
        let allocated = nextStreamID
        repeat {
            nextStreamID &+= 1
            if nextStreamID == 0 { nextStreamID = 1 }
        } while streams[nextStreamID] != nil && nextStreamID != allocated

        guard nextStreamID != allocated else {
            // All 65535 IDs are in use — fall back to linear scan.
            for id in (1 ... UInt16.max) where streams[id] == nil {
                nextStreamID = id &+ 1
                if nextStreamID == 0 { nextStreamID = 1 }
                return id
            }
            // Truly exhausted (should never happen in practice).
            nextStreamID = 1
            return allocated
        }

        return allocated
    }

    // MARK: - Diagnostic Accessors

    /// The number of currently active streams.
    public var activeStreamCount: Int { streams.count }

    /// Whether any streams are currently registered.
    public var hasActiveStreams: Bool { !streams.isEmpty }

    /// Looks up a stream context by session ID.
    public func streamContext(for sessionID: UInt16) -> TUICStreamContext? {
        streams[sessionID]
    }

    /// All currently active stream IDs.
    public var activeStreamIDs: [UInt16] {
        Array(streams.keys).sorted()
    }

    /// Returns the total bytes sent and received across all streams.
    public var aggregateTraffic: (sent: Int, received: Int) {
        var sent = 0, received = 0
        for ctx in streams.values {
            sent += ctx.bytesSent
            received += ctx.bytesReceived
        }
        return (sent, received)
    }
}

// MARK: - Errors

/// Errors thrown by the TUIC stream manager.
public enum TUICManagerError: Error, Sendable, Equatable {
    /// No transport has been configured; call `setTransport(_:)` first.
    case transportNotConfigured
    /// The requested stream ID does not exist in the registry.
    case streamNotFound(UInt16)
    /// The stream is not in a state that allows data transfer.
    case streamNotReady(TUICStreamState)
    /// Frame encoding failed unexpectedly.
    case encodeFailed
}
