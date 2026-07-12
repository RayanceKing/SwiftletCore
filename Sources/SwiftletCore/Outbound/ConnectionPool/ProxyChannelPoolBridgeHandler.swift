//===----------------------------------------------------------------------===//
//
//  ProxyChannelPoolBridgeHandler.swift
//  SwiftletCore — Pipeline Detachment & Pool Recycle Handler
//
//  A `ChannelInboundHandler` that sits at the boundary between the raw
//  TCP/TLS transport and the protocol‑specific handlers.  It enables
//  dynamic session detachment without tearing down the underlying
//  connection — the foundational primitive for connection pooling.
//
//  Pipeline Placement
//  ------------------
//  ```
//  [TCP Socket]
//    → ProxyChannelPoolBridgeHandler   ◄── this handler (bottom)
//    → [Optional Obfuscation Layers]
//    → [NIOSSLHandler / Reality / etc.]
//    → [Protocol Core: SS / Trojan / VMess / VLESS]
//    → [Per‑Session Bridge Handler]    ◄── added on acquire
//    → [Inbound Client Relay]          ◄── detachable session layer
//  ```
//
//  Lifecycle
//  ---------
//  ```
//  acquire  →  addSessionHandler(...)  →  mark active
//  session  →  ... proxy traffic ...
//  release  →  detachSessionHandlers() →  flush, return to pool
//  idle     →  [TTL expires]           →  close channel
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Pool Bridge Handler

/// Manages the transition of a channel between "active session" and
/// "idle pooled" states.
///
/// When a session completes, this handler strips the session‑specific
/// layers from the pipeline and returns the raw transport channel to
/// the connection pool for immediate reuse.
///
/// - Important: One instance per outbound channel.  The handler is
///   **not** shareable across channels.
public final class ProxyChannelPoolBridgeHandler: ChannelInboundHandler,
                                                    RemovableChannelHandler,
                                                    @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer

    // MARK: - State

    /// Whether this channel is currently leased to an active session.
    public private(set) var isLeased: Bool = false

    /// The pool key for this channel's destination.
    public let poolKey: PoolKey

    /// The proxy node configuration that established this channel.
    public let node: ProxyNodeConfiguration

    /// The names of session‑specific handlers that were added above
    /// this handler.  Tracked so they can be precisely removed on detach.
    private var sessionHandlerNames: [String] = []

    /// Callback invoked when the underlying TCP connection closes while
    /// the channel is idle in the pool.  The pool uses this to remove
    /// the dead entry from its inventory without polling.
    private var onChannelClosedWhileIdle: ((PoolKey) -> Void)?

    // MARK: - Initialisation

    /// - Parameters:
    ///   - poolKey: The pool coordinate for this channel.
    ///   - node: The proxy node configuration.
    public init(poolKey: PoolKey, node: ProxyNodeConfiguration) {
        self.poolKey = poolKey
        self.node = node
    }

    // MARK: - Session Lease

    /// Marks the channel as actively leased to a session.
    ///
    /// Called by the pool's acquire path after session handlers have
    /// been added to the pipeline.  Puts the handler in forwarding mode.
    public func markLeased() {
        isLeased = true
    }

    // MARK: - Session Detach

    /// Detaches all session‑specific handlers from the pipeline and
    /// returns the channel to the pool.
    ///
    /// - Parameters:
    ///   - context: The channel handler context for pipeline manipulation.
    ///   - onComplete: Called after the channel has been recycled into
    ///     the pool (or closed if recycling failed).
    public func detachAndRecycle(
        context: ChannelHandlerContext,
        onComplete: @escaping @Sendable () -> Void = {}
    ) {
        // Remove all session‑specific handlers (in reverse order —
        // topmost first, down to just above this handler).
        let names = sessionHandlerNames
        sessionHandlerNames.removeAll()
        isLeased = false

        // Extract references before entering @Sendable / Task closures.
        let pipeline = context.pipeline
        let channel  = context.channel
        let loop     = context.eventLoop

        // Chain removals via flatMap, then release to pool.
        var future: EventLoopFuture<Void> = loop.makeSucceededVoidFuture()
        for name in names.reversed() {
            future = future.flatMap {
                pipeline.removeHandler(name: name)
            }
        }

        future.whenComplete { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success:
                // Successfully stripped session handlers — return to pool.
                Task { [channel, node = self.node] in
                    await OutboundConnectionPool.shared.releaseChannel(
                        channel, for: node
                    )
                }
            case .failure:
                // Pipeline manipulation failed — close the channel.
                channel.close(mode: .all, promise: nil)
            }
            onComplete()
        }
    }

    /// Registers a session handler name to track for later removal.
    public func trackSessionHandler(name: String) {
        sessionHandlerNames.append(name)
    }

    /// Registers a callback for when the channel closes while idle.
    public func setOnIdleClose(_ callback: @escaping (PoolKey) -> Void) {
        onChannelClosedWhileIdle = callback
    }

    // MARK: - ChannelInboundHandler

    /// While leased, forward data up the pipeline.  While idle, buffer
    /// is empty — any data arriving on an idle pooled channel is a
    /// protocol error (the remote end sent unsolicited data).
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if isLeased {
            context.fireChannelRead(data)
        } else {
            // Unsolicited data on idle pooled connection — the remote
            // server may have timed us out.  Drain and close silently.
            var buffer = unwrapInboundIn(data)
            _ = buffer.readBytes(length: buffer.readableBytes)
        }
    }

    /// Propagate writability changes only while leased.
    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        if isLeased {
            context.fireChannelWritabilityChanged()
        }
    }

    /// When the underlying TCP connection closes, notify the pool if
    /// we are idle, or propagate the event if leased.
    public func channelInactive(context: ChannelHandlerContext) {
        if !isLeased {
            // Died while idle — tell the pool so it can remove the
            // dead entry without waiting for the next eviction scan.
            onChannelClosedWhileIdle?(poolKey)
        }
        context.fireChannelInactive()
    }

    /// Propagate errors only while leased; suppress while idle.
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        if isLeased {
            context.fireErrorCaught(error)
        } else {
            // Error on idle pooled connection — close it.
            context.close(mode: .all, promise: nil)
        }
    }

    // MARK: - Diagnostic

    /// Number of tracked session handlers currently stacked above this
    /// bridge handler.
    public var trackedHandlerCount: Int { sessionHandlerNames.count }
}
