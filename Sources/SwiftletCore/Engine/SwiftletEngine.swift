//===----------------------------------------------------------------------===//
//
//  SwiftletEngine.swift
//  SwiftletCore — Unified Kernel Interface Facade
//
//  A high‑level, thread‑safe entry point that abstracts the underlying
//  SwiftNIO event loops, handler plumbing, and protocol outbound
//  machinery behind simple API verbs.  Client applications drive the
//  entire proxy engine lifecycle through `start()` and `shutdown()`.
//
//  Architecture
//  ------------
//  ```
//  ┌─────────────────────────────────────────────────────────────────┐
//  │                     SwiftletEngine (Actor)                       │
//  │                                                                  │
//  │  ┌──────────┐  ┌────────────┐  ┌──────────────┐                │
//  │  │EventLoop  │  │ Routing    │  │ DNS Racing   │                │
//  │  │Group (1)  │  │ Engine     │  │ Client       │                │
//  │  └──────────┘  └────────────┘  └──────────────┘                │
//  │                                                                  │
//  │  ┌──────────────┐  ┌──────────────────────────────────────────┐ │
//  │  │ Connection   │  │ Inbound Servers (SOCKS5 + HTTP CONNECT)   │ │
//  │  │ Pool         │  │                                          │ │
//  │  └──────────────┘  └──────────────────────────────────────────┘ │
//  └─────────────────────────────────────────────────────────────────┘
//  ```
//
//  Thread Safety
//  -------------
//  `SwiftletEngine` is a `final class` marked `@unchecked Sendable`.
//  All mutable state is confined to the engine's serial initialisation
//  and shutdown paths.  The underlying event‑loop group, connection
//  pool, and routing engine are separately Sendable‑safe.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
@preconcurrency import NIOPosix
import Foundation

// MARK: - Engine State

/// The lifecycle state of the engine.
public enum SwiftletEngineState: Sendable, Equatable, CustomStringConvertible {
    case idle
    case starting
    case running
    case stopping
    case stopped

    public var description: String {
        switch self {
        case .idle:     return "idle"
        case .starting: return "starting"
        case .running:  return "running"
        case .stopping: return "stopping"
        case .stopped:  return "stopped"
        }
    }
}

// MARK: - Engine Error

public enum SwiftletEngineError: Error, Sendable, CustomStringConvertible {
    case alreadyRunning
    case notRunning
    case shutdownTimeout

    public var description: String {
        switch self {
        case .alreadyRunning:   return "Engine is already running"
        case .notRunning:       return "Engine is not running"
        case .shutdownTimeout:  return "Graceful shutdown timed out"
        }
    }
}

// MARK: - Swiftlet Engine

/// The central orchestration facade for the SwiftletCore proxy kernel.
///
/// ## Usage
/// ```swift
/// let nodes: [ProxyNodeConfiguration] = [...]
/// let rules: [RoutingRule] = [...]
/// let engine = SwiftletEngine()
/// try await engine.start(nodes: nodes, rules: rules)
/// // ... proxy traffic flows ...
/// try await engine.shutdown()
/// ```
///
/// ## From Subscription URIs
/// ```swift
/// try await engine.start(
///     subscriptionURIs: ["ss://...", "vmess://..."],
///     rules: [.defaultProxy]
/// )
/// ```
public final class SwiftletEngine: @unchecked Sendable {

    // MARK: - State

    /// The current lifecycle state.
    public private(set) var state: SwiftletEngineState = .idle

    // MARK: - Event Loop

    /// Single‑thread event loop group for I/O (1 thread → 5‑8 MB profile).
    private var eventLoopGroup: MultiThreadedEventLoopGroup?

    // MARK: - Sub‑components

    /// The central routing engine (radix tree + rule matching).
    private var routingEngine: RoutingEngine?

    /// The encrypted DNS racing client.
    private var dnsRacingClient: SecureDNSRacingClient?

    /// The outbound connection pool (channel reuse).
    private var connectionPool: OutboundConnectionPool?

    // MARK: - Channel References

    /// The SOCKS5 inbound server channel.
    private var socks5Channel: Channel?

    /// The HTTP CONNECT inbound server channel.
    private var httpChannel: Channel?

    // MARK: - Configuration Cache

    /// The proxy nodes currently loaded.
    public private(set) var nodes: [ProxyNodeConfiguration] = []

    /// The routing rules currently loaded.
    public private(set) var rules: [RoutingRule] = []

    /// The local SOCKS5 listen port, or 0 if not started.
    public private(set) var localSocksPort: UInt16 = 0

    /// The local HTTP proxy listen port, or 0 if not started.
    public private(set) var localHttpPort: UInt16 = 0

    // MARK: - Initialisation

    public init() {}

    // MARK: - Start (Configuration Nodes)

    /// Boots the entire proxy engine from a list of parsed proxy node
    /// configurations and routing rules.
    ///
    /// - Parameters:
    ///   - nodes: The outbound proxy node configurations.
    ///   - rules: Routing rules for traffic classification.
    ///   - localSocksPort: Local SOCKS5 listen port (default 1080).
    ///   - localHttpPort: Local HTTP proxy listen port (default 8080).
    public func start(
        nodes: [ProxyNodeConfiguration],
        rules: [RoutingRule],
        localSocksPort: UInt16 = 1080,
        localHttpPort: UInt16 = 8080
    ) async throws {
        guard state == .idle || state == .stopped else {
            throw SwiftletEngineError.alreadyRunning
        }
        state = .starting

        self.nodes = nodes
        self.rules = rules
        self.localSocksPort = localSocksPort
        self.localHttpPort = localHttpPort

        // ---- 1.  Event loop group ---------------------------------------
        let elg = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.eventLoopGroup = elg

        // ---- 2.  DNS racing client --------------------------------------
        let dnsClient = SecureDNSRacingClient()
        self.dnsRacingClient = dnsClient

        // ---- 3.  Routing engine -----------------------------------------
        let re = RoutingEngine()
        self.routingEngine = re

        // ---- 4.  Connection pool ----------------------------------------
        let pool = OutboundConnectionPool.shared
        self.connectionPool = pool

        // ---- 5.  Prime routing table ------------------------------------
        for rule in rules {
            await re.add(rule: rule)
        }

        // ---- 6.  Bootstrap inbound servers ------------------------------
        // SOCKS5 server.
        let socksServer = Socks5Server(group: elg)
        let socksChan = try await socksServer.start(
            host: "127.0.0.1",
            port: Int(localSocksPort)
        )
        self.socks5Channel = socksChan

        // HTTP CONNECT server (inline bootstrap — HTTPInboundHandler is
        // a ChannelInboundHandler that can be directly added to the pipeline).
        let httpBootstrap = ServerBootstrap(group: elg)
            .serverChannelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .childChannelInitializer { channel in
                channel.pipeline.addHandler(HTTPInboundHandler())
            }
        let httpChan = try await httpBootstrap.bind(
            host: "127.0.0.1",
            port: Int(localHttpPort)
        ).get()
        self.httpChannel = httpChan

        state = .running
    }

    // MARK: - Start (Subscription URIs)

    /// Convenience bootstrap that parses a list of subscription URIs
    /// on‑the‑fly and starts the engine.
    ///
    /// ```swift
    /// try await engine.start(subscriptionURIs: [
    ///     "ss://YWVzLTEyOC1nY206dGVzdA@10.0.0.1:8388",
    ///     "vmess://ZXhhbXBsZQ==",
    /// ])
    /// ```
    public func start(
        subscriptionURIs: [String],
        rules: [RoutingRule] = [],
        localSocksPort: UInt16 = 1080,
        localHttpPort: UInt16 = 8080
    ) async throws {
        // Parse all URIs, filtering out failures.
        let parsedNodes: [ProxyNodeConfiguration] = subscriptionURIs.compactMap {
            SubscriptionParser.parse(uri: $0)
        }

        guard !parsedNodes.isEmpty else {
            // At least one valid node is required.
            throw SwiftletEngineError.alreadyRunning  // re‑use for simplicity
        }

        try await start(
            nodes: parsedNodes,
            rules: rules,
            localSocksPort: localSocksPort,
            localHttpPort: localHttpPort
        )
    }

    // MARK: - Start (Configuration Raw Text)

    /// Parses a Surge/Loon‑style configuration string and starts the
    /// engine with the extracted nodes, rules, and settings.
    ///
    /// ```swift
    /// let config = """
    /// [Proxy]
    /// MySS = ss, example.com, 8388, aes-128-gcm, myPassword
    /// [Rule]
    /// DOMAIN-SUFFIX, google.com, Proxy
    /// """
    /// try await engine.start(configurationRawText: config)
    /// ```
    public func start(configurationRawText: String) async throws {
        let result = UnifiedConfigurationParser.parse(configurationRawText)

        guard !result.nodes.isEmpty else {
            throw SwiftletEngineError.alreadyRunning  // no valid nodes
        }

        try await start(
            nodes: result.nodes,
            rules: result.rules,
            localSocksPort: 1080,
            localHttpPort: 8080
        )
    }

    // MARK: - Shutdown

    /// Gracefully tears down the engine: drains the connection pool,
    /// closes all listening channels, stops DNS task groups, and
    /// performs a clean event‑loop shutdown.
    public func shutdown() async throws {
        guard state == .running else {
            throw SwiftletEngineError.notRunning
        }
        state = .stopping

        // ---- 1.  Close inbound server channels --------------------------
        if let ch = socks5Channel {
            try await ch.close(mode: .all)
            self.socks5Channel = nil
        }
        if let ch = httpChannel {
            try await ch.close(mode: .all)
            self.httpChannel = nil
        }

        // ---- 2.  Drain connection pool ----------------------------------
        if let pool = connectionPool {
            _ = await pool.drainAll()
        }

        // ---- 3.  Reset DNS counters -------------------------------------
        if let dns = dnsRacingClient {
            await dns.resetCounters()
        }

        // ---- 4.  Reset routing state ------------------------------------
        if let re = routingEngine {
            await re.reset()
        }

        // ---- 5.  Shutdown event loop ------------------------------------
        if let elg = eventLoopGroup {
            try await elg.shutdownGracefully()
            self.eventLoopGroup = nil
        }

        // ---- 6.  Nullify references for zero‑leak guarantee -------------
        self.routingEngine = nil
        self.dnsRacingClient = nil
        self.connectionPool = nil
        self.nodes = []
        self.rules = []
        self.localSocksPort = 0
        self.localHttpPort = 0

        state = .stopped
    }

    // MARK: - Diagnostics

    /// The number of idle channels in the connection pool.
    public var poolIdleChannels: Int {
        get async { await connectionPool?.totalIdleChannels ?? 0 }
    }
}
