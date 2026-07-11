//===----------------------------------------------------------------------===//
//
//  Socks5Server.swift
//  SwiftletCore — SOCKS5 Listener Bootstrap
//
//  Provides a convenience API for creating a SOCKS5 proxy listener backed by
//  SwiftNIO's `ServerBootstrap`.  Callers may supply any `EventLoopGroup`
//  implementation — `MultiThreadedEventLoopGroup` (POSIX sockets) or
//  `NIOTSEventLoopGroup` (Network.framework on Apple platforms) — and the
//  handler pipeline is identical in both cases.
//
//  Usage (async/await)
//  -------------------
//  ```swift
//  let group  = MultiThreadedEventLoopGroup(numberOfThreads: 1)
//  let server = Socks5Server(group: group)
//  let channel = try await server.start(host: "127.0.0.1", port: 1080)
//  // … proxy is now listening …
//  try await server.shutdown()
//  try await group.shutdownGracefully()
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
@preconcurrency import NIOPosix

// MARK: - Server

/// A high‑level SOCKS5 proxy server that manages the listening socket and
/// configures each child channel with the complete SOCKS5 pipeline.
///
/// The server is not an `actor` — it is intended to be used from a single
/// controlling context (typically `main` or a structured concurrency task).
public final class Socks5Server: @unchecked Sendable {

    // MARK: - Stored Properties

    /// The event‑loop group used for both the listening socket and all
    /// child channels (passed through to `ClientBootstrap` for upstream
    /// connections via `context.eventLoop`).
    private let group: EventLoopGroup

    /// The bound listening channel, if `start()` has been called.
    private var channel: Channel?

    // MARK: - Initialisation

    /// - Parameter group: The event‑loop group that will own the listening
    ///   socket and all child channels.  Use `NIOTSEventLoopGroup` for
    ///   Apple‑platform Network Extensions.
    public init(group: EventLoopGroup) {
        self.group = group
    }

    // MARK: - Public API

    /// Binds the SOCKS5 server to the given host and port and returns the
    /// listening `Channel` once it is active.
    ///
    /// - Parameters:
    ///   - host: The bind address (e.g. `"127.0.0.1"` or `"::1"`).
    ///   - port: The TCP port to listen on.
    /// - Returns: The bound `Channel`.
    @discardableResult
    public func start(host: String, port: Int) async throws -> Channel {
        let bootstrap = ServerBootstrap(group: group)
            // Allow the kernel to queue up to 256 pending connections.
            .serverChannelOption(ChannelOptions.backlog, value: 256)
            // Reuse the address for fast restarts.
            .serverChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            // ---- Child channel pipeline ---------------------------------
            .childChannelInitializer { channel in
                // Install the SOCKS5 codec and handshake handler.
                // Names match `Socks5PipelineName` constants so the relay
                // reconfiguration can locate them deterministically.
                channel.pipeline.addHandler(
                    Socks5Decoder(),
                    name: Socks5PipelineName.decoder
                ).flatMap {
                    channel.pipeline.addHandler(
                        Socks5Encoder(),
                        name: Socks5PipelineName.encoder
                    )
                }.flatMap {
                    channel.pipeline.addHandler(
                        Socks5InboundHandler(),
                        name: Socks5PipelineName.handler
                    )
                }
            }
            // ---- Child channel options ----------------------------------
            // Enable SO_REUSEADDR on child sockets.
            .childChannelOption(
                ChannelOptions.socketOption(.so_reuseaddr),
                value: 1
            )
            // Start reading immediately — the decoder will buffer data until
            // a complete SOCKS5 message arrives.
            .childChannelOption(ChannelOptions.autoRead, value: true)

        let channel = try await bootstrap.bind(host: host, port: port).get()
        self.channel = channel
        return channel
    }

    /// Gracefully closes the listening socket and all active child channels.
    ///
    /// - Note: This does **not** shut down the `EventLoopGroup` — the caller
    ///   owns the group and must call `syncShutdownGracefully()` or
    ///   `asyncShutdownGracefully()` separately when the process is exiting.
    public func shutdown() async throws {
        guard let channel = channel else { return }
        try await channel.close()
        self.channel = nil
    }

    /// The bound listening address, or `nil` if `start()` has not been called.
    public var localAddress: SocketAddress? {
        channel?.localAddress
    }
}
