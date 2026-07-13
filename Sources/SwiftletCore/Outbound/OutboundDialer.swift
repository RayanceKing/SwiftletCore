//===----------------------------------------------------------------------===//
//
//  OutboundDialer.swift
//  SwiftletCore — Outbound Protocol Pipeline Factory
//
//  Central registry of supported outbound protocol stack combinations.
//  Each case encodes the correct handler ordering so callers can
//  assemble a pipeline without manual handler wiring.
//
//  Pipeline Stack Ordering (bottom → top)
//  --------------------------------------
//  ```
//  [TCP Socket]
//    → StreamingHttpObfsHandler  (if HTTP wrapping enabled)
//    → SimpleObfsHandler         (Simple‑Obfs masquerade)
//    → NIOSSLHandler             (if TLS enabled)
//    → ShadowTLSMorpherHandler   (ShadowTLS hijacking)
//    → Proxy Core                (VMess / VLESS / Trojan / Shadowsocks)
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Outbound Protocol

/// Enumerates the supported outbound protocol stack combinations with
/// their associated configuration parameters.
///
/// Each case bundles the parameters needed to instantiate the full
/// handler chain.  The factory methods on this type produce an ordered
/// array of handler descriptions that can be used to assemble a
/// SwiftNIO `ChannelPipeline`.
public enum OutboundProtocol: Sendable, Equatable {

    // MARK: - Base Protocols

    /// Shadowsocks AEAD (direct TCP, no additional wrapping).
    case shadowsocks(
        cipher: String,      // "aes-128-gcm" | "aes-256-gcm" | "chacha20-poly1305"
        password: String
    )

    /// Trojan‑TLS (TLS‑wrapped, Trojan header).
    case trojan(
        host: String,        // destination proxy host
        port: UInt16,
        password: String     // SHA‑224 hashed password
    )

    /// VLESS‑REALITY (XTLS‑compatible, REALITY TLS).
    case vless(
        uuid: String,
        serverName: String,  // REALITY SNI
        authKey: Data?       // REALITY auth key bytes
    )

    /// VMess v1 (MD5 + AES‑128‑CFB).
    case vmess(
        uuid: String,
        alterId: Int = 0
    )

    /// WireGuard (Noise_IKpsk2 + Transport Data).
    case wireGuard(
        privateKey: String,
        peerPublicKey: String,
        presharedKey: String?
    )

    // MARK: - HTTP‑Wrapped Variants

    /// VMess v1 tunnelled through streaming HTTP POST obfuscation.
    /// Pipeline: `VMess → StreamingHttpObfsHandler → [TLS?] → TCP`
    case vmessHttp(
        uuid: String,
        alterId: Int = 0,
        httpHost: String,    // fake HTTP Host header domain
        httpPath: String = "/video/stream"
    )

    /// VLESS tunnelled through streaming HTTP POST obfuscation.
    /// Pipeline: `VLESS → StreamingHttpObfsHandler → [TLS?] → TCP`
    case vlessHttp(
        uuid: String,
        httpHost: String,
        httpPath: String = "/video/stream"
    )

    /// Trojan tunnelled through streaming HTTP POST obfuscation.
    /// Pipeline: `Trojan → StreamingHttpObfsHandler → [TLS?] → TCP`
    case trojanHttp(
        host: String,
        port: UInt16,
        password: String,
        httpHost: String,
        httpPath: String = "/video/stream"
    )

    /// Shadowsocks tunnelled through streaming HTTP POST obfuscation.
    case shadowsocksHttp(
        cipher: String,
        password: String,
        httpHost: String,
        httpPath: String = "/video/stream"
    )

    // MARK: - Simple‑Obfs Variants

    /// Trojan with Simple‑Obfs HTTP masquerade (single initial header).
    case trojanSimpleObfs(
        host: String,
        port: UInt16,
        password: String,
        obfsHost: String     // masquerade Host header
    )

    /// Shadowsocks with Simple‑Obfs TLS masquerade.
    case shadowsocksSimpleTLSObfs(
        cipher: String,
        password: String,
        obfsHost: String     // TLS SNI
    )

    // MARK: - gRPC‑Wrapped Variants

    /// Trojan tunnelled through gRPC streaming (HTTP/2 + gRPC frame).
    /// Pipeline: `Trojan → gRPCFrameCodec → HTTP/2 Stream → TCP`
    case trojanGRPC(
        host: String,
        port: UInt16,
        password: String,
        serviceName: String,
        authority: String?
    )

    /// VLESS tunnelled through gRPC streaming.
    case vlessGRPC(
        uuid: String,
        serviceName: String,
        authority: String?
    )

    /// VMess tunnelled through gRPC streaming.
    case vmessGRPC(
        uuid: String,
        alterId: Int = 0,
        serviceName: String,
        authority: String?
    )

    // MARK: - ShadowsocksR Variant

    /// ShadowsocksR with protocol plugin and obfuscation plugin layers.
    /// Pipeline: `SSR Obfs → SSR Protocol → Shadowsocks Cipher → TCP`
    case shadowsocksR(
        cipher: String,
        password: String,
        protocolMode: String,
        protocolParam: String?,
        obfsMode: String,
        obfsParam: String?
    )

    // MARK: - Diagnostic

    /// A human‑readable label for this protocol stack.
    public var label: String {
        switch self {
        case .shadowsocks:              return "Shadowsocks"
        case .trojan:                   return "Trojan"
        case .vless:                    return "VLESS-REALITY"
        case .vmess:                    return "VMess"
        case .wireGuard:               return "WireGuard"
        case .vmessHttp:               return "VMess+HTTP"
        case .vlessHttp:               return "VLESS+HTTP"
        case .trojanHttp:              return "Trojan+HTTP"
        case .shadowsocksHttp:         return "Shadowsocks+HTTP"
        case .trojanSimpleObfs:        return "Trojan+SimpleObfs"
        case .shadowsocksSimpleTLSObfs: return "Shadowsocks+SimpleTLS"
        case .trojanGRPC:              return "Trojan+gRPC"
        case .vlessGRPC:               return "VLESS+gRPC"
        case .vmessGRPC:               return "VMess+gRPC"
        case .shadowsocksR:            return "ShadowsocksR"
        }
    }

    /// Whether this protocol stack includes streaming HTTP obfuscation.
    public var isHTTPWrapped: Bool {
        switch self {
        case .vmessHttp, .vlessHttp, .trojanHttp, .shadowsocksHttp:
            return true
        default:
            return false
        }
    }

    /// Whether this protocol stack uses gRPC transport.
    public var isGRPC: Bool {
        switch self {
        case .trojanGRPC, .vlessGRPC, .vmessGRPC:
            return true
        default:
            return false
        }
    }

    /// Whether this protocol stack includes Simple‑Obfs masquerade.
    public var isSimpleObfs: Bool {
        switch self {
        case .trojanSimpleObfs, .shadowsocksSimpleTLSObfs:
            return true
        default:
            return false
        }
    }

    /// Whether this protocol stack typically uses TLS.
    public var isTLS: Bool {
        switch self {
        case .shadowsocks, .shadowsocksHttp,
             .shadowsocksSimpleTLSObfs, .wireGuard:
            return false
        case .trojan, .vless, .vmess,
             .vmessHttp, .vlessHttp, .trojanHttp,
             .trojanSimpleObfs,
             .trojanGRPC, .vlessGRPC, .vmessGRPC:
            return true
        case .shadowsocksR:
            return false
        }
    }

    // MARK: - Connection Pool Integration

    /// Creates a connection to the target proxy server, first consulting
    /// the global `OutboundConnectionPool` for an idle cached channel.
    ///
    /// If a pooled channel is found with a matching protocol fingerprint,
    /// it is reused immediately — bypassing TCP connect, TLS handshake,
    /// and cryptographic key exchange (Shadowsocks AEAD, Noise, REALITY).
    ///
    /// If no pooled channel is available, a fresh `ClientBootstrap`
    /// connection is established and instrumented with a
    /// `ProxyChannelPoolBridgeHandler` so it can be recycled after the
    /// session completes.
    ///
    /// - Parameters:
    ///   - group: The event‑loop group for fresh connections.
    ///   - host: Destination proxy host.
    ///   - port: Destination proxy port.
    ///   - configuration: The parsed node configuration for fingerprint
    ///     derivation and pool key matching.
    ///   - channelInitializer: A closure that installs protocol‑specific
    ///     handlers (Shadowsocks, VMess, Trojan, etc.) above the pool
    ///     bridge handler.
    /// - Returns: An `EventLoopFuture<Channel>` resolving to the active,
    ///   instrumented outbound channel.
    public func connectPooled(
        using group: EventLoopGroup,
        to host: String,
        port: Int,
        configuration: ProxyNodeConfiguration,
        channelInitializer: @escaping @Sendable (Channel) -> EventLoopFuture<Void>
    ) async throws -> Channel {
        let loop = group.next()

        // ---- Hot path: try the pool first -------------------------------
        if let pooled = await OutboundConnectionPool.shared.acquireChannel(
            for: configuration, on: loop
        ) {
            // Locate the bridge handler and mark it as leased.
            if let bridge = try? await pooled.pipeline.handler(
                type: ProxyChannelPoolBridgeHandler.self
            ).get() {
                bridge.markLeased()
            }
            // Re‑apply the session‑specific initialiser (adds handlers
           //  above the bridge that were stripped on the previous detach).
            try await channelInitializer(pooled).get()
            return pooled
        }

        // ---- Cold path: establish a fresh connection ---------------------
        let poolKey = PoolKey(from: configuration)
        let bridgeHandler = ProxyChannelPoolBridgeHandler(
            poolKey: poolKey,
            node: configuration
        )

        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .channelOption(ChannelOptions.autoRead, value: false)
            .channelInitializer { channel in
                // Install the pool bridge at the bottom of the pipeline.
                channel.pipeline.addHandler(
                    bridgeHandler,
                    name: "poolBridge"
                ).flatMap {
                    // Let the caller install protocol handlers above.
                    channelInitializer(channel)
                }.flatMap {
                    // Mark as leased once the pipeline is fully assembled.
                    bridgeHandler.markLeased()
                    return channel.eventLoop.makeSucceededVoidFuture()
                }
            }

        return try await bootstrap.connect(host: host, port: port).get()
    }
}
