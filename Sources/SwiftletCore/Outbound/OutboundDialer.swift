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
             .trojanSimpleObfs:
            return true
        }
    }
}
