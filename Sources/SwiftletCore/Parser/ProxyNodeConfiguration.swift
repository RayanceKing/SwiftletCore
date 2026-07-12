//===----------------------------------------------------------------------===//
//
//  ProxyNodeConfiguration.swift
//  SwiftletCore — Universal Proxy Node Configuration Enum
//
//  A type‑safe, Sendable, Equatable enum that represents a fully‑parsed
//  outbound proxy node for every protocol in the SwiftletCore weapon
//  matrix.  Each case carries the minimal set of fields needed to
//  provision an `OutboundDialer` pipeline without further parsing.
//
//  Protocol Coverage
//  -----------------
//  ┌──────────────────┬──────────────────────────────────────────────┐
//  │ Shadowsocks       │ host, port, cipher, password, obfs plugin   │
//  │ VMess v1          │ uuid, alterId, transport, tlsEnabled        │
//  │ VLESS‑REALITY     │ uuid, flow, xtls, sni, pbk, transport       │
//  │ Trojan            │ password, transport, sni                    │
//  │ Hysteria 2        │ password, obfs option                       │
//  │ TUIC v5           │ uuid, password, congestion control          │
//  │ WireGuard         │ privateKey, peerPublicKey, endpoint, rsv    │
//  └──────────────────┴──────────────────────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Proxy Node Configuration

/// A fully‑parsed proxy node configuration, ready for direct injection
/// into the outbound dialling pipeline.
///
/// Each case is a value type — no reference semantics, no shared mutable
/// state.  The entire enum is `Sendable` and `Equatable` by construction.
public enum ProxyNodeConfiguration: Sendable, Equatable {

    // MARK: - Shadowsocks

    /// Shadowsocks AEAD (aes-128-gcm / aes-256-gcm / chacha20-poly1305).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - cipher: AEAD cipher identifier (e.g. `"chacha20-ietf-poly1305"`).
    ///   - password: Pre‑shared key.
    ///   - obfsMode: Optional Simple‑Obfs plugin mode (`"http"` or `"tls"`).
    ///   - obfsHost: Optional obfuscation host header / SNI.
    case shadowsocks(
        host: String,
        port: UInt16,
        cipher: String,
        password: String,
        obfsMode: String?,
        obfsHost: String?
    )

    // MARK: - VMess v1

    /// VMess v1 (MD5 + AES-128-CFB).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - uuid: Client UUID string.
    ///   - alterId: Alter ID (typically 0 for AEAD‑era clients).
    ///   - transport: Transport mode (`"tcp"`, `"ws"`, `"grpc"`, etc.).
    ///   - tlsEnabled: Whether TLS wrapping is enabled.
    ///   - sni: Optional TLS SNI override.
    ///   - wsPath: Optional WebSocket path.
    ///   - wsHost: Optional WebSocket Host header override.
    case vmess(
        host: String,
        port: UInt16,
        uuid: String,
        alterId: Int,
        transport: String,
        tlsEnabled: Bool,
        sni: String?,
        wsPath: String?,
        wsHost: String?
    )

    // MARK: - VLESS

    /// VLESS v0 (XTLS‑compatible, REALITY).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - uuid: Client UUID string.
    ///   - flow: Optional flow control mode (`"xtls-rprx-vision"`).
    ///   - xtls: Whether XTLS mode is enabled.
    ///   - sni: REALITY SNI / TLS server name.
    ///   - pbk: REALITY public key (base64‑encoded).
    ///   - transport: Transport mode (`"tcp"`, `"ws"`, `"grpc"`).
    ///   - wsPath: Optional WebSocket path.
    ///   - wsHost: Optional WebSocket Host header.
    ///   - fingerprint: Optional TLS fingerprint (`"chrome"`, `"firefox"`, etc.).
    ///   - shortId: Optional REALITY shortId.
    ///   - spiderX: Optional REALITY spiderX path.
    case vless(
        host: String,
        port: UInt16,
        uuid: String,
        flow: String?,
        xtls: Bool,
        sni: String?,
        pbk: String?,
        transport: String,
        wsPath: String?,
        wsHost: String?,
        fingerprint: String?,
        shortId: String?,
        spiderX: String?
    )

    // MARK: - Trojan

    /// Trojan‑TLS (TLS‑wrapped, SHA‑224 hashed password).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - password: Trojan password (plaintext; hashed at connection time).
    ///   - transport: Transport mode (`"tcp"`, `"ws"`).
    ///   - sni: TLS SNI override.
    ///   - wsPath: Optional WebSocket path.
    ///   - wsHost: Optional WebSocket Host header.
    ///   - fingerprint: Optional TLS fingerprint.
    case trojan(
        host: String,
        port: UInt16,
        password: String,
        transport: String,
        sni: String?,
        wsPath: String?,
        wsHost: String?,
        fingerprint: String?
    )

    // MARK: - Hysteria 2

    /// Hysteria 2 (QUIC‑based, Salamander obfuscation).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - password: Authentication password.
    ///   - obfsOption: Optional obfuscation option (`"salamander"`).
    ///   - obfsPassword: Optional Salamander obfuscation password.
    ///   - sni: Optional TLS SNI.
    ///   - insecure: Whether to skip certificate verification.
    case hysteria2(
        host: String,
        port: UInt16,
        password: String,
        obfsOption: String?,
        obfsPassword: String?,
        sni: String?,
        insecure: Bool
    )

    // MARK: - TUIC v5

    /// TUIC v5 (QUIC‑based, binary frame multiplexing).
    ///
    /// - Parameters:
    ///   - host: Proxy server hostname or IP.
    ///   - port: Proxy server port.
    ///   - uuid: Client UUID string.
    ///   - password: Authentication password.
    ///   - congestionControl: QUIC congestion control algorithm
    ///     (`"bbr"`, `"cubic"`, `"new_reno"`).
    ///   - sni: Optional TLS SNI.
    ///   - alpn: Optional ALPN protocol list (comma‑separated).
    ///   - insecure: Whether to skip certificate verification.
    case tuic(
        host: String,
        port: UInt16,
        uuid: String,
        password: String,
        congestionControl: String,
        sni: String?,
        alpn: String?,
        insecure: Bool
    )

    // MARK: - WireGuard

    /// WireGuard (Noise_IKpsk2 + Transport Data AEAD).
    ///
    /// - Parameters:
    ///   - privateKey: Base64‑encoded Curve25519 private key.
    ///   - peerPublicKey: Base64‑encoded peer Curve25519 public key.
    ///   - endpoint: Peer endpoint in `host:port` format.
    ///   - presharedKey: Optional base64‑encoded pre‑shared key.
    ///   - reservedBytes: Optional 3‑byte reservation for obfuscation.
    ///   - addresses: Optional list of assigned IP addresses (CIDR).
    ///   - mtu: Optional tunnel MTU override.
    case wireguard(
        privateKey: String,
        peerPublicKey: String,
        endpoint: String,
        presharedKey: String?,
        reservedBytes: [UInt8]?,
        addresses: [String]?,
        mtu: Int?
    )

    // MARK: - Computed Properties

    /// A human‑readable label for this protocol configuration.
    public var label: String {
        switch self {
        case .shadowsocks:  return "Shadowsocks"
        case .vmess:        return "VMess"
        case .vless:        return "VLESS"
        case .trojan:       return "Trojan"
        case .hysteria2:    return "Hysteria2"
        case .tuic:         return "TUIC v5"
        case .wireguard:    return "WireGuard"
        }
    }

    /// The destination host for this node.
    public var host: String {
        switch self {
        case .shadowsocks(let h, _, _, _, _, _):  return h
        case .vmess(let h, _, _, _, _, _, _, _, _): return h
        case .vless(let h, _, _, _, _, _, _, _, _, _, _, _, _): return h
        case .trojan(let h, _, _, _, _, _, _, _):  return h
        case .hysteria2(let h, _, _, _, _, _, _):  return h
        case .tuic(let h, _, _, _, _, _, _, _):    return h
        case .wireguard: return ""  // endpoint is composite
        }
    }

    /// The destination port for this node, or 0 if not applicable.
    public var port: UInt16 {
        switch self {
        case .shadowsocks(_, let p, _, _, _, _):  return p
        case .vmess(_, let p, _, _, _, _, _, _, _): return p
        case .vless(_, let p, _, _, _, _, _, _, _, _, _, _, _): return p
        case .trojan(_, let p, _, _, _, _, _, _):  return p
        case .hysteria2(_, let p, _, _, _, _, _): return p
        case .tuic(_, let p, _, _, _, _, _, _):  return p
        case .wireguard: return 0
        }
    }
}

// MARK: - CustomStringConvertible

extension ProxyNodeConfiguration: CustomStringConvertible {
    public var description: String {
        switch self {
        case .shadowsocks(let h, let p, let c, _, let obfs, _):
            let obfsTag = obfs.map { "+\($0)" } ?? ""
            return "ss://\(h):\(p) [\(c)\(obfsTag)]"

        case .vmess(let h, let p, _, _, let t, let tls, _, _, _):
            let tlsTag = tls ? "+TLS" : ""
            return "vmess://\(h):\(p) [\(t)\(tlsTag)]"

        case .vless(let h, let p, _, let f, _, let sni, _, let t, _, _, _, _, _):
            let flowTag = f.map { " flow=\($0)" } ?? ""
            let sniTag = sni.map { " sni=\($0)" } ?? ""
            return "vless://\(h):\(p) [\(t)\(flowTag)\(sniTag)]"

        case .trojan(let h, let p, _, let t, let sni, _, _, _):
            let sniTag = sni.map { " sni=\($0)" } ?? ""
            return "trojan://\(h):\(p) [\(t)\(sniTag)]"

        case .hysteria2(let h, let p, _, let obfs, _, _, _):
            let obfsTag = obfs.map { " obfs=\($0)" } ?? ""
            return "hysteria2://\(h):\(p)\(obfsTag)"

        case .tuic(let h, let p, _, _, let cc, _, _, _):
            return "tuic://\(h):\(p) [cc=\(cc)]"

        case .wireguard(let pk, let ppk, let ep, _, _, _, _):
            return "wireguard://\(ep) [pk=\(pk.prefix(8))… ppk=\(ppk.prefix(8))…]"
        }
    }
}
