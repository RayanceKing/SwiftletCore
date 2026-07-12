//===----------------------------------------------------------------------===//
//
//  SecureDNSServerConfiguration.swift
//  SwiftletCore — Encrypted Upstream DNS Server Topography
//
//  Type‑safe configuration for DNS‑over‑HTTPS (DoH) and DNS‑over‑QUIC
//  (DoQ) upstream servers.  Ships with a curated preset registry of
//  major public resolvers.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Secure DNS Protocol

/// The transport protocol and endpoint for an encrypted DNS upstream.
public enum SecureDNSServerProtocol: Sendable, Equatable {

    /// DNS‑over‑HTTPS (RFC 8484).
    /// - Parameter url: Full DoH endpoint (e.g. `https://1.1.1.1/dns-query`).
    case doh(url: URL)

    /// DNS‑over‑QUIC (RFC 9250).
    /// - Parameters:
    ///   - host: QUIC server hostname or IP.
    ///   - port: QUIC port (typically 853 or 784).
    ///   - serverName: TLS SNI for certificate validation.
    case doq(host: String, port: UInt16, serverName: String)

    /// A human‑readable label for this upstream.
    public var label: String {
        switch self {
        case .doh(let url):
            return "DoH(\(url.host ?? url.absoluteString))"
        case .doq(let host, let port, _):
            return "DoQ(\(host):\(port))"
        }
    }

    /// The host component of this server (for diagnostics).
    public var host: String {
        switch self {
        case .doh(let url):    return url.host ?? url.absoluteString
        case .doq(let h, _, _): return h
        }
    }
}

// MARK: - Preset Registry

/// Curated collection of trusted, high‑availability encrypted DNS upstreams.
///
/// Usage:
/// ```swift
/// let client = SecureDNSRacingClient(servers: SecureDNSServerConfiguration.presets.all)
/// let ip = try await client.resolveA(domain: "example.com")
/// ```
public struct SecureDNSServerConfiguration: Sendable {

    /// All preset servers in a single array, suitable for racing.
    public static let allPresets: [SecureDNSServerProtocol] = [
        presets.cloudflare,
        presets.cloudflareMalware,
        presets.google,
        presets.quad9,
        presets.aliDNS,
        presets.adGuard,
    ]

    /// Commonly used preset servers grouped by provider.
    public enum presets {

        /// Cloudflare (1.1.1.1) — primary.
        public static let cloudflare: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://1.1.1.1/dns-query")!
        )

        /// Cloudflare Malware Blocking (1.1.1.2).
        public static let cloudflareMalware: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://1.1.1.2/dns-query")!
        )

        /// Cloudflare Family (1.1.1.3) — blocks adult content.
        public static let cloudflareFamily: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://1.1.1.3/dns-query")!
        )

        /// Google Public DNS (8.8.8.8).
        public static let google: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://dns.google/dns-query")!
        )

        /// Quad9 (9.9.9.9) — threat‑intelligence filtered.
        public static let quad9: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://dns.quad9.net/dns-query")!
        )

        /// Quad9 over QUIC (DoQ on port 784).
        public static let quad9DoQ: SecureDNSServerProtocol = .doq(
            host: "dns.quad9.net", port: 784, serverName: "dns.quad9.net"
        )

        /// AliDNS (Alibaba, China mainland optimised).
        public static let aliDNS: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://dns.alidns.com/dns-query")!
        )

        /// AdGuard Public DNS — blocks ads & trackers.
        public static let adGuard: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://dns.adguard-dns.com/dns-query")!
        )

        /// AdGuard Family Protection.
        public static let adGuardFamily: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://family.adguard-dns.com/dns-query")!
        )

        /// Mullvad (privacy‑focused, no logging).
        public static let mullvad: SecureDNSServerProtocol = .doh(
            url: URL(string: "https://dns.mullvad.net/dns-query")!
        )

        /// NextDNS — configurable filtering (default endpoint).
        public static func nextDNS(configID: String) -> SecureDNSServerProtocol {
            .doh(url: URL(string: "https://dns.nextdns.io/\(configID)")!)
        }

        /// A latency‑optimised selection: Cloudflare, Google, Quad9.
        public static let lowLatency: [SecureDNSServerProtocol] = [
            cloudflare, google, quad9,
        ]

        /// A privacy‑focused selection: Quad9, Mullvad, Cloudflare.
        public static let privacyFocused: [SecureDNSServerProtocol] = [
            quad9, mullvad, cloudflare,
        ]
    }
}
