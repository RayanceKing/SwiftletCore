//===----------------------------------------------------------------------===//
//
//  VifConfigurator.swift
//  SwiftletCore — Apple Virtual Interface Dual‑Stack Configuration
//
//  Builds a complete `NEPacketTunnelNetworkSettings` payload that governs
//  the PacketTunnelProvider's virtual interface with both IPv4 and IPv6
//  topologies.  This is the single configuration entry‑point called from
//  `startTunnel(options:completionHandler:)` before packet ingestion begins.
//
//  Configuration Summary
//  ---------------------
//  ┌─────────────────────────────────────────────────────────────────┐
//  │  IPv4                                                            │
//  │  • Tunnel Address : 198.18.0.1  /  255.255.0.0  (RFC 2544)      │
//  │  • Default Route  : 0.0.0.0     /  0.0.0.0                      │
//  ├─────────────────────────────────────────────────────────────────┤
//  │  IPv6 (Anti‑Leak Shield)                                         │
//  │  • Tunnel Address : fd00:a:b:c::1  /  64  (ULA)                 │
//  │  • Default Route  : ::             /  0   (catch‑all)            │
//  ├─────────────────────────────────────────────────────────────────┤
//  │  DNS (Unified Hijack)                                            │
//  │  • Servers        : 198.18.0.2, fd00:a:b:c::2                  │
//  │  • Match Domains  : [""]  (universal wildcard)                  │
//  ├─────────────────────────────────────────────────────────────────┤
//  │  MTU              : 1420  (prevents nested‑encap fragmentation)  │
//  └─────────────────────────────────────────────────────────────────┘
//
//  startTunnel Integration
//  -----------------------
//  ```swift
//  override func startTunnel(
//      options: [String : NSObject]?,
//      completionHandler: @escaping (Error?) -> Void
//  ) {
//      let settings = VifConfigurator.build()
//      setTunnelNetworkSettings(settings) { error in
//          guard error == nil else {
//              completionHandler(error)
//              return
//          }
//          // Begin packet ingestion loop.
//          self.readPackets()
//          completionHandler(nil)
//      }
//  }
//
//  private func readPackets() {
//      packetFlow.readPackets { packets, protocols in
//          for (data, proto) in zip(packets, protocols) {
//              self.bridge.processInbound(
//                  packet: data, protocolFamily: proto
//              )
//          }
//          self.readPackets()  // loop
//      }
//  }
//  ```
//
//===----------------------------------------------------------------------===//

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension
#endif
import Foundation

// MARK: - VIF Configuration Constants

/// Immutable constants for the virtual interface configuration.
public enum VIFConfig {

    // MARK: - IPv4

    /// The virtual tunnel's IPv4 address (RFC 2544 benchmarking range,
    /// guaranteed not to conflict with any real network).
    public static let ipv4Address = "198.18.0.1"

    /// Subnet mask for the IPv4 tunnel network.
    public static let ipv4SubnetMask = "255.255.0.0"

    /// Catch‑all IPv4 route destination (forces all IPv4 traffic into
    /// the tunnel).
    public static let ipv4DefaultRouteDestination = "0.0.0.0"

    /// Catch‑all IPv4 route subnet mask.
    public static let ipv4DefaultRouteMask = "0.0.0.0"

    // MARK: - IPv6

    /// Unique Local Address (ULA) for the IPv6 tunnel endpoint.
    /// Uses the `fd00::/8` prefix reserved for private networks.
    public static let ipv6Address = "fd00:a:b:c::1"

    /// Network prefix length for the IPv6 tunnel subnet.
    public static let ipv6PrefixLength: NSNumber = 64

    /// Catch‑all IPv6 route destination (forces ALL IPv6 traffic into
    /// the tunnel — no leak to physical interfaces).
    public static let ipv6DefaultRouteDestination = "::"

    /// Catch‑all IPv6 route prefix length (0 = entire address space).
    public static let ipv6DefaultRoutePrefixLength: NSNumber = 0

    // MARK: - DNS

    /// Primary DNS server (IPv4) inside the virtual network.
    public static let dnsServerIPv4 = "198.18.0.2"

    /// Secondary DNS server (IPv6) inside the virtual network.
    public static let dnsServerIPv6 = "fd00:a:b:c::2"

    /// Universal match‑domain rule — hijacks ALL DNS queries.
    public static let dnsMatchDomains = [""]

    // MARK: - MTU

    /// Maximum Transmission Unit for the tunnel interface.
    ///
    /// 1420 bytes leaves headroom for:
    /// • 40 bytes outer IPv6 header (worst‑case)
    /// • 40 bytes WireGuard / QUIC encapsulation
    /// • 8 bytes Shadowsocks AEAD salt + chunk header
    ///
    /// …while staying safely under the 1500‑byte Ethernet MTU.
    public static let tunnelMTU: NSNumber = 1420
}

// MARK: - VIF Configurator

/// Assembles a complete `NEPacketTunnelNetworkSettings` payload for the
/// Apple PacketTunnelProvider virtual interface.
///
/// ## Thread Safety
/// This type has no mutable state — `build()` is safe to call from any
/// thread or queue.
///
/// ## Sendability
/// All configuration parameters are value types or immutable `NSNumber`
/// wrappers, making the builder `Sendable` by construction.
public struct VifConfigurator: Sendable {

    // MARK: - IPv4 Configuration

    /// Creates the IPv4 settings payload.
    ///
    /// - Returns: An `NEIPv4Settings` configured with a fixed tunnel
    ///   address and a default route that captures all IPv4 traffic.
    public static func makeIPv4Settings() -> NEIPv4Settings {
        let ipv4 = NEIPv4Settings(
            addresses: [VIFConfig.ipv4Address],
            subnetMasks: [VIFConfig.ipv4SubnetMask]
        )

        // Default route — force all IPv4 traffic into the tunnel.
        let defaultRoute = NEIPv4Route(
            destinationAddress: VIFConfig.ipv4DefaultRouteDestination,
            subnetMask: VIFConfig.ipv4DefaultRouteMask
        )
        ipv4.includedRoutes = [defaultRoute]

        return ipv4
    }

    // MARK: - IPv6 Configuration (Anti‑Leak Shield)

    /// Creates the IPv6 settings payload with a ULA tunnel address and
    /// a catch‑all `::/0` route.
    ///
    /// Without this configuration, IPv6 traffic on dual‑stack cellular
    /// or Wi‑Fi networks would bypass the tunnel entirely — a critical
    /// DNS and traffic leak vector.
    ///
    /// - Returns: An `NEIPv6Settings` with ULA addressing and default route.
    public static func makeIPv6Settings() -> NEIPv6Settings {
        let ipv6 = NEIPv6Settings(
            addresses: [VIFConfig.ipv6Address],
            networkPrefixLengths: [VIFConfig.ipv6PrefixLength]
        )

        // Catch‑all `::/0` route — the kernel forces every IPv6 packet
        // into our user‑space buffer pipeline.
        let defaultRoute = NEIPv6Route(
            destinationAddress: VIFConfig.ipv6DefaultRouteDestination,
            networkPrefixLength: VIFConfig.ipv6DefaultRoutePrefixLength
        )
        ipv6.includedRoutes = [defaultRoute]

        return ipv6
    }

    // MARK: - DNS Configuration (Unified Hijack)

    /// Creates DNS settings that redirect ALL domain resolution queries
    /// to the virtual network's internal DNS servers.
    ///
    /// The match‑domain `[""]` (empty string) is the universal wildcard
    /// rule in Apple's NetworkExtension DNS matching — it causes every
    /// outbound `getaddrinfo` / `CFHost` / `NWResolver` call to be
    /// intercepted and forwarded to the configured servers.
    ///
    /// - Returns: `NEDNSSettings` with dual‑stack servers and wildcard
    ///   domain matching.
    public static func makeDNSSettings() -> NEDNSSettings {
        let dns = NEDNSSettings(servers: [
            VIFConfig.dnsServerIPv4,
            VIFConfig.dnsServerIPv6,
        ])

        // Match all domains — global DNS hijack.
        dns.matchDomains = VIFConfig.dnsMatchDomains

        return dns
    }

    // MARK: - Full Settings Assembly

    /// Builds the complete `NEPacketTunnelNetworkSettings` payload
    /// including IPv4, IPv6, DNS, and MTU configuration.
    ///
    /// This is the single method called from
    /// `startTunnel(options:completionHandler:)` before the packet
    /// ingestion loop begins.
    ///
    /// - Parameter tunnelRemoteAddress: An optional remote endpoint
    ///   address (typically the proxy server IP).  Defaults to the
    ///   tunnel's own IPv4 address.
    /// - Returns: A fully configured settings object ready for
    ///   `setTunnelNetworkSettings(_:completionHandler:)`.
    public static func build(
        tunnelRemoteAddress: String = VIFConfig.ipv4Address
    ) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(
            tunnelRemoteAddress: tunnelRemoteAddress
        )

        // Attach dual‑stack layers.
        settings.ipv4Settings = makeIPv4Settings()
        settings.ipv6Settings = makeIPv6Settings()
        settings.dnsSettings  = makeDNSSettings()

        // Hardcode protective MTU.
        settings.mtu = VIFConfig.tunnelMTU

        return settings
    }
}
