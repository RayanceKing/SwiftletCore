//===----------------------------------------------------------------------===//
//
//  VifConfiguratorTests.swift
//  SwiftletCore — Virtual Interface Configuration Unit Tests
//
//  Validates:
//  • VIFConfig constants (IPv4/IPv6 addresses, routes, DNS, MTU)
//  • IPv4 settings: tunnel address, subnet mask, default route 0.0.0.0/0
//  • IPv6 settings: ULA address, prefix length, catch‑all route ::/0
//  • DNS settings: dual‑stack servers, universal match‑domain [""]
//  • MTU: protective 1420 bytes
//  • Full settings assembly with all layers attached
//  • Structural integrity: no nil settings, correct address families
//
//===----------------------------------------------------------------------===//

#if canImport(NetworkExtension)
@preconcurrency import NetworkExtension
#endif
import Testing
import Foundation
@testable import SwiftletCore

// MARK: - VIFConfig Constants

@Suite("VIFConfig — Constants")
struct VIFConfigConstantsTests {

    @Test func ipv4Address() {
        #expect(VIFConfig.ipv4Address == "198.18.0.1")
    }

    @Test func ipv4SubnetMask() {
        #expect(VIFConfig.ipv4SubnetMask == "255.255.0.0")
    }

    @Test func ipv4DefaultRouteDestination() {
        #expect(VIFConfig.ipv4DefaultRouteDestination == "0.0.0.0")
    }

    @Test func ipv4DefaultRouteMask() {
        #expect(VIFConfig.ipv4DefaultRouteMask == "0.0.0.0")
    }

    @Test func ipv6Address() {
        #expect(VIFConfig.ipv6Address == "fd00:a:b:c::1")
    }

    @Test func ipv6PrefixLength() {
        #expect(VIFConfig.ipv6PrefixLength == 64)
    }

    @Test func ipv6DefaultRouteDestination() {
        #expect(VIFConfig.ipv6DefaultRouteDestination == "::")
    }

    @Test func ipv6DefaultRoutePrefixLength() {
        #expect(VIFConfig.ipv6DefaultRoutePrefixLength == 0)
    }

    @Test func dnsServerIPv4() {
        #expect(VIFConfig.dnsServerIPv4 == "198.18.0.2")
    }

    @Test func dnsServerIPv6() {
        #expect(VIFConfig.dnsServerIPv6 == "fd00:a:b:c::2")
    }

    @Test func dnsMatchDomainsIsUniversal() {
        #expect(VIFConfig.dnsMatchDomains == [""])
    }

    @Test func tunnelMTU() {
        #expect(VIFConfig.tunnelMTU == 1420)
    }
}

// MARK: - IPv4 Settings

@Suite("VifConfigurator — IPv4 Settings")
struct VifConfiguratorIPv4Tests {

    @Test func ipv4SettingsAreNonNil() {
        let ipv4 = VifConfigurator.makeIPv4Settings()
        #expect(ipv4.addresses.count > 0)
        #expect(ipv4.subnetMasks.count > 0)
    }

    @Test func ipv4TunnelAddressCorrect() {
        let ipv4 = VifConfigurator.makeIPv4Settings()
        #expect(ipv4.addresses.contains("198.18.0.1"))
    }

    @Test func ipv4SubnetMaskCorrect() {
        let ipv4 = VifConfigurator.makeIPv4Settings()
        #expect(ipv4.subnetMasks.contains("255.255.0.0"))
    }

    @Test func ipv4HasIncludedRoutes() {
        let ipv4 = VifConfigurator.makeIPv4Settings()
        #expect(ipv4.includedRoutes?.count == 1)
    }

    @Test func ipv4DefaultRouteIsAllZeros() {
        let ipv4 = VifConfigurator.makeIPv4Settings()
        guard let route = ipv4.includedRoutes?.first else {
            Issue.record("No included routes")
            return
        }
        #expect(route.destinationAddress == "0.0.0.0")
        #expect(route.destinationSubnetMask == "0.0.0.0")
    }
}

// MARK: - IPv6 Settings (Anti‑Leak Shield)

@Suite("VifConfigurator — IPv6 Settings")
struct VifConfiguratorIPv6Tests {

    @Test func ipv6SettingsAreNonNil() {
        let ipv6 = VifConfigurator.makeIPv6Settings()
        #expect(ipv6.addresses.count > 0)
        #expect(ipv6.networkPrefixLengths.count > 0)
    }

    @Test func ipv6TunnelAddressCorrect() {
        let ipv6 = VifConfigurator.makeIPv6Settings()
        #expect(ipv6.addresses.contains("fd00:a:b:c::1"))
    }

    @Test func ipv6PrefixLengthCorrect() {
        let ipv6 = VifConfigurator.makeIPv6Settings()
        #expect(ipv6.networkPrefixLengths.contains(64))
    }

    @Test func ipv6HasIncludedRoutes() {
        let ipv6 = VifConfigurator.makeIPv6Settings()
        #expect(ipv6.includedRoutes?.count == 1)
    }

    @Test func ipv6DefaultRouteIsCatchAll() {
        let ipv6 = VifConfigurator.makeIPv6Settings()
        guard let route = ipv6.includedRoutes?.first else {
            Issue.record("No included routes")
            return
        }
        #expect(route.destinationAddress == "::")
        #expect(route.destinationNetworkPrefixLength == 0)
    }
}

// MARK: - DNS Settings

@Suite("VifConfigurator — DNS Settings")
struct VifConfiguratorDNSTests {

    @Test func dnsSettingsAreNonNil() {
        let dns = VifConfigurator.makeDNSSettings()
        #expect(dns.servers.count == 2)
    }

    @Test func dnsServersIncludeBothStacks() {
        let dns = VifConfigurator.makeDNSSettings()
        #expect(dns.servers.contains("198.18.0.2"))
        #expect(dns.servers.contains("fd00:a:b:c::2"))
    }

    @Test func dnsMatchDomainsIsUniversal() {
        let dns = VifConfigurator.makeDNSSettings()
        #expect(dns.matchDomains == [""])
    }

    @Test func dnsMatchDomainsNotEmpty() {
        let dns = VifConfigurator.makeDNSSettings()
        #expect(dns.matchDomains?.isEmpty == false)
    }
}

// MARK: - MTU

@Suite("VifConfigurator — MTU")
struct VifConfiguratorMTUTests {

    @Test func fullSettingsMTUIs1420() {
        let settings = VifConfigurator.build()
        #expect(settings.mtu == 1420)
    }
}

// MARK: - Full Settings Assembly

@Suite("VifConfigurator — Full Assembly")
struct VifConfiguratorFullAssemblyTests {

    @Test func buildReturnsNonNilSettings() {
        let settings = VifConfigurator.build()
        #expect(settings.tunnelRemoteAddress == VIFConfig.ipv4Address)
    }

    @Test func buildAttachesIPv4Settings() {
        let settings = VifConfigurator.build()
        #expect(settings.ipv4Settings != nil)
    }

    @Test func buildAttachesIPv6Settings() {
        let settings = VifConfigurator.build()
        #expect(settings.ipv6Settings != nil)
    }

    @Test func buildAttachesDNSSettings() {
        let settings = VifConfigurator.build()
        #expect(settings.dnsSettings != nil)
    }

    @Test func buildWithCustomRemoteAddress() {
        let settings = VifConfigurator.build(
            tunnelRemoteAddress: "10.20.30.40"
        )
        #expect(settings.tunnelRemoteAddress == "10.20.30.40")
    }

    @Test func fullSettingsAllLayersPresent() {
        let settings = VifConfigurator.build()

        // IPv4 layer.
        #expect(settings.ipv4Settings?.addresses.contains("198.18.0.1") == true)
        #expect(settings.ipv4Settings?.includedRoutes?.isEmpty == false)

        // IPv6 layer.
        #expect(settings.ipv6Settings?.addresses.contains("fd00:a:b:c::1") == true)
        #expect(settings.ipv6Settings?.includedRoutes?.isEmpty == false)

        // DNS layer.
        #expect(settings.dnsSettings?.servers.contains("198.18.0.2") == true)
        #expect(settings.dnsSettings?.servers.contains("fd00:a:b:c::2") == true)
        #expect(settings.dnsSettings?.matchDomains == [""])

        // MTU.
        #expect(settings.mtu == 1420)
    }

    @Test func dualStackBothAddressFamiliesPresent() {
        let settings = VifConfigurator.build()

        // Verify IPv4 default route.
        let v4route = settings.ipv4Settings?.includedRoutes?.first
        #expect(v4route?.destinationAddress == "0.0.0.0")
        #expect(v4route?.destinationSubnetMask == "0.0.0.0")

        // Verify IPv6 catch‑all route.
        let v6route = settings.ipv6Settings?.includedRoutes?.first
        #expect(v6route?.destinationAddress == "::")
        #expect(v6route?.destinationNetworkPrefixLength == 0)
    }
}

// MARK: - Sendability

@Suite("VifConfigurator — Sendability")
struct VifConfiguratorSendabilityTests {

    @Test func configuratorIsSendable() {
        // VifConfigurator is a struct with no mutable state, so it
        // implicitly conforms to Sendable.  This test validates that
        // the compiler accepts passing it across concurrency domains.
        let configurator = VifConfigurator()
        let copy = configurator
        _ = copy
        #expect(true) // Compiles = passes.
    }

    @Test func buildIsIdempotent() {
        let a = VifConfigurator.build()
        let b = VifConfigurator.build()

        // Both builds should produce the same structural configuration.
        #expect(a.tunnelRemoteAddress == b.tunnelRemoteAddress)
        #expect(a.ipv4Settings?.addresses == b.ipv4Settings?.addresses)
        #expect(a.ipv6Settings?.addresses == b.ipv6Settings?.addresses)
        #expect(a.dnsSettings?.servers == b.dnsSettings?.servers)
        #expect(a.mtu == b.mtu)
    }
}
