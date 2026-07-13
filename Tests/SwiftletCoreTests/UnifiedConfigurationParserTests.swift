//===----------------------------------------------------------------------===//
//
//  UnifiedConfigurationParserTests.swift
//  SwiftletCoreTests — Unified INI/CONF Configuration Parser Tests
//
//  Validates Surge/Loon‑style configuration parsing against all
//  supported block types, proxy protocol definitions, routing rule
//  patterns, and edge‑case resilience.
//
//  Test Coverage
//  -------------
//  ┌──────────────────────────────────────────┬──────────────────────────────┐
//  │ Test                                     │ What it verifies             │
//  ├──────────────────────────────────────────┼──────────────────────────────┤
//  │ testParseShadowsocksProxy                │ ss node definition          │
//  │ testParseShadowsocksWithObfs             │ ss + obfs params            │
//  │ testParseSnellProxy                      │ snell node definition       │
//  │ testParseShadowsocksRProxy               │ ssr node definition         │
//  │ testParseVMessProxy                      │ vmess node definition       │
//  │ testParseTrojanProxy                     │ trojan node definition      │
//  │ testParseVLESSProxy                      │ vless node definition       │
//  │ testParseMultipleProxies                 │ Multiple proxy nodes         │
//  │ testParseDomainSuffixRule                │ DOMAIN-SUFFIX → RoutingRule  │
//  │ testParseIPCIDRRule                      │ IP-CIDR → RoutingRule        │
//  │ testParseFinalRule                       │ FINAL → catch‑all rule       │
//  │ testParseDomainKeywordRule               │ DOMAIN-KEYWORD rule          │
//  │ testParseGeoIPRule                       │ GEOIP rule                  │
//  │ testParseUserAgentRule                   │ USER-AGENT rule              │
//  │ testParseGeneralBlock                    │ dns-server + skip-proxy     │
//  │ testParseMitmBlock                       │ hostname extraction          │
//  │ testCommentsAreSkipped                   │ # and ; comment lines       │
//  │ testEmptyBlocksGraceful                  │ Empty blocks don't crash    │
//  │ testInvalidProxySkipped                  │ Malformed proxy skipped     │
//  │ testFullConfigRoundTrip                  │ Complete config parse       │
//  │ testSplitCommaSeparated                  │ CSV helper function         │
//  │ testUnknownBlockSkipped                  │ Unknown block diagnostic   │
//  └──────────────────────────────────────────┴──────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
import Foundation

// MARK: - Proxy Parsing Tests

final class UnifiedConfigurationProxyTests: XCTestCase {

    /// Verifies parsing a basic Shadowsocks node via conf format.
    func testParseShadowsocksProxy() {
        let config = """
        [Proxy]
        MySS = ss, example.com, 8388, aes-128-gcm, secretPwd
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 1)

        if case .shadowsocks(let h, let p, let c, let pw, _, _) = result.nodes[0] {
            XCTAssertEqual(h, "example.com")
            XCTAssertEqual(p, 8388)
            XCTAssertEqual(c, "aes-128-gcm")
            XCTAssertEqual(pw, "secretPwd")
        } else {
            XCTFail("Expected .shadowsocks")
        }
    }

    /// Verifies parsing a Shadowsocks node with obfs parameters.
    func testParseShadowsocksWithObfs() {
        let config = """
        [Proxy]
        ObfsSS = ss, ss.example.com, 443, chacha20-poly1305, p@ss, obfs=http, obfs-host=cloudflare.com
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .shadowsocks(_, _, _, _, let obfs, let obfsHost) = result.nodes[0] {
            XCTAssertEqual(obfs, "http")
            XCTAssertEqual(obfsHost, "cloudflare.com")
        } else {
            XCTFail("Expected .shadowsocks")
        }
    }

    /// Verifies parsing a Snell node.
    func testParseSnellProxy() {
        let config = """
        [Proxy]
        SnellNode = snell, snell.example.com, 8920, psk=mySecretKey, version=4
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .snell(let h, let p, let psk, let v) = result.nodes[0] {
            XCTAssertEqual(h, "snell.example.com")
            XCTAssertEqual(p, 8920)
            XCTAssertEqual(psk, "mySecretKey")
            XCTAssertEqual(v, 4)
        } else {
            XCTFail("Expected .snell")
        }
    }

    /// Verifies parsing a ShadowsocksR node.
    func testParseShadowsocksRProxy() {
        let config = """
        [Proxy]
        SSRNode = ssr, ssr.example.com, 443, protocol=auth_aes128_sha1, obfs=tls1.2_ticket_auth, encrypt-method=aes-256-cfb, password=ssrPassword
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .shadowsocksr(let h, let p, let c, let pw,
                               let proto, _, let obfs, _) = result.nodes[0] {
            XCTAssertEqual(h, "ssr.example.com")
            XCTAssertEqual(p, 443)
            XCTAssertEqual(c, "aes-256-cfb")
            XCTAssertEqual(pw, "ssrPassword")
            XCTAssertEqual(proto, "auth_aes128_sha1")
            XCTAssertEqual(obfs, "tls1.2_ticket_auth")
        } else {
            XCTFail("Expected .shadowsocksr")
        }
    }

    /// Verifies parsing a VMess node.
    func testParseVMessProxy() {
        let config = """
        [Proxy]
        VNode = vmess, vm.example.com, 443, uuid=abc-def-ghi, alterId=0, tls=true, net=ws
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .vmess(let h, let p, let uuid, _, let t, let tls, _, _, _,
                        _, _) = result.nodes[0] {
            XCTAssertEqual(h, "vm.example.com")
            XCTAssertEqual(p, 443)
            XCTAssertEqual(uuid, "abc-def-ghi")
            XCTAssertEqual(t, "ws")
            XCTAssertTrue(tls)
        } else {
            XCTFail("Expected .vmess")
        }
    }

    /// Verifies parsing a Trojan node.
    func testParseTrojanProxy() {
        let config = """
        [Proxy]
        TNode = trojan, trojan.example.com, 443, password=trojanPwd, sni=sni.example.com
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .trojan(let h, let p, let pw, _, let sni, _, _, _, _, _) = result.nodes[0] {
            XCTAssertEqual(h, "trojan.example.com")
            XCTAssertEqual(p, 443)
            XCTAssertEqual(pw, "trojanPwd")
            XCTAssertEqual(sni, "sni.example.com")
        } else {
            XCTFail("Expected .trojan")
        }
    }

    /// Verifies parsing a VLESS node.
    func testParseVLESSProxy() {
        let config = """
        [Proxy]
        VLNode = vless, vless.example.com, 443, uuid=550e8400-e29b-41d4-a716-446655440000, security=reality, sni=swift.org, fp=chrome
        """
        let result = UnifiedConfigurationParser.parse(config)

        if case .vless(let h, let p, let uuid, _, let xtls, let sni, _,
                        _, _, _, let fp, _, _, _, _) = result.nodes[0] {
            XCTAssertEqual(h, "vless.example.com")
            XCTAssertEqual(p, 443)
            XCTAssertEqual(uuid, "550e8400-e29b-41d4-a716-446655440000")
            XCTAssertTrue(xtls)
            XCTAssertEqual(sni, "swift.org")
            XCTAssertEqual(fp, "chrome")
        } else {
            XCTFail("Expected .vless")
        }
    }

    /// Verifies parsing multiple proxy nodes in one block.
    func testParseMultipleProxies() {
        let config = """
        [Proxy]
        NodeA = ss, a.com, 1000, aes-128-gcm, pw1
        NodeB = snell, b.com, 2000, psk=key2
        NodeC = ss, c.com, 3000, chacha20-poly1305, pw3
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(result.nodes[0].host, "a.com")
        XCTAssertEqual(result.nodes[1].host, "b.com")
        XCTAssertEqual(result.nodes[2].host, "c.com")
    }
}

// MARK: - Rule Parsing Tests

final class UnifiedConfigurationRuleTests: XCTestCase {

    /// Verifies DOMAIN-SUFFIX rule parsing.
    func testParseDomainSuffixRule() {
        let config = """
        [Rule]
        DOMAIN-SUFFIX, google.com, PROXY
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.rules.count, 1)

        guard case .domainSuffix(let pattern, let decision) = result.rules[0] else {
            XCTFail("Expected domainSuffix"); return
        }
        XCTAssertEqual(pattern, "google.com")
        XCTAssertEqual(decision, .proxy)
    }

    /// Verifies IP-CIDR rule parsing.
    func testParseIPCIDRRule() {
        let config = """
        [Rule]
        IP-CIDR, 192.168.0.0/16, DIRECT
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.rules.count, 1)

        guard case .ipv4CIDR(_, let prefixLen, let decision) = result.rules[0] else {
            XCTFail("Expected ipv4CIDR"); return
        }
        XCTAssertEqual(prefixLen, 16)
        XCTAssertEqual(decision, .direct)
    }

    /// Verifies FINAL / MATCH catch‑all rule parsing.
    func testParseFinalRule() {
        let config = """
        [Rule]
        FINAL, PROXY
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.rules.count, 1)
        guard case .domainSuffix(_, .proxy) = result.rules[0] else {
            XCTFail("Expected catch‑all proxy rule"); return
        }
    }

    /// Verifies DOMAIN-KEYWORD rule parsing.
    func testParseDomainKeywordRule() {
        let config = """
        [Rule]
        DOMAIN-KEYWORD, ads, REJECT
        """
        let result = UnifiedConfigurationParser.parse(config)
        guard case .domainKeyword(let kw, .block) = result.rules[0] else {
            XCTFail("Expected domainKeyword"); return
        }
        XCTAssertEqual(kw, "ads")
    }

    /// Verifies GEOIP rule parsing.
    func testParseGeoIPRule() {
        let config = """
        [Rule]
        GEOIP, CN, DIRECT
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.rules.count, 1)
    }

    /// Verifies USER-AGENT rule parsing.
    func testParseUserAgentRule() {
        let config = """
        [Rule]
        USER-AGENT, Safari*, PROXY
        """
        let result = UnifiedConfigurationParser.parse(config)
        guard case .userAgent(let pattern, .proxy) = result.rules[0] else {
            XCTFail("Expected userAgent"); return
        }
        XCTAssertEqual(pattern, "Safari*")
    }
}

// MARK: - General & MITM Block Tests

final class UnifiedConfigurationGeneralTests: XCTestCase {

    /// Verifies dns-server and skip-proxy extraction.
    func testParseGeneralBlock() {
        let config = """
        [General]
        dns-server = 8.8.8.8, 1.1.1.1
        skip-proxy = 192.168.0.0/16, 10.0.0.0/8, localhost
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.dnsServers, ["8.8.8.8", "1.1.1.1"])
        XCTAssertEqual(result.bypassDomains.count, 3)
        XCTAssertTrue(result.bypassDomains.contains("localhost"))
    }

    /// Verifies MITM hostname extraction.
    func testParseMitmBlock() {
        let config = """
        [MITM]
        hostname = *.taobao.com, *.jd.com, *.example.org
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.mitmHostnames.count, 3)
        XCTAssertTrue(result.mitmHostnames.contains("*.taobao.com"))
        XCTAssertTrue(result.mitmHostnames.contains("*.example.org"))
    }
}

// MARK: - Resilience & Edge Cases

final class UnifiedConfigurationEdgeCaseTests: XCTestCase {

    /// Verifies that comment lines (# and ;) are skipped.
    func testCommentsAreSkipped() {
        let config = """
        # This is a comment
        [Proxy]
        ; Another comment line
        MySS = ss, host.com, 443, aes-128-gcm, pwd
        # Inline should work too
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 1)
        XCTAssertEqual(result.nodes[0].host, "host.com")
    }

    /// Verifies that empty blocks produce no nodes and no crash.
    func testEmptyBlocksGraceful() {
        let config = """
        [Proxy]
        [Rule]
        [General]
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 0)
        XCTAssertEqual(result.rules.count, 0)
    }

    /// Verifies that malformed proxy lines are skipped gracefully.
    func testInvalidProxySkipped() {
        let config = """
        [Proxy]
        BadNode = unknownproto, host, 123
        GoodNode = ss, good.com, 443, aes-128-gcm, password
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 1)
        XCTAssertEqual(result.nodes[0].host, "good.com")
    }

    /// Verifies that unknown blocks generate diagnostics.
    func testUnknownBlockSkipped() {
        let config = """
        [URLRewrite]
        something = value
        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertTrue(result.diagnostics.contains { $0.contains("URLRewrite") })
    }

    /// Verifies that blank lines and spacing are handled correctly.
    func testWhitespaceResilience() {
        let config = """

        [Proxy]

        NodeA  =  ss  ,  spaced.com  ,  8388  ,  aes-128-gcm  ,  testPwd

        [Rule]
          DOMAIN-SUFFIX  ,  example.com  ,  PROXY

        """
        let result = UnifiedConfigurationParser.parse(config)
        XCTAssertEqual(result.nodes.count, 1)
        XCTAssertEqual(result.nodes[0].host, "spaced.com")
        XCTAssertEqual(result.rules.count, 1)
    }
}

// MARK: - Full Configuration Round‑Trip Test

final class UnifiedConfigurationIntegrationTests: XCTestCase {

    /// Verifies a complete multi‑section configuration.
    func testFullConfigRoundTrip() {
        let config = """
        [General]
        dns-server = 1.1.1.1, 8.8.8.8
        skip-proxy = 192.168.0.0/16

        [Proxy]
        HomeSS = ss, home.example.com, 8388, aes-256-gcm, homePassword
        OfficeSS = ss, office.example.com, 443, chacha20-poly1305, officePwd, obfs=tls, obfs-host=cdn.example.com
        VNode = vmess, vm.example.com, 443, uuid=test-uuid, tls=true, net=ws

        [Rule]
        DOMAIN-SUFFIX, apple.com, DIRECT
        DOMAIN-SUFFIX, google.com, PROXY
        DOMAIN-KEYWORD, ad, REJECT
        IP-CIDR, 10.0.0.0/8, DIRECT
        GEOIP, CN, DIRECT
        FINAL, PROXY

        [MITM]
        hostname = *.example.com, *.test.org
        """

        let result = UnifiedConfigurationParser.parse(config)

        // General.
        XCTAssertEqual(result.dnsServers.count, 2)
        XCTAssertEqual(result.dnsServers, ["1.1.1.1", "8.8.8.8"])
        XCTAssertEqual(result.bypassDomains.count, 1)

        // Proxies.
        XCTAssertEqual(result.nodes.count, 3)
        XCTAssertEqual(result.nodes[0].host, "home.example.com")
        XCTAssertEqual(result.nodes[1].host, "office.example.com")
        XCTAssertEqual(result.nodes[2].host, "vm.example.com")

        // Rules.
        XCTAssertEqual(result.rules.count, 6)
        // Rule 0: DOMAIN-SUFFIX apple.com DIRECT
        if case .domainSuffix("apple.com", .direct) = result.rules[0] {} else { XCTFail() }
        // Rule 1: DOMAIN-SUFFIX google.com PROXY
        if case .domainSuffix("google.com", .proxy) = result.rules[1] {} else { XCTFail() }
        // Rule 5: FINAL PROXY
        if case .domainSuffix("", .proxy) = result.rules[5] {} else { XCTFail() }

        // MITM.
        XCTAssertEqual(result.mitmHostnames.count, 2)
    }
}

// MARK: - Helper Function Tests

final class UnifiedConfigurationHelperTests: XCTestCase {

    /// Verifies the CSV helper function.
    func testSplitCommaSeparated() {
        let parts = UnifiedConfigurationParser.splitCommaSeparated(
            "  a  ,  b , c  "
        )
        XCTAssertEqual(parts, ["a", "b", "c"])

        let single = UnifiedConfigurationParser.splitCommaSeparated(" only-one ")
        XCTAssertEqual(single, ["only-one"])

        let empty = UnifiedConfigurationParser.splitCommaSeparated("  ,  ,  ")
        XCTAssertEqual(empty, [])
    }
}
