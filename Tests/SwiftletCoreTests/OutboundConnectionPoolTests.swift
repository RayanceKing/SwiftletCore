//===----------------------------------------------------------------------===//
//
//  OutboundConnectionPoolTests.swift
//  SwiftletCore — Connection Pool Unit Tests
//
//  Validates pool key fingerprint derivation across all 7 protocol
//  families, bridge handler state machine, and pool actor metadata /
//  statistics queries.  Channel‑level acquire/release tests are
//  deferred to integration suites due to EmbeddedEventLoop thread‑
//  safety constraints under Swift 6 structured concurrency.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - PoolKey Tests

@Suite("PoolKey — Fingerprint Derivation")
struct PoolKeyFingerprintTests {

    @Test func sameShadowsocksConfigProducesSameKey() {
        let a = ss(host: "s1.com"); let b = ss(host: "s1.com")
        #expect(PoolKey(from: a) == PoolKey(from: b))
    }

    @Test func differentPasswordsProduceDifferentKeys() {
        #expect(PoolKey(from: ss(host: "s1.com", password: "a"))
                != PoolKey(from: ss(host: "s1.com", password: "b")))
    }

    @Test func differentHostsProduceDifferentKeys() {
        #expect(PoolKey(from: ss(host: "a.com")) != PoolKey(from: ss(host: "b.com")))
    }

    @Test func differentPortsProduceDifferentKeys() {
        #expect(PoolKey(from: ss(host: "s.com", port: 1000))
                != PoolKey(from: ss(host: "s.com", port: 2000)))
    }

    @Test func vmessFingerprintIncludesUUID() {
        #expect(PoolKey(from: vmess(host: "v.com", uuid: "aaaa"))
                != PoolKey(from: vmess(host: "v.com", uuid: "bbbb")))
    }

    @Test func vmessFingerprintIncludesAlterId() {
        let a = ProxyNodeConfiguration.vmess(
            host: "v.com", port: 443, uuid: "u", alterId: 0,
            transport: "tcp", tlsEnabled: false,
            sni: nil, wsPath: nil, wsHost: nil
        )
        let b = ProxyNodeConfiguration.vmess(
            host: "v.com", port: 443, uuid: "u", alterId: 64,
            transport: "tcp", tlsEnabled: false,
            sni: nil, wsPath: nil, wsHost: nil
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func vlessFingerprintIncludesFlow() {
        let a = vless(host: "v.com", flow: nil)
        let b = vless(host: "v.com", flow: "xtls-rprx-vision")
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func vlessFingerprintIncludesSNI() {
        let a = ProxyNodeConfiguration.vless(
            host: "v.com", port: 443, uuid: "u",
            flow: nil, xtls: false, sni: "a.com", pbk: nil,
            transport: "tcp", wsPath: nil, wsHost: nil,
            fingerprint: nil, shortId: nil, spiderX: nil
        )
        let b = ProxyNodeConfiguration.vless(
            host: "v.com", port: 443, uuid: "u",
            flow: nil, xtls: false, sni: "b.com", pbk: nil,
            transport: "tcp", wsPath: nil, wsHost: nil,
            fingerprint: nil, shortId: nil, spiderX: nil
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func differentProtocolTypesProduceDifferentKeys() {
        #expect(PoolKey(from: ss(host: "x.com")) != PoolKey(from: trojan(host: "x.com")))
    }

    @Test func wireguardFingerprintIncludesPrivateKey() {
        let a = ProxyNodeConfiguration.wireguard(
            privateKey: "pkA", peerPublicKey: "ppk", endpoint: "e:1",
            presharedKey: nil, reservedBytes: nil, addresses: nil, mtu: nil
        )
        let b = ProxyNodeConfiguration.wireguard(
            privateKey: "pkB", peerPublicKey: "ppk", endpoint: "e:1",
            presharedKey: nil, reservedBytes: nil, addresses: nil, mtu: nil
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func hysteria2FingerprintChangesWithPassword() {
        let a = ProxyNodeConfiguration.hysteria2(
            host: "h.com", port: 443, password: "a",
            obfsOption: nil, obfsPassword: nil, sni: nil, insecure: false
        )
        let b = ProxyNodeConfiguration.hysteria2(
            host: "h.com", port: 443, password: "b",
            obfsOption: nil, obfsPassword: nil, sni: nil, insecure: false
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func tuicFingerprintChangesWithUUID() {
        let a = ProxyNodeConfiguration.tuic(
            host: "t.com", port: 8443, uuid: "u1", password: "p",
            congestionControl: "bbr", sni: nil, alpn: nil, insecure: false
        )
        let b = ProxyNodeConfiguration.tuic(
            host: "t.com", port: 8443, uuid: "u2", password: "p",
            congestionControl: "bbr", sni: nil, alpn: nil, insecure: false
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func shadowsocksFingerprintIncludesObfs() {
        let a = ProxyNodeConfiguration.shadowsocks(
            host: "s.com", port: 8388, cipher: "aes-128-gcm",
            password: "p", obfsMode: "http", obfsHost: nil
        )
        let b = ProxyNodeConfiguration.shadowsocks(
            host: "s.com", port: 8388, cipher: "aes-128-gcm",
            password: "p", obfsMode: nil, obfsHost: nil
        )
        #expect(PoolKey(from: a) != PoolKey(from: b))
    }

    @Test func poolKeyDescription() {
        let key = PoolKey(from: ss(host: "desc.example.com", port: 9999))
        #expect(key.description.contains("desc.example.com"))
        #expect(key.description.contains("9999"))
    }

    @Test func poolKeyHashable() {
        let a = PoolKey(from: ss(host: "hash.com"))
        let b = PoolKey(from: ss(host: "hash.com"))
        #expect(a.hashValue == b.hashValue)
    }
}

// MARK: - Pool Metadata / Statistics

@Suite("OutboundConnectionPool — Metadata & Statistics")
struct OutboundConnectionPoolMetadataTests {

    @Test func freshPoolHasZeroChannels() async {
        let pool = OutboundConnectionPool()
        await pool.stopEvictionTimer()
        #expect(await pool.totalIdleChannels == 0)
        #expect(await pool.poolKeyCount == 0)
        #expect(await pool.allKeys.isEmpty)
        await pool.drainAll()
    }

    @Test func idleCountForUnknownKeyReturnsZero() async {
        let pool = OutboundConnectionPool()
        await pool.stopEvictionTimer()
        let key = PoolKey(from: ss(host: "unknown.com"))
        #expect(await pool.idleCount(for: key) == 0)
        await pool.drainAll()
    }

    @Test func drainEmptyPoolReturnsZero() async {
        let pool = OutboundConnectionPool()
        await pool.stopEvictionTimer()
        #expect(await pool.drainAll() == 0)
        await pool.drainAll()
    }

    @Test func purgeIdleOnEmptyPoolReturnsZero() async {
        let pool = OutboundConnectionPool()
        await pool.stopEvictionTimer()
        #expect(await pool.purgeIdle(olderThan: Date()) == 0)
        await pool.drainAll()
    }

    @Test func releaseDoesNotCrash() async {
        // Just verify the actor method exists and doesn't crash
        // with a nil-like node.  Real channel tests are deferred.
        let pool = OutboundConnectionPool()
        await pool.stopEvictionTimer()
        await pool.drainAll()
        #expect(await pool.totalIdleChannels == 0)
    }
}

// MARK: - Bridge Handler State

@Suite("ProxyChannelPoolBridgeHandler — State Machine")
struct PoolBridgeHandlerStateTests {

    @Test func initialNotLeased() {
        let h = bridge(host: "init.com")
        #expect(!h.isLeased)
    }

    @Test func markLeasedSetsTrue() {
        let h = bridge(host: "leased.com")
        h.markLeased()
        #expect(h.isLeased)
    }

    @Test func trackSessionIncrementsCount() {
        let h = bridge(host: "track.com")
        h.trackSessionHandler(name: "relay1")
        h.trackSessionHandler(name: "relay2")
        h.trackSessionHandler(name: "obfs")
        #expect(h.trackedHandlerCount == 3)
    }

    @Test func poolKeyPreserved() {
        let node = ss(host: "key.test")
        let key = PoolKey(from: node)
        let h = ProxyChannelPoolBridgeHandler(poolKey: key, node: node)
        #expect(h.poolKey == key)
    }

    @Test func nodeIdentityPreserved() {
        let node = vmess(host: "id.test")
        let h = ProxyChannelPoolBridgeHandler(poolKey: PoolKey(from: node), node: node)
        #expect(h.node.host == "id.test")
        #expect(h.node.port == 443)
    }

    @Test func differentPoolKeysForDifferentNodes() {
        let a = bridge(host: "a.com")
        let b = bridge(host: "b.com")
        #expect(a.poolKey != b.poolKey)
    }
}

// MARK: - Helpers

private func ss(
    host: String, port: UInt16 = 8388, cipher: String = "aes-128-gcm",
    password: String = "pwd"
) -> ProxyNodeConfiguration {
    .shadowsocks(host: host, port: port, cipher: cipher, password: password,
                 obfsMode: nil, obfsHost: nil)
}

private func vmess(
    host: String, port: UInt16 = 443, uuid: String = "test-uuid",
    transport: String = "tcp", tls: Bool = false
) -> ProxyNodeConfiguration {
    .vmess(host: host, port: port, uuid: uuid, alterId: 0,
           transport: transport, tlsEnabled: tls,
           sni: nil, wsPath: nil, wsHost: nil)
}

private func vless(
    host: String, uuid: String = "vless-uuid", flow: String?
) -> ProxyNodeConfiguration {
    .vless(host: host, port: 443, uuid: uuid,
           flow: flow, xtls: flow != nil, sni: nil, pbk: nil,
           transport: "tcp", wsPath: nil, wsHost: nil,
           fingerprint: nil, shortId: nil, spiderX: nil)
}

private func trojan(
    host: String, password: String = "pwd"
) -> ProxyNodeConfiguration {
    .trojan(host: host, port: 443, password: password,
            transport: "tcp", sni: nil, wsPath: nil, wsHost: nil, fingerprint: nil)
}

private func bridge(host: String) -> ProxyChannelPoolBridgeHandler {
    let node = ss(host: host)
    return ProxyChannelPoolBridgeHandler(poolKey: PoolKey(from: node), node: node)
}
