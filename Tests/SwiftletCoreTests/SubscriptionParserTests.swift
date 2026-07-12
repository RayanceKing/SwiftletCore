//===----------------------------------------------------------------------===//
//
//  SubscriptionParserTests.swift
//  SwiftletCore — Universal Proxy Subscription URI Parser Unit Tests
//
//  Validates the parsing of all seven protocol families, both legacy and
//  modern share‑link formats, Base64 padding repair, URL‑encoding
//  resilience, VMess JSON key handling, and edge‑case rejection.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - Shadowsocks (ss://)

@Suite("SubscriptionParser — Shadowsocks")
struct SubscriptionParserShadowsocksTests {

    @Test func parseLegacyFormat() {
        // ss://BASE64(method:password)@host:port#remarks
        let b64 = Data("aes-128-gcm:testPassword".utf8).base64EncodedString()
        let uri = "ss://\(b64)@10.0.0.1:8388#MySS"
        let node = SubscriptionParser.parse(uri: uri)

        guard case .shadowsocks(let host, let port, let cipher, let password, let obfs, let obfsHost) = node else {
            #expect(Bool(false), "Expected shadowsocks node"); return
        }
        #expect(host == "10.0.0.1")
        #expect(port == 8388)
        #expect(cipher == "aes-128-gcm")
        #expect(password == "testPassword")
        #expect(obfs == nil)
        #expect(obfsHost == nil)
    }

    @Test func parseLegacyFormatChacha20() {
        let b64 = Data("chacha20-ietf-poly1305:secureKey!".utf8).base64EncodedString()
        let uri = "ss://\(b64)@server.example.com:443"
        let node = SubscriptionParser.parse(uri: uri)

        guard case .shadowsocks(_, let port, let cipher, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(port == 443)
        #expect(cipher == "chacha20-ietf-poly1305")
    }

    @Test func parseSIP002WithPlugin() throws {
        // SIP002: ss://BASE64@host:port?plugin=obfs-local;obfs=http;obfs-host=bing.com
        let b64 = Data("aes-256-gcm:myPassword".utf8).base64EncodedString()
        let pluginRaw = "obfs-local;obfs=http;obfs-host=bing.com"
        let pluginEncoded = pluginRaw.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? pluginRaw
        let uri = "ss://\(b64)@192.168.1.1:1080?plugin=\(pluginEncoded)#ObfsNode"
        let node = SubscriptionParser.parse(uri: uri)

        guard case .shadowsocks(_, _, _, _, let obfs, let obfsHost) = node else {
            #expect(Bool(false)); return
        }
        #expect(obfs == "http")
        #expect(obfsHost == "bing.com")
    }

    @Test func parseSIP002WithTLSObfs() {
        let b64 = Data("aes-128-gcm:pwd".utf8).base64EncodedString()
        let plugin = "obfs-local;obfs=tls;obfs-host=cloudflare.com"
        let encoded = plugin.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? plugin
        let uri = "ss://\(b64)@10.10.10.10:8888?plugin=\(encoded)"
        let node = SubscriptionParser.parse(uri: uri)

        guard case .shadowsocks(_, _, _, _, let obfs, let obfsHost) = node else {
            #expect(Bool(false)); return
        }
        #expect(obfs == "tls")
        #expect(obfsHost == "cloudflare.com")
    }

    @Test func parseUnpaddedBase64() {
        // Manually craft unpadded base64 (length % 4 != 0).
        let raw = "YWVzLTEyOC1nY206dGVzdA"  // "aes-128-gcm:test" truncated
        let uri = "ss://\(raw)@10.0.0.1:8388"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
        if case .shadowsocks(let host, let port, _, _, _, _) = node {
            #expect(host == "10.0.0.1")
            #expect(port == 8388)
        }
    }

    @Test func parseIPv6Address() {
        let b64 = Data("aes-256-gcm:ipv6test".utf8).base64EncodedString()
        let uri = "ss://\(b64)@[::1]:1080"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .shadowsocks(let host, let port, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(host == "::1")
        #expect(port == 1080)
    }

    @Test func parseWithSpecialCharsInPassword() {
        let b64 = Data("aes-128-gcm:p@ss:w0rd!".utf8).base64EncodedString()
        let uri = "ss://\(b64)@1.2.3.4:54321"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .shadowsocks(_, _, _, let password, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(password == "p@ss:w0rd!")
    }
}

// MARK: - VMess (vmess://)

@Suite("SubscriptionParser — VMess")
struct SubscriptionParserVMessTests {

    @Test func parseStandardVMessJSON() {
        let json: [String: Any] = [
            "v": "2",
            "ps": "TestNode",
            "add": "vmess.example.com",
            "port": 443,
            "id": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "aid": 0,
            "net": "ws",
            "type": "none",
            "host": "cdn.example.com",
            "path": "/ws",
            "tls": "tls",
            "sni": "vmess.example.com",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let jsonStr = String(data: jsonData, encoding: .utf8)!
        let b64 = jsonStr.data(using: .utf8)!.base64EncodedString()
        let uri = "vmess://\(b64)#VMessWS"

        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(let host, let port, let uuid, let aid, let transport,
                          let tls, let sni, let wsPath, let wsHost) = node else {
            #expect(Bool(false), "Expected vmess node"); return
        }
        #expect(host == "vmess.example.com")
        #expect(port == 443)
        #expect(uuid == "b831381d-6324-4d53-ad4f-8cda48b30811")
        #expect(aid == 0)
        #expect(transport == "ws")
        #expect(tls == true)
        #expect(sni == "vmess.example.com")
        #expect(wsPath == "/ws")
        #expect(wsHost == "cdn.example.com")
    }

    @Test func parseVMessWithStringPort() {
        let json: [String: Any] = [
            "add": "srv.local",
            "port": "8080",
            "id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "aid": "4",
            "net": "tcp",
            "tls": "none",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(_, let port, let uuid, let aid, _, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(port == 8080)
        #expect(uuid == "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        #expect(aid == 4)
    }

    @Test func parseVMessWithNumericPort() {
        let json: [String: Any] = [
            "add": "direct.example.com",
            "port": 10086,
            "id": "00000000-0000-0000-0000-000000000001",
            "aid": 0,
            "net": "tcp",
            "tls": "",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(_, let port, _, _, _, let tls, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(port == 10086)
        #expect(tls == false)
    }

    @Test func parseVMessGRPC() {
        let json: [String: Any] = [
            "add": "grpc.node.org",
            "port": 443,
            "id": "c0ffee00-1234-5678-9abc-def012345678",
            "aid": 0,
            "net": "grpc",
            "type": "gun",
            "host": "",
            "path": "/grpc.Service/Method",
            "tls": "tls",
            "sni": "grpc.node.org",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(_, _, _, _, let transport, let tls, _, let path, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(transport == "grpc")
        #expect(tls == true)
        #expect(path == "/grpc.Service/Method")
    }

    @Test func parseVMessUnpaddedBase64() {
        let json: [String: Any] = [
            "add": "unpadded.test",
            "port": 8888,
            "id": "11111111-1111-1111-1111-111111111111",
            "aid": 0,
            "net": "tcp",
            "tls": "",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        var b64 = jsonData.base64EncodedString()
        // Strip padding.
        b64 = b64.replacingOccurrences(of: "=", with: "")
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
        if case .vmess(let host, _, _, _, _, _, _, _, _) = node {
            #expect(host == "unpadded.test")
        }
    }

    @Test func parseVMessWithRemarkFragment() {
        let json: [String: Any] = [
            "add": "remark.test",
            "port": 443,
            "id": "22222222-2222-2222-2222-222222222222",
            "aid": 0,
            "net": "tcp",
            "tls": "",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)#My Awesome Node"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }

    @Test func parseVMessMissingOptionalFields() {
        let json: [String: Any] = [
            "add": "minimal.node",
            "port": 80,
            "id": "33333333-3333-3333-3333-333333333333",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(let host, let port, _, let aid, let transport,
                          let tls, let sni, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(host == "minimal.node")
        #expect(port == 80)
        #expect(aid == 0)
        #expect(transport == "tcp")
        #expect(tls == false)
        #expect(sni == nil)
    }

    @Test func parseVMessRejectsMissingAdd() {
        let json: [String: Any] = [
            "port": 443,
            "id": "no-add-uuid",
        ]
        let jsonData = try! JSONSerialization.data(withJSONObject: json)
        let b64 = jsonData.base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }
}

// MARK: - VLESS (vless://)

@Suite("SubscriptionParser — VLESS")
struct SubscriptionParserVLESSesTests {

    @Test func parseBasicVLESS() {
        let uri = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@vless.example.com:443"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(let host, let port, let uuid, _, _, _, _, let transport, _, _, _, _, _) = node else {
            #expect(Bool(false), "Expected vless node"); return
        }
        #expect(host == "vless.example.com")
        #expect(port == 443)
        #expect(uuid == "b831381d-6324-4d53-ad4f-8cda48b30811")
        #expect(transport == "tcp")
    }

    @Test func parseVLESSWithReality() {
        let uri = "vless://my-uuid@reality.node.com:443"
            + "?type=tcp&security=reality"
            + "&sni=yahoo.com&pbk=REALITY_PUBLIC_KEY_BASE64"
            + "&flow=xtls-rprx-vision"
            + "&fp=chrome"
            + "&sid=abcd"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(_, _, let uuid, let flow, let xtls, let sni, let pbk,
                          _, _, _, let fp, let sid, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(uuid == "my-uuid")
        #expect(flow == "xtls-rprx-vision")
        #expect(xtls == true)
        #expect(sni == "yahoo.com")
        #expect(pbk == "REALITY_PUBLIC_KEY_BASE64")
        #expect(fp == "chrome")
        #expect(sid == "abcd")
    }

    @Test func parseVLESSWithWebSocket() {
        let uri = "vless://ws-uuid@ws.node.com:8080"
            + "?type=ws"
            + "&path=%2Fmy%2Fws%2Fpath"
            + "&host=cdn-override.com"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(_, _, _, _, _, _, _, let transport,
                          let wsPath, let wsHost, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(transport == "ws")
        #expect(wsPath == "/my/ws/path")
        #expect(wsHost == "cdn-override.com")
    }

    @Test func parseVLESSWithSpiderX() {
        let uri = "vless://spx-uuid@spx.node.com:443"
            + "?security=reality&sni=spx-target.com&spx=%2Fapi%2Fspx"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(_, _, _, _, _, let sni, _, _, _, _, _, _, let spx) = node else {
            #expect(Bool(false)); return
        }
        #expect(sni == "spx-target.com")
        #expect(spx == "/api/spx")
    }

    @Test func parseVLESSWithFlowOnly() {
        let uri = "vless://flow-uuid@flow.node.com:443?flow=xtls-rprx-vision"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(_, _, _, let flow, let xtls, _, _, _, _, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(flow == "xtls-rprx-vision")
        #expect(xtls == true)
    }

    @Test func parseVLESSIPv6Endpoint() {
        let uri = "vless://ipv6-uuid@[fd12:3456:789a:1::1]:8080"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(let host, let port, _, _, _, _, _, _, _, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(host == "fd12:3456:789a:1::1")
        #expect(port == 8080)
    }
}

// MARK: - Trojan (trojan://)

@Suite("SubscriptionParser — Trojan")
struct SubscriptionParserTrojanTests {

    @Test func parseBasicTrojan() {
        let uri = "trojan://mySecurePassword@trojan.server.com:443"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .trojan(let host, let port, let password, let transport, _, _, _, _) = node else {
            #expect(Bool(false), "Expected trojan node"); return
        }
        #expect(host == "trojan.server.com")
        #expect(port == 443)
        #expect(password == "mySecurePassword")
        #expect(transport == "tcp")
    }

    @Test func parseTrojanWithWebSocket() {
        let uri = "trojan://pwd@ws-trojan.com:443"
            + "?type=ws&path=%2Ftrojan-ws&host=host-override.com"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .trojan(_, _, _, let transport, _, let wsPath, let wsHost, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(transport == "ws")
        #expect(wsPath == "/trojan-ws")
        #expect(wsHost == "host-override.com")
    }

    @Test func parseTrojanWithSNI() {
        let uri = "trojan://secure@trojan-sni.com:443?sni=trojan-sni.com"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .trojan(_, _, _, _, let sni, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(sni == "trojan-sni.com")
    }

    @Test func parseTrojanWithFingerprint() {
        let uri = "trojan://pwd@fp.node.com:443?fp=firefox"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .trojan(_, _, _, _, _, _, _, let fp) = node else {
            #expect(Bool(false)); return
        }
        #expect(fp == "firefox")
    }

    @Test func parseTrojanURLEncodedPassword() {
        let uri = "trojan://p%40ssw0rd%21@encoded.node.com:443"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .trojan(_, _, let password, _, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(password == "p@ssw0rd!")
    }
}

// MARK: - Hysteria 2 (hysteria2:// / hy2://)

@Suite("SubscriptionParser — Hysteria2")
struct SubscriptionParserHysteria2Tests {

    @Test func parseBasicHysteria2() {
        let uri = "hysteria2://superSecret@hy2.example.com:443"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .hysteria2(let host, let port, let password, _, _, _, _) = node else {
            #expect(Bool(false), "Expected hysteria2 node"); return
        }
        #expect(host == "hy2.example.com")
        #expect(port == 443)
        #expect(password == "superSecret")
    }

    @Test func parseHysteria2ShortAlias() {
        let uri = "hy2://fastPassw0rd@hy2-short.com:1080"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .hysteria2(let host, let port, let password, _, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(host == "hy2-short.com")
        #expect(port == 1080)
        #expect(password == "fastPassw0rd")
    }

    @Test func parseHysteria2WithSalamanderObfs() {
        let uri = "hysteria2://obfsPwd@obfs.node.com:443"
            + "?obfs=salamander&obfs-password=obfsSecret"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .hysteria2(_, _, _, let obfsOption, let obfsPwd, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(obfsOption == "salamander")
        #expect(obfsPwd == "obfsSecret")
    }

    @Test func parseHysteria2WithInsecure() {
        let uri = "hysteria2://skipVerify@insecure.node.com:443?insecure=1"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .hysteria2(_, _, _, _, _, _, let insecure) = node else {
            #expect(Bool(false)); return
        }
        #expect(insecure == true)
    }

    @Test func parseHysteria2WithSNI() {
        let uri = "hysteria2://sniPwd@sni.node.com:443?sni=hidden-sni.com"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .hysteria2(_, _, _, _, _, let sni, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(sni == "hidden-sni.com")
    }
}

// MARK: - TUIC v5 (tuic://)

@Suite("SubscriptionParser — TUIC v5")
struct SubscriptionParserTUICTests {

    @Test func parseBasicTUIC() {
        let uri = "tuic://uuid-here:password123@tuic.server.com:8443"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(let host, let port, let uuid, let password, let cc, _, _, _) = node else {
            #expect(Bool(false), "Expected tuic node"); return
        }
        #expect(host == "tuic.server.com")
        #expect(port == 8443)
        #expect(uuid == "uuid-here")
        #expect(password == "password123")
        #expect(cc == "bbr")
    }

    @Test func parseTUICWithCubic() {
        let uri = "tuic://myuuid:mypwd@cubic.node.com:443?congestion_control=cubic"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(_, _, _, _, let cc, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(cc == "cubic")
    }

    @Test func parseTUICWithALPN() {
        let uri = "tuic://u:p@alpn.node.com:443?alpn=h3,h2,http%2F1.1"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(_, _, _, _, _, _, let alpn, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(alpn == "h3,h2,http/1.1")
    }

    @Test func parseTUICWithInsecure() {
        let uri = "tuic://u:p@insecure.node.com:443?insecure=true"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(_, _, _, _, _, _, _, let insecure) = node else {
            #expect(Bool(false)); return
        }
        #expect(insecure == true)
    }

    @Test func parseTUICWithSNI() {
        let uri = "tuic://uuid123:password@tuic-sni.com:443?sni=real-sni.com"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(_, _, _, _, _, let sni, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(sni == "real-sni.com")
    }

    @Test func parseTUICWithNewReno() {
        let uri = "tuic://u:p@reno.node.com:443?congestion_control=new_reno"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .tuic(_, _, _, _, let cc, _, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(cc == "new_reno")
    }
}

// MARK: - WireGuard (wireguard:// / wg://)

@Suite("SubscriptionParser — WireGuard")
struct SubscriptionParserWireGuardTests {

    @Test func parseWireGuardQueryParams() {
        let uri = "wireguard://"
            + "?privateKey=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789%2B%2F"
            + "&peerPublicKey=ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba9876543210%2B%2F"
            + "&endpoint=wg.example.com:51820"
            + "&mtu=1420"
            + "&addresses=10.0.0.2%2F24,fd00%3A%3A2%2F64"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .wireguard(let pk, let ppk, let ep, _, _, let addrs, let mtu) = node else {
            #expect(Bool(false), "Expected wireguard node"); return
        }
        #expect(pk.contains("ABCDEFGHIJKLMNOPQRSTUVWXYZ"))
        #expect(ppk.contains("ZYXWVUTSRQPONMLKJIHGFEDCBA"))
        #expect(ep == "wg.example.com:51820")
        #expect(mtu == 1420)
        #expect(addrs?.count == 2)
    }

    @Test func parseWireGuardWithReservedBytes() {
        let uri = "wireguard://"
            + "?privateKey=AA==&peerPublicKey=BB==&endpoint=1.1.1.1:51820"
            + "&reserved=1,2,3"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .wireguard(_, _, _, _, let rsv, _, _) = node else {
            #expect(Bool(false)); return
        }
        #expect(rsv == [1, 2, 3])
    }

    @Test func parseWireGuardShortAlias() {
        let uri = "wg://?privateKey=pk&peerPublicKey=ppk&endpoint=peer.com:51820"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
        if case .wireguard(_, _, let ep, _, _, _, _) = node {
            #expect(ep == "peer.com:51820")
        }
    }

    @Test func parseWireGuardINIConfig() {
        let ini = """
        [Interface]
        PrivateKey = gIGxyKzG2dqWBVplLXaTsIWb1EwJGb0Rg+GnRqNSa14=
        Address = 10.7.0.2/32, fd42:42:42::2/128
        MTU = 1280

        [Peer]
        PublicKey = JIDuGsAHi48mHlc3xXvJ2UtAq5kRUQCqMnLpCImqth8=
        Endpoint = engage.cloudflareclient.com:2408
        PresharedKey = pskValueHere
        """
        let b64 = ini.data(using: .utf8)!.base64EncodedString()
        let uri = "wireguard://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .wireguard(let pk, let ppk, let ep, let psk, _, let addrs, let mtu) = node else {
            #expect(Bool(false), "Expected wireguard INI node"); return
        }
        #expect(pk == "gIGxyKzG2dqWBVplLXaTsIWb1EwJGb0Rg+GnRqNSa14=")
        #expect(ppk == "JIDuGsAHi48mHlc3xXvJ2UtAq5kRUQCqMnLpCImqth8=")
        #expect(ep == "engage.cloudflareclient.com:2408")
        #expect(psk == "pskValueHere")
        #expect(mtu == 1280)
        #expect(addrs?.count == 2)
    }

    @Test func parseWireGuardRejectsMissingKey() {
        let uri = "wireguard://?peerPublicKey=BB==&endpoint=1.1.1.1:51820"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }
}

// MARK: - Base64 Resilience

@Suite("SubscriptionParser — Base64 Resilience")
struct SubscriptionParserBase64Tests {

    @Test func repairMissingSinglePadding() {
        // Data that encodes to a string with length % 4 == 3.
        let raw = Data("test-method:test-password".utf8)
        let b64Full = raw.base64EncodedString()
        #expect(b64Full.hasSuffix("="))
        // Remove ALL padding characters to simulate a malformed share link.
        let b64 = b64Full.replacingOccurrences(of: "=", with: "")

        let uri = "ss://\(b64)@10.0.0.1:8388"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }

    @Test func repairMissingDoublePadding() {
        let raw = Data("ab:cd".utf8)
        var b64 = raw.base64EncodedString()
        // Should have == at end.
        b64 = b64.replacingOccurrences(of: "=", with: "")
        let uri = "ss://\(b64)@10.0.0.1:8388"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }

    @Test func handleURLSafeBase64() {
        // URL-safe base64 uses - and _ instead of + and /.
        let raw = Data("chacha20-ietf-poly1305:test?".utf8)
        var b64 = raw.base64EncodedString()
        b64 = b64.replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
        let uri = "ss://\(b64)@10.0.0.1:443"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }
}

// MARK: - Edge Cases & Rejection

@Suite("SubscriptionParser — Edge Cases & Rejection")
struct SubscriptionParserEdgeCasesTests {

    @Test func emptyStringReturnsNil() {
        #expect(SubscriptionParser.parse(uri: "") == nil)
    }

    @Test func whitespaceOnlyReturnsNil() {
        #expect(SubscriptionParser.parse(uri: "   \n\t   ") == nil)
    }

    @Test func unknownSchemeReturnsNil() {
        #expect(SubscriptionParser.parse(uri: "http://example.com") == nil)
        #expect(SubscriptionParser.parse(uri: "socks5://127.0.0.1:1080") == nil)
        #expect(SubscriptionParser.parse(uri: "random://garbage") == nil)
    }

    @Test func trimsLeadingTrailingWhitespace() {
        let b64 = Data("aes-128-gcm:test".utf8).base64EncodedString()
        let uri = "  \t  ss://\(b64)@10.0.0.1:8388  \n  "
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }

    @Test func handlesControlCharacters() {
        let b64 = Data("aes-128-gcm:ctrl".utf8).base64EncodedString()
        let uri = "ss://\(b64)@10.0.0.1:8388\r\n"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node != nil)
    }

    @Test func vlessWithoutAtSignReturnsNil() {
        let uri = "vless://no-at-sign-here"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }

    @Test func trojanWithoutAtSignReturnsNil() {
        let uri = "trojan://missing-at-sign-443"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }

    @Test func shadowsocksWithoutPortReturnsNil() {
        let b64 = Data("aes-128-gcm:test".utf8).base64EncodedString()
        let uri = "ss://\(b64)@noport.example.com"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }

    @Test func vmessMalformedJSONReturnsNil() {
        let b64 = Data("not valid json".utf8).base64EncodedString()
        let uri = "vmess://\(b64)"
        let node = SubscriptionParser.parse(uri: uri)
        #expect(node == nil)
    }
}

// MARK: - ProxyNodeConfiguration Equatable & Description

@Suite("ProxyNodeConfiguration — Equatable & Label")
struct ProxyNodeConfigurationMetaTests {

    @Test func shadowsocksLabelIsCorrect() {
        let node = ProxyNodeConfiguration.shadowsocks(
            host: "s", port: 1, cipher: "c", password: "p", obfsMode: nil, obfsHost: nil
        )
        #expect(node.label == "Shadowsocks")
    }

    @Test func vmessLabelIsCorrect() {
        let node = ProxyNodeConfiguration.vmess(
            host: "v", port: 2, uuid: "u", alterId: 0,
            transport: "tcp", tlsEnabled: false,
            sni: nil, wsPath: nil, wsHost: nil
        )
        #expect(node.label == "VMess")
    }

    @Test func vlessLabelIsCorrect() {
        let node = ProxyNodeConfiguration.vless(
            host: "v", port: 3, uuid: "u",
            flow: nil, xtls: false, sni: nil, pbk: nil,
            transport: "tcp", wsPath: nil, wsHost: nil,
            fingerprint: nil, shortId: nil, spiderX: nil
        )
        #expect(node.label == "VLESS")
    }

    @Test func trojanLabelIsCorrect() {
        let node = ProxyNodeConfiguration.trojan(
            host: "t", port: 4, password: "p",
            transport: "tcp", sni: nil, wsPath: nil, wsHost: nil, fingerprint: nil
        )
        #expect(node.label == "Trojan")
    }

    @Test func hysteria2LabelIsCorrect() {
        let node = ProxyNodeConfiguration.hysteria2(
            host: "h", port: 5, password: "p",
            obfsOption: nil, obfsPassword: nil, sni: nil, insecure: false
        )
        #expect(node.label == "Hysteria2")
    }

    @Test func tuicLabelIsCorrect() {
        let node = ProxyNodeConfiguration.tuic(
            host: "t", port: 6, uuid: "u", password: "p",
            congestionControl: "bbr", sni: nil, alpn: nil, insecure: false
        )
        #expect(node.label == "TUIC v5")
    }

    @Test func wireguardLabelIsCorrect() {
        let node = ProxyNodeConfiguration.wireguard(
            privateKey: "pk", peerPublicKey: "ppk", endpoint: "e:1",
            presharedKey: nil, reservedBytes: nil, addresses: nil, mtu: nil
        )
        #expect(node.label == "WireGuard")
    }

    @Test func equatableComparesCorrectly() {
        let a = ProxyNodeConfiguration.shadowsocks(
            host: "a", port: 1, cipher: "c", password: "p", obfsMode: nil, obfsHost: nil
        )
        let b = ProxyNodeConfiguration.shadowsocks(
            host: "a", port: 1, cipher: "c", password: "p", obfsMode: nil, obfsHost: nil
        )
        let c = ProxyNodeConfiguration.shadowsocks(
            host: "b", port: 1, cipher: "c", password: "p", obfsMode: nil, obfsHost: nil
        )
        #expect(a == b)
        #expect(a != c)
    }

    @Test func differentProtocolsNotEqual() {
        let ss = ProxyNodeConfiguration.shadowsocks(
            host: "x", port: 1, cipher: "c", password: "p", obfsMode: nil, obfsHost: nil
        )
        let vm = ProxyNodeConfiguration.vmess(
            host: "x", port: 1, uuid: "u", alterId: 0,
            transport: "tcp", tlsEnabled: false,
            sni: nil, wsPath: nil, wsHost: nil
        )
        #expect(ss != vm)
    }

    @Test func hostGetterWorks() {
        let node = ProxyNodeConfiguration.trojan(
            host: "getter.test", port: 443, password: "p",
            transport: "tcp", sni: nil, wsPath: nil, wsHost: nil, fingerprint: nil
        )
        #expect(node.host == "getter.test")
    }

    @Test func portGetterWorks() {
        let node = ProxyNodeConfiguration.vless(
            host: "p.test", port: 9999, uuid: "u",
            flow: nil, xtls: false, sni: nil, pbk: nil,
            transport: "tcp", wsPath: nil, wsHost: nil,
            fingerprint: nil, shortId: nil, spiderX: nil
        )
        #expect(node.port == 9999)
    }

    @Test func wireguardHostIsEmpty() {
        let node = ProxyNodeConfiguration.wireguard(
            privateKey: "pk", peerPublicKey: "ppk", endpoint: "ep:1",
            presharedKey: nil, reservedBytes: nil, addresses: nil, mtu: nil
        )
        #expect(node.host == "")
    }

    @Test func wireguardPortIsZero() {
        let node = ProxyNodeConfiguration.wireguard(
            privateKey: "pk", peerPublicKey: "ppk", endpoint: "ep:1",
            presharedKey: nil, reservedBytes: nil, addresses: nil, mtu: nil
        )
        #expect(node.port == 0)
    }
}

// MARK: - Integration: Round‑Trip Parser to Configuration

@Suite("SubscriptionParser — Integration Round‑Trip")
struct SubscriptionParserIntegrationTests {

    @Test func ssFullRoundTrip() {
        let b64 = Data("aes-256-gcm:integrationTest".utf8).base64EncodedString()
        let uri = "ss://\(b64)@integration.ss.com:8388?plugin=obfs-local%3Bobfs%3Dtls%3Bobfs-host%3Dcdn.com#TestNode"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .shadowsocks(let h, let p, let c, let pw, let obfs, let obfsHost) = node else {
            #expect(Bool(false)); return
        }
        #expect(h == "integration.ss.com")
        #expect(p == 8388)
        #expect(c == "aes-256-gcm")
        #expect(pw == "integrationTest")
        #expect(obfs == "tls")
        #expect(obfsHost == "cdn.com")
    }

    @Test func vmessFullRoundTrip() {
        let json: [String: Any] = [
            "v": "2", "ps": "Integration", "add": "full.vmess.com",
            "port": "8443", "id": "full-uuid-here-1234-integration",
            "aid": "0", "net": "ws", "type": "none",
            "host": "ws-override.com", "path": "/integrate",
            "tls": "tls", "sni": "full.vmess.com",
        ]
        let jsonStr = String(data: try! JSONSerialization.data(withJSONObject: json), encoding: .utf8)!
        let b64 = jsonStr.data(using: .utf8)!.base64EncodedString()
        let uri = "vmess://\(b64)#FullIntegration"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vmess(let h, let p, let id, let aid, let net, let tls, let sni, let path, let host) = node else {
            #expect(Bool(false)); return
        }
        #expect(h == "full.vmess.com")
        #expect(p == 8443)
        #expect(id == "full-uuid-here-1234-integration")
        #expect(aid == 0)
        #expect(net == "ws")
        #expect(tls == true)
        #expect(sni == "full.vmess.com")
        #expect(path == "/integrate")
        #expect(host == "ws-override.com")
    }

    @Test func vlessRealityFullRoundTrip() {
        let uri = "vless://real-uuid@reality-full.com:443"
            + "?type=tcp&security=reality&sni=swift.org&pbk=AAABBBCCC"
            + "&flow=xtls-rprx-vision&fp=chrome&sid=6ba7b8&spx=%2Freality"
        let node = SubscriptionParser.parse(uri: uri)
        guard case .vless(let h, let p, let id, let flow, let xtls, let sni, let pbk,
                          let net, _, _, let fp, let sid, let spx) = node else {
            #expect(Bool(false)); return
        }
        #expect(h == "reality-full.com")
        #expect(p == 443)
        #expect(id == "real-uuid")
        #expect(flow == "xtls-rprx-vision")
        #expect(xtls == true)
        #expect(sni == "swift.org")
        #expect(pbk == "AAABBBCCC")
        #expect(net == "tcp")
        #expect(fp == "chrome")
        #expect(sid == "6ba7b8")
        #expect(spx == "/reality")
    }
}
