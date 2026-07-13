//===----------------------------------------------------------------------===//
//
//  UnifiedConfigurationParser.swift
//  SwiftletCore — Unified INI/CONF Configuration Lexer & Parser
//
//  Parses Surge / Loon / Shadowrocket‑style `.conf` text profiles into
//  SwiftletCore's type‑safe internal models (`ProxyNodeConfiguration`,
//  `RoutingRule`, and MITM contexts).
//
//  Block Structure
//  ---------------
//  ```
//  [General]     → dns-server, skip-proxy, bypass-tun
//  [Proxy]       → comma‑delimited node definitions
//  [Rule]        → DOMAIN-SUFFIX, IP-CIDR, GEOIP, FINAL, etc.
//  [Host]        → host‑name ↔ IP mappings (future)
//  [MITM]        → hostname listings for TLS interception
//  ```
//
//  Usage
//  -----
//  ```swift
//  let result = UnifiedConfigurationParser.parse(configText)
//  // result.nodes: [ProxyNodeConfiguration]
//  // result.rules: [RoutingRule]
//  // result.mitmHostnames: [String]
//  ```
//
//  Resilience
//  ----------
//  • Leading/trailing whitespace trimmed on every token.
//  • Comments (`#` and `;`) stripped inline and at line start.
//  • Missing block headers default to graceful skip.
//  • Unquoted parameter values parsed safely without dead loops.
//  • Empty lines and blank blocks are silently ignored.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Parse Result

/// The structured output of parsing a configuration profile.
public struct UnifiedConfigurationResult: Sendable, CustomStringConvertible {
    /// All parsed proxy node configurations.
    public var nodes: [ProxyNodeConfiguration] = []

    /// All parsed routing rules.
    public var rules: [RoutingRule] = []

    /// DNS server override (from `[General] dns-server`).
    public var dnsServers: [String] = []

    /// Bypass / skip‑proxy domain patterns.
    public var bypassDomains: [String] = []

    /// MITM hostname patterns for TLS interception.
    public var mitmHostnames: [String] = []

    /// The parser's diagnostic log (warnings, skipped lines).
    public var diagnostics: [String] = []

    public var description: String {
        "nodes=\(nodes.count) rules=\(rules.count) bypass=\(bypassDomains.count) mitm=\(mitmHostnames.count)"
    }

    /// Adds a diagnostic message.
    internal mutating func warn(_ message: String) {
        diagnostics.append("[Parser] \(message)")
    }
}

// MARK: - Parser

/// A stateless one‑shot parser for Surge/Loon‑style configuration text.
///
/// All methods are `static` — no instance state is ever created.
public enum UnifiedConfigurationParser {

    // MARK: - Public Entry Point

    /// Parses a complete configuration string into a structured result.
    ///
    /// - Parameter text: The raw `.conf` file content.
    /// - Returns: A `UnifiedConfigurationResult` with parsed nodes,
    ///   rules, and metadata.
    public static func parse(_ text: String) -> UnifiedConfigurationResult {
        var result = UnifiedConfigurationResult()
        var currentBlock: String? = nil

        let lines = text.components(separatedBy: .newlines)
        var blockLines: [String] = []

        /// Flushes accumulated lines for the current block.
        func flushBlock() {
            guard let block = currentBlock, !blockLines.isEmpty else {
                blockLines.removeAll(); return
            }
            parseBlock(block, lines: blockLines, into: &result)
            blockLines.removeAll()
        }

        for line in lines {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            // Skip blank lines and full‑line comments.
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                continue
            }

            // Inline comment stripping (keep everything before `#` or `;`
            // provided the character is preceded by whitespace).
            var content = trimmed
            if let hashIdx = content.range(of: " #")?.lowerBound {
                content = String(content[..<hashIdx]).trimmingCharacters(in: .whitespaces)
            } else if let semiIdx = content.range(of: " ;")?.lowerBound {
                content = String(content[..<semiIdx]).trimmingCharacters(in: .whitespaces)
            }

            if content.isEmpty { continue }

            // Block header detection.
            if content.hasPrefix("[") && content.hasSuffix("]") {
                flushBlock()
                currentBlock = String(content.dropFirst().dropLast()).trimmingCharacters(in: .whitespaces)
                continue
            }

            blockLines.append(content)
        }

        flushBlock()
        return result
    }

    // MARK: - Block Dispatcher

    /// Routes a block's lines to the appropriate handler.
    private static func parseBlock(
        _ block: String,
        lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        switch block.lowercased() {
        case "general":
            parseGeneralBlock(lines, into: &result)
        case "proxy":
            parseProxyBlock(lines, into: &result)
        case "rule":
            parseRuleBlock(lines, into: &result)
        case "host":
            parseHostBlock(lines, into: &result)
        case "mitm":
            parseMitmBlock(lines, into: &result)
        default:
            // Unknown block — skip gracefully.
            result.warn("Skipping unknown block: [\(block)]")
        }
    }

    // MARK: - [General] Block

    private static func parseGeneralBlock(
        _ lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        for line in lines {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            switch key {
            case "dns-server":
                result.dnsServers = splitCommaSeparated(String(value))
            case "skip-proxy", "bypass-tun":
                result.bypassDomains.append(contentsOf: splitCommaSeparated(String(value)))
            default:
                break
            }
        }
    }

    // MARK: - [Proxy] Block

    private static func parseProxyBlock(
        _ lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        for line in lines {
            guard let eq = line.firstIndex(of: "=") else {
                // Could be a direct protocol definition line.
                continue
            }

            let name = line[..<eq].trimmingCharacters(in: .whitespaces)
            let valueStr = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
            let parts = splitCommaSeparated(String(valueStr))

            guard parts.count >= 2 else {
                result.warn("Skipping malformed proxy line: \(name)")
                continue
            }

            if let node = parseProxyNode(name: String(name), parts: parts, into: &result) {
                result.nodes.append(node)
            }
        }
    }

    /// Parses a single proxy node definition from comma‑delimited parts.
    private static func parseProxyNode(
        name: String,
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        let proto = parts[0].lowercased()

        switch proto {
        case "ss", "shadowsocks":
            return parseShadowsocksNode(parts: parts, into: &result)
        case "snell":
            return parseSnellNode(parts: parts, into: &result)
        case "ssr", "shadowsocksr":
            return parseShadowsocksRNode(parts: parts, into: &result)
        case "vmess":
            return parseVMessNode(parts: parts, into: &result)
        case "trojan":
            return parseTrojanNode(parts: parts, into: &result)
        case "vless":
            return parseVLESSNode(parts: parts, into: &result)
        case "http", "https":
            return parseHTTPNode(parts: parts, into: &result)
        default:
            result.warn("Unknown proxy protocol: \(proto) for \(name)")
            return nil
        }
    }

    // MARK: - Shadowsocks Parser

    /// `Name = ss, host, port, encrypt-method, password, [obfs=..., obfs-host=...]`
    private static func parseShadowsocksNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 5 else {
            result.warn("Shadowsocks node requires at least 5 parts: ss,host,port,cipher,password")
            return nil
        }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else {
            result.warn("Invalid port for Shadowsocks: \(parts[2])")
            return nil
        }
        let cipher = parts[3]
        let password = parts[4]

        var obfsMode: String?
        var obfsHost: String?

        // Parse remaining key=value parameters.
        for i in 5 ..< parts.count {
            let kv = parts[i].trimmingCharacters(in: .whitespaces)
            if kv.hasPrefix("obfs=") {
                obfsMode = String(kv.dropFirst(5)).trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("obfs-host=") {
                obfsHost = String(kv.dropFirst(10)).trimmingCharacters(in: .whitespaces)
            }
        }

        return .shadowsocks(
            host: host,
            port: port,
            cipher: cipher,
            password: password,
            obfsMode: obfsMode,
            obfsHost: obfsHost
        )
    }

    // MARK: - Snell Parser

    /// `Name = snell, host, port, psk=..., version=4, ...`
    private static func parseSnellNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else {
            result.warn("Snell node requires at least 3 parts: snell,host,port")
            return nil
        }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else {
            result.warn("Invalid port for Snell: \(parts[2])")
            return nil
        }

        var psk = ""
        var version = 4

        for i in 3 ..< parts.count {
            let kv = parts[i].trimmingCharacters(in: .whitespaces)
            if kv.hasPrefix("psk=") {
                psk = String(kv.dropFirst(4)).trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("version=") {
                version = Int(String(kv.dropFirst(8)).trimmingCharacters(in: .whitespaces)) ?? 4
            }
        }

        guard !psk.isEmpty else {
            result.warn("Snell node missing psk parameter")
            return nil
        }

        return .snell(host: host, port: port, psk: psk, version: version)
    }

    // MARK: - ShadowsocksR Parser

    /// `Name = ssr, host, port, protocol=..., obfs=..., encrypt-method=..., password=..., ...`
    private static func parseShadowsocksRNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else { return nil }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else { return nil }

        var cipher = "aes-128-cfb"
        var password = ""
        var protocolMode = "origin"
        var obfsMode = "plain"
        var protocolParam: String?
        var obfsParam: String?

        for i in 3 ..< parts.count {
            let kv = parts[i].trimmingCharacters(in: .whitespaces)
            if kv.hasPrefix("encrypt-method=") || kv.hasPrefix("method=") {
                cipher = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("password=") {
                password = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("protocol=") {
                protocolMode = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("protocol-param=") || kv.hasPrefix("protoparam=") {
                protocolParam = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("obfs=") {
                obfsMode = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            } else if kv.hasPrefix("obfs-param=") || kv.hasPrefix("obfsparam=") {
                obfsParam = String(kv.split(separator: "=", maxSplits: 1).last ?? "").trimmingCharacters(in: .whitespaces)
            }
        }

        return .shadowsocksr(
            host: host, port: port, cipher: cipher, password: password,
            protocolMode: protocolMode, protocolParam: protocolParam,
            obfsMode: obfsMode, obfsParam: obfsParam
        )
    }

    // MARK: - VMess Parser

    /// `Name = vmess, host, port, uuid=..., alterId=0, tls=true, ws-path=..., ...`
    private static func parseVMessNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else { return nil }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else { return nil }

        var uuid = ""
        var alterId = 0
        var transport = "tcp"
        var tlsEnabled = false
        var sni: String?
        var wsPath: String?
        var wsHost: String?
        var serviceName: String?
        var authority: String?

        for i in 3 ..< parts.count {
            let kv = parts[i].trimmingCharacters(in: .whitespaces)
            let pair = kv.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = String(pair[0]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(pair[1]).trimmingCharacters(in: .whitespaces)

            switch key {
            case "uuid", "id": uuid = val
            case "alterid": alterId = Int(val) ?? 0
            case "transport", "net": transport = val
            case "tls": tlsEnabled = (val == "true" || val == "tls" || val == "1")
            case "sni": sni = val
            case "ws-path", "path": wsPath = val
            case "ws-host", "host": wsHost = val
            case "servicename": serviceName = val
            case "authority": authority = val
            default: break
            }
        }

        guard !uuid.isEmpty else { result.warn("VMess node missing uuid"); return nil }

        return .vmess(
            host: host, port: port, uuid: uuid, alterId: alterId,
            transport: transport, tlsEnabled: tlsEnabled, sni: sni,
            wsPath: wsPath, wsHost: wsHost,
            serviceName: serviceName, authority: authority
        )
    }

    // MARK: - Trojan Parser

    /// `Name = trojan, host, port, password=..., sni=..., ...`
    private static func parseTrojanNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else { return nil }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else { return nil }

        var password = ""
        var transport = "tcp"
        var sni: String?
        var wsPath: String?
        var wsHost: String?
        var fingerprint: String?

        for i in 3 ..< parts.count {
            let kv = parts[i]
            let pair = kv.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = String(pair[0]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(pair[1]).trimmingCharacters(in: .whitespaces)

            switch key {
            case "password": password = val
            case "transport", "network": transport = val
            case "sni": sni = val
            case "ws-path", "path": wsPath = val
            case "ws-host": wsHost = val
            case "fingerprint", "fp": fingerprint = val
            default: break
            }
        }

        guard !password.isEmpty else { result.warn("Trojan node missing password"); return nil }

        return .trojan(
            host: host, port: port, password: password,
            transport: transport, sni: sni,
            wsPath: wsPath, wsHost: wsHost, fingerprint: fingerprint,
            serviceName: nil, authority: nil
        )
    }

    // MARK: - VLESS Parser

    private static func parseVLESSNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else { return nil }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else { return nil }

        var uuid = ""
        var flow: String?
        var xtls = false
        var sni: String?
        var pbk: String?
        var transport = "tcp"
        var wsPath: String?
        var wsHost: String?
        var fingerprint: String?
        var shortId: String?
        var spiderX: String?

        for i in 3 ..< parts.count {
            let kv = parts[i]
            let pair = kv.split(separator: "=", maxSplits: 1)
            guard pair.count == 2 else { continue }
            let key = String(pair[0]).trimmingCharacters(in: .whitespaces).lowercased()
            let val = String(pair[1]).trimmingCharacters(in: .whitespaces)

            switch key {
            case "uuid", "id": uuid = val
            case "flow": flow = val
            case "security": xtls = (val == "reality" || val == "xtls")
            case "sni": sni = val
            case "pbk": pbk = val
            case "transport", "type", "net": transport = val
            case "ws-path", "path": wsPath = val
            case "ws-host": wsHost = val
            case "fingerprint", "fp": fingerprint = val
            case "sid", "shortid": shortId = val
            case "spx", "spiderx": spiderX = val
            default: break
            }
        }

        guard !uuid.isEmpty else { result.warn("VLESS node missing uuid"); return nil }

        return .vless(
            host: host, port: port, uuid: uuid,
            flow: flow, xtls: xtls, sni: sni, pbk: pbk,
            transport: transport, wsPath: wsPath, wsHost: wsHost,
            fingerprint: fingerprint, shortId: shortId, spiderX: spiderX,
            serviceName: nil, authority: nil
        )
    }

    // MARK: - HTTP Proxy Parser

    private static func parseHTTPNode(
        parts: [String],
        into result: inout UnifiedConfigurationResult
    ) -> ProxyNodeConfiguration? {
        guard parts.count >= 3 else { return nil }

        let host = parts[1]
        guard let port = UInt16(parts[2]) else { return nil }

        // HTTP proxies map to a Shadowsocks‑like config with no encryption.
        return .shadowsocks(
            host: host, port: port,
            cipher: "none", password: "http",
            obfsMode: nil, obfsHost: nil
        )
    }

    // MARK: - [Rule] Block

    private static func parseRuleBlock(
        _ lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        for line in lines {
            let parts = splitCommaSeparated(line)

            guard parts.count >= 2 else {
                result.warn("Skipping malformed rule: \(line)")
                continue
            }

            let ruleType = parts[0].uppercased()
            let targetStr = parts.count >= 3
                ? parts[2].trimmingCharacters(in: .whitespaces).uppercased()
                : "PROXY"

            let decision: RoutingDecision = targetStr == "DIRECT" ? .direct
                : targetStr == "REJECT" || targetStr == "BLOCK" ? .block
                : .proxy

            switch ruleType {
            case "DOMAIN-SUFFIX":
                let pattern = parts[1].trimmingCharacters(in: .whitespaces)
                result.rules.append(.domainSuffix(pattern, decision: decision))

            case "DOMAIN-KEYWORD":
                let pattern = parts[1].trimmingCharacters(in: .whitespaces)
                result.rules.append(.domainKeyword(pattern, decision: decision))

            case "DOMAIN":
                let pattern = parts[1].trimmingCharacters(in: .whitespaces)
                result.rules.append(.domainSuffix(pattern, decision: decision))

            case "IP-CIDR", "IP-CIDR6":
                let cidr = parts[1].trimmingCharacters(in: .whitespaces)
                let parts = cidr.split(separator: "/", maxSplits: 1)
                if parts.count == 2,
                   let prefixLen = Int(parts[1]),
                   let network = parseIPv4ToUInt32(String(parts[0])) {
                    result.rules.append(.ipv4CIDR(
                        network: network, prefixLength: prefixLen,
                        decision: decision
                    ))
                } else {
                    result.warn("Failed to parse CIDR: \(cidr)")
                }

            case "GEOIP":
                let country = parts[1].trimmingCharacters(in: .whitespaces)
                result.rules.append(.domainKeyword(
                    country.lowercased(), decision: decision
                ))

            case "USER-AGENT":
                let pattern = parts[1].trimmingCharacters(in: .whitespaces)
                result.rules.append(.userAgent(pattern: pattern, decision: decision))

            case "FINAL", "MATCH":
                result.rules.append(.domainSuffix("", decision: decision))

            default:
                result.warn("Unknown rule type: \(ruleType)")
            }
        }
    }

    // MARK: - [Host] Block

    private static func parseHostBlock(
        _ lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        // Host mappings are informational; parse for future DNS override.
        for line in lines {
            let parts = line.components(separatedBy: .whitespaces)
                .filter { !$0.isEmpty }
            if parts.count >= 2, let eq = line.firstIndex(of: "=") {
                let host = line[..<eq].trimmingCharacters(in: .whitespaces)
                let ip = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)
                _ = (host, ip)  // Retained for future DNS override mapping.
            }
        }
    }

    // MARK: - [MITM] Block

    private static func parseMitmBlock(
        _ lines: [String],
        into result: inout UnifiedConfigurationResult
    ) {
        for line in lines {
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            if key == "hostname" {
                result.mitmHostnames = splitCommaSeparated(String(value))
            }
        }
    }

    // MARK: - Helpers

    /// Parses an IPv4 address string into a host‑byte‑order `UInt32`.
    internal static func parseIPv4ToUInt32(_ string: String) -> UInt32? {
        let octets = string.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4 else { return nil }
        var result: UInt32 = 0
        for (i, octet) in octets.enumerated() {
            guard let val = UInt8(octet), String(val) == String(octet) else { return nil }
            result |= UInt32(val) << ((3 - i) * 8)
        }
        return result
    }

    /// Splits a comma‑separated string, trimming whitespace from each element.
    internal static func splitCommaSeparated(_ string: String) -> [String] {
        string.components(separatedBy: ",").map {
            $0.trimmingCharacters(in: .whitespaces)
        }.filter { !$0.isEmpty }
    }
}
