//===----------------------------------------------------------------------===//
//
//  SubscriptionParser.swift
//  SwiftletCore — Universal Proxy Subscription URI Decoder
//
//  A hyper‑robust, allocation‑conscious parser that transforms legacy,
//  variant‑heavy proxy share links (ss://, vmess://, vless://, trojan://,
//  hysteria2://, tuic://, wireguard://) into type‑safe `ProxyNodeConfiguration`
//  values.
//
//  Resilience Guarantees
//  ---------------------
//  • Automatic Base64 padding repair — un‑padded strings are corrected
//    before decoding (no silent failures).
//  • Percent‑encoding is decoded at every layer (URI userinfo, host,
//    query values).
//  • VMess JSON `port` fields accept both numeric and string encodings.
//  • Obfs plugin parameters (semicolon‑delimited) are parsed regardless
//    of percent‑encoding state.
//  • Trailing whitespace, newlines, and illegal URL padding are stripped
//    before any parsing begins.
//  • `#fragment` remarks are extracted before parameter processing to
//    avoid false‑positive `#` matches inside base64 payloads.
//
//  Entry Point
//  -----------
//  ```swift
//  if let node = SubscriptionParser.parse(uri: shareLinkString) {
//      // node is ready for OutboundDialer provisioning
//  }
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Parser

/// Stateless parser for proxy subscription URIs.
///
/// All methods are `static` — the class exists only for namespace
/// grouping.  No instance state is ever created.
public final class SubscriptionParser {

    // MARK: - Public Entry Point

    /// Parses a proxy share‑link URI into a `ProxyNodeConfiguration`.
    ///
    /// Supports all seven protocol families:
    /// - `ss://`     — Shadowsocks (legacy + SIP002)
    /// - `vmess://`  — VMess v1 (base64‑JSON)
    /// - `vless://`  — VLESS‑REALITY
    /// - `trojan://` — Trojan‑TLS
    /// - `hysteria2://` — Hysteria 2
    /// - `tuic://`   — TUIC v5
    /// - `wireguard://` — WireGuard
    ///
    /// - Parameter uri: The raw share‑link string (may contain leading /
    ///   trailing whitespace).
    /// - Returns: A fully‑parsed `ProxyNodeConfiguration`, or `nil` if
    ///   the URI is unrecognised or irrecoverably malformed.
    public static func parse(uri: String) -> ProxyNodeConfiguration? {
        let cleaned = uri
            .trimmingCharacters(in: .whitespacesAndNewlines)
            // Strip stray control characters.
            .filter { $0.asciiValue ?? 0 >= 0x20 }

        guard !cleaned.isEmpty else { return nil }

        // Detect protocol scheme.
        let lower = cleaned.lowercased()

        if lower.hasPrefix("ss://") {
            return parseShadowsocks(cleaned)
        }
        if lower.hasPrefix("ssr://") {
            return parseShadowsocksR(cleaned)
        }
        if lower.hasPrefix("vmess://") {
            return parseVMess(cleaned)
        }
        if lower.hasPrefix("vless://") {
            return parseVLESS(cleaned)
        }
        if lower.hasPrefix("trojan://") {
            return parseTrojan(cleaned)
        }
        if lower.hasPrefix("hysteria2://") || lower.hasPrefix("hy2://") {
            return parseHysteria2(cleaned)
        }
        if lower.hasPrefix("tuic://") {
            return parseTUIC(cleaned)
        }
        if lower.hasPrefix("snell://") {
            return parseSnell(cleaned)
        }
        if lower.hasPrefix("wireguard://") || lower.hasPrefix("wg://") {
            return parseWireGuard(cleaned)
        }

        return nil
    }

    // MARK: - Shadowsocks (ss://)

    /// Parses both legacyUserInfo (`ss://BASE64@host:port`) and SIP002
    /// (`ss://BASE64@host:port?plugin=...`) formats.
    private static func parseShadowsocks(_ raw: String) -> ProxyNodeConfiguration? {
        // ---- 1. Strip scheme ----------------------------------------------
        let body = raw.hasPrefix("ss://")
            ? String(raw.dropFirst(5))
            : String(raw.dropFirst(5))

        // ---- 2. Extract fragment (remarks) before any further processing ---
        let (bodyWithoutFragment, remarks) = extractFragment(from: body)

        // ---- 3. Split query string ----------------------------------------
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        // ---- 4. Determine format: legacy (no @) or SIP002 (@-delimited) ---
        let credentialsBase64: String
        let hostPart: String

        if let atIndex = core.firstIndex(of: "@") {
            credentialsBase64 = String(core[..<atIndex])
            hostPart = String(core[core.index(after: atIndex)...])
        } else {
            // Legacy format: everything in base64.
            // Decode to get "method:password@host:port".
            guard let decoded = decodeBase64URLSafe(core),
                  let atIdx = decoded.firstIndex(of: "@") else {
                // Maybe just "method:password" — try SIP002 with
                // host:port in query or missing.
                return nil
            }
            credentialsBase64 = core
            hostPart = String(decoded[decoded.index(after: atIdx)...])
        }

        // ---- 5. Decode credentials ("method:password") --------------------
        let credString: String
        if credentialsBase64.contains("@") {
            // If the base64 itself had the @, use the decoded version.
            credString = decodeBase64URLSafe(credentialsBase64)
                .flatMap { decoded in
                    if let at = decoded.firstIndex(of: "@") {
                        return String(decoded[..<at])
                    }
                    return decoded
                } ?? ""
        } else {
            credString = decodeBase64URLSafe(credentialsBase64) ?? ""
        }

        let credParts = credString.split(separator: ":", maxSplits: 1,
                                          omittingEmptySubsequences: false)
        guard credParts.count == 2 else { return nil }
        let cipher = String(credParts[0])
        let password = String(credParts[1])

        // ---- 6. Parse host:port -------------------------------------------
        let (host, port) = parseHostPort(hostPart)
        guard let port = port else { return nil }

        // ---- 7. Parse plugin parameters -----------------------------------
        var obfsMode: String?
        var obfsHost: String?

        if let pluginRaw = queryValue(for: "plugin", in: queryItems) {
            // Plugin format: "obfs-local;obfs=http;obfs-host=bing.com"
            // May be URL‑encoded or not.
            let pluginStr = pluginRaw.removingPercentEncoding ?? pluginRaw
            let pluginParams = parseObfsPluginParams(pluginStr)
            obfsMode = pluginParams["obfs"]
            obfsHost = pluginParams["obfs-host"]
        }

        _ = remarks

        return .shadowsocks(
            host: host,
            port: port,
            cipher: cipher,
            password: password,
            obfsMode: obfsMode,
            obfsHost: obfsHost
        )
    }

    // MARK: - VMess (vmess://)

    /// Parses a base64‑encoded VMess JSON configuration block.
    private static func parseVMess(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("vmess://")
            ? String(raw.dropFirst(8))
            : String(raw.dropFirst(8))

        // ---- 1. Extract fragment (remarks) --------------------------------
        let (bodyWithoutFragment, _) = extractFragment(from: body)

        // ---- 2. Base64 decode the JSON payload ----------------------------
        guard let jsonString = decodeBase64URLSafe(bodyWithoutFragment) else {
            return nil
        }

        guard let jsonData = jsonString.data(using: .utf8),
              let json = try? JSONSerialization.jsonObject(
                  with: jsonData, options: []
              ) as? [String: Any] else {
            return nil
        }

        // ---- 3. Extract fields --------------------------------------------
        let host = (json["add"] as? String) ?? ""
        let port: UInt16 = {
            if let p = json["port"] as? UInt16 { return p }
            if let p = json["port"] as? Int { return UInt16(clamping: p) }
            if let p = json["port"] as? String, let pn = UInt16(p) { return pn }
            return 0
        }()
        let uuid = (json["id"] as? String) ?? ""
        let alterId: Int = {
            if let a = json["aid"] as? Int { return a }
            if let a = json["aid"] as? String, let an = Int(a) { return an }
            return 0
        }()
        let transport = (json["net"] as? String) ?? "tcp"
        let tlsEnabled: Bool = {
            if let t = json["tls"] as? String {
                return t == "tls" || t == "1" || t == "true"
            }
            return false
        }()
        let sni = json["sni"] as? String
        let wsPath = json["path"] as? String
        let wsHost = json["host"] as? String

        // gRPC transport parameters.
        let serviceName = json["serviceName"] as? String
        let authority = json["authority"] as? String

        guard !host.isEmpty, port > 0, !uuid.isEmpty else {
            return nil
        }

        return .vmess(
            host: host,
            port: port,
            uuid: uuid,
            alterId: alterId,
            transport: transport,
            tlsEnabled: tlsEnabled,
            sni: sni,
            wsPath: wsPath,
            wsHost: wsHost,
            serviceName: serviceName,
            authority: authority
        )
    }

    // MARK: - VLESS (vless://)

    /// Parses a VLESS URI with `@`‑delimited UUID and query‑string
    /// transport parameters.
    private static func parseVLESS(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("vless://")
            ? String(raw.dropFirst(8))
            : String(raw.dropFirst(8))

        let (bodyWithoutFragment, _) = extractFragment(from: body)
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        // Split at @ to get uuid and host:port.
        guard let atIndex = core.firstIndex(of: "@") else { return nil }
        let uuid = String(core[..<atIndex])
        let hostPortPart = String(core[core.index(after: atIndex)...])

        let (host, port) = parseHostPort(hostPortPart)
        guard let port = port, !uuid.isEmpty else { return nil }

        let flow = queryValue(for: "flow", in: queryItems)
        let security = queryValue(for: "security", in: queryItems)
        let sni = queryValue(for: "sni", in: queryItems)
        let pbk = queryValue(for: "pbk", in: queryItems)
        let transport = queryValue(for: "type", in: queryItems) ?? "tcp"
        let wsPath = queryValue(for: "path", in: queryItems)
        let wsHost = queryValue(for: "host", in: queryItems)
        let fingerprint = queryValue(for: "fp", in: queryItems)
        let shortId = queryValue(for: "sid", in: queryItems)
        let spiderX = queryValue(for: "spx", in: queryItems)

        // gRPC transport parameters.
        let serviceName = queryValue(for: "serviceName", in: queryItems)
        let authority = queryValue(for: "authority", in: queryItems)

        let xtls = (security == "reality" || flow?.contains("xtls") == true)

        return .vless(
            host: host,
            port: port,
            uuid: uuid,
            flow: flow,
            xtls: xtls,
            sni: sni,
            pbk: pbk,
            transport: transport,
            wsPath: wsPath,
            wsHost: wsHost,
            fingerprint: fingerprint,
            shortId: shortId,
            spiderX: spiderX,
            serviceName: serviceName,
            authority: authority
        )
    }

    // MARK: - Trojan (trojan://)

    /// Parses a Trojan URI with `@`‑delimited password and query‑string
    /// transport parameters.
    private static func parseTrojan(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("trojan://")
            ? String(raw.dropFirst(9))
            : String(raw.dropFirst(9))

        let (bodyWithoutFragment, _) = extractFragment(from: body)
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        guard let atIndex = core.firstIndex(of: "@") else { return nil }
        let password = String(core[..<atIndex])
            .removingPercentEncoding ?? String(core[..<atIndex])
        let hostPortPart = String(core[core.index(after: atIndex)...])

        let (host, port) = parseHostPort(hostPortPart)
        guard let port = port, !password.isEmpty else { return nil }

        let transport = queryValue(for: "type", in: queryItems) ?? "tcp"
        let sni = queryValue(for: "sni", in: queryItems)
        let wsPath = queryValue(for: "path", in: queryItems)
        let wsHost = queryValue(for: "host", in: queryItems)
        let fingerprint = queryValue(for: "fp", in: queryItems)

        // gRPC transport parameters.
        let serviceName = queryValue(for: "serviceName", in: queryItems)
        let authority = queryValue(for: "authority", in: queryItems)

        return .trojan(
            host: host,
            port: port,
            password: password,
            transport: transport,
            sni: sni,
            wsPath: wsPath,
            wsHost: wsHost,
            fingerprint: fingerprint,
            serviceName: serviceName,
            authority: authority
        )
    }

    // MARK: - Hysteria 2 (hysteria2:// / hy2://)

    private static func parseHysteria2(_ raw: String) -> ProxyNodeConfiguration? {
        let body: String
        if raw.hasPrefix("hysteria2://") {
            body = String(raw.dropFirst(12))
        } else if raw.hasPrefix("hy2://") {
            body = String(raw.dropFirst(6))
        } else {
            return nil
        }

        let (bodyWithoutFragment, _) = extractFragment(from: body)
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        // Format: password@host:port OR host:port (password in query)
        let password: String
        let hostPortPart: String

        if let atIndex = core.firstIndex(of: "@") {
            password = String(core[..<atIndex])
                .removingPercentEncoding ?? String(core[..<atIndex])
            hostPortPart = String(core[core.index(after: atIndex)...])
        } else {
            // Password might be in query params.
            password = queryValue(for: "password", in: queryItems)
                ?? queryValue(for: "auth", in: queryItems)
                ?? ""
            hostPortPart = core
        }

        let (host, port) = parseHostPort(hostPortPart)
        guard let port = port, !host.isEmpty else { return nil }

        let obfsOption = queryValue(for: "obfs", in: queryItems)
        let obfsPassword = queryValue(for: "obfs-password", in: queryItems)
        let sni = queryValue(for: "sni", in: queryItems)
        let insecure = queryValue(for: "insecure", in: queryItems)
            .map { $0 == "1" || $0 == "true" } ?? false

        return .hysteria2(
            host: host,
            port: port,
            password: password,
            obfsOption: obfsOption,
            obfsPassword: obfsPassword,
            sni: sni,
            insecure: insecure
        )
    }

    // MARK: - TUIC v5 (tuic://)

    private static func parseTUIC(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("tuic://")
            ? String(raw.dropFirst(7))
            : String(raw.dropFirst(7))

        let (bodyWithoutFragment, _) = extractFragment(from: body)
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        // Format: uuid:password@host:port
        guard let atIndex = core.firstIndex(of: "@") else { return nil }
        let userinfo = String(core[..<atIndex])
            .removingPercentEncoding ?? String(core[..<atIndex])
        let hostPortPart = String(core[core.index(after: atIndex)...])

        let userParts = userinfo.split(separator: ":", maxSplits: 1,
                                       omittingEmptySubsequences: false)
        let uuid: String
        let password: String
        if userParts.count == 2 {
            uuid = String(userParts[0])
            password = String(userParts[1])
        } else {
            // Single value — could be just password (legacy TUIC format).
            uuid = String(userParts[0])
            password = queryValue(for: "password", in: queryItems) ?? ""
        }

        let (host, port) = parseHostPort(hostPortPart)
        guard let port = port, !uuid.isEmpty else { return nil }

        let congestionControl = queryValue(for: "congestion_control",
                                            in: queryItems) ?? "bbr"
        let sni = queryValue(for: "sni", in: queryItems)
        let alpn = queryValue(for: "alpn", in: queryItems)
        let insecure = queryValue(for: "insecure", in: queryItems)
            .map { $0 == "1" || $0 == "true" } ?? false

        return .tuic(
            host: host,
            port: port,
            uuid: uuid,
            password: password,
            congestionControl: congestionControl,
            sni: sni,
            alpn: alpn,
            insecure: insecure
        )
    }

    // MARK: - Snell v4 (snell://)

    /// Parses a Snell v4 URI: `snell://psk@host:port?version=4`
    private static func parseSnell(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("snell://")
            ? String(raw.dropFirst(8))
            : String(raw.dropFirst(8))

        let (bodyWithoutFragment, _) = extractFragment(from: body)
        let (core, queryItems) = splitQuery(from: bodyWithoutFragment)

        // Format: psk@host:port
        guard let atIndex = core.firstIndex(of: "@") else { return nil }
        let psk = String(core[..<atIndex])
            .removingPercentEncoding ?? String(core[..<atIndex])
        let hostPortPart = String(core[core.index(after: atIndex)...])

        let (host, port) = parseHostPort(hostPortPart)
        guard let port = port, !psk.isEmpty else { return nil }

        let version = queryValue(for: "version", in: queryItems)
            .flatMap(Int.init) ?? 4

        return .snell(host: host, port: port, psk: psk, version: version)
    }

    // MARK: - WireGuard (wireguard:// / wg://)

    private static func parseWireGuard(_ raw: String) -> ProxyNodeConfiguration? {
        let body: String
        if raw.hasPrefix("wireguard://") {
            body = String(raw.dropFirst(12))
        } else if raw.hasPrefix("wg://") {
            body = String(raw.dropFirst(5))
        } else {
            return nil
        }

        let (bodyWithoutFragment, _) = extractFragment(from: body)

        // Try base64‑encoded config first.
        if let decoded = decodeBase64URLSafe(bodyWithoutFragment),
           decoded.contains("PrivateKey") || decoded.contains("[Interface]") {
            return parseWireGuardINI(decoded)
        }

        // Fall back to query‑parameter style.
        let (_, queryItems) = splitQuery(from: bodyWithoutFragment)

        let privateKey = queryValue(for: "privateKey", in: queryItems) ?? ""
        let peerPublicKey = queryValue(for: "peerPublicKey", in: queryItems) ?? ""
        let endpoint = queryValue(for: "endpoint", in: queryItems)
            ?? queryValue(for: "peer", in: queryItems) ?? ""
        let presharedKey = queryValue(for: "presharedKey", in: queryItems)
        let mtu = queryValue(for: "mtu", in: queryItems).flatMap(Int.init)
        let addresses = queryValue(for: "addresses", in: queryItems)?
            .components(separatedBy: ",")

        // Decode reserved bytes if present.
        var reservedBytes: [UInt8]?
        if let rsvStr = queryValue(for: "reserved", in: queryItems) {
            reservedBytes = rsvStr.split(separator: ",").compactMap {
                UInt8($0.trimmingCharacters(in: .whitespaces))
            }
        }

        guard !privateKey.isEmpty, !peerPublicKey.isEmpty,
              !endpoint.isEmpty else {
            return nil
        }

        return .wireguard(
            privateKey: privateKey,
            peerPublicKey: peerPublicKey,
            endpoint: endpoint,
            presharedKey: presharedKey,
            reservedBytes: reservedBytes,
            addresses: addresses,
            mtu: mtu
        )
    }

    /// Parses a WireGuard INI‑style config into a node configuration.
    private static func parseWireGuardINI(_ ini: String) -> ProxyNodeConfiguration? {
        var privateKey = ""
        var peerPublicKey = ""
        var endpoint = ""
        var presharedKey: String?
        var addresses: [String] = []
        var mtu: Int?
        var reservedBytes: [UInt8]?

        var currentSection = ""
        for line in ini.components(separatedBy: .newlines) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)

            if trimmed.hasPrefix("[") && trimmed.hasSuffix("]") {
                currentSection = trimmed
                continue
            }

            let parts = trimmed.split(separator: "=", maxSplits: 1,
                                      omittingEmptySubsequences: false)
            guard parts.count == 2 else { continue }
            let key = parts[0].trimmingCharacters(in: .whitespaces)
            let value = parts[1].trimmingCharacters(in: .whitespaces)

            if currentSection == "[Interface]" {
                switch key {
                case "PrivateKey":   privateKey = value
                case "Address":      addresses = value.components(separatedBy: ",")
                    .map { $0.trimmingCharacters(in: .whitespaces) }
                case "MTU":          mtu = Int(value)
                default: break
                }
            } else if currentSection == "[Peer]" {
                switch key {
                case "PublicKey":    peerPublicKey = value
                case "Endpoint":     endpoint = value
                case "PresharedKey": presharedKey = value
                case "Reserved":     reservedBytes = parseReservedBytes(value)
                default: break
                }
            }
        }

        guard !privateKey.isEmpty, !peerPublicKey.isEmpty,
              !endpoint.isEmpty else { return nil }

        return .wireguard(
            privateKey: privateKey,
            peerPublicKey: peerPublicKey,
            endpoint: endpoint,
            presharedKey: presharedKey,
            reservedBytes: reservedBytes,
            addresses: addresses.isEmpty ? nil : addresses,
            mtu: mtu
        )
    }

    private static func parseReservedBytes(_ value: String) -> [UInt8]? {
        let parts = value.components(separatedBy: ",")
        let bytes = parts.compactMap { UInt8($0.trimmingCharacters(in: .whitespaces)) }
        return bytes.isEmpty ? nil : bytes
    }

    // MARK: - URI Helpers

    /// Extracts the fragment (`#remarks`) from a URI body.
    /// Returns `(bodyWithoutFragment, fragmentRemarks?)`.
    private static func extractFragment(
        from body: String
    ) -> (bodyWithoutFragment: String, remarks: String?) {
        guard let hashIndex = body.firstIndex(of: "#") else {
            return (body, nil)
        }
        let before = String(body[..<hashIndex])
        let remarks = String(body[body.index(after: hashIndex)...])
            .removingPercentEncoding ?? String(body[body.index(after: hashIndex)...])
        return (before, remarks.isEmpty ? nil : remarks)
    }

    /// Splits the query string (after `?`) from the main URI body.
    /// Returns `(coreBody, [(key, value)])`.
    private static func splitQuery(
        from body: String
    ) -> (core: String, queryItems: [(String, String)]) {
        guard let queryIndex = body.firstIndex(of: "?") else {
            return (body, [])
        }
        let core = String(body[..<queryIndex])
        let queryString = String(body[body.index(after: queryIndex)...])
        let items = parseQueryItems(queryString)
        return (core, items)
    }

    /// Parses a query string into an array of `(key, value)` tuples.
    private static func parseQueryItems(_ query: String) -> [(String, String)] {
        var items: [(String, String)] = []
        let pairs = query.components(separatedBy: "&")
        for pair in pairs {
            let kv = pair.split(separator: "=", maxSplits: 1,
                                omittingEmptySubsequences: false)
            if kv.count == 2 {
                let key = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                let value = String(kv[1]).removingPercentEncoding ?? String(kv[1])
                items.append((key, value))
            } else if kv.count == 1 {
                let key = String(kv[0]).removingPercentEncoding ?? String(kv[0])
                items.append((key, ""))
            }
        }
        return items
    }

    /// Looks up a value by key in parsed query items.
    private static func queryValue(
        for key: String,
        in items: [(String, String)]
    ) -> String? {
        for (k, v) in items where k == key {
            return v.isEmpty ? nil : v
        }
        return nil
    }

    /// Parses `host:port` from a string, handling IPv6 bracket notation
    /// (`[::1]:443`) and bare `host:port`.
    private static func parseHostPort(_ s: String) -> (host: String, port: UInt16?) {
        let str = s.trimmingCharacters(in: CharacterSet(charactersIn: "/"))

        // IPv6 bracket notation: [::1]:port
        if str.hasPrefix("[") {
            guard let closeBracket = str.firstIndex(of: "]") else {
                return (str, nil)
            }
            let host = String(str[str.index(after: str.startIndex)..<closeBracket])
            let remainder = str[str.index(after: closeBracket)...]
            if remainder.hasPrefix(":") {
                let portStr = String(remainder.dropFirst())
                return (host, UInt16(portStr))
            }
            return (host, nil)
        }

        // Standard host:port
        let parts = str.split(separator: ":", maxSplits: 1,
                              omittingEmptySubsequences: false)
        if parts.count == 2, let port = UInt16(parts[1]) {
            return (String(parts[0]), port)
        }
        return (str, nil)
    }

    // MARK: - ShadowsocksR (ssr://)

    /// Parses a ShadowsocksR `ssr://` URI with Base64‑encoded payload.
    ///
    /// Format: `ssr://base64(host:port:protocol:method:obfs:base64_password/?params)`
    private static func parseShadowsocksR(_ raw: String) -> ProxyNodeConfiguration? {
        let body = raw.hasPrefix("ssr://")
            ? String(raw.dropFirst(6))
            : String(raw.dropFirst(6))

        // ---- 1. Strip fragment --------------------------------------------
        let (bodyWithoutFragment, _) = extractFragment(from: body)

        // ---- 2. Base64 decode the main payload ----------------------------
        guard let decoded = decodeBase64URLSafe(bodyWithoutFragment) else {
            return nil
        }

        // ---- 3. Split main part and query ---------------------------------
        let (mainPart, queryItems): (String, [(String, String)])
        if let queryIdx = decoded.firstIndex(of: "?") {
            mainPart = String(decoded[..<queryIdx])
            let queryString = String(decoded[decoded.index(after: queryIdx)...])
            queryItems = parseQueryItems(queryString)
        } else {
            mainPart = decoded
            queryItems = []
        }

        // ---- 4. Parse colon‑delimited SSR fields --------------------------
        // Format: host:port:protocol:method:obfs:base64_password
        let parts = mainPart.components(separatedBy: ":")
        guard parts.count >= 6 else { return nil }

        let host = parts[0]
        guard let port = UInt16(parts[1]), !host.isEmpty, port > 0 else {
            return nil
        }
        let protocolMode = parts[2]
        let cipher = parts[3]
        let obfsMode = parts[4]

        // Decode the base64‑encoded password (last field).
        let passwordBase64 = parts[5]
        let password = decodeBase64URLSafe(passwordBase64) ?? passwordBase64

        // ---- 5. Extract base64‑encoded query parameters --------------------
        var protocolParam: String?
        var obfsParam: String?

        if let obfsParamB64 = queryValue(for: "obfsparam", in: queryItems) {
            obfsParam = decodeBase64URLSafe(obfsParamB64) ?? obfsParamB64
        }
        if let protoParamB64 = queryValue(for: "protoparam", in: queryItems) {
            protocolParam = decodeBase64URLSafe(protoParamB64) ?? protoParamB64
        }

        return .shadowsocksr(
            host: host,
            port: port,
            cipher: cipher,
            password: password,
            protocolMode: protocolMode,
            protocolParam: protocolParam,
            obfsMode: obfsMode,
            obfsParam: obfsParam
        )
    }

    // MARK: - Obfs Plugin Parsing

    /// Parses semicolon‑delimited obfs plugin parameters.
    ///
    /// Input: `"obfs-local;obfs=http;obfs-host=bing.com"`
    /// Output: `["obfs": "http", "obfs-host": "bing.com"]`
    private static func parseObfsPluginParams(
        _ plugin: String
    ) -> [String: String] {
        var params: [String: String] = [:]
        let parts = plugin.components(separatedBy: ";")
        for part in parts {
            let kv = part.split(separator: "=", maxSplits: 1,
                                omittingEmptySubsequences: false)
            if kv.count == 2 {
                let key = String(kv[0]).trimmingCharacters(in: .whitespaces)
                let value = String(kv[1]).trimmingCharacters(in: .whitespaces)
                if !key.isEmpty { params[key] = value }
            }
        }
        return params
    }

    // MARK: - Base64 Helpers

    /// Attempts to decode a base64 string, automatically repairing
    /// missing padding characters before decoding.
    private static func decodeBase64URLSafe(_ string: String) -> String? {
        // Strip any percent‑encoding first.
        let decoded = string.removingPercentEncoding ?? string

        // Repair missing padding.
        var padded = decoded
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = padded.count % 4
        if remainder > 0 {
            padded += String(repeating: "=", count: 4 - remainder)
        }

        guard let data = Data(base64Encoded: padded) else {
            return nil
        }
        return String(data: data, encoding: .utf8)
    }

    /// Decodes base64 data directly (for WireGuard keys, etc.).
    private static func decodeBase64ToData(_ string: String) -> Data? {
        var padded = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let remainder = padded.count % 4
        if remainder > 0 {
            padded += String(repeating: "=", count: 4 - remainder)
        }
        return Data(base64Encoded: padded)
    }
}
