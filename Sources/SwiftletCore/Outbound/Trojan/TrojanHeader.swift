//===----------------------------------------------------------------------===//
//
//  TrojanHeader.swift
//  SwiftletCore — Trojan Protocol Request Frame Builder
//
//  Implements the Trojan-GFW request header format:
//
//    [SHA224(password) hex (56 bytes)] [CRLF] [CMD] [ATYP] [DST.ADDR] [DST.PORT] [CRLF]
//
//  The password hash is computed using SHA‑224 over the raw UTF‑8 bytes of
//  the password string.  The destination address uses SOCKS5‑style encoding.
//
//===----------------------------------------------------------------------===//

import CommonCrypto
import Foundation

// MARK: - Trojan Address Type

/// SOCKS5‑compatible address type byte used in Trojan request headers.
public enum TrojanAddressType: UInt8, Sendable {
    case ipv4   = 0x01
    case domain = 0x03
    case ipv6   = 0x04
}

// MARK: - Trojan Command

/// Trojan request commands.
public enum TrojanCommand: UInt8, Sendable {
    case connect    = 0x01
    case udpAssociate = 0x03
}

// MARK: - Trojan Header Builder

/// Builds the binary Trojan request header frame.
public enum TrojanHeader {

    /// CRLF constant used twice in every Trojan header.
    private static let crlf: [UInt8] = [0x0D, 0x0A]

    // MARK: - Public API

    /// Computes the SHA‑224 hash of the password and returns the lowercase
    /// 56‑character hexadecimal string.
    ///
    /// - Parameter password: The user's Trojan password.
    /// - Returns: A 56‑character lowercase hex string.
    public static func passwordHash(for password: String) -> String {
        let passwordBytes = Data(password.utf8)
        let digest = Self.sha224(data: passwordBytes)
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    /// Computes the SHA‑224 digest of the given data using CommonCrypto.
    /// CryptoKit does not expose SHA‑224 natively; CommonCrypto provides
    /// the canonical implementation available on all Apple platforms.
    private static func sha224(data: Data) -> Data {
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA224_DIGEST_LENGTH))
        data.withUnsafeBytes { rawBuffer in
            let ptr = rawBuffer.bindMemory(to: UInt8.self)
            _ = CC_SHA224(ptr.baseAddress, CC_LONG(data.count), &digest)
        }
        return Data(digest)
    }

    /// Builds the complete Trojan request header for a TCP CONNECT to the
    /// given destination.
    ///
    /// - Parameters:
    ///   - password: The Trojan password.
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    /// - Returns: The binary header frame ready to be prepended to the first
    ///   outbound payload after the TLS handshake completes.
    public static func buildConnect(
        password: String,
        address: String,
        port: UInt16
    ) -> Data {
        let hashHex = passwordHash(for: password)
        var data = Data()

        // 1. SHA224 hex string (56 bytes)
        data.append(contentsOf: hashHex.utf8)

        // 2. CRLF
        data.append(contentsOf: crlf)

        // 3. Command (0x01 = TCP CONNECT)
        data.append(TrojanCommand.connect.rawValue)

        // 4. Address type + address
        if let ipv4Addr = parseIPv4(address) {
            data.append(TrojanAddressType.ipv4.rawValue)
            data.append(contentsOf: ipv4Addr)
        } else if let ipv6Addr = parseIPv6(address) {
            data.append(TrojanAddressType.ipv6.rawValue)
            data.append(contentsOf: ipv6Addr)
        } else {
            // Domain name
            let domainBytes = address.utf8
            data.append(TrojanAddressType.domain.rawValue)
            data.append(UInt8(domainBytes.count))
            data.append(contentsOf: domainBytes)
        }

        // 5. Port (2 bytes, big-endian)
        data.append(UInt8(port >> 8))
        data.append(UInt8(port & 0xFF))

        // 6. CRLF
        data.append(contentsOf: crlf)

        return data
    }

    // MARK: - Address Parsing Helpers

    /// Attempts to parse the string as an IPv4 dotted‑decimal address.
    /// Returns 4 raw octets, or `nil` if the string is not a valid IPv4.
    private static func parseIPv4(_ string: String) -> [UInt8]? {
        let parts = string.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for part in parts {
            guard let value = UInt8(part) else { return nil }
            octets.append(value)
        }
        return octets
    }

    /// Attempts to parse the string as an IPv6 address.
    /// Returns 16 raw octets in network order, or `nil`.
    private static func parseIPv6(_ string: String) -> [UInt8]? {
        // Expand `::` compressed notation.
        var groups = string.split(separator: ":", omittingEmptySubsequences: false)
            .map(String.init)

        // Special case: leading `::` or trailing `::`
        if groups.count < 8 {
            // Find the empty part indicating `::`
            if let emptyIndex = groups.firstIndex(of: "") {
                let missing = 8 - (groups.count - 1)
                groups.replaceSubrange(emptyIndex ... emptyIndex,
                                       with: Array(repeating: "0", count: missing))
            }
        }

        guard groups.count == 8 else { return nil }

        var bytes: [UInt8] = []
        for group in groups {
            guard let value = UInt16(group, radix: 16) else { return nil }
            bytes.append(UInt8(value >> 8))
            bytes.append(UInt8(value & 0xFF))
        }
        return bytes.count == 16 ? bytes : nil
    }
}
