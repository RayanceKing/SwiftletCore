//===----------------------------------------------------------------------===//
//
//  VLESSProtocol.swift
//  SwiftletCore — VLESS Protocol Frame Builder (Version 0)
//
//  VLESS is a stateless, lightweight proxy protocol.  Each connection
//  carries a 16‑byte UUID for authentication and a destination address
//  right in the first frame — no separate handshake or command channel.
//
//  Request Format (after REALITY/TLS handshake completes):
//  ```
//  [1]  Version    = 0x00
//  [16] UUID       = raw binary UUID bytes
//  [1]  AddonLen   = 0x00  (no protocol‑addon, e.g. Mux, Flow)
//  [1]  Command    = 0x01  (TCP)
//  [2]  Port       = big‑endian UInt16
//  [1]  ATYP       = 0x01 (IPv4) | 0x03 (domain) | 0x04 (IPv6)
//  [n]  Address    = variable per ATYP
//  ```
//
//  Server Response:
//  ```
//  [1]  Status     = 0x00 (success)  →  then raw streaming begins
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - VLESS Constants

public enum VLESSProtocol {

    /// Protocol version (currently 0).
    public static let version: UInt8 = 0x00

    /// TCP CONNECT command byte.
    public static let commandTCP: UInt8 = 0x01

    /// No additional protocol options.
    public static let addonLength: UInt8 = 0x00

    /// The server responds with this byte to signal success.
    public static let responseSuccess: UInt8 = 0x00
}

// MARK: - VLESS Request Builder

/// Builds the raw binary VLESS request frame for a TCP CONNECT.
public enum VLESSRequestBuilder {

    /// Extracts the 16 raw bytes from a `UUID`.
    ///
    /// VLESS uses the UUID's binary representation directly — no hex encoding.
    public static func uuidBytes(from uuid: UUID) -> [UInt8] {
        let u = uuid.uuid
        return [
            u.0,  u.1,  u.2,  u.3,  u.4,  u.5,  u.6,  u.7,
            u.8,  u.9,  u.10, u.11, u.12, u.13, u.14, u.15,
        ]
    }

    /// Builds the full VLESS TCP CONNECT request frame.
    ///
    /// - Parameters:
    ///   - uuid: The user's VLESS UUID.
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    /// - Returns: The complete VLESS request frame.
    public static func buildConnect(
        uuid: UUID,
        address: String,
        port: UInt16
    ) -> Data {
        var data = Data()

        // 1. Version
        data.append(VLESSProtocol.version)

        // 2. UUID (16 raw bytes)
        data.append(contentsOf: uuidBytes(from: uuid))

        // 3. Additional Options Length
        data.append(VLESSProtocol.addonLength)

        // 4. Command (TCP CONNECT = 0x01)
        data.append(VLESSProtocol.commandTCP)

        // 5. Port (2 bytes, big‑endian)
        data.append(UInt8(port >> 8))
        data.append(UInt8(port & 0xFF))

        // 6. Address Type + Address
        if let ipv4 = parseIPv4(address) {
            data.append(0x01) // IPv4
            data.append(contentsOf: ipv4)
        } else if let ipv6 = tryParseIPv6(address) {
            data.append(0x04) // IPv6
            data.append(contentsOf: ipv6)
        } else {
            // Domain name
            let domainBytes = Array(address.utf8)
            data.append(0x03) // Domain
            data.append(UInt8(domainBytes.count))
            data.append(contentsOf: domainBytes)
        }

        return data
    }

    // MARK: - Address Parsing

    private static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for p in parts {
            guard let v = UInt8(p) else { return nil }
            octets.append(v)
        }
        return octets
    }

    private static func tryParseIPv6(_ s: String) -> [UInt8]? {
        var groups = s.split(separator: ":", omittingEmptySubsequences: false)
            .map(String.init)
        if groups.count < 8, let idx = groups.firstIndex(of: "") {
            groups.replaceSubrange(idx ... idx,
                                   with: Array(repeating: "0", count: 8 - (groups.count - 1)))
        }
        guard groups.count == 8 else { return nil }
        var bytes: [UInt8] = []
        for g in groups {
            guard let v = UInt16(g, radix: 16) else { return nil }
            bytes.append(UInt8(v >> 8))
            bytes.append(UInt8(v & 0xFF))
        }
        return bytes.count == 16 ? bytes : nil
    }
}

// MARK: - VLESS Configuration

/// Parameters for a VLESS‑REALITY outbound connection.
public struct VLESSConfiguration: Sendable {

    /// The user's VLESS UUID.
    public let uuid: UUID

    /// The REALITY pre‑shared authentication key (raw bytes).
    public let realityAuthKey: Data

    /// The SNI hostname that the REALITY handshake presents to the target
    /// server (e.g. `"www.apple.com"`).
    public let serverName: String

    /// The REALITY custom extension type code (GREASE range, e.g. 0xF001).
    public let realityExtensionType: UInt16

    /// Number of zero bytes to append as a padding extension for JA4
    /// fingerprint matching.  Typical values range from 32–512.
    public let paddingBytes: Int

    /// The ultimate destination address carried in the VLESS header.
    public let destinationAddress: String

    /// The ultimate destination port carried in the VLESS header.
    public let destinationPort: UInt16

    public init(
        uuid: UUID,
        realityAuthKey: Data,
        serverName: String,
        realityExtensionType: UInt16 = 0xF001,
        paddingBytes: Int = 128,
        destinationAddress: String,
        destinationPort: UInt16
    ) {
        self.uuid = uuid
        self.realityAuthKey = realityAuthKey
        self.serverName = serverName
        self.realityExtensionType = realityExtensionType
        self.paddingBytes = paddingBytes
        self.destinationAddress = destinationAddress
        self.destinationPort = destinationPort
    }
}

// MARK: - Outbound Errors

public enum OutboundError: Error, Sendable, Equatable {
    case vlessRejected(UInt8)
    case connectionFailed
    case invalidState(String)
}
