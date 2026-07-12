//===----------------------------------------------------------------------===//
//
//  Hysteria2FrameBuilder.swift
//  SwiftletCore — Hysteria 2 HTTP/3 Auth + TCP Request Framing
//
//  Implements the Hysteria 2 v4 control‑stream protocol:
//
//  1. **Auth Header** — Mimics an HTTP/3 POST request with pseudo‑headers
//     carrying the authentication secret, flow‑control limits, and random
//     padding to defeat DPI signature matching.
//
//  2. **TCP Request Frame** — Uses QUIC varint encoding to request a new
//     TCP connection: `[0x401] [addrLen] ["host:port"] [padLen] [padding]`.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Handshake Builder

/// Builds Hysteria 2 control‑stream frames for authentication and
/// TCP connection requests.
public enum Hysteria2HandshakeBuilder {

    // MARK: - Constants

    /// The TCP request command ID per Hysteria 2 specification.
    public static let tcpRequestCommand: UInt64 = 0x401

    // MARK: - Auth Header

    /// Builds the Hysteria 2 v4 HTTP/3 pseudo‑header auth frame.
    ///
    /// The wire format encodes each pseudo‑header as a length‑prefixed
    /// key‑value pair, wrapped in an outer length prefix:
    ///
    /// ```
    /// [QUIC Varint: total headers length]
    ///   [QUIC Varint: ":method"]  [QUIC Varint: "POST"]
    ///   [QUIC Varint: ":path"]    [QUIC Varint: "/auth"]
    ///   [QUIC Varint: ":host"]    [QUIC Varint: "hysteria"]
    ///   [QUIC Varint: "Hysteria-Auth"]    [QUIC Varint: authSecret]
    ///   [QUIC Varint: "Hysteria-CC-RX"]   [QUIC Varint: "\(maxRxBps)"]
    ///   [QUIC Varint: "Hysteria-Padding"] [QUIC Varint: randomPadding]
    /// ```
    ///
    /// - Parameters:
    ///   - authSecret: The pre‑shared authentication secret.
    ///   - maxRxBps: Maximum receive bandwidth (0 = unlimited).
    ///   - paddingLength: Number of random padding bytes (default 64).
    /// - Returns: The binary auth frame.
    public static func buildAuthHeader(
        authSecret: String,
        maxRxBps: UInt64 = 0,
        paddingLength: Int = 64
    ) -> Data {
        let headers: [(String, String)] = [
            (":method",           "POST"),
            (":path",             "/auth"),
            (":host",             "hysteria"),
            ("Hysteria-Auth",     authSecret),
            ("Hysteria-CC-RX",    "\(maxRxBps)"),
            ("Hysteria-Padding",  randomString(length: paddingLength)),
        ]

        // Build the inner headers block.
        var headersBlock = Data()
        for (key, value) in headers {
            let keyBytes   = Array(key.utf8)
            let valueBytes = Array(value.utf8)
            headersBlock.append(contentsOf: QUICVarint.encode(UInt64(keyBytes.count)))
            headersBlock.append(contentsOf: keyBytes)
            headersBlock.append(contentsOf: QUICVarint.encode(UInt64(valueBytes.count)))
            headersBlock.append(contentsOf: valueBytes)
        }

        // Wrap with total length.
        var frame = Data()
        frame.append(contentsOf: QUICVarint.encode(UInt64(headersBlock.count)))
        frame.append(headersBlock)

        return frame
    }

    // MARK: - TCP Request

    /// Builds the binary TCP connection request frame.
    ///
    /// Wire format:
    /// ```
    /// [QUIC Varint] 0x401            — TCPRequest command ID
    /// [QUIC Varint] Address Length
    /// [Bytes]       Address string   — "host:port"
    /// [QUIC Varint] Padding Length
    /// [Bytes]       Random padding
    /// ```
    ///
    /// - Parameters:
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    ///   - paddingLength: Number of random padding bytes (default 16).
    /// - Returns: The binary TCP request frame.
    public static func buildTCPRequest(
        address: String,
        port: UInt16,
        paddingLength: Int = 16
    ) -> Data {
        let addrString = "\(address):\(port)"
        let addrBytes  = Array(addrString.utf8)

        var frame = Data()

        // 1. Command ID = 0x401
        frame.append(contentsOf: QUICVarint.encode(tcpRequestCommand))

        // 2. Address length + address
        frame.append(contentsOf: QUICVarint.encode(UInt64(addrBytes.count)))
        frame.append(contentsOf: addrBytes)

        // 3. Padding length + random padding
        let padBytes = generateRandomBytes(count: paddingLength)
        frame.append(contentsOf: QUICVarint.encode(UInt64(padBytes.count)))
        frame.append(contentsOf: padBytes)

        return frame
    }

    // MARK: - Helpers

    private static func randomString(length: Int) -> String {
        guard length > 0 else { return "" }
        let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0 ..< length).map { _ in chars.randomElement()! })
    }

    private static func generateRandomBytes(count: Int) -> [UInt8] {
        guard count > 0 else { return [] }
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return bytes
    }
}
