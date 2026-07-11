//===----------------------------------------------------------------------===//
//
//  Socks5Encoder.swift
//  SwiftletCore — SOCKS5 Frame Encoder
//
//  A `MessageToByteEncoder` that serialises outbound SOCKS5 protocol messages
//  (method‑selection and request‑reply) directly into `ByteBuffer` for
//  transmission on the wire.
//
//  Encoding formats (RFC 1928)
//  ---------------------------
//  **Method selection** (2 bytes):
//  ```
//  +----+--------+
//  |VER | METHOD |
//  +----+--------+
//  | 1  |   1    |
//  +----+--------+
//  ```
//
//  **Request reply** (variable):
//  ```
//  +----+-----+-------+------+----------+----------+
//  |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//  +----+-----+-------+------+----------+----------+
//  | 1  |  1  | X'00' |  1   | Variable |    2     |
//  +----+-----+-------+------+----------+----------+
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

/// Encodes `Socks5OutboundMessage` values into the wire format expected by
/// a SOCKS5 client.
///
/// This encoder is stateless and may be reused safely, but each channel
/// pipeline should receive its own instance to avoid lifecycle surprises.
public final class Socks5Encoder: MessageToByteEncoder, RemovableChannelHandler, @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias OutboundIn = Socks5OutboundMessage

    // MARK: - MessageToByteEncoder

    public func encode(data: Socks5OutboundMessage, out: inout ByteBuffer) throws {
        switch data {
        case .methodSelection(let method):
            encodeMethodSelection(method, out: &out)

        case .response(let response):
            encodeResponse(response, out: &out)
        }
    }

    // MARK: - Private Encoders

    /// Encodes a 2‑byte method‑selection message.
    private func encodeMethodSelection(
        _ method: Socks5AuthMethod,
        out: inout ByteBuffer
    ) {
        out.writeInteger(Socks5Constants.version, as: UInt8.self)
        out.writeInteger(method.rawValue, as: UInt8.self)
    }

    /// Encodes a variable‑length request reply.
    ///
    /// BND.ADDR is always emitted as the IPv4 address `0.0.0.0` with port `0`
    /// (the most common convention for CONNECT‑only proxies).  Clients
    /// rarely inspect these fields for TCP forwarding.
    private func encodeResponse(
        _ response: Socks5Response,
        out: inout ByteBuffer
    ) {
        out.writeInteger(Socks5Constants.version, as: UInt8.self)
        out.writeInteger(response.reply.rawValue, as: UInt8.self)
        out.writeInteger(Socks5Constants.reserved, as: UInt8.self)

        // Always emit an IPv4 zero‑address — the client ignores this for
        // CONNECT, and it keeps the encoder fast and branch‑free.
        out.writeInteger(Socks5AddressType.ipv4.rawValue, as: UInt8.self)
        out.writeBytes([0x00, 0x00, 0x00, 0x00])   // 0.0.0.0
        out.writeInteger(UInt16(0), as: UInt16.self) // port 0
    }
}
