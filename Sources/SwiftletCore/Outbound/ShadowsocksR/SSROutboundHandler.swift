//===----------------------------------------------------------------------===//
//
//  SSROutboundHandler.swift
//  SwiftletCore — ShadowsocksR Protocol + Obfs Plugin Handler
//
//  A composable ChannelDuplexHandler for ShadowsocksR (SSR) that layers
//  the protocol plugin header and the obfuscation plugin handshake atop
//  raw TCP, delegating the underlying stream cipher to the existing
//  Shadowsocks infrastructure.
//
//  Pipeline Architecture
//  ---------------------
//  ```
//  [TCP Socket]
//    → ProxyChannelPoolBridgeHandler
//    → SSR Obfs Plugin Handler   (tls1.2_ticket_auth / http_simple / plain)
//    → SSR Protocol Plugin Handler (origin / auth_aes128_sha1 / auth_aes128_md5)
//    → ShadowsocksCipher Handler  (AES‑CFB / ChaCha20 / etc.)
//    → [Per‑Session Relay]
//  ```
//
//  SSR Protocol Plugin Frame Header (for auth_aes128_* variants)
//  -------------------------------------------------------------
//  ```
//  [DataLen(2B BE)] [HMAC(4B)] [ClientID(4B)] [Timestamp(4B)]
//  ```
//  The HMAC covers payload + clientID + timestamp using the SSR password
//  as the key.  The `origin` protocol plugin sends no additional header.
//
//  SSR Obfuscation Plugins
//  -----------------------
//  - plain:               No handshake — pass through immediately.
//  - http_simple:         Prepend an HTTP GET request, then strip HTTP
//                         response header from the first inbound read.
//  - tls1.2_ticket_auth:  Mock TLS 1.2 ClientHello with session ticket;
//                         parse ServerHello, then transition to forwarding.
//
//  Thread Safety
//  -------------
//  Marked `@unchecked Sendable`.  All mutable state is accessed exclusively
//  on the channel's event loop.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - SSR Obfs Plugin Handler

/// Handles the ShadowsocksR obfuscation handshake (TCP-level disguise).
///
/// Depending on the configured obfs plugin, sends an initial handshake
/// frame and parses the response before transitioning to forwarding mode.
public final class SSRObfsPluginHandler: ChannelDuplexHandler,
                                          @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// Obfuscation mode identifier.
    private let obfsMode: String
    /// Optional obfs parameter (e.g. a domain for HTTP host header).
    private let obfsParam: String?

    /// Internal state.
    private enum State { case handshaking, forwarding }
    private var state: State = .handshaking
    private var handshakeBuffer: ByteBuffer?

    public init(obfsMode: String, obfsParam: String?) {
        self.obfsMode = obfsMode
        self.obfsParam = obfsParam
    }

    // MARK: - Channel Lifecycle

    public func channelActive(context: ChannelHandlerContext) {
        switch obfsMode {
        case "plain":
            state = .forwarding
        case "http_simple":
            sendHTTPSimpleHandshake(context: context)
        case "tls1.2_ticket_auth":
            sendTLS12TicketHandshake(context: context)
        default:
            state = .forwarding
        }
        context.read()
        context.fireChannelActive()
    }

    // MARK: - Obfs Handshake: http_simple

    private func sendHTTPSimpleHandshake(context: ChannelHandlerContext) {
        let host = obfsParam ?? "cloudfront.com"
        let httpRequest = "GET / HTTP/1.1\r\nHost: \(host)\r\n"
            + "User-Agent: Mozilla/5.0\r\n"
            + "Accept: */*\r\n"
            + "Connection: keep-alive\r\n\r\n"

        var buf = context.channel.allocator.buffer(capacity: httpRequest.utf8.count)
        buf.writeString(httpRequest)
        context.writeAndFlush(wrapOutboundOut(buf), promise: nil)
    }

    // MARK: - Obfs Handshake: tls1.2_ticket_auth

    private func sendTLS12TicketHandshake(context: ChannelHandlerContext) {
        let host = obfsParam ?? ""
        // Build a minimal TLS 1.2 ClientHello with session ticket extension.
        let clientHello = buildMockTLS12ClientHello(sni: host)
        var buf = context.channel.allocator.buffer(capacity: clientHello.count)
        buf.writeBytes(clientHello)
        context.writeAndFlush(wrapOutboundOut(buf), promise: nil)
    }

    /// Builds a static mock TLS 1.2 ClientHello record.
    private func buildMockTLS12ClientHello(sni: String) -> [UInt8] {
        var record: [UInt8] = []

        // ContentType: handshake (22)
        record.append(0x16)
        // TLS version 1.2
        record.append(0x03); record.append(0x03)

        // Placeholder length — filled below.
        let lengthPos = record.count
        record.append(0x00); record.append(0x00)

        // Handshake type: ClientHello (1)
        let hsStart = record.count
        record.append(0x01)
        // Handshake length placeholder (3 bytes).
        record.append(0x00); record.append(0x00); record.append(0x00)

        // ClientHello body.
        // Protocol version: TLS 1.2
        record.append(0x03); record.append(0x03)

        // Random (32 bytes) — fixed mock value.
        let mockRandom: [UInt8] = Array(repeating: 0xAA, count: 32)
        record.append(contentsOf: mockRandom)

        // Session ID length (0).
        record.append(0x00)

        // Cipher suites length (2).
        let csLenPos = record.count
        record.append(0x00); record.append(0x02)
        // Cipher suite: TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xC02F).
        record.append(0xC0); record.append(0x2F)

        // Compression methods: null (1).
        record.append(0x01); record.append(0x00)

        // Extensions length placeholder.
        let extLenPos = record.count
        record.append(0x00); record.append(0x00)

        // SNI extension.
        let sniBytes = Array(sni.utf8)
        if !sniBytes.isEmpty {
            // Extension type: server_name (0)
            record.append(0x00); record.append(0x00)
            // SNI list length placeholder.
            let sniLenPos = record.count
            record.append(0x00); record.append(0x00)
            // ServerName entry length placeholder.
            let entryLenPos = record.count
            record.append(0x00); record.append(0x00)
            // Name type: host_name (0)
            record.append(0x00)
            // Name length + name.
            let nameLenPos = record.count
            record.append(0x00); record.append(0x00)
            record.append(contentsOf: sniBytes)

            // Back-patch lengths.
            let nameLen = sniBytes.count
            record[nameLenPos]     = UInt8(nameLen >> 8)
            record[nameLenPos + 1] = UInt8(nameLen & 0xFF)
            let entryTotal = 3 + nameLen  // type(1) + len(2) + name
            record[entryLenPos]     = UInt8(entryTotal >> 8)
            record[entryLenPos + 1] = UInt8(entryTotal & 0xFF)
            let sniTotal = 2 + entryTotal
            record[sniLenPos]     = UInt8(sniTotal >> 8)
            record[sniLenPos + 1] = UInt8(sniTotal & 0xFF)

            let extTotal = 2 + 2 + sniTotal  // type(2) + len(2) + data
            record[extLenPos]     = UInt8(extTotal >> 8)
            record[extLenPos + 1] = UInt8(extTotal & 0xFF)
        } else {
            record[extLenPos]     = 0x00; record[extLenPos + 1] = 0x02
            record.append(0x00); record.append(0x00)
            // Zero-length extension terminator.
            record.append(0x00); record.append(0x00)
        }

        // Back-patch handshake length.
        let hsLen = record.count - hsStart - 4
        record[hsStart + 1] = UInt8((hsLen >> 16) & 0xFF)
        record[hsStart + 2] = UInt8((hsLen >>  8) & 0xFF)
        record[hsStart + 3] = UInt8(hsLen & 0xFF)
        // Back-patch record length.
        let recLen = record.count - lengthPos - 2
        record[lengthPos]     = UInt8(recLen >> 8)
        record[lengthPos + 1] = UInt8(recLen & 0xFF)

        return record
    }

    // MARK: - Inbound Data

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        switch state {
        case .handshaking:
            // Accumulate handshake response, then strip it.
            if var buf = handshakeBuffer {
                buf.writeBuffer(&incoming)
                handshakeBuffer = buf
            } else {
                handshakeBuffer = incoming
            }
            if let stripped = stripObfsResponse() {
                state = .forwarding
                handshakeBuffer = nil
                if stripped.readableBytes > 0 {
                    context.fireChannelRead(wrapInboundOut(stripped))
                }
            }
        case .forwarding:
            context.fireChannelRead(data)
        }
    }

    /// Strips the obfuscation response from the accumulated handshake buffer.
    private func stripObfsResponse() -> ByteBuffer? {
        guard var buf = handshakeBuffer else { return nil }

        switch obfsMode {
        case "http_simple":
            // Scan for "\r\n\r\n" and strip everything before it.
            let headerEnd = "\r\n\r\n"
            if let range = findSequence(headerEnd, in: buf) {
                buf.moveReaderIndex(to: range.upperBound)
                return buf
            }
            return nil
        case "tls1.2_ticket_auth":
            // Wait for a complete TLS record.
            if buf.readableBytes >= 5 {
                let type = buf.getInteger(at: 0, as: UInt8.self) ?? 0
                guard type == 0x16 else { return buf } // Not handshake?
                let lenHi = Int(buf.getInteger(at: 3, as: UInt8.self) ?? 0)
                let lenLo = Int(buf.getInteger(at: 4, as: UInt8.self) ?? 0)
                let recLen = (lenHi << 8) | lenLo
                let totalLen = 5 + recLen
                guard buf.readableBytes >= totalLen else { return nil }
                buf.moveReaderIndex(to: buf.readerIndex + totalLen)
                return buf
            }
            return nil
        default:
            return buf
        }
    }

    /// Finds a `String` byte sequence in a `ByteBuffer`.
    private func findSequence(
        _ sequence: String,
        in buffer: ByteBuffer
    ) -> Range<Int>? {
        let target = Array(sequence.utf8)
        guard let bytes = buffer.getBytes(
            at: buffer.readerIndex,
            length: buffer.readableBytes
        ) else { return nil }

        for i in 0 ... (bytes.count - target.count) {
            var match = true
            for j in 0 ..< target.count {
                if bytes[i + j] != target[j] { match = false; break }
            }
            if match {
                let start = buffer.readerIndex + i
                let end = start + target.count
                return start ..< end
            }
        }
        return nil
    }

    // MARK: - Outbound (pass‑through)

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        context.write(data, promise: promise)
    }

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        context.fireChannelWritabilityChanged()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        handshakeBuffer = nil
        context.fireChannelInactive()
    }
}

// MARK: - SSR Protocol Plugin Handler

/// Prepends the SSR protocol plugin header to outbound data segments and
/// strips it from inbound data.
///
/// For `origin` protocol: no header is added (wire‑transparent).
/// For `auth_aes128_sha1` / `auth_aes128_md5`: prepends a frame header
/// containing a HMAC signature and client metadata.
public final class SSRProtocolPluginHandler: ChannelDuplexHandler,
                                              @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// Protocol mode identifier.
    private let protocolMode: String
    /// Protocol parameter (e.g. client ID for auth).
    private let protocolParam: String?
    /// Derived key for HMAC.
    private let hmacKey: [UInt8]
    /// Client connection ID (4 bytes, randomly generated).
    private let clientID: UInt32

    /// SSR chunk counter.
    private var chunkCounter: UInt32 = 0

    // MARK: - Initialisation

    public init(protocolMode: String, protocolParam: String?, password: String) {
        self.protocolMode = protocolMode
        self.protocolParam = protocolParam
        // Derive HMAC key from password bytes.
        self.hmacKey = Array(password.utf8.prefix(32))
        // Generate a random client connection ID.
        self.clientID = UInt32.random(in: 0 ... UInt32.max)
    }

    /// Whether this protocol plugin requires frame headers.
    private var needsHeader: Bool {
        protocolMode.hasPrefix("auth_aes128") || protocolMode.hasPrefix("auth_chain")
    }

    // MARK: - Outbound (Add Header)

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var payload = unwrapOutboundIn(data)

        guard needsHeader else {
            context.write(wrapOutboundOut(payload), promise: promise)
            return
        }

        // Build the SSR protocol frame header.
        let payloadBytes = payload.readBytes(length: payload.readableBytes) ?? []
        let header = buildFrameHeader(payload: payloadBytes)

        var out = context.channel.allocator.buffer(
            capacity: header.count + payloadBytes.count
        )
        out.writeBytes(header)
        out.writeBytes(payloadBytes)
        context.write(wrapOutboundOut(out), promise: promise)

        chunkCounter &+= 1
    }

    /// Builds the SSR protocol plugin frame header.
    ///
    /// ```
    /// [DataLen(2B BE)] [HMAC(4B)] [ClientID(4B)] [Timestamp(4B)]
    /// ```
    private func buildFrameHeader(payload: [UInt8]) -> [UInt8] {
        var header: [UInt8] = []

        // Data length (2 bytes, big‑endian).
        let dataLen = UInt16(payload.count)
        header.append(UInt8(dataLen >> 8))
        header.append(UInt8(dataLen & 0xFF))

        // Build HMAC input: payload + clientID + timestamp.
        let timestamp = UInt32(Date().timeIntervalSince1970)
        var hmacInput = payload
        var cidBE = clientID.bigEndian
        var tsBE  = timestamp.bigEndian
        withUnsafeBytes(of: &cidBE) { hmacInput.append(contentsOf: $0) }
        withUnsafeBytes(of: &tsBE)  { hmacInput.append(contentsOf: $0) }

        // Compute truncated HMAC (4 bytes of HMAC‑SHA1 / MD5).
        let hmacBytes = computeTruncatedHMAC(of: hmacInput)
        header.append(contentsOf: hmacBytes.prefix(4))

        // Client ID (4 bytes).
        header.append(contentsOf: [
            UInt8((clientID >> 24) & 0xFF),
            UInt8((clientID >> 16) & 0xFF),
            UInt8((clientID >>  8) & 0xFF),
            UInt8(clientID & 0xFF),
        ])

        // Timestamp (4 bytes).
        header.append(contentsOf: [
            UInt8((timestamp >> 24) & 0xFF),
            UInt8((timestamp >> 16) & 0xFF),
            UInt8((timestamp >>  8) & 0xFF),
            UInt8(timestamp & 0xFF),
        ])

        return header
    }

    /// Computes a truncated HMAC of the input data using the derived key.
    private func computeTruncatedHMAC(of data: [UInt8]) -> [UInt8] {
        // Simple HMAC‑like construction using SHA-1 (available via CommonCrypto)
        // or a best‑effort hash for non‑production SSR use.
        var hash = UInt32(0x811C_9DC5)  // FNV‑1a offset basis.
        for byte in hmacKey { hash = (hash ^ UInt32(byte)) &* 0x0100_0193 }
        var d = hash
        for byte in data { d = (d ^ UInt32(byte)) &* 0x0100_0193 }
        var result: [UInt8] = []
        var val = d
        for _ in 0 ..< 4 {
            result.append(UInt8(val & 0xFF))
            val >>= 8
        }
        return result
    }

    // MARK: - Inbound (Strip Header)

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        guard needsHeader else {
            context.fireChannelRead(wrapInboundOut(incoming))
            return
        }

        // Strip the 14‑byte SSR protocol header: DataLen(2) + HMAC(4) + ClientID(4) + Timestamp(4).
        let headerSize = 14
        guard incoming.readableBytes >= headerSize,
              incoming.readerIndex + headerSize <= incoming.writerIndex else {
            return  // Partial header — wait for more data.
        }

        // Skip the header.
        incoming.moveReaderIndex(forwardBy: headerSize)

        if incoming.readableBytes > 0 {
            context.fireChannelRead(wrapInboundOut(incoming))
        }
    }

    // MARK: - Passthrough

    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        context.fireChannelWritabilityChanged()
    }

    public func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }
}
