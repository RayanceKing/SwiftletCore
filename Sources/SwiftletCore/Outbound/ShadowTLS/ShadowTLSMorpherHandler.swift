//===----------------------------------------------------------------------===//
//
//  ShadowTLSMorpherHandler.swift
//  SwiftletCore — ShadowTLS‑v3 Dynamic TLS Hijacking Handler
//
//  ShadowTLS‑v3 defeats Deep Packet Inspection by initiating a genuine,
//  unbroken TLS 1.3 handshake with a real trusted domain (e.g. `icloud.com`)
//  and then dynamically hijacking the connection once the handshake
//  completes.  The DPI engine sees a legitimate TLS session; after the
//  handshake, the ShadowTLS server severs the relay and the remaining
//  traffic carries the actual proxy protocol (Shadowsocks, etc.).
//
//  v3 Challenge‑Response (HMAC‑SHA256)
//  -----------------------------------
//  To defeat active probing, the handler computes an 8‑byte time‑and‑key‑
//  locked challenge token over the ClientHello.random field and injects it
//  into the TLS Session ID.  The remote ShadowTLS server verifies this
//  token before relaying the handshake.  On the inbound side, the handler
//  tracks whether the server responded with a valid ServerHello (handshake
//  type 0x02), confirming the challenge was accepted.
//
//  Three‑Phase State Machine
//  -------------------------
//  ```
//  .sniffingClientHello ──[ClientHello detected + token injected]──► .transparentHandshakeRelay
//                                                                          │
//                                                            [Handshake complete + 0x17 seen]
//                                                                          │
//                                                                          ▼
//                                                                .shadowTunnelActivated
//  ```
//
//  Pipeline placement
//  ------------------
//  ```
//  [Proxy Protocol] → [NIOSSL] → ShadowTLSMorpherHandler → [TCP Socket]
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation
import CryptoKit

// MARK: - ShadowTLS State

/// The three phases of a ShadowTLS‑v3 connection.
public enum ShadowTLSState: UInt8, Sendable, Equatable, CustomStringConvertible {
    case sniffingClientHello       = 0
    case transparentHandshakeRelay = 1
    case shadowTunnelActivated     = 2
    case failed                    = 3

    public var description: String {
        switch self {
        case .sniffingClientHello:       return "SNIFFING_CLIENT_HELLO"
        case .transparentHandshakeRelay: return "TRANSPARENT_HANDSHAKE_RELAY"
        case .shadowTunnelActivated:     return "SHADOW_TUNNEL_ACTIVATED"
        case .failed:                    return "FAILED"
        }
    }
}

// MARK: - ShadowTLS Morpher Handler

public final class ShadowTLSMorpherHandler: ChannelDuplexHandler,
                                              RemovableChannelHandler,
                                              @unchecked Sendable {

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - State

    public private(set) var state: ShadowTLSState = .sniffingClientHello

    // MARK: - Handshake Tracking

    public private(set) var outboundHandshakeCount: Int = 0
    public private(set) var inboundHandshakeCount: Int  = 0
    public private(set) var seenOutboundCCS: Bool = false
    public private(set) var seenInboundCCS: Bool  = false
    public private(set) var bytesRelayed: UInt64 = 0

    // MARK: - SNI Configuration

    public let expectedSNI: String?
    public let overrideSNI: String?

    // MARK: - v3 Challenge‑Response

    /// The pre‑shared password for HMAC‑SHA256 challenge derivation.
    public let password: String?

    /// The 8‑byte challenge token injected into the ClientHello, derived
    /// from `HMAC<SHA256>(password, clientRandom).prefix(8)`.
    public private(set) var challengeToken: Data?

    /// Whether the server has responded with a valid ServerHello,
    /// confirming the challenge was accepted.
    public private(set) var challengeVerified: Bool = false

    // MARK: - Callbacks

    public var onActivated: (@Sendable () -> Void)?
    public var onError: (@Sendable (Error) -> Void)?

    // MARK: - Initialisation

    /// Creates a new ShadowTLS‑v3 handler.
    ///
    /// - Parameters:
    ///   - password: Pre‑shared key for v3 HMAC‑SHA256 challenge token
    ///     generation.  Pass `nil` to disable challenge injection (legacy
    ///     mode — only state tracking, no byte mutation).
    ///   - expectedSNI: If set, validates the ClientHello SNI.
    ///   - overrideSNI: If set, replaces the SNI in the ClientHello.
    public init(
        password: String? = nil,
        expectedSNI: String? = nil,
        overrideSNI: String? = nil
    ) {
        self.password = password
        self.expectedSNI = expectedSNI
        self.overrideSNI = overrideSNI
    }

    // MARK: - ChannelOutboundHandler (Write Path)

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var buffer = unwrapOutboundIn(data)
        guard buffer.readableBytes > 0 else {
            context.write(data, promise: promise)
            return
        }

        // ---- v3 Challenge Injection (sniffing phase only) ------------
        if state == .sniffingClientHello, password != nil {
            if let mutated = tryInjectV3Challenge(into: &buffer) {
                bytesRelayed &+= UInt64(mutated.readableBytes)
                context.write(wrapOutboundOut(mutated), promise: promise)

                // After successful injection, transition to relay.
                state = .transparentHandshakeRelay
                outboundHandshakeCount += 1
                return
            }
            // If injection fails (not a ClientHello, missing fields),
            // fall through to normal inspection.
        }

        // Normal inspection (non‑mutating peek).
        inspectOutbound(buffer: &buffer)

        bytesRelayed &+= UInt64(buffer.readableBytes)
        context.write(wrapOutboundOut(buffer), promise: promise)
    }

    // MARK: - ChannelInboundHandler (Read Path)

    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        var buffer = unwrapInboundIn(data)
        guard buffer.readableBytes > 0 else { return }

        // ---- Challenge Response Verification -------------------------
        if !challengeVerified, password != nil {
            verifyServerResponse(buffer: &buffer)
        }

        inspectInbound(buffer: &buffer)

        bytesRelayed &+= UInt64(buffer.readableBytes)
        context.fireChannelRead(wrapInboundOut(buffer))
    }

    // MARK: - Channel Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .failed
        onError?(error)
        context.fireErrorCaught(error)
    }

    // MARK: - v3 Challenge Injection

    /// Attempts to parse a ClientHello from `buffer`, extract the 32‑byte
    /// random, compute an HMAC‑SHA256 challenge token, and inject it into
    /// the Session ID field.
    ///
    /// - Parameter buffer: The outbound buffer (mutated in‑place on success).
    /// - Returns: The mutated buffer if injection succeeded, or `nil` if
    ///   the buffer does not contain a well‑formed ClientHello.
    private func tryInjectV3Challenge(
        into buffer: inout ByteBuffer
    ) -> ByteBuffer? {
        guard let pw = password, !pw.isEmpty else { return nil }

        let base = buffer.readerIndex
        let available = buffer.readableBytes

        // ---- Validate TLS Record header (5 bytes) --------------------
        guard available >= 5 else { return nil }
        guard let contentType: UInt8 = buffer.getInteger(at: base) else { return nil }
        guard contentType == TLSRecord.contentTypeHandshake else { return nil }

        guard let recordLen: UInt16 = buffer.getInteger(
            at: base + 3, endianness: .big, as: UInt16.self
        ) else { return nil }
        let totalRecord = 5 + Int(recordLen)
        guard available >= totalRecord else { return nil }

        // ---- Validate Handshake header inside record -----------------
        let hsOffset = base + 5
        guard available >= hsOffset + 4 else { return nil }
        guard let hsType: UInt8 = buffer.getInteger(at: hsOffset) else { return nil }
        guard hsType == 0x01 else { return nil } // ClientHello = 0x01

        // ---- Extract ClientHello.random (32 bytes at offset 11) ------
        let randomOffset = base + 11  // 5(record) + 1(type) + 3(len) + 2(version)
        guard available >= randomOffset + 32 else { return nil }
        guard let clientRandom = buffer.getBytes(
            at: randomOffset, length: 32
        ) else { return nil }

        // ---- Read Session ID Length (byte at offset 43) ---------------
        let sidLenOffset = base + 43
        guard available > sidLenOffset else { return nil }
        guard let sidLen: UInt8 = buffer.getInteger(at: sidLenOffset) else { return nil }

        // ---- Compute HMAC‑SHA256 challenge token (first 8 bytes) ------
        let token = Self.generateV3Challenge(
            password: pw, clientRandom: Data(clientRandom)
        )
        self.challengeToken = token

        // ---- Inject token into the raw buffer ------------------------
        guard let mutated = injectToken(
            token,
            sidLen: Int(sidLen),
            sidDataStart: sidLenOffset + 1,
            hsOffset: hsOffset,
            recordLenOffset: base + 3,
            into: &buffer
        ) else { return nil }

        return mutated
    }

    /// Overwrites the last 8 bytes of the Session ID with the challenge
    /// token.  If the Session ID is shorter than 8 bytes, it is extended
    /// (zero‑padded) and all downstream length fields are recalculated.
    private func injectToken(
        _ token: Data,
        sidLen: Int,
        sidDataStart: Int,
        hsOffset: Int,
        recordLenOffset: Int,
        into buffer: inout ByteBuffer
    ) -> ByteBuffer? {
        guard token.count == 8 else { return nil }

        if sidLen >= 8 {
            // ---- Simple case: overwrite last 8 bytes of Session ID ----
            let overwriteAt = sidDataStart + sidLen - 8
            let written = buffer.setBytes(token, at: overwriteAt)
            guard written == token.count else { return nil }

        } else {
            // ---- Extend case: insert zero‑padding to reach 8 bytes ----
            let padNeeded = 8 - sidLen

            // Read everything from the Session ID data onward.
            let tailStart = sidDataStart + sidLen
            let tailLen = buffer.readableBytes - (tailStart - buffer.readerIndex)
            guard buffer.getBytes(at: tailStart, length: tailLen) != nil
            else { return nil }

            // Update the Session ID length byte to 8.
            let sidLenOffset = sidDataStart - 1
            let w2 = buffer.setBytes([UInt8(8)], at: sidLenOffset)
            guard w2 == 1 else { return nil }

            // Write zero padding + token at the Session ID data start.
            // We overwrite the existing Session ID (sidLen bytes) with
            // 8 bytes: (8 - sidLen) zeros + the token.
            // But wait — the token is 8 bytes and we need sidLen bytes
            // of existing data to be replaced, then padNeeded extra bytes
            // inserted.  This requires shifting the tail.
            //
            // Strategy: read the entire record into Data, modify in‑place,
            // and write back.
            let recordStart = buffer.readerIndex
            let recordLen = buffer.readableBytes
            guard var rawBytes = buffer.getBytes(at: recordStart, length: recordLen)
            else { return nil }

            // Insert `padNeeded` zero bytes at `tailStart - recordStart`.
            let insertAt = tailStart - recordStart
            let zeros = [UInt8](repeating: 0, count: padNeeded)
            rawBytes.insert(contentsOf: zeros, at: insertAt)

            // Now overwrite the last 8 bytes of the (now 8‑byte) Session
            // ID with the token.
            let tokenOverwriteAt = insertAt + padNeeded
            for i in 0 ..< 8 {
                rawBytes[tokenOverwriteAt + i] = token[i]
            }

            // ---- Recalculate HandshakeLength -------------------------
            let hsLenOffset = hsOffset + 1 // after handshake type byte
            let oldHSLen = (UInt32(rawBytes[hsLenOffset]) << 16)
                         | (UInt32(rawBytes[hsLenOffset + 1]) << 8)
                         |  UInt32(rawBytes[hsLenOffset + 2])
            let newHSLen = oldHSLen + UInt32(padNeeded)
            rawBytes[hsLenOffset]     = UInt8((newHSLen >> 16) & 0xFF)
            rawBytes[hsLenOffset + 1] = UInt8((newHSLen >>  8) & 0xFF)
            rawBytes[hsLenOffset + 2] = UInt8( newHSLen        & 0xFF)

            // ---- Recalculate RecordLength ----------------------------
            let oldRecLen = (UInt16(rawBytes[recordLenOffset]) << 8)
                          |  UInt16(rawBytes[recordLenOffset + 1])
            let newRecLen = oldRecLen + UInt16(padNeeded)
            rawBytes[recordLenOffset]     = UInt8((newRecLen >> 8) & 0xFF)
            rawBytes[recordLenOffset + 1] = UInt8( newRecLen       & 0xFF)

            // Write the modified record back into a fresh buffer.
            buffer = ByteBuffer(bytes: rawBytes)
        }

        return buffer
    }

    // MARK: - Server Response Verification

    /// Scans the inbound buffer for a ServerHello (handshake type 0x02)
    /// and marks the challenge as verified when one is found.
    private func verifyServerResponse(buffer: inout ByteBuffer) {
        let base = buffer.readerIndex
        let available = buffer.readableBytes

        // Need at least a TLS record header (5) + handshake header (4).
        guard available >= 9 else { return }

        guard let contentType: UInt8 = buffer.getInteger(at: base),
              contentType == TLSRecord.contentTypeHandshake
        else { return }

        guard let recordLen: UInt16 = buffer.getInteger(
            at: base + 3, endianness: .big, as: UInt16.self
        ) else { return }

        let totalRecord = 5 + Int(recordLen)
        guard available >= totalRecord else { return }

        // Check the handshake type at base + 5.
        guard let hsType: UInt8 = buffer.getInteger(at: base + 5),
              hsType == 0x02   // ServerHello = 0x02
        else { return }

        challengeVerified = true
    }

    // MARK: - TLS Record Inspection

    private func inspectOutbound(buffer: inout ByteBuffer) {
        guard state == .sniffingClientHello
           || state == .transparentHandshakeRelay else { return }

        let baseIndex = buffer.readerIndex

        while buffer.readableBytes >= 5 {
            guard let contentType: UInt8 = buffer.getInteger(at: buffer.readerIndex)
            else { break }

            guard let recordLength: UInt16 = buffer.getInteger(
                at: buffer.readerIndex + 3,
                endianness: .big,
                as: UInt16.self
            ) else { break }

            let totalRecordSize = 5 + Int(recordLength)
            guard buffer.readableBytes >= totalRecordSize else { return }

            buffer.moveReaderIndex(forwardBy: totalRecordSize)
            processOutboundContentType(contentType)
        }

        buffer.moveReaderIndex(to: baseIndex)
    }

    private func inspectInbound(buffer: inout ByteBuffer) {
        guard state == .transparentHandshakeRelay else { return }

        let baseIndex = buffer.readerIndex

        while buffer.readableBytes >= 5 {
            guard let contentType: UInt8 = buffer.getInteger(at: buffer.readerIndex)
            else { break }

            guard let recordLength: UInt16 = buffer.getInteger(
                at: buffer.readerIndex + 3,
                endianness: .big,
                as: UInt16.self
            ) else { break }

            let totalRecordSize = 5 + Int(recordLength)
            guard buffer.readableBytes >= totalRecordSize else { return }

            buffer.moveReaderIndex(forwardBy: totalRecordSize)
            processInboundContentType(contentType)
        }

        buffer.moveReaderIndex(to: baseIndex)
    }

    // MARK: - State Transitions

    private func processOutboundContentType(_ contentType: UInt8) {
        switch state {
        case .sniffingClientHello:
            if contentType == TLSRecord.contentTypeHandshake {
                state = .transparentHandshakeRelay
                outboundHandshakeCount += 1
            }

        case .transparentHandshakeRelay:
            switch contentType {
            case TLSRecord.contentTypeHandshake:
                outboundHandshakeCount += 1
            case TLSRecord.contentTypeChangeCipherSpec:
                seenOutboundCCS = true
            case TLSRecord.contentTypeApplicationData:
                if isHandshakeComplete() { activate() }
            default: break
            }

        case .shadowTunnelActivated, .failed:
            break
        }
    }

    private func processInboundContentType(_ contentType: UInt8) {
        guard state == .transparentHandshakeRelay else { return }

        switch contentType {
        case TLSRecord.contentTypeHandshake:
            inboundHandshakeCount += 1
        case TLSRecord.contentTypeChangeCipherSpec:
            seenInboundCCS = true
        case TLSRecord.contentTypeApplicationData:
            if isHandshakeComplete() { activate() }
        default: break
        }
    }

    // MARK: - Handshake Completion

    private func isHandshakeComplete() -> Bool {
        guard seenInboundCCS && seenOutboundCCS else { return false }
        guard outboundHandshakeCount >= 2 && inboundHandshakeCount >= 1 else { return false }
        return true
    }

    // MARK: - Activation

    private func activate() {
        guard state == .transparentHandshakeRelay else { return }
        state = .shadowTunnelActivated
        onActivated?()
    }

    // MARK: - v3 Challenge Crypto

    /// Computes the ShadowTLS‑v3 HMAC‑SHA256 challenge token.
    ///
    /// The token is the first 8 bytes of `HMAC<SHA256>(password, clientRandom)`.
    ///
    /// - Parameters:
    ///   - password: The pre‑shared key string.
    ///   - clientRandom: The 32‑byte `ClientHello.random` field.
    /// - Returns: An 8‑byte challenge token.
    public static func generateV3Challenge(
        password: String,
        clientRandom: Data
    ) -> Data {
        let key = SymmetricKey(data: Data(password.utf8))
        let authCode = HMAC<SHA256>.authenticationCode(
            for: clientRandom, using: key
        )
        return Data(authCode.prefix(8))
    }

    // MARK: - ClientHello Random Extraction

    /// Extracts the 32‑byte `ClientHello.random` from a raw TLS record.
    ///
    /// The random is at offset 11 from the start of the TLS record:
    /// `5 (record header) + 1 (handshake type) + 3 (length) + 2 (version)`
    ///
    /// - Parameter tlsRecord: Raw TLS record bytes (must be a ClientHello).
    /// - Returns: 32 bytes of random data, or `nil` if the record is
    ///   too short or not a ClientHello.
    public static func extractClientRandom(
        from tlsRecord: Data
    ) -> Data? {
        // Validate Record Layer header.
        guard tlsRecord.count >= 5 else { return nil }
        guard tlsRecord[0] == TLSRecord.contentTypeHandshake else { return nil }

        // Validate Handshake header.
        guard tlsRecord.count >= 9 else { return nil }
        guard tlsRecord[5] == 0x01 else { return nil } // ClientHello

        // Random at offset 11, 32 bytes.
        guard tlsRecord.count >= 43 else { return nil }
        return tlsRecord.subdata(in: 11 ..< 43)
    }

    // MARK: - Diagnostic

    public var isActivated: Bool   { state == .shadowTunnelActivated }
    public var isHandshaking: Bool {
        state == .sniffingClientHello || state == .transparentHandshakeRelay
    }
}
