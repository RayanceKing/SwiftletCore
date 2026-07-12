//===----------------------------------------------------------------------===//
//
//  WireGuardOutboundHandler.swift
//  SwiftletCore — WireGuard Transport Data Pipeline Handler
//
//  A SwiftNIO `ChannelDuplexHandler` designed for `DatagramChannel`.  It
//  sits between the TUN‑layer bridge and the WireGuard UDP socket,
//  performing ChaCha20‑Poly1305 authenticated encryption on outbound inner
//  IP packets and authenticated decryption on inbound Type 4 datagrams.
//
//  Pipeline placement
//  ------------------
//  ```
//  [TUN2SocksBridge] → WireGuardOutboundHandler → DatagramChannel (UDP socket)
//  DatagramChannel   → WireGuardOutboundHandler → [TUN2SocksBridge]
//  ```
//
//  Transport Data Message (Type 4) — 16‑byte header
//  -------------------------------------------------
//  ```
//  [4]  Type           = 0x04_000000  (little‑endian UInt32)
//  [4]  Receiver Index
//  [8]  Counter        (little‑endian UInt64)
//  [N]  Encrypted      = ChaCha20‑Poly1305(inner IP packet)
//                         ciphertext ‖ 16‑byte AEAD tag
//  ```
//
//  AEAD Nonce (12 bytes)
//  ---------------------
//  ```
//  [0…7]   Counter as little‑endian UInt64
//  [8…11]  Zero padding (0x00000000)
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation
import CryptoKit

// MARK: - WireGuard Outbound Handler

/// A `ChannelDuplexHandler` that encrypts outbound inner‑tunnel IP packets
/// into WireGuard Type 4 Transport Data messages and decrypts inbound
/// Type 4 messages back into inner IP packets.
///
/// - Important: Not shareable — one instance per WireGuard peer session.
///   Session keys are derived from the `WireGuardNoiseMachine` after a
///   successful Handshake Initiation / Response exchange.
public final class WireGuardOutboundHandler: ChannelDuplexHandler,
                                               RemovableChannelHandler,
                                               @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn   = AddressedEnvelope<ByteBuffer>
    public typealias InboundOut  = AddressedEnvelope<ByteBuffer>
    public typealias OutboundIn  = AddressedEnvelope<ByteBuffer>
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    // MARK: - Session Keys

    /// Symmetric key for encrypting outbound transport data (Type 4).
    private let sendKey: SymmetricKey

    /// Symmetric key for decrypting inbound transport data (Type 4).
    private let receiveKey: SymmetricKey

    // MARK: - Peer State

    /// The remote peer's sender index, obtained from the Type 2 Handshake
    /// Response.  Used as the *Receiver Index* field in outbound Type 4
    /// messages so the peer knows this datagram belongs to this session.
    private let receiverIndex: UInt32

    /// Monotonically‑increasing 64‑bit counter for outbound packets.
    /// Each packet gets a unique, strictly‑greater value.
    /// Used for nonce derivation and replay defence.
    private var sendCounter: UInt64 = 0

    /// Highest counter value received from the peer on inbound packets.
    /// Used for basic replay detection.
    private var receiveCounter: UInt64 = 0

    /// The remote peer's UDP socket address (set on the first inbound
    /// datagram or provided at init).
    private var remoteAddress: SocketAddress?

    // MARK: - Initialisation

    /// Creates a new WireGuard transport data handler for a single peer
    /// session.
    ///
    /// - Parameters:
    ///   - sendKey: Symmetric key for outbound encryption (derived by the
    ///     Noise machine as the *sender's* transport key).
    ///   - receiveKey: Symmetric key for inbound decryption (derived by
    ///     the Noise machine as the *receiver's* transport key).
    ///   - receiverIndex: The peer's sender index from the Type 2 Response.
    ///   - remoteAddress: Optional pre‑known peer UDP address; can also
    ///     be learned from the first inbound datagram.
    public init(
        sendKey: SymmetricKey,
        receiveKey: SymmetricKey,
        receiverIndex: UInt32,
        remoteAddress: SocketAddress? = nil
    ) {
        self.sendKey = sendKey
        self.receiveKey = receiveKey
        self.receiverIndex = receiverIndex
        self.remoteAddress = remoteAddress
    }

    // MARK: - ChannelOutboundHandler (Write → Encrypt)

    /// Wraps an outbound inner IP packet into a Type 4 Transport Data
    /// message, encrypts it with ChaCha20‑Poly1305, and writes it to the
    /// UDP socket.
    ///
    /// The counter is incremented **atomically** within this call — the
    /// NIO event‑loop serialises all writes on the same channel, so no
    /// additional synchronisation is required.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var envelope = unwrapOutboundIn(data)
        guard let payload = envelope.data.readBytes(
            length: envelope.data.readableBytes
        ) else {
            promise?.succeed(())
            return
        }

        // Use the envelope's remote address.
        let destAddr = envelope.remoteAddress
        // Remember for subsequent writes that don't carry an address.
        self.remoteAddress = destAddr

        do {
            let encrypted = try WireGuardOutboundHandler.encryptPayload(
                plaintext: Data(payload),
                key: sendKey,
                counter: sendCounter
            )

            let datagram = WireGuardMessages.buildTransportData(
                receiverIndex: receiverIndex,
                counter: sendCounter,
                encryptedPayload: encrypted
            )

            sendCounter &+= 1

            var outBuffer = context.channel.allocator.buffer(
                capacity: datagram.count
            )
            outBuffer.writeBytes(datagram)

            let outEnvelope = AddressedEnvelope(
                remoteAddress: destAddr,
                data: outBuffer
            )
            context.write(wrapOutboundOut(outEnvelope), promise: promise)
        } catch {
            promise?.fail(error)
        }
    }

    // MARK: - ChannelInboundHandler (Read → Decrypt)

    /// Receives a UDP datagram from the remote WireGuard peer, validates
    /// the Type 4 header, decrypts the payload, and fires the resulting
    /// inner IP packet upstream.
    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        let envelope = unwrapInboundIn(data)
        var buffer   = envelope.data

        // Remember the peer's address for subsequent outbound writes.
        self.remoteAddress = envelope.remoteAddress

        guard let rawBytes = buffer.readBytes(length: buffer.readableBytes),
              rawBytes.count >= WireGuardMessages.transportHeaderSize else {
            return
        }

        let frameData = Data(rawBytes)

        guard let parsed = WireGuardMessages.parseTransportData(frameData) else {
            // Not a Type 4 message — could be a handshake or cookie reply.
            // Forward upstream for other handlers to process.
            context.fireChannelRead(data)
            return
        }

        // Validate that this is intended for our receiver index.
        // In a full implementation this would use a lookup table for
        // multi‑peer scenarios; for the single‑peer handler we verify
        // directly.
        guard parsed.receiverIndex == receiverIndex || receiverIndex == 0 else {
            // Drop packets not addressed to this session.
            return
        }

        // Basic replay protection: reject packets with a counter not
        // greater than the highest seen.
        // (Full WireGuard uses a sliding window; this is a minimal guard.)
        if parsed.counter <= receiveCounter && receiveCounter > 0 {
            return
        }
        receiveCounter = parsed.counter

        do {
            let plaintext = try WireGuardOutboundHandler.decryptPayload(
                encryptedPayload: parsed.encryptedPayload,
                key: receiveKey,
                counter: parsed.counter
            )

            var outBuffer = context.channel.allocator.buffer(
                capacity: plaintext.count
            )
            outBuffer.writeBytes(plaintext)

            let outEnvelope = AddressedEnvelope(
                remoteAddress: envelope.remoteAddress,
                data: outBuffer
            )
            context.fireChannelRead(wrapInboundOut(outEnvelope))
        } catch {
            // AEAD authentication failure — drop the packet silently.
            // The peer will retransmit if necessary.
        }
    }

    // MARK: - Channel Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        // Reset counter state — the session key is now invalid.
        sendCounter = 0
        receiveCounter = 0
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        context.fireErrorCaught(error)
    }

    // MARK: - Static Crypto Helpers

    /// AEAD authentication tag size — ChaCha20‑Poly1305 always uses
    /// 16 bytes (128 bits).
    private static let aeadTagSize = 16

    /// Serialises access to `ChaChaPoly` operations that use explicit
    /// nonces.  On some SDK versions concurrent `seal`/`open` calls
    /// with constructed nonces can produce a data race.  In production
    /// the handler runs on a single NIO event‑loop, so this lock is
    /// uncontended.
    private static let cryptoLock = NSLock()

    /// Encrypts `plaintext` using `ChaCha20‑Poly1305` with the given key
    /// and counter‑based nonce.
    ///
    /// - Parameters:
    ///   - plaintext: The inner IP packet to encrypt.
    ///   - key: The symmetric send key.
    ///   - counter: The 64‑bit counter for nonce derivation.
    /// - Returns: `ciphertext + 16‑byte AEAD tag`.
    /// - Throws: `CryptoKitError` if encryption fails.
    public static func encryptPayload(
        plaintext: Data,
        key: SymmetricKey,
        counter: UInt64
    ) throws -> Data {
        let nonce = makeNonce(counter: counter)
        return try Self.cryptoLock.withLock {
            let sealed = try ChaChaPoly.seal(plaintext, using: key, nonce: nonce)
            return sealed.ciphertext + sealed.tag
        }
    }

    /// Decrypts a Type 4 encrypted payload using `ChaCha20‑Poly1305`.
    ///
    /// - Parameters:
    ///   - encryptedPayload: `ciphertext + 16‑byte AEAD tag` from the
    ///     WireGuard transport data message.
    ///   - key: The symmetric receive key.
    ///   - counter: The counter extracted from the Type 4 header.
    /// - Returns: The decrypted inner IP packet.
    /// - Throws: `CryptoKitError` if the AEAD tag fails to verify.
    public static func decryptPayload(
        encryptedPayload: Data,
        key: SymmetricKey,
        counter: UInt64
    ) throws -> Data {
        guard encryptedPayload.count >= Self.aeadTagSize else {
            throw CryptoKitError.authenticationFailure
        }

        let tagOffset = encryptedPayload.count - Self.aeadTagSize
        let ciphertext = encryptedPayload.prefix(tagOffset)
        let tag        = encryptedPayload.suffix(Self.aeadTagSize)

        let nonce = makeNonce(counter: counter)
        return try Self.cryptoLock.withLock {
            let sealedBox = try ChaChaPoly.SealedBox(
                nonce: nonce,
                ciphertext: ciphertext,
                tag: tag
            )
            return try ChaChaPoly.open(sealedBox, using: key)
        }
    }

    // MARK: - Nonce Construction

    /// Builds the 12‑byte AEAD nonce from a 64‑bit counter per the
    /// WireGuard specification:
    ///
    /// ```
    /// [0…7]   Counter as little‑endian UInt64
    /// [8…11]  Zero padding
    /// ```
    ///
    /// Creates a random nonce via `ChaChaPoly.Nonce()` then overwrites
    /// its bytes to avoid potential issues with `Nonce.init(data:)` on
    /// certain SDK versions.
    public static func makeNonce(counter: UInt64) -> ChaChaPoly.Nonce {
        var nonce = ChaChaPoly.Nonce()
        let counterLE = counter.littleEndian
        withUnsafeMutableBytes(of: &nonce) { ptr in
            ptr.storeBytes(of: counterLE, as: UInt64.self)    // bytes 0…7
            ptr.storeBytes(of: UInt32(0), toByteOffset: 8, as: UInt32.self) // bytes 8…11
        }
        return nonce
    }

    // MARK: - Diagnostic Accessors

    /// The current outbound counter value (for testing).
    public var currentSendCounter: UInt64 { sendCounter }

    /// The highest inbound counter seen (for testing).
    public var currentReceiveCounter: UInt64 { receiveCounter }
}

// MARK: - Errors

/// Errors thrown by the WireGuard outbound handler.
public enum WireGuardHandlerError: Error, Sendable, Equatable {
    /// No remote peer address is known — a destination must be provided
    /// on the first write or set at init.
    case noRemoteAddress
}
