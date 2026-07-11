//===----------------------------------------------------------------------===//
//
//  ShadowsocksOutboundHandler.swift
//  SwiftletCore — Shadowsocks Outbound Channel Handler
//
//  A SwiftNIO `ChannelDuplexHandler` that sits in the outbound pipeline
//  between the `RoutingEngine` and the remote SOCKS5 / Shadowsocks server.
//
//  Outbound (write) path
//  ---------------------
//  Plaintext bytes written by the application are split into AEAD chunks
//  (max 0x3FFF bytes each), encrypted, and flushed to the wire.  On the
//  very first write the per‑connection salt is prepended.
//
//  Inbound (read) path
//  -------------------
//  Encrypted chunks arriving from the remote peer are reassembled,
//  decrypted, and the resulting plaintext is fired into the pipeline.
//  Partial reads are handled transparently via an internal accumulation
//  buffer and a state machine (`waitingForSalt` → `waitingForChunk`).
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Outbound Handler

/// A `ChannelDuplexHandler` that performs Shadowsocks AEAD encryption on
/// outbound data and decryption on inbound data.
///
/// - Important: This handler is **not** shareable — a fresh instance must
///   be created for each outbound connection.
public final class ShadowsocksOutboundHandler: ChannelDuplexHandler,
                                                RemovableChannelHandler,
                                                @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer
    public typealias OutboundIn = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Cipher & Session

    /// The cipher engine used to create / restore sessions.
    private let cipher: ShadowsocksCipher

    /// The active session (created on first write or received salt).
    private var session: ShadowsocksSession?

    /// The salt bytes to prepend on the first outbound write.
    private var pendingSalt: Data?

    // MARK: - Inbound Reassembly State

    private enum InboundState {
        case waitingForSalt
        case waitingForChunk
    }

    private var inboundState: InboundState = .waitingForSalt
    private var inboundBuffer = Data()

    // MARK: - Initialisation

    /// - Parameter cipher: A pre‑configured `ShadowsocksCipher` with the
    ///   master key and desired AEAD algorithm.
    public init(cipher: ShadowsocksCipher) {
        self.cipher = cipher
    }

    // MARK: - Channel Lifecycle

    public func channelActive(context: ChannelHandlerContext) {
        // Generate a fresh session and stage the salt for the first write.
        let (salt, sess) = cipher.newSession()
        self.session = sess
        self.pendingSalt = salt
        context.fireChannelActive()
    }

    // MARK: - Outbound (Write) Path — Encryption

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        guard let session = session else {
            promise?.fail(CipherError.invalidSalt(0))
            return
        }

        var plaintext = unwrapOutboundIn(data)
        guard plaintext.readableBytes > 0 else {
            context.write(data, promise: promise)
            return
        }

        // Read all bytes from the ByteBuffer.
        let bytes = plaintext.readBytes(length: plaintext.readableBytes) ?? []
        let plainData = Data(bytes)

        // ---- Split into chunks (max 0x3FFF bytes each) ------------------
        let maxChunk = cipher.cipherType.maxChunkSize
        var offset = 0
        var allCiphertext = Data()

        while offset < plainData.count {
            let chunkSize = min(maxChunk, plainData.count - offset)
            let chunk = plainData.subdata(in: offset ..< offset + chunkSize)
            offset += chunkSize

            do {
                let encrypted = try session.encryptChunk(plaintext: chunk)
                allCiphertext.append(encrypted)
            } catch {
                promise?.fail(error)
                return
            }
        }

        // ---- Prepend salt on the very first write ------------------------
        if let salt = pendingSalt {
            var salted = Data()
            salted.append(salt)
            salted.append(allCiphertext)
            allCiphertext = salted
            pendingSalt = nil
        }

        // ---- Write encrypted bytes to the wire ---------------------------
        var outBuffer = context.channel.allocator.buffer(capacity: allCiphertext.count)
        outBuffer.writeBytes(allCiphertext)
        context.write(wrapOutboundOut(outBuffer), promise: promise)
    }

    // MARK: - Inbound (Read) Path — Decryption

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        inboundBuffer.append(contentsOf: bytes)

        // Process all complete chunks in the buffer.
        processInboundBuffer(context: context)
    }

    /// Drains the internal `inboundBuffer`, parsing salt and decrypting
    /// complete AEAD chunks.  Any incomplete trailing data is left in the
    /// buffer for the next `channelRead` call.
    private func processInboundBuffer(context: ChannelHandlerContext) {
        let tagLen = cipher.cipherType.tagLength
        let saltLen = cipher.cipherType.saltLength

        while inboundBuffer.count > 0 {
            switch inboundState {
            case .waitingForSalt:
                guard inboundBuffer.count >= saltLen else { return }

                let salt = Data(inboundBuffer.prefix(saltLen))
                inboundBuffer.removeFirst(saltLen)
                self.session = cipher.session(from: salt)
                inboundState = .waitingForChunk
                // Fall through to process the first chunk.

            case .waitingForChunk:
                guard let session = session else { return }

                // Each chunk: [encrypted data] + [tag]
                // We need at least tagLen bytes to attempt decryption, but
                // we cannot know the chunk size without decrypting the first
                // 2 + tagLen bytes (length prefix).
                //
                // Strategy: try to decrypt the chunk. If it fails due to
                // insufficient data, wait for more bytes.

                // Minimum bytes for a valid chunk: 2 (length) + tagLen
                let minChunkSize = 2 + tagLen
                guard inboundBuffer.count >= minChunkSize else { return }

                // Copy the buffer for decryption attempt.
                let available = Data(inboundBuffer)

                do {
                    let plaintext = try session.decryptChunk(ciphertext: available)

                    // Success — remove consumed bytes from buffer.
                    // We don't know exactly how many bytes were consumed;
                    // the ciphertext length is: 2 + plaintext.count + tagLen
                    let consumed = 2 + plaintext.count + tagLen
                    inboundBuffer.removeFirst(min(consumed, inboundBuffer.count))

                    // Emit the plaintext.
                    var outBuffer = context.channel.allocator.buffer(
                        capacity: plaintext.count
                    )
                    outBuffer.writeBytes(plaintext)
                    context.fireChannelRead(wrapInboundOut(outBuffer))

                } catch CipherError.invalidChunkLength {
                    // Not enough data yet — wait for more.
                    return
                } catch {
                    // Irrecoverable error — tear down the connection.
                    context.fireErrorCaught(error)
                    return
                }
            }
        }
    }

    // MARK: - Lifecycle Cleanup

    public func channelInactive(context: ChannelHandlerContext) {
        inboundBuffer.removeAll()
        pendingSalt = nil
        context.fireChannelInactive()
    }
}
