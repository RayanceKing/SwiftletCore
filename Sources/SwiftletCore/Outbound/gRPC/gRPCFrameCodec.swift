//===----------------------------------------------------------------------===//
//
//  gRPCFrameCodec.swift
//  SwiftletCore — gRPC Stream Frame Marshalling Codec
//
//  Implements the standard gRPC 5‑byte framing protocol (compression flag +
//  4‑byte big‑endian length) as a pair of composable SwiftNIO
//  `ChannelDuplexHandler` components suitable for insertion into an HTTP/2
//  stream channel pipeline.
//
//  Wire Format
//  -----------
//  ```
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |  Compressed   │                 Length (4)                    │
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  │                    Payload (variable)                        …
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  ```
//
//  - Byte 0: Compression flag (0x00 = uncompressed, 0x01 = gzip).
//  - Bytes 1–4: 32‑bit unsigned big‑endian integer — payload length.
//  - Remaining: Payload of exactly `Length` bytes.
//
//  Thread Safety
//  -------------
//  Both handlers are `@unchecked Sendable` because they carry mutable
//  `ByteBuffer` accumulator state accessed exclusively on the channel's
//  event loop (serial executor).  No locks are needed.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Constants

/// Standard gRPC frame header size: 1 byte compression flag + 4 bytes length.
internal let gRPCPrefixLength = 5

/// Compression flag value for uncompressed payloads.
internal let gRPCUncompressed: UInt8 = 0x00

// MARK: - gRPC Frame Encoder

/// Outbound channel handler that wraps raw proxy payload bytes in a
/// standard gRPC data frame.
///
/// ```
/// [Inbound]  raw payload bytes
///     ↓
/// [Encoder]  prepends 5‑byte header (0x00 + big‑endian length)
///     ↓
/// [Outbound] gRPC frame → HTTP/2 DATA frame
/// ```
///
/// The encoder is stateless — it processes each `ByteBuffer` write
/// independently and prepends the 5‑byte framing header.
public final class gRPCFrameEncoder: ChannelOutboundHandler,
                                     @unchecked Sendable {

    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    /// Compression flag to write in every frame header.
    /// `0x00` for uncompressed (default).  Set to `0x01` for gzip.
    public let compressionFlag: UInt8

    /// Creates a new gRPC frame encoder.
    ///
    /// - Parameter compressionFlag: Compression flag byte (default `0x00`).
    public init(compressionFlag: UInt8 = gRPCUncompressed) {
        self.compressionFlag = compressionFlag
    }

    /// Wraps the outgoing `ByteBuffer` payload in a gRPC frame by
    /// prepending the 5‑byte header.
    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        let payload = unwrapOutboundIn(data)
        let payloadLength = payload.readableBytes

        // Allocate a buffer large enough for the header + payload.
        var header = context.channel.allocator.buffer(capacity: gRPCPrefixLength + payloadLength)

        // Byte 0: Compression flag.
        header.writeInteger(compressionFlag, endianness: .big, as: UInt8.self)

        // Bytes 1–4: Payload length as 32‑bit big‑endian.
        header.writeInteger(UInt32(payloadLength), endianness: .big, as: UInt32.self)

        // Append the payload bytes.
        var payloadCopy = payload
        header.writeBuffer(&payloadCopy)

        context.write(wrapOutboundOut(header), promise: promise)
    }
}

// MARK: - gRPC Frame Decoder

/// Inbound channel handler that accumulates bytes, peeks the 5‑byte gRPC
/// header, extracts the payload length, waits for the complete chunk, and
/// fires the inner payload (with the 5‑byte header stripped) up the
/// pipeline.
///
/// ```
/// [Inbound]  TCP bytes (possibly fragmented)
///     ↓
/// [Decoder]  accumulates → peeks 5‑byte header → extracts length
///     ↓
/// [Decoder]  waits for `length` payload bytes → strips header
///     ↓
/// [Inbound]  raw payload bytes (zero‑copy where possible)
/// ```
///
/// The decoder maintains an accumulator `ByteBuffer` across multiple
/// `channelRead` calls to handle TCP segmentation.
public final class gRPCFrameDecoder: ChannelInboundHandler,
                                     @unchecked Sendable {

    public typealias InboundIn  = ByteBuffer
    public typealias InboundOut = ByteBuffer

    /// Accumulator buffer for partial frame data.
    private var accumulator: ByteBuffer?

    /// The length of the current frame's payload once the header has been
    /// fully read.  `nil` while reading the header.
    private var expectedPayloadLength: Int?

    // MARK: - Initialisation

    public init() {}

    // MARK: - ChannelInboundHandler

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var incoming = unwrapInboundIn(data)

        // Append to the accumulator if we already have buffered data.
        if var acc = accumulator {
            acc.writeBuffer(&incoming)
            accumulator = acc
        } else {
            accumulator = incoming
        }

        // Process as many complete frames as are buffered.
        processAccumulator(context: context)
    }

    /// Attempts to extract complete gRPC frames from the accumulator,
    /// firing each payload up the pipeline.
    private func processAccumulator(context: ChannelHandlerContext) {
        guard var acc = accumulator else { return }

        while true {
            // ---- Step 1: Read the 5‑byte header ----------------------------
            if expectedPayloadLength == nil {
                guard acc.readableBytes >= gRPCPrefixLength else {
                    // Not enough data for the header — wait for more.
                    accumulator = acc
                    return
                }

                // Read compression flag (byte 0).
                let _ = acc.readInteger(endianness: .big, as: UInt8.self)

                // Read payload length (bytes 1–4).
                guard let length = acc.readInteger(endianness: .big, as: UInt32.self) else {
                    // Should not happen — we already checked readableBytes.
                    accumulator = acc
                    return
                }
                expectedPayloadLength = Int(length)
            }

            // ---- Step 2: Wait for the complete payload ---------------------
            guard let needed = expectedPayloadLength else {
                accumulator = acc
                return
            }

            guard acc.readableBytes >= needed else {
                // Still waiting for payload bytes.
                accumulator = acc
                return
            }

            // ---- Step 3: Extract the payload (strip header) ----------------
            guard let payload = acc.readSlice(length: needed) else {
                // Should not happen — we already checked readableBytes.
                expectedPayloadLength = nil
                accumulator = acc
                return
            }

            // Reset for the next frame.
            expectedPayloadLength = nil

            // Fire the unwrapped payload up the pipeline.
            context.fireChannelRead(wrapOutboundOut(payload))

            // Continue the loop to check for another complete frame.
        }
    }

    /// Flush any partial frame data on channel close.
    public func channelInactive(context: ChannelHandlerContext) {
        // If we have a partial frame, discard it — the gRPC stream is dead.
        accumulator = nil
        expectedPayloadLength = nil
        context.fireChannelInactive()
    }
}

// MARK: - Convenience Factory

extension ChannelPipeline {

    /// Adds the gRPC frame encoder and decoder to the pipeline, with the
    /// encoder outbound and decoder inbound.
    ///
    /// - Parameters:
    ///   - encoder: The frame encoder (default: uncompressed).
    ///   - decoder: The frame decoder.
    ///   - position: Pipeline position (default: `.last`).
    /// - Returns: An `EventLoopFuture` that succeeds when both handlers
    ///   have been added.
    public func addGRPCFrameCodec(
        encoder: gRPCFrameEncoder = gRPCFrameEncoder(),
        decoder: gRPCFrameDecoder = gRPCFrameDecoder(),
        position: ChannelPipeline.Position = .last
    ) -> EventLoopFuture<Void> {
        addHandler(decoder, name: "gRPCFrameDecoder", position: position)
            .flatMap {
                self.addHandler(encoder, name: "gRPCFrameEncoder", position: position)
            }
    }
}
