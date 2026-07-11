//===----------------------------------------------------------------------===//
//
//  VLESSWebSocketHandler.swift
//  SwiftletCore — VLESS over WebSocket Binary Frame Transformer
//
//  A SwiftNIO `ChannelDuplexHandler` that wraps outbound raw bytes into
//  RFC 6455 WebSocket binary frames (masked, client→server) and unwraps
//  inbound WebSocket frames back into raw payload bytes.
//
//  Pipeline placement
//  ------------------
//  ```
//  [VLESSOutboundHandler] → VLESSWebSocketHandler → [raw TCP]
//  [raw TCP] → VLESSWebSocketHandler → [VLESSOutboundHandler]
//  ```
//
//  Frame format (client‑to‑server, per RFC 6455 §5)
//  -------------------------------------------------
//  ```
//  [1]  FIN=1, Opcode=0x2 (binary)     → 0x82
//  [1]  MASK=1, PayloadLen (7 bits)    → 0x80 | len
//  [0|2|8] Extended payload length (if len ≥ 126)
//  [4]  Masking‑key (random)
//  [n]  Masked payload
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - WebSocket Handler

/// Wraps / unwraps WebSocket binary frames so that VLESS traffic can
/// traverse CDN and reverse‑proxy layers that speak WebSocket.
///
/// - Important: Not shareable — one instance per channel.
public final class VLESSWebSocketHandler: ChannelDuplexHandler,
                                           RemovableChannelHandler,
                                           @unchecked Sendable {

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - WebSocket Constants

    private enum WS {
        static let finBit: UInt8        = 0x80
        static let opcodeBinary: UInt8  = 0x02
        static let maskBit: UInt8       = 0x80
        static let payloadLenMask: UInt8 = 0x7F
        static let extendedLen16: UInt8  = 126
        static let extendedLen64: UInt8  = 127
    }

    // MARK: - Inbound Reassembly

    /// Accumulates raw bytes until a complete WebSocket frame is available.
    private var inboundBuffer = Data()

    /// Tracks the expected total frame size once the header is parsed.
    private var expectedFrameSize: Int? = nil

    /// Whether the current frame being decoded has the MASK bit set.
    private var currentFrameMasked: Bool = false

    // MARK: - Initialisation

    public init() {}

    // MARK: - Outbound (Write) — Encode to WebSocket Frame

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var buffer = unwrapOutboundIn(data)
        guard let payload = buffer.readBytes(length: buffer.readableBytes) else {
            context.write(data, promise: promise)
            return
        }

        let frame = encodeBinaryFrame(payload: payload)
        var out = context.channel.allocator.buffer(capacity: frame.count)
        out.writeBytes(frame)
        context.write(wrapOutboundOut(out), promise: promise)
    }

    /// Encodes raw bytes into a masked WebSocket binary frame.
    private func encodeBinaryFrame(payload: [UInt8]) -> [UInt8] {
        let payloadLen = payload.count
        var frame: [UInt8] = []

        // ---- Byte 0: FIN + Binary opcode ---------------------------------
        frame.append(WS.finBit | WS.opcodeBinary)

        // ---- Byte 1 + extended length -----------------------------------
        let maskByte = WS.maskBit
        if payloadLen < 126 {
            frame.append(maskByte | UInt8(payloadLen))
        } else if payloadLen < 65536 {
            frame.append(maskByte | WS.extendedLen16)
            frame.append(UInt8((payloadLen >> 8) & 0xFF))
            frame.append(UInt8( payloadLen       & 0xFF))
        } else {
            frame.append(maskByte | WS.extendedLen64)
            // 8‑byte extended length (big‑endian)
            for shift in stride(from: 56, through: 0, by: -8) {
                frame.append(UInt8((payloadLen >> shift) & 0xFF))
            }
        }

        // ---- Masking key (4 random bytes) --------------------------------
        let maskKey: [UInt8] = [
            UInt8.random(in: 0 ... 255),
            UInt8.random(in: 0 ... 255),
            UInt8.random(in: 0 ... 255),
            UInt8.random(in: 0 ... 255),
        ]
        frame.append(contentsOf: maskKey)

        // ---- Masked payload ----------------------------------------------
        for (i, byte) in payload.enumerated() {
            frame.append(byte ^ maskKey[i % 4])
        }

        return frame
    }

    // MARK: - Inbound (Read) — Decode from WebSocket Frame

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        var buffer = unwrapInboundIn(data)
        guard let bytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }
        inboundBuffer.append(contentsOf: bytes)

        // Process as many complete frames as possible.
        while inboundBuffer.count > 0 {
            guard let (payload, consumed) = tryDecodeOneFrame() else {
                break // incomplete frame — wait for more data
            }
            inboundBuffer.removeFirst(consumed)

            if !payload.isEmpty {
                var out = context.channel.allocator.buffer(
                    capacity: payload.count
                )
                out.writeBytes(payload)
                context.fireChannelRead(wrapInboundOut(out))
            }
        }
    }

    /// Attempts to decode a single WebSocket binary frame from the
    /// accumulation buffer.  Returns `nil` if the frame is incomplete.
    private func tryDecodeOneFrame() -> (payload: [UInt8], consumed: Int)? {
        let data = inboundBuffer
        var offset = 0
        let count = data.count

        // ---- Need at least 2‑byte header ---------------------------------
        guard count >= 2 else { return nil }

        let byte0 = data[offset]; offset += 1
        let byte1 = data[offset]; offset += 1

        // Validate: FIN must be set, opcode must be Binary.
        let fin    = (byte0 & 0x80) != 0
        let opcode = byte0 & 0x0F
        guard fin, opcode == 0x02 else {
            // Skip this malformed frame by discarding header bytes so we
            // don't loop forever.  Return empty payload so the caller
            // removes the consumed bytes.
            return ([], 2)
        }

        let isMasked   = (byte1 & 0x80) != 0
        var payloadLen = Int(byte1 & 0x7F)

        // ---- Extended payload length -------------------------------------
        if payloadLen == 126 {
            guard count >= offset + 2 else { return nil }
            payloadLen = (Int(data[offset]) << 8) | Int(data[offset + 1])
            offset += 2
        } else if payloadLen == 127 {
            guard count >= offset + 8 else { return nil }
            var len: UInt64 = 0
            for i in 0 ..< 8 {
                len = (len << 8) | UInt64(data[offset + i])
            }
            payloadLen = Int(len)
            offset += 8
        }

        // ---- Masking key ------------------------------------------------
        let maskOffset = offset
        if isMasked {
            guard count >= offset + 4 else { return nil }
            offset += 4
        }

        // ---- Payload ----------------------------------------------------
        guard count >= offset + payloadLen else { return nil }

        let payloadStart = offset
        var payload = Array(data[payloadStart ..< payloadStart + payloadLen])

        // Unmask if needed.
        if isMasked {
            let maskKey = Array(data[maskOffset ..< maskOffset + 4])
            for i in 0 ..< payloadLen {
                payload[i] ^= maskKey[i % 4]
            }
        }

        let consumed = payloadStart + payloadLen
        return (payload, consumed)
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        inboundBuffer.removeAll()
        expectedFrameSize = nil
        context.fireChannelInactive()
    }
}
