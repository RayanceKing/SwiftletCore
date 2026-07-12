//===----------------------------------------------------------------------===//
//
//  Hysteria2ClientHandler.swift
//  SwiftletCore — Hysteria 2 UDP Datagram Pipeline Handler
//
//  A SwiftNIO `ChannelInboundHandler` designed for `DatagramChannel`.
//  It wraps outbound data into Hysteria 2 data frames and unwraps
//  inbound frames back into raw payload, integrating with the
//  `UdpAssociationManager` for session lifecycle tracking.
//
//  Pipeline placement
//  ------------------
//  ```
//  [TUN2SocksBridge] → Hysteria2ClientHandler → DatagramChannel (UDP socket)
//  DatagramChannel   → Hysteria2ClientHandler → [TUN2SocksBridge]
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Handler

/// Wraps / unwraps Hysteria 2 frames on a `DatagramChannel`.
///
/// - Important: Not shareable — one instance per UDP channel.
public final class Hysteria2ClientHandler: ChannelInboundHandler,
                                            RemovableChannelHandler,
                                            @unchecked Sendable {

    public typealias InboundIn  = AddressedEnvelope<ByteBuffer>
    public typealias InboundOut = AddressedEnvelope<ByteBuffer>
    public typealias OutboundOut = AddressedEnvelope<ByteBuffer>

    // MARK: - Configuration

    /// Session identifier for this connection.
    private let sessionID: UInt16

    /// Whether to apply padding obfuscation to outbound datagrams.
    public var obfuscationEnabled: Bool = true

    /// Maximum random padding bytes per datagram.
    public var maxObfuscationPadding: Int = 64

    /// The remote address this handler sends to.
    private var remoteAddress: SocketAddress?

    // MARK: - Initialisation

    /// - Parameter sessionID: The Hysteria 2 session identifier.
    public init(sessionID: UInt16) {
        self.sessionID = sessionID
    }

    // MARK: - ChannelInboundHandler (Reads from UDP socket)

    /// Receives a UDP datagram from the remote Hysteria 2 server.
    /// Parses the Hysteria 2 frame and fires the extracted payload
    /// upstream.
    public func channelRead(
        context: ChannelHandlerContext,
        data: NIOAny
    ) {
        let envelope = unwrapInboundIn(data)
        var buffer   = envelope.data
        self.remoteAddress = envelope.remoteAddress

        guard let rawBytes = buffer.readBytes(length: buffer.readableBytes) else {
            return
        }

        let frameData = Data(rawBytes)

        do {
            let frame = try Hysteria2FrameParser.parse(frameData)
            switch frame {
            case .tcpData(_, let payload):
                var outBuffer = context.channel.allocator.buffer(
                    capacity: payload.count
                )
                outBuffer.writeBytes(payload)
                let outEnvelope = AddressedEnvelope(
                    remoteAddress: envelope.remoteAddress,
                    data: outBuffer
                )
                context.fireChannelRead(wrapInboundOut(outEnvelope))

            case .udpData(_, let payload):
                var outBuffer = context.channel.allocator.buffer(
                    capacity: payload.count
                )
                outBuffer.writeBytes(payload)
                let outEnvelope = AddressedEnvelope(
                    remoteAddress: envelope.remoteAddress,
                    data: outBuffer
                )
                context.fireChannelRead(wrapInboundOut(outEnvelope))

            case .auth, .ping:
                // Control frames are handled internally.
                break
            }
        } catch {
            // Malformed frame — drop silently; the peer will retransmit.
            _ = error
        }
    }

    // MARK: - ChannelOutboundHandler (Writes to UDP socket)

    /// Wraps outbound payload bytes into a Hysteria 2 TCP data frame
    /// and sends them to the remote address as a UDP datagram.
//    public func write(
//        context: ChannelHandlerContext,
//        data: NIOAny,
//        promise: EventLoopPromise<Void>?
//    ) {
//        var buffer = unwrapOutboundIn(data)
//        guard let payload = buffer.readBytes(length: buffer.readableBytes) else {
//            promise?.succeed(())
//            return
//        }
//
//        let frame = Hysteria2Frame.tcpData(
//            streamID: sessionID,
//            payload: Data(payload)
//        )
//        var frameData = Hysteria2FrameBuilder.build(frame)
//
//        // Apply padding obfuscation.
//        if obfuscationEnabled {
//            var padBuffer = ByteBuffer(bytes: frameData)
//            Hysteria2Obfuscator.obfuscatePayload(
//                &padBuffer,
//                maxPadding: maxObfuscationPadding
//            )
//            if let padded = padBuffer.readBytes(length: padBuffer.readableBytes) {
//                frameData = Data(padded)
//            }
//        }
//
//        guard let remoteAddr = remoteAddress else {
//            promise?.fail(Hysteria2Error.noRemoteAddress)
//            return
//        }
//
//        var outBuffer = context.channel.allocator.buffer(
//            capacity: frameData.count
//        )
//        outBuffer.writeBytes(frameData)
//        let envelope = AddressedEnvelope(
//            remoteAddress: remoteAddr,
//            data: outBuffer
//        )
//        context.write(wrapOutboundOut(envelope), promise: promise)
//    }

    // MARK: - Convenience: Build a framed datagram

    /// Builds a Hysteria 2 TCP data frame as a `ByteBuffer` ready for
    /// sending via `context.write`.
    public func buildFrame(
        allocator: ByteBufferAllocator,
        payload: Data,
        frameType: Hysteria2FrameType = .tcpData
    ) -> ByteBuffer {
        let frame: Hysteria2Frame = switch frameType {
        case .tcpData:
            .tcpData(streamID: sessionID, payload: payload)
        case .udpData:
            .udpData(sessionID: sessionID, payload: payload)
        default:
            .tcpData(streamID: sessionID, payload: payload)
        }

        var frameData = Hysteria2FrameBuilder.build(frame)

        if obfuscationEnabled {
            var padBuffer = ByteBuffer(bytes: frameData)
            Hysteria2Obfuscator.obfuscatePayload(
                &padBuffer,
                maxPadding: maxObfuscationPadding
            )
            if let padded = padBuffer.readBytes(length: padBuffer.readableBytes) {
                frameData = Data(padded)
            }
        }

        var buffer = allocator.buffer(capacity: frameData.count)
        buffer.writeBytes(frameData)
        return buffer
    }

    /// Builds an auth frame for the initial handshake.
    public func buildAuthFrame(
        allocator: ByteBufferAllocator,
        secret: Data
    ) -> ByteBuffer {
        let frame = Hysteria2Frame.auth(secret: secret)
        let frameData = Hysteria2FrameBuilder.build(frame)
        var buffer = allocator.buffer(capacity: frameData.count)
        buffer.writeBytes(frameData)
        return buffer
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        context.fireChannelInactive()
    }
}

// MARK: - Errors

public enum Hysteria2Error: Error, Sendable, Equatable {
    case noRemoteAddress
}
