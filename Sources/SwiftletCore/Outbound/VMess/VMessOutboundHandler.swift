//===----------------------------------------------------------------------===//
//
//  VMessOutboundHandler.swift
//  SwiftletCore — VMess Protocol Outbound Handler
//
//  A SwiftNIO `ChannelDuplexHandler` that sends the encrypted VMess v1
//  authentication header as the first bytes of the TCP connection and
//  then transitions into transparent zero‑copy bidirectional relay.
//
//  Pipeline placement
//  ------------------
//  ```
//  [App writes] → VMessOutboundHandler → [raw TCP]
//  [raw TCP]    → VMessOutboundHandler → [App reads]
//  ```
//
//  State Machine
//  -------------
//  ```
//  channelActive → .vmessHeaderSent ──► .rawStreaming
//  ```
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Handler

/// Sends the VMess v1 encrypted header on channel activation and then
/// becomes a transparent pass‑through relay.
///
/// - Important: Not shareable — one instance per outbound channel.
public final class VMessOutboundHandler: ChannelDuplexHandler,
                                          RemovableChannelHandler,
                                          @unchecked Sendable {

    public typealias InboundIn   = ByteBuffer
    public typealias InboundOut  = ByteBuffer
    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - State

    public enum State: Sendable, CustomStringConvertible {
        /// VMess header dispatched; waiting for raw streaming.
        case vmessHeaderSent
        /// Transparent bidirectional relay active.
        case rawStreaming
        /// Irrecoverable error.
        case failed(Error)

        public var description: String {
            switch self {
            case .vmessHeaderSent: return "VMESS_HEADER_SENT"
            case .rawStreaming:    return "RAW_STREAMING"
            case .failed:          return "FAILED"
            }
        }
    }

    // MARK: - Stored Properties

    /// Pre‑built VMess header frame.
    private let header: Data

    /// Connection lifecycle state.
    public private(set) var state: State = .vmessHeaderSent

    /// Buffers outbound writes that arrive before `.rawStreaming`.
    private var pendingWrites: [(
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    )] = []

    // MARK: - Initialisation

    /// - Parameters:
    ///   - uuid: The user's VMess UUID.
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    ///   - timestamp: Unix epoch timestamp. If `nil`, current time is used.
    ///   - paddingLength: Random padding bytes (0–255, default 16).
    public init(
        uuid: UUID,
        address: String,
        port: UInt16,
        timestamp: UInt64? = nil,
        paddingLength: UInt8 = 16
    ) {
        self.header = VMessHeaderBuilder.build(
            uuid: uuid,
            address: address,
            port: port,
            timestamp: timestamp,
            paddingLength: paddingLength
        )
    }

    /// Creates a handler with a pre‑built header (useful for testing).
    public init(header: Data) {
        self.header = header
    }

    // MARK: - Channel Lifecycle

    public func channelActive(context: ChannelHandlerContext) {
        var buffer = context.channel.allocator.buffer(capacity: header.count)
        buffer.writeBytes(header)
        context.writeAndFlush(wrapOutboundOut(buffer), promise: nil)
        state = .vmessHeaderSent
        context.fireChannelActive()
    }

    // MARK: - Inbound (Read) Path

    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        if case .rawStreaming = state {
            context.fireChannelRead(data)
            return
        }
        // During header phase, the server's response is minimal.
        // We transition to streaming on the first successful read.
        state = .rawStreaming
        context.fireChannelRead(data)
    }

    // MARK: - Outbound (Write) Path

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        switch state {
        case .rawStreaming:
            context.write(data, promise: promise)
        case .vmessHeaderSent:
            pendingWrites.append((data, promise))
        case .failed:
            promise?.fail(VMessError.connectionFailed)
        }
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        pendingWrites.removeAll()
        context.fireChannelInactive()
    }

    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        state = .failed(error)
        pendingWrites.removeAll()
        context.close(mode: .all, promise: nil)
        context.fireErrorCaught(error)
    }
}

// MARK: - Errors

public enum VMessError: Error, Sendable, Equatable {
    case connectionFailed
}
