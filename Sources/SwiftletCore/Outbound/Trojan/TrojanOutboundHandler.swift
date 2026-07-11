//===----------------------------------------------------------------------===//
//
//  TrojanOutboundHandler.swift
//  SwiftletCore — Trojan Protocol Outbound Handler
//
//  A SwiftNIO `ChannelOutboundHandler` that prepends the Trojan request
//  header to the very first outbound write after the TLS handshake.
//  Subsequent writes pass through unchanged.
//
//  Pipeline placement
//  ------------------
//  ```
//  [App writes] → TrojanOutboundHandler → NIOSSLClientHandler → [Socket]
//  [Socket] → NIOSSLClientHandler → [App reads]
//  ```
//
//  The handler is intentionally **inbound‑transparent** — the Trojan
//  protocol does not add any framing to server responses, so the read
//  path is a straight pass‑through.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore
import Foundation

// MARK: - Trojan Outbound Handler

/// Prepends the Trojan request header to the first outbound write on a
/// channel and is otherwise fully transparent.
///
/// - Important: This handler must be placed **before** `NIOSSLClientHandler`
///   in the pipeline so that the header is encrypted along with the rest of
///   the stream.
public final class TrojanOutboundHandler: ChannelOutboundHandler,
                                           RemovableChannelHandler,
                                           @unchecked Sendable {

    public typealias OutboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Stored Properties

    /// The pre‑built Trojan request header bytes.
    private let header: Data

    /// Whether the header has already been sent on this channel.
    private var headerSent: Bool = false

    // MARK: - Initialisation

    /// - Parameters:
    ///   - password: The Trojan password.
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    public init(password: String, address: String, port: UInt16) {
        self.header = TrojanHeader.buildConnect(
            password: password,
            address: address,
            port: port
        )
    }

    /// Creates a handler with a pre‑built header (useful for testing).
    public init(header: Data) {
        self.header = header
    }

    // MARK: - ChannelOutboundHandler

    public func write(
        context: ChannelHandlerContext,
        data: NIOAny,
        promise: EventLoopPromise<Void>?
    ) {
        var buffer = unwrapOutboundIn(data)

        if !headerSent {
            // Prepend the Trojan header to the first write.
            headerSent = true

            var combined = context.channel.allocator.buffer(
                capacity: header.count + buffer.readableBytes
            )
            combined.writeBytes(header)

            if let bytes = buffer.readBytes(length: buffer.readableBytes) {
                combined.writeBytes(bytes)
            }

            context.write(wrapOutboundOut(combined), promise: promise)
        } else {
            // Pass‑through for subsequent writes.
            context.write(data, promise: promise)
        }
    }

    // MARK: - Lifecycle

    public func channelInactive(context: ChannelHandlerContext) {
        headerSent = false
        context.fireChannelInactive()
    }
}

// MARK: - Trojan Pipeline Helper

public enum TrojanPipeline {

    /// Well‑known handler name for the Trojan outbound handler.
    public static let handlerName = "trojan-outbound-handler"
}
