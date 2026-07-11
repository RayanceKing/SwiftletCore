//===----------------------------------------------------------------------===//
//
//  Socks5Relay.swift
//  SwiftletCore — Bidirectional TCP Relay
//
//  After the SOCKS5 handshake completes successfully, the codec and handshake
//  handler are removed from the client‑channel pipeline and replaced by a
//  lightweight `Socks5RelayHandler`.  A symmetric instance is installed on
//  the remote (upstream) channel.
//
//  Each relay handler blindly copies every `ByteBuffer` it reads from its
//  own channel into the peer channel's outbound buffer and monitors
//  writability for basic back‑pressure.  When either side closes, the peer
//  is torn down automatically.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

/// A no‑allocation relay that pipes raw bytes from one TCP channel to another.
///
/// Two instances are installed per proxied connection:
/// 1. **Client‑side relay** — reads from the SOCKS5 client, writes to the
///    upstream remote channel.
/// 2. **Remote‑side relay** — reads from the upstream channel, writes back
///    to the SOCKS5 client.
///
/// - Important: This handler does **not** examine or buffer the byte stream;
///   it is a thin veneer over `writeAndFlush`.  Higher‑level inspection
///   (e.g. traffic accounting, protocol detection) should be inserted as a
///   separate handler in front of the relay.
public final class Socks5RelayHandler: ChannelInboundHandler, RemovableChannelHandler, @unchecked Sendable {

    // MARK: - NIO Type Aliases

    public typealias InboundIn  = ByteBuffer
    public typealias OutboundOut = ByteBuffer

    // MARK: - Stored Properties

    /// The peer channel to which all read bytes are forwarded.
    private let peerChannel: Channel

    /// Tracks whether the peer's outbound buffer is currently saturated so we
    /// can pause reading from our own channel until it drains.
    private var peerWritable: Bool = true

    // MARK: - Initialisation

    /// - Parameter peerChannel: The channel to forward bytes to.
    public init(peerChannel: Channel) {
        self.peerChannel = peerChannel
    }

    // MARK: - ChannelInboundHandler

    /// Triggered whenever data arrives from the local channel.
    ///
    /// The entire `ByteBuffer` is forwarded to the peer channel as‑is;
    /// the buffer's reader index is **not** modified — SwiftNIO already
    /// advances it past the readable bytes before delivering the event.
    public func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let buffer = unwrapInboundIn(data)

        // If the peer is not writable we still enqueue the write (NIO will
        // buffer it), but we stop issuing `context.read()` until the peer
        // signals writability again — preventing unbounded buffer growth.
        peerChannel.writeAndFlush(buffer, promise: nil)

        if peerWritable {
            context.read()
        }
    }

    /// When our channel becomes writable we notify the *opposite* direction
    /// by resuming reads.  This is a back‑pressure signal from the peer side.
    public func channelWritabilityChanged(context: ChannelHandlerContext) {
        // When we become writable again, the peer can resume reading.
        // NIO calls this on the event loop, so no synchronisation is needed.
        context.read()
    }

    /// When the peer's writability changes we track it so we can stop / start
    /// issuing reads on our own channel.
    ///
    /// This is registered via the peer channel's pipeline during setup.
    public func peerWritabilityChanged(peerContext: ChannelHandlerContext) {
        peerWritable = peerContext.channel.isWritable
        if peerWritable {
            peerContext.read()
        }
    }

    /// When our channel closes (client hang‑up, error, or normal shutdown),
    /// tear down the peer channel as well.
    public func channelInactive(context: ChannelHandlerContext) {
        peerChannel.close(mode: .all, promise: nil)
        context.fireChannelInactive()
    }

    /// Propagate errors to the peer channel so both sides clean up.
    public func errorCaught(context: ChannelHandlerContext, error: Error) {
        peerChannel.close(mode: .all, promise: nil)
        context.close(mode: .all, promise: nil)
    }
}
