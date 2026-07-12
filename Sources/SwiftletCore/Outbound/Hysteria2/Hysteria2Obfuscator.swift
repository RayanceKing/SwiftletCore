//===----------------------------------------------------------------------===//
//
//  Hysteria2Obfuscator.swift
//  SwiftletCore — Salamander‑Inspired Dynamic Padding Obfuscator
//
//  Reactive DPI engines fingerprint QUIC / Hysteria 2 traffic by analysing
//  UDP datagram length distributions.  The Salamander obfuscator defeats
//  this by appending a cryptographically random number of padding bytes
//  to each outbound datagram, controlled by a pre‑shared seed combined
//  with a monotonic per‑packet counter.  Both sides independently compute
//  the same pad‑length sequence, so the receiver can strip padding without
//  any extra wire‑format overhead.
//
//  Algorithm
//  ---------
//  1. Combine `seed` ⊕ `counter` via xorshift64 to produce a
//     deterministic pseudo‑random value.
//  2. Modulo `multi` yields a pad length in `0 … multi‑1`.
//  3. Fill with `SecRandomCopyBytes` entropy and append to the buffer.
//  4. Increment `counter` so the next packet gets a fresh pad length.
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore

// MARK: - Salamander Obfuscator

/// Injects (and strips) Salamander dynamic padding from Hysteria 2 UDP
/// datagrams.  Both ends of the connection share the same `seed` and
/// `multi`, and each call to `injectSalamanderPadding` / `stripSalamanderPadding`
/// advances the internal counter in lock‑step.
public struct SalamanderObfuscator: Sendable {

    /// Pre‑shared 64‑bit seed controlling the pad‑length distribution.
    public let seed: UInt64

    /// Maximum padding bytes per datagram (0 … multi‑1).
    public let multi: Int

    /// Monotonic packet counter, advanced on each inject/strip call.
    /// Both sides must process packets in the same order.
    public private(set) var counter: UInt64 = 0

    // MARK: - Initialisation

    /// - Parameters:
    ///   - seed: Pre‑shared 64‑bit seed.
    ///   - multi: Max padding bytes per datagram (default 128).
    public init(seed: UInt64, multi: Int = 128) {
        self.seed = seed
        self.multi = max(1, multi)
    }

    // MARK: - Padding Injection

    /// Appends a deterministic-but-unpredictable number of random padding
    /// bytes to the tail of `buffer`.  Advances the internal counter.
    ///
    /// - Parameter buffer: The datagram buffer (mutated in‑place).
    public mutating func injectSalamanderPadding(to buffer: inout ByteBuffer) {
        let padLen = computePadLength()
        counter &+= 1
        guard padLen > 0, buffer.readableBytes > 0 else { return }

        var padding = [UInt8](repeating: 0, count: padLen)
        _ = SecRandomCopyBytes(kSecRandomDefault, padLen, &padding)
        buffer.writeBytes(padding)
    }

    /// Strips Salamander padding from the tail of `buffer`.  Advances the
    /// internal counter.  Must be called in the same order as the sender's
    /// `injectSalamanderPadding` calls.
    ///
    /// - Parameter buffer: The padded datagram (mutated in‑place).
    public mutating func stripSalamanderPadding(from buffer: inout ByteBuffer) {
        let padLen = computePadLength()
        counter &+= 1
        guard padLen > 0, buffer.readableBytes >= padLen else { return }

        buffer.moveWriterIndex(to: buffer.writerIndex - padLen)
    }

    // MARK: - Private

    /// Derives the pad length from the seed + counter using xorshift64,
    /// then clamps to `[0, multi)`.
    private func computePadLength() -> Int {
        guard multi > 1 else { return 0 }

        var state = seed ^ counter
        state ^= state << 13
        state ^= state >> 7
        state ^= state << 17

        return Int(state % UInt64(multi))
    }
}
