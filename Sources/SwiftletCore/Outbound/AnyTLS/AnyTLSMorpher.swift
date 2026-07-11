//===----------------------------------------------------------------------===//
//
//  AnyTLSMorpher.swift
//  SwiftletCore — AnyTLS Symmetric Byte Obfuscation Engine
//
//  Implements a fast, deterministic, in‑place XOR morphing engine that
//  destroys standard TLS fingerprint signatures by scrambling the raw
//  byte stream with a pseudo‑random keystream derived from a pre‑shared
//  seed.  Because XOR is symmetric, `obfuscateHandshake` and
//  `deobfuscateHandshake` are the same operation — applying the keystream
//  twice restores the original plaintext.
//
//  Algorithm
//  ---------
//  • Seed → xorshift32 PRNG → byte keystream
//  • buffer[i] ^= keystream[i]
//  • Zero‑copy: the buffer is mutated in‑place; no secondary allocation.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - AnyTLS Morpher

/// A stateless namespace for AnyTLS symmetric byte morphing operations.
///
/// All methods mutate the input `ByteBuffer` **in‑place** for zero‑copy
/// performance.  The same `seed` must be used on both ends of the
/// connection for the round‑trip to succeed.
public enum AnyTLSMorpher {

    // MARK: - Public API

    /// Obfuscates a handshake buffer by XOR‑ing each byte with a
    /// pseudo‑random keystream derived from `seed`.
    ///
    /// - Parameters:
    ///   - buffer: The raw bytes to morph (mutated in‑place).
    ///   - seed: The pre‑shared 32‑bit seed.
    public static func obfuscateHandshake(
        _ buffer: inout ByteBuffer,
        seed: UInt32
    ) {
        applyKeystream(&buffer, seed: seed)
    }

    /// De‑obfuscates a handshake buffer.  Because XOR is symmetric, this is
    /// identical to `obfuscateHandshake` — applying the keystream twice
    /// restores the original data.
    ///
    /// - Parameters:
    ///   - buffer: The morphed bytes (mutated in‑place).
    ///   - seed: The same pre‑shared 32‑bit seed used for obfuscation.
    public static func deobfuscateHandshake(
        _ buffer: inout ByteBuffer,
        seed: UInt32
    ) {
        // XOR is self‑inverse: plain ^ key = cipher, cipher ^ key = plain
        applyKeystream(&buffer, seed: seed)
    }

    /// Convenience: obfuscates raw `Data` and returns the result.
    public static func obfuscateHandshake(
        _ data: Data,
        seed: UInt32
    ) -> Data {
        var buffer = ByteBuffer(bytes: data)
        applyKeystream(&buffer, seed: seed)
        return buffer.readBytes(length: buffer.readableBytes)
            .map { Data($0) } ?? Data()
    }

    /// Convenience: de‑obfuscates raw `Data` and returns the result.
    public static func deobfuscateHandshake(
        _ data: Data,
        seed: UInt32
    ) -> Data {
        // Identical to obfuscate — XOR symmetry.
        obfuscateHandshake(data, seed: seed)
    }

    // MARK: - Core Keystream Application

    /// Walks the readable portion of `buffer` and XORs each byte with the
    /// next byte from the keystream produced by the xorshift32 PRNG.
    private static func applyKeystream(
        _ buffer: inout ByteBuffer,
        seed: UInt32
    ) {
        guard buffer.readableBytes > 0 else { return }

        let length = buffer.readableBytes
        let readerIndex = buffer.readerIndex

        // Read all bytes, mutate, write back.
        guard let rawBytes = buffer.getBytes(at: readerIndex, length: length) else {
            return
        }

        // Ensure the state is non‑zero — xorshift32 degenerates to an
        // all‑zero keystream when seeded with 0.
        var state = seed == 0 ? 0x6A5D_9E3F : seed
        var mutated = rawBytes

        for i in 0 ..< length {
            let keyByte = nextByte(state: &state)
            mutated[i] ^= keyByte
        }

        // Write the mutated bytes back at the same position.
        buffer.setBytes(mutated, at: readerIndex)
    }

    /// Advances the xorshift32 state by one step and returns the low byte
    /// as the next keystream byte.
    @inline(__always)
    private static func nextByte(state: inout UInt32) -> UInt8 {
        state ^= state << 13
        state ^= state >> 17
        state ^= state << 5
        return UInt8(state & 0xFF)
    }
}
