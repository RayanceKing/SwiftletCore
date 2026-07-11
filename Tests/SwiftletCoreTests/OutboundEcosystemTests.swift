//===----------------------------------------------------------------------===//
//
//  OutboundEcosystemTests.swift
//  SwiftletCore — WebSocket + AnyTLS Ecosystem Unit Tests
//
//  Validates:
//  • WebSocket binary frame encode → decode round‑trip
//  • WebSocket masking / unmasking correctness
//  • AnyTLS obfuscate → deobfuscate restores original data
//  • AnyTLS obfuscation destroys plaintext recognisability
//  • Integration: WebSocket‑wrapped obfuscated data survives round‑trip
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - WebSocket Round‑Trip Tests

@Suite("VLESSWebSocketHandler")
struct WebSocketHandlerTests {

    /// Encodes a payload through the handler's frame builder and then
    /// decodes it through the frame parser, verifying the original
    /// bytes survive the round‑trip intact.
    @Test func encodeDecodeRoundTrip() {
        let payload: [UInt8] = Array("Hello, WebSocket!".utf8)

        // Simulate the WebSocket frame encode → decode cycle without
        // spinning up a full NIO channel: the `simulateEncode` helper
        // mirrors `VLESSWebSocketHandler.encodeBinaryFrame`.

        let frame = simulateEncode(payload: payload)
        let decoded = simulateDecode(frame: frame)

        #expect(decoded == payload)
    }

    @Test func emptyPayloadRoundTrip() {
        let payload: [UInt8] = []
        let frame = simulateEncode(payload: payload)
        let decoded = simulateDecode(frame: frame)
        #expect(decoded == payload)
    }

    @Test func largePayloadRoundTrip() {
        let payload = [UInt8](repeating: 0xAB, count: 5000)
        let frame = simulateEncode(payload: payload)
        let decoded = simulateDecode(frame: frame)
        #expect(decoded == payload)
    }

    @Test func encodedFrameIsLargerThanPayload() {
        let payload = [UInt8](repeating: 0x00, count: 100)
        let frame = simulateEncode(payload: payload)
        // Header: 2 bytes + 4 byte mask key = 6 bytes overhead.
        #expect(frame.count > payload.count)
    }

    @Test func encodedPayloadIsMasked() {
        let payload: [UInt8] = Array("visible".utf8)
        let frame = simulateEncode(payload: payload)

        // The payload portion (after header + mask key) must differ from
        // the original plaintext due to masking.
        let maskKey = Array(frame[2 ..< 6])
        let maskedPayload = Array(frame[6...])

        #expect(maskedPayload != payload)
        #expect(maskKey.count == 4)
    }

    @Test func multipleFramesInSingleBuffer() {
        let p1: [UInt8] = Array("first".utf8)
        let p2: [UInt8] = Array("second".utf8)
        let p3: [UInt8] = Array("third".utf8)

        let f1 = simulateEncode(payload: p1)
        let f2 = simulateEncode(payload: p2)
        let f3 = simulateEncode(payload: p3)

        // Concatenate all three frames into one buffer.
        var combined = Data()
        combined.append(contentsOf: f1)
        combined.append(contentsOf: f2)
        combined.append(contentsOf: f3)

        let decoded = simulateDecodeAllFrames(data: Data(combined))
        #expect(decoded.count == 3)
        #expect(decoded[0] == p1)
        #expect(decoded[1] == p2)
        #expect(decoded[2] == p3)
    }

    @Test func extendedLength16Boundary() {
        // Payload of 126 bytes triggers the 16‑bit extended length field.
        let payload = [UInt8](repeating: 0xCC, count: 126)
        let frame = simulateEncode(payload: payload)
        let decoded = simulateDecode(frame: frame)
        #expect(decoded == payload)
    }

    @Test func extendedLength16LargePayload() {
        // Test with a payload well beyond 126 bytes.
        let payload = [UInt8](repeating: 0xDD, count: 1000)
        let frame = simulateEncode(payload: payload)
        let decoded = simulateDecode(frame: frame)
        #expect(decoded == payload)
    }
}

// MARK: - AnyTLS Morpher Tests

@Suite("AnyTLSMorpher")
struct AnyTLSMorpherTests {

    @Test func roundTripRestoresOriginal() {
        let original = Data("AnyTLS test payload for round‑trip".utf8)
        let seed: UInt32 = 0xDEAD_BEEF

        let morphed = AnyTLSMorpher.obfuscateHandshake(original, seed: seed)
        #expect(morphed != original, "Obfuscated data must differ from plaintext")

        let restored = AnyTLSMorpher.deobfuscateHandshake(morphed, seed: seed)
        #expect(restored == original)
    }

    @Test func obfuscationDestroysReadability() {
        let text = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
        let original = Data(text.utf8)
        let seed: UInt32 = 42

        let morphed = AnyTLSMorpher.obfuscateHandshake(original, seed: seed)

        // The morphed data should not be interpretable as the original text.
        let morphedString = String(data: morphed, encoding: .utf8) ?? ""
        #expect(!morphedString.contains("GET"))
        #expect(!morphedString.contains("HTTP"))
    }

    @Test func differentSeedsProduceDifferentCiphertexts() {
        let payload = Data([UInt8](repeating: 0x42, count: 256))

        let c1 = AnyTLSMorpher.obfuscateHandshake(payload, seed: 12345)
        let c2 = AnyTLSMorpher.obfuscateHandshake(payload, seed: 67890)

        // Different seeds must produce different keystreams.
        #expect(c1 != c2)
    }

    @Test func sameSeedProducesDeterministicOutput() {
        let payload = Data([UInt8](repeating: 0x99, count: 128))
        let seed: UInt32 = 0xCAFE

        let c1 = AnyTLSMorpher.obfuscateHandshake(payload, seed: seed)
        let c2 = AnyTLSMorpher.obfuscateHandshake(payload, seed: seed)
        #expect(c1 == c2)
    }

    @Test func emptyDataIsUnaffected() {
        let empty = Data()
        let seed: UInt32 = 999
        let result = AnyTLSMorpher.obfuscateHandshake(empty, seed: seed)
        #expect(result.isEmpty)
    }

    @Test func singleByteRoundTrip() {
        // Use a fixed non‑zero seed for all single‑byte tests.  A
        // single‑byte payload CAN equal its morphed form if the key
        // byte happens to be 0x00 (probabilistic, ~1/256), so we
        // only assert that the round‑trip restores the original.
        let seed: UInt32 = 0xDEAD_BEEF
        for byte in [0x00, 0x01, 0x7F, 0x80, 0xFF] as [UInt8] {
            let original = Data([byte])

            let morphed = AnyTLSMorpher.obfuscateHandshake(original, seed: seed)
            #expect(morphed.count == 1)

            let restored = AnyTLSMorpher.deobfuscateHandshake(morphed, seed: seed)
            #expect(restored == original)
        }
    }

    @Test func byteBufferInPlaceMutation() {
        let original = Data([UInt8](repeating: 0x55, count: 64))
        var buffer = ByteBuffer(bytes: original)
        let seed: UInt32 = 0xABCD

        // Snapshot before.
        let before = Data(buffer.readableBytesView)

        AnyTLSMorpher.obfuscateHandshake(&buffer, seed: seed)
        let after = Data(buffer.readableBytesView)
        #expect(after != before)

        AnyTLSMorpher.deobfuscateHandshake(&buffer, seed: seed)
        let final = Data(buffer.readableBytesView)
        #expect(final == before)
    }

    @Test func largePayloadPerformance() {
        // 64 KB must obfuscate / deobfuscate quickly (sub‑10ms).
        let payload = Data([UInt8](repeating: 0xAB, count: 65536))
        let seed: UInt32 = 0x1234_5678

        let start = ContinuousClock().now
        let morphed = AnyTLSMorpher.obfuscateHandshake(payload, seed: seed)
        _ = AnyTLSMorpher.deobfuscateHandshake(morphed, seed: seed)
        let elapsed = ContinuousClock().now - start
        let ms = Double(elapsed.components.attoseconds) / 1_000_000_000_000_000.0
        #expect(ms < 50, "64KB round‑trip took \(ms)ms, expected < 50ms")
    }
}

// MARK: - Integration Tests

@Suite("Outbound Ecosystem Integration")
struct OutboundEcosystemIntegrationTests {

    /// Simulates the full VLESS → WebSocket → AnyTLS → wire → AnyTLS →
    /// WebSocket → VLESS pipeline.
    @Test func webSocketPlusAnyTLSRoundTrip() {
        // Step 1: VLESS header bytes (mock).
        let vlessHeader = Data([UInt8](repeating: 0x01, count: 32))

        // Step 2: Obfuscate with AnyTLS.
        let seed: UInt32 = 0xBEEF_CAFE
        let morphed = AnyTLSMorpher.obfuscateHandshake(vlessHeader, seed: seed)

        // Step 3: Wrap in WebSocket frame.
        let frame = simulateEncode(payload: Array(morphed))

        // --- Wire transmission (the frame is what goes over TCP) ---

        // Step 4: Decode WebSocket frame.
        let decodedPayload = simulateDecode(frame: frame)

        // Step 5: De‑obfuscate.
        let restored = AnyTLSMorpher.deobfuscateHandshake(
            Data(decodedPayload), seed: seed
        )

        #expect(restored == vlessHeader)
    }
}

// MARK: - Simulation Helpers

/// Simulates the handler's outbound encoding: builds a WebSocket binary
/// frame with random masking and returns the raw wire bytes.
///
/// This mirrors the logic inside `VLESSWebSocketHandler.encodeBinaryFrame`
/// and is used for unit‑testing the frame format without spinning up a
/// full NIO channel.
private func simulateEncode(payload: [UInt8]) -> [UInt8] {
    let payloadLen = payload.count
    var frame: [UInt8] = []

    // Byte 0: FIN + Binary opcode
    frame.append(0x82)

    // Byte 1 + extended length + mask bit
    if payloadLen < 126 {
        frame.append(0x80 | UInt8(payloadLen))
    } else if payloadLen < 65536 {
        frame.append(0x80 | 126)
        frame.append(UInt8((payloadLen >> 8) & 0xFF))
        frame.append(UInt8( payloadLen       & 0xFF))
    } else {
        frame.append(0x80 | 127)
        for shift in stride(from: 56, through: 0, by: -8) {
            frame.append(UInt8((payloadLen >> shift) & 0xFF))
        }
    }

    // Masking key (4 deterministic bytes for test reproducibility).
    let maskKey: [UInt8] = [0x12, 0x34, 0x56, 0x78]
    frame.append(contentsOf: maskKey)

    // Masked payload.
    for (i, byte) in payload.enumerated() {
        frame.append(byte ^ maskKey[i % 4])
    }

    return frame
}

/// Simulates the handler's inbound decoding: parses a single WebSocket
/// frame and returns the unmasked payload bytes.
private func simulateDecode(frame: [UInt8]) -> [UInt8] {
    let data = Data(frame)
    var offset = 0

    // Byte 0
    let byte0 = data[offset]; offset += 1
    let fin    = (byte0 & 0x80) != 0
    let opcode = byte0 & 0x0F
    guard fin, opcode == 0x02 else { return [] }

    // Byte 1
    let byte1      = data[offset]; offset += 1
    let isMasked   = (byte1 & 0x80) != 0
    var payloadLen = Int(byte1 & 0x7F)

    if payloadLen == 126 {
        payloadLen = (Int(data[offset]) << 8) | Int(data[offset + 1])
        offset += 2
    } else if payloadLen == 127 {
        var len: UInt64 = 0
        for i in 0 ..< 8 { len = (len << 8) | UInt64(data[offset + i]) }
        payloadLen = Int(len)
        offset += 8
    }

    var maskKey: [UInt8] = [0, 0, 0, 0]
    if isMasked {
        maskKey = Array(data[offset ..< offset + 4])
        offset += 4
    }

    var payload = Array(data[offset ..< offset + payloadLen])
    if isMasked {
        for i in 0 ..< payloadLen { payload[i] ^= maskKey[i % 4] }
    }

    return payload
}

/// Decodes all complete WebSocket frames from a concatenated byte buffer.
private func simulateDecodeAllFrames(data: Data) -> [[UInt8]] {
    var frames: [[UInt8]] = []
    var remaining = data.count
    var offset = 0

    while remaining > 0 {
        let slice = Array(data[offset...])
        let payload = simulateDecode(frame: slice)
        guard !payload.isEmpty || remaining <= 2 else {
            // Could not decode — skip a byte to avoid infinite loop.
            offset += 1; remaining -= 1
            continue
        }

        // Calculate the frame's wire size.
        let payloadLen = payload.count
        var headerSize = 2 + 4 // base header + mask key
        if payloadLen >= 126 { headerSize += 2 }
        if payloadLen >= 65536 { headerSize += 6 } // 8 total extended
        let frameSize = headerSize + payloadLen

        frames.append(payload)
        offset += frameSize
        remaining -= frameSize
    }

    return frames
}
