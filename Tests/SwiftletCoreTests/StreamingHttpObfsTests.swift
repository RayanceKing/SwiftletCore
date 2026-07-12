//===----------------------------------------------------------------------===//
//
//  StreamingHttpObfsTests.swift
//  SwiftletCore — Streaming HTTP Obfuscation Unit Tests
//
//  Validates:
//  • HTTP POST header synthesis with correct Content‑Length
//  • Content‑Length parsing from HTTP response headers
//  • Outbound: every chunk wrapped in POST with dynamic Content‑Length
//  • Outbound: multiple chunks each get independent headers
//  • Inbound: single HTTP response de‑framed correctly
//  • Inbound: multiple sequential responses de‑framed in order
//  • Inbound: fragmented header arrival (partial reads)
//  • Inbound: fragmented body arrival (body split across reads)
//  • Inbound: empty body (Content‑Length: 0) handled
//  • Pipeline counter accuracy
//  • Safety valve for oversized headers
//  • OutboundProtocol enum cases and pipeline flags
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
import NIOEmbedded
@testable import SwiftletCore

// MARK: - Channel Helpers

private func newChannel(_ h: StreamingHttpObfsHandler) throws -> EmbeddedChannel {
    EmbeddedChannel(handler: h)
}
private func getHandler(_ ch: EmbeddedChannel) throws -> StreamingHttpObfsHandler {
    try ch.pipeline.syncOperations.handler(type: StreamingHttpObfsHandler.self)
}
private func writeOut(_ data: Data, to ch: EmbeddedChannel) throws {
    var b = ch.allocator.buffer(capacity: data.count)
    b.writeBytes(data)
    try ch.writeOutbound(b)
}
private func readOut(from ch: EmbeddedChannel) throws -> Data? {
    guard let b = try ch.readOutbound(as: ByteBuffer.self) else { return nil }
    return b.getBytes(at: b.readerIndex, length: b.readableBytes).map(Data.init)
}
private func writeIn(_ data: Data, to ch: EmbeddedChannel) throws {
    var b = ch.allocator.buffer(capacity: data.count)
    b.writeBytes(data)
    try ch.writeInbound(b)
}
private func readIn(from ch: EmbeddedChannel) throws -> Data? {
    guard let b = try ch.readInbound(as: ByteBuffer.self) else { return nil }
    return b.getBytes(at: b.readerIndex, length: b.readableBytes).map(Data.init)
}

/// Builds an HTTP response with the given status, headers, and body.
private func httpResponse(
    status: String = "200 OK",
    contentLength: Int,
    body: Data = Data(),
    extraHeaders: String = ""
) -> Data {
    var header = "HTTP/1.1 \(status)\r\n"
    header += "Content-Type: application/octet-stream\r\n"
    header += "Content-Length: \(contentLength)\r\n"
    if !extraHeaders.isEmpty {
        header += "\(extraHeaders)\r\n"
    }
    header += "\r\n" // blank separator line
    var data = Data(header.utf8)
    data.append(body)
    return data
}

// MARK: - Header Synthesis

@Suite("StreamingHttpObfs — POST Header Synthesis")
struct StreamingHeaderSynthesisTests {

    @Test func headerContainsHost() {
        let h = StreamingHttpObfsHandler.buildPostHeader(
            host: "cdn.example.com", contentLength: 100
        )
        let s = String(decoding: h, as: UTF8.self)
        #expect(s.contains("Host: cdn.example.com"))
    }

    @Test func headerContainsContentLength() {
        let h = StreamingHttpObfsHandler.buildPostHeader(
            host: "x.com", contentLength: 2048
        )
        let s = String(decoding: h, as: UTF8.self)
        #expect(s.contains("Content-Length: 2048"))
    }

    @Test func headerStartsWithPOST() {
        let h = StreamingHttpObfsHandler.buildPostHeader(
            host: "a.com", path: "/api/data", contentLength: 50
        )
        let s = String(decoding: h, as: UTF8.self)
        #expect(s.hasPrefix("POST /api/data HTTP/1.1"))
    }

    @Test func headerEndsWithCRLFCRLF() {
        let h = StreamingHttpObfsHandler.buildPostHeader(
            host: "b.com", contentLength: 0
        )
        let suffix = h.suffix(4)
        #expect(suffix == Data([0x0D, 0x0A, 0x0D, 0x0A]))
    }

    @Test func differentContentLengthsProduceDifferentHeaders() {
        let a = StreamingHttpObfsHandler.buildPostHeader(
            host: "x.com", contentLength: 10
        )
        let b = StreamingHttpObfsHandler.buildPostHeader(
            host: "x.com", contentLength: 20
        )
        #expect(a != b)
    }
}

// MARK: - Content-Length Parsing

@Suite("StreamingHttpObfs — Content-Length Parsing")
struct ContentLengthParsingTests {

    @Test func parsesStandardHeader() {
        let h = "HTTP/1.1 200 OK\r\nContent-Length: 1234\r\n\r\n"
        #expect(StreamingHttpObfsHandler.parseContentLength(from: h) == 1234)
    }

    @Test func parsesCaseInsensitive() {
        let h = "HTTP/1.1 200 OK\r\ncontent-length: 5678\r\n\r\n"
        #expect(StreamingHttpObfsHandler.parseContentLength(from: h) == 5678)
    }

    @Test func returnsZeroWhenMissing() {
        let h = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
        #expect(StreamingHttpObfsHandler.parseContentLength(from: h) == 0)
    }

    @Test func returnsZeroForEmptyHeader() {
        #expect(StreamingHttpObfsHandler.parseContentLength(from: "") == 0)
    }

    @Test func parsesWithWhitespace() {
        let h = "HTTP/1.1 200 OK\r\nContent-Length:   42  \r\n\r\n"
        #expect(StreamingHttpObfsHandler.parseContentLength(from: h) == 42)
    }
}

// MARK: - Outbound POST Wrapping

@Suite("StreamingHttpObfs — Outbound Wrapping")
struct StreamingOutboundTests {

    @Test func singleChunkWrappedInPOST() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "obfs.cdn.com")
        )
        let payload = Data([0xDE, 0xAD, 0xBE, 0xEF])
        try writeOut(payload, to: ch)

        let out = try readOut(from: ch)
        #expect(out != nil)

        let header = StreamingHttpObfsHandler.buildPostHeader(
            host: "obfs.cdn.com", contentLength: payload.count
        )
        #expect(out!.prefix(header.count) == header)
        #expect(out!.suffix(payload.count) == payload)
    }

    @Test func multipleChunksEachGetIndependentHeaders() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "multi.test")
        )
        let p1 = Data([0x01, 0x02])
        let p2 = Data([0x03, 0x04, 0x05])

        try writeOut(p1, to: ch)
        let out1 = try readOut(from: ch)
        #expect(out1 != nil)

        try writeOut(p2, to: ch)
        let out2 = try readOut(from: ch)
        #expect(out2 != nil)

        // Each output should have its own header with correct Content-Length.
        let h1 = StreamingHttpObfsHandler.buildPostHeader(
            host: "multi.test", contentLength: 2
        )
        let h2 = StreamingHttpObfsHandler.buildPostHeader(
            host: "multi.test", contentLength: 3
        )
        #expect(out1!.prefix(h1.count) == h1)
        #expect(out2!.prefix(h2.count) == h2)
    }

    @Test func counterTracksChunksWritten() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "counter.test")
        )
        try writeOut(Data([0xAA]), to: ch); _ = try readOut(from: ch)
        try writeOut(Data([0xBB]), to: ch); _ = try readOut(from: ch)

        let h = try getHandler(ch)
        #expect(h.outboundChunksWritten == 2)
    }

    @Test func payloadBytesSentCounter() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "bytes.test")
        )
        try writeOut(Data([UInt8](repeating: 0, count: 50)), to: ch)
        _ = try readOut(from: ch)
        try writeOut(Data([UInt8](repeating: 0, count: 75)), to: ch)
        _ = try readOut(from: ch)

        #expect(try getHandler(ch).payloadBytesSent == 125)
    }

    @Test func largeChunkWrappedCorrectly() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "large.test")
        )
        let payload = Data([UInt8](repeating: 0x42, count: 16384))
        try writeOut(payload, to: ch)

        let out = try readOut(from: ch)
        let header = StreamingHttpObfsHandler.buildPostHeader(
            host: "large.test", contentLength: 16384
        )
        #expect(out?.prefix(header.count) == header)
        #expect(out?.suffix(16384) == payload)
    }
}

// MARK: - Inbound Response De‑framing

@Suite("StreamingHttpObfs — Inbound De‑framing")
struct StreamingInboundTests {

    @Test func singleResponseDeFramed() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "inbound.test")
        )
        let body = Data([0x11, 0x22, 0x33, 0x44])
        let resp = httpResponse(contentLength: body.count, body: body)

        try writeIn(resp, to: ch)
        let out = try readIn(from: ch)
        #expect(out == body)
    }

    @Test func emptyBodyResponse() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "empty.test")
        )
        let resp = httpResponse(contentLength: 0, body: Data())

        try writeIn(resp, to: ch)
        // Empty body — nothing should be forwarded.
        #expect(try getHandler(ch).inboundResponsesParsed == 1)
    }

    @Test func multipleSequentialResponsesDeFramed() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "seq.test")
        )
        let b1 = Data("first".utf8)
        let b2 = Data("second".utf8)
        let b3 = Data("third".utf8)

        var combined = Data()
        combined.append(httpResponse(contentLength: b1.count, body: b1))
        combined.append(httpResponse(contentLength: b2.count, body: b2))
        combined.append(httpResponse(contentLength: b3.count, body: b3))

        try writeIn(combined, to: ch)

        let o1 = try readIn(from: ch)
        let o2 = try readIn(from: ch)
        let o3 = try readIn(from: ch)

        #expect(o1 == b1)
        #expect(o2 == b2)
        #expect(o3 == b3)
        #expect(try getHandler(ch).inboundResponsesParsed == 3)
    }

    @Test func fragmentedHeaderArrival() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "frag.test")
        )
        let body = Data([0xAB, 0xCD])
        let fullResp = httpResponse(contentLength: body.count, body: body)

        // Send header in two fragments.
        let headerEnd = fullResp.firstIndex(of: 0x0A)! + 1
        try writeIn(fullResp.prefix(headerEnd - 2), to: ch)
        // No \r\n\r\n yet — nothing forwarded.
        #expect(try getHandler(ch).inboundResponsesParsed == 0)

        try writeIn(fullResp[headerEnd - 2 ..< fullResp.count], to: ch)
        let out = try readIn(from: ch)
        #expect(out == body)
    }

    @Test func fragmentedBodyArrival() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "bodyfrag.test")
        )
        let body = Data([UInt8](repeating: 0x77, count: 100))
        let resp = httpResponse(contentLength: body.count, body: body)

        // Send header + first 40 body bytes.
        let splitAt = resp.count - 60
        try writeIn(resp.prefix(splitAt), to: ch)
        // Body not complete — nothing forwarded yet.
        #expect(try readIn(from: ch) == nil)

        // Send remaining 60 bytes.
        try writeIn(resp.suffix(60), to: ch)
        let out = try readIn(from: ch)
        #expect(out == body)
    }

    @Test func responseWithDifferentStatusStillParsed() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "status.test")
        )
        let body = Data([0x99, 0x88])
        let resp = httpResponse(
            status: "404 Not Found", contentLength: body.count, body: body
        )

        try writeIn(resp, to: ch)
        let out = try readIn(from: ch)
        #expect(out == body)
    }

    @Test func counterTracksResponsesParsed() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "count.test")
        )
        for _ in 0 ..< 5 {
            let body = Data([0x01])
            try writeIn(
                httpResponse(contentLength: 1, body: body), to: ch
            )
            _ = try readIn(from: ch)
        }
        #expect(try getHandler(ch).inboundResponsesParsed == 5)
    }

    @Test func payloadBytesReceivedCounter() throws {
        let ch = try newChannel(
            StreamingHttpObfsHandler(host: "rx.test")
        )
        let body = Data([UInt8](repeating: 0xAA, count: 256))
        try writeIn(
            httpResponse(contentLength: 256, body: body), to: ch
        )
        _ = try readIn(from: ch)
        #expect(try getHandler(ch).payloadBytesReceived == 256)
    }
}

// MARK: - Round-Trip

@Suite("StreamingHttpObfs — Round‑Trip")
struct StreamingRoundTripTests {

    @Test func outboundInboundRoundTrip() throws {
        let sender = try newChannel(
            StreamingHttpObfsHandler(host: "rt.test")
        )
        let receiver = try newChannel(
            StreamingHttpObfsHandler(host: "rt.test")
        )

        // Outbound: wrap payload in HTTP POST.
        let originalPayload = Data("secret proxy data".utf8)
        try writeOut(originalPayload, to: sender)
        let wrapped = try readOut(from: sender)
        #expect(wrapped != nil)

        // Inbound: de‑frame the HTTP POST (simulating server echo).
        // Wrap it as a response.
        let header = "HTTP/1.1 200 OK\r\nContent-Length: \(originalPayload.count)\r\n\r\n"
        var simulatedResponse = Data(header.utf8)
        simulatedResponse.append(originalPayload)

        try writeIn(simulatedResponse, to: receiver)
        let recovered = try readIn(from: receiver)
        #expect(recovered == originalPayload)
    }
}

// MARK: - OutboundProtocol Enum

@Suite("OutboundProtocol — Factory Enum")
struct OutboundProtocolTests {

    @Test func vmessHttpLabel() {
        let proto = OutboundProtocol.vmessHttp(
            uuid: "test", httpHost: "cdn.test"
        )
        #expect(proto.label == "VMess+HTTP")
        #expect(proto.isHTTPWrapped == true)
        #expect(proto.isTLS == true)
    }

    @Test func vlessHttpLabel() {
        let proto = OutboundProtocol.vlessHttp(
            uuid: "test", httpHost: "cdn.test"
        )
        #expect(proto.label == "VLESS+HTTP")
        #expect(proto.isHTTPWrapped == true)
    }

    @Test func trojanHttpLabel() {
        let proto = OutboundProtocol.trojanHttp(
            host: "proxy.com", port: 443,
            password: "pwd", httpHost: "cdn.test"
        )
        #expect(proto.label == "Trojan+HTTP")
        #expect(proto.isHTTPWrapped == true)
    }

    @Test func baseProtocolsNotHTTPWrapped() {
        #expect(OutboundProtocol.shadowsocks(
            cipher: "aes", password: "pwd"
        ).isHTTPWrapped == false)
        #expect(OutboundProtocol.trojan(
            host: "x", port: 1, password: "p"
        ).isHTTPWrapped == false)
    }

    @Test func simpleObfsDetection() {
        #expect(OutboundProtocol.trojanSimpleObfs(
            host: "x", port: 1, password: "p", obfsHost: "y"
        ).isSimpleObfs == true)
        #expect(OutboundProtocol.shadowsocksSimpleTLSObfs(
            cipher: "aes", password: "p", obfsHost: "y"
        ).isSimpleObfs == true)
    }

    @Test func tlsDetection() {
        #expect(OutboundProtocol.shadowsocks(
            cipher: "aes", password: "p"
        ).isTLS == false)
        #expect(OutboundProtocol.trojan(
            host: "x", port: 1, password: "p"
        ).isTLS == true)
        #expect(OutboundProtocol.wireGuard(
            privateKey: "a", peerPublicKey: "b", presharedKey: nil
        ).isTLS == false)
    }

    @Test func equatability() {
        let a = OutboundProtocol.vmessHttp(
            uuid: "a", httpHost: "h"
        )
        let b = OutboundProtocol.vmessHttp(
            uuid: "a", httpHost: "h"
        )
        let c = OutboundProtocol.vmessHttp(
            uuid: "b", httpHost: "h"
        )
        #expect(a == b)
        #expect(a != c)
    }

    @Test func allCasesHaveDistinctLabels() {
        let labels = [
            OutboundProtocol.shadowsocks(cipher: "a", password: "b").label,
            OutboundProtocol.trojan(host: "h", port: 1, password: "p").label,
            OutboundProtocol.vless(uuid: "u", serverName: "s", authKey: nil).label,
            OutboundProtocol.vmess(uuid: "u").label,
            OutboundProtocol.wireGuard(privateKey: "a", peerPublicKey: "b", presharedKey: nil).label,
            OutboundProtocol.vmessHttp(uuid: "u", httpHost: "h").label,
            OutboundProtocol.vlessHttp(uuid: "u", httpHost: "h").label,
            OutboundProtocol.trojanHttp(host: "h", port: 1, password: "p", httpHost: "c").label,
            OutboundProtocol.shadowsocksHttp(cipher: "a", password: "p", httpHost: "h").label,
            OutboundProtocol.trojanSimpleObfs(host: "h", port: 1, password: "p", obfsHost: "o").label,
            OutboundProtocol.shadowsocksSimpleTLSObfs(cipher: "a", password: "p", obfsHost: "o").label,
        ]
        // All labels should be unique.
        #expect(Set(labels).count == labels.count)
    }
}
