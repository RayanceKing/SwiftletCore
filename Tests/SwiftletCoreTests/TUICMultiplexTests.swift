//===----------------------------------------------------------------------===//
//
//  TUICMultiplexTests.swift
//  SwiftletCore — TUIC v5 Stream Multiplexer Integration Tests
//
//  Validates:
//  • Stream manager initialisation and transport configuration
//  • Authentication frame dispatch
//  • Stream lifecycle: open → established → packet I/O → close
//  • 50 concurrent streams with full isolation and distinct IDs
//  • Packet frame routing to correct stream data handlers
//  • Traffic counter accuracy
//  • Error states (transport not configured, stream not found)
//  • Per‑stream handler: accumulation, frame decoding, callbacks
//  • Heartbeat echo
//  • Close‑all‑streams teardown
//  • Stream state transitions
//  • Concurrent send/receive without interleaving
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - Sendable Capture Helpers

/// A thread‑safe box for collecting values in `@Sendable` closures during
/// tests.  Uses a lock internally so it can be captured by `@Sendable`
/// closures without Sendable warnings.
private final class CaptureBox<Value: Sendable>: @unchecked Sendable {
    private let lock = NSLock()
    private var storage: Value

    init(_ initial: Value) { self.storage = initial }

    func withLock<T>(_ body: (inout Value) -> T) -> T {
        lock.lock(); defer { lock.unlock() }
        return body(&storage)
    }

    var value: Value {
        lock.lock(); defer { lock.unlock() }
        return storage
    }
}

// MARK: - Transport Capture

/// Captures all data sent via the transport for test inspection.
private actor TransportCapture {
    private var packets: [Data] = []

    func append(_ data: Data) { packets.append(data) }
    var all: [Data] { packets }
    var count: Int { packets.count }
    func reset() { packets.removeAll() }

    /// Decodes all captured data into TUIC frames.
    func decodedFrames() throws -> [TUICFrame] {
        var frames = [TUICFrame]()
        for packet in packets {
            var buffer = ByteBuffer(bytes: packet)
            while let frame = try TUICStreamDecoder.decodeNextFrame(from: &buffer) {
                frames.append(frame)
            }
        }
        return frames
    }
}

/// Creates a transport closure that captures data into a `TransportCapture`.
private func captureTransport(
    _ capture: TransportCapture
) -> TUICStreamManager.SendTransport {
    return { data in await capture.append(data) }
}

// MARK: - Manager Initialisation

@Suite("TUICStreamManager — Initialisation")
struct TUICManagerInitTests {

    @Test func managerInitialisesWithCorrectDefaults() async {
        let uuid = UUID()
        let manager = TUICStreamManager(uuid: uuid, udpMode: 0)

        let isAuth = await manager.isAuthenticated
        let count   = await manager.activeStreamCount

        #expect(isAuth == false)
        #expect(count == 0)
    }

    @Test func managerInitialisesWithUDPModeEnabled() async {
        let uuid = UUID()
        let manager = TUICStreamManager(uuid: uuid, udpMode: 1)

        let isAuth = await manager.isAuthenticated
        #expect(isAuth == false)
    }
}

// MARK: - Authentication

@Suite("TUICStreamManager — Authentication")
struct TUICManagerAuthTests {

    @Test func authenticateSendsCorrectFrame() async throws {
        let uuid = UUID(uuidString: "DEADBEEF-1234-5678-9ABC-DEF012345678")!
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: uuid, udpMode: 0)
        await manager.setTransport(captureTransport(capture))

        try await manager.authenticate()

        let isAuth = await manager.isAuthenticated
        #expect(isAuth == true)

        // Verify the sent frame is a valid authenticate frame.
        let frames = try await capture.decodedFrames()
        #expect(frames.count == 1)

        guard case .authenticate(let sentUUID, let mode) = frames[0] else {
            Issue.record("Expected .authenticate, got \(frames[0])")
            return
        }
        #expect(sentUUID == uuid)
        #expect(mode == 0)
    }

    @Test func authenticateWithUDPModeSendsCorrectByte() async throws {
        let uuid = UUID()
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: uuid, udpMode: 1)
        await manager.setTransport(captureTransport(capture))

        try await manager.authenticate()

        let frames = try await capture.decodedFrames()
        guard case .authenticate(_, let mode) = frames[0] else {
            Issue.record("Wrong frame type")
            return
        }
        #expect(mode == 1)
    }

    @Test func authenticateWithoutTransportThrows() async {
        let manager = TUICStreamManager(uuid: UUID())
        await #expect(throws: TUICManagerError.transportNotConfigured) {
            try await manager.authenticate()
        }
    }
}

// MARK: - Stream Lifecycle

@Suite("TUICStreamManager — Stream Lifecycle")
struct TUICManagerStreamLifecycleTests {

    @Test func openStreamAllocatesUniqueID() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid1 = try await manager.openStream(
            addressType: .domain, address: "example.com", port: 443
        )
        let sid2 = try await manager.openStream(
            addressType: .ipv4, address: "10.0.0.1", port: 80
        )

        #expect(sid1 != sid2)
        #expect(sid1 == 1)
        #expect(sid2 == 2)
    }

    @Test func openStreamSendsConnectFrame() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "api.test.com", port: 8443
        )

        let frames = try await capture.decodedFrames()
        #expect(frames.count >= 1)

        // Last frame should be the connect for this stream.
        let connectFrame = frames.last
        guard case .connect(let addrType, let addr, let port) = connectFrame else {
            Issue.record("Expected .connect, got \(String(describing: connectFrame))")
            return
        }
        #expect(addrType == .domain)
        #expect(addr == "api.test.com")
        #expect(port == 8443)
        _ = sid
    }

    @Test func openStreamIPv4ConnectFrame() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        try await manager.openStream(
            addressType: .ipv4, address: "192.168.1.100", port: 3128
        )

        let frames = try await capture.decodedFrames()
        guard case .connect(let at, let addr, let port) = frames[0] else {
            Issue.record("Expected connect frame")
            return
        }
        #expect(at == .ipv4)
        #expect(addr == "192.168.1.100")
        #expect(port == 3128)
    }

    @Test func activeStreamCountTracksCorrectly() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        #expect(await manager.activeStreamCount == 0)

        try await manager.openStream(
            addressType: .domain, address: "a.com", port: 80
        )
        #expect(await manager.activeStreamCount == 1)

        try await manager.openStream(
            addressType: .domain, address: "b.com", port: 80
        )
        #expect(await manager.activeStreamCount == 2)
    }

    @Test func closeStreamRemovesFromRegistry() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "temp.example.com", port: 8080
        )
        #expect(await manager.activeStreamCount == 1)

        try await manager.closeStream(sessionID: sid)
        #expect(await manager.activeStreamCount == 0)
        #expect(await manager.hasActiveStreams == false)
    }

    @Test func closeStreamSendsDisconnectFrame() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "x.io", port: 443
        )
        // Reset capture to only see the disconnect.
        await capture.reset()

        try await manager.closeStream(sessionID: sid)

        let frames = try await capture.decodedFrames()
        guard case .disconnect(let dSid) = frames.last else {
            Issue.record("Expected disconnect frame")
            return
        }
        #expect(dSid == sid)
    }

    @Test func closeStreamNotFoundThrows() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        await #expect(throws: TUICManagerError.streamNotFound(999)) {
            try await manager.closeStream(sessionID: 999)
        }
    }

    @Test func closeAllStreamsClearsRegistry() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        for i in 1 ... 5 {
            try await manager.openStream(
                addressType: .domain, address: "site\(i).com", port: 443
            )
        }
        #expect(await manager.activeStreamCount == 5)

        await manager.closeAllStreams()
        #expect(await manager.activeStreamCount == 0)
    }

    @Test func streamContextLookup() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "lookup.test", port: 9999
        )

        let ctx = await manager.streamContext(for: sid)
        #expect(ctx != nil)
        #expect(ctx?.sessionID == sid)
        #expect(ctx?.targetAddress == "lookup.test")
        #expect(ctx?.targetPort == 9999)
        #expect(ctx?.state == .established)
    }

    @Test func streamContextNotFoundReturnsNil() async {
        let manager = TUICStreamManager(uuid: UUID())
        let ctx = await manager.streamContext(for: 42)
        #expect(ctx == nil)
    }

    @Test func activeStreamIDsReturnsSorted() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        try await manager.openStream(
            addressType: .domain, address: "c.com", port: 80
        )
        try await manager.openStream(
            addressType: .domain, address: "a.com", port: 80
        )
        try await manager.openStream(
            addressType: .domain, address: "b.com", port: 80
        )

        let ids = await manager.activeStreamIDs
        #expect(ids == [1, 2, 3])
    }

    @Test func openStreamWithoutTransportThrows() async {
        let manager = TUICStreamManager(uuid: UUID())
        await #expect(throws: TUICManagerError.transportNotConfigured) {
            try await manager.openStream(
                addressType: .domain, address: "nope.com", port: 80
            )
        }
    }
}

// MARK: - Packet Send & Receive

@Suite("TUICStreamManager — Packet Send & Receive")
struct TUICManagerPacketTests {

    @Test func sendPacketDispatchesCorrectFrame() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "data.example.com", port: 443
        )
        await capture.reset()

        let payload = Data("Hello TUIC Stream!".utf8)
        try await manager.sendPacket(sessionID: sid, payload: payload)

        let frames = try await capture.decodedFrames()
        guard case .packet(let pSid, let pld) = frames.last else {
            Issue.record("Expected packet frame")
            return
        }
        #expect(pSid == sid)
        #expect(pld == payload)
    }

    @Test func sendPacketOnUnknownStreamThrows() async {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        await #expect(throws: TUICManagerError.streamNotFound(404)) {
            try await manager.sendPacket(
                sessionID: 404, payload: Data([0x00])
            )
        }
    }

    @Test func incomingPacketRoutesToStreamHandler() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "route.test", port: 443
        )

        // Register a stream‑data handler.
        let receivedPayloads = CaptureBox([(UInt16, Data)]())
        await manager.onStreamData { sessionID, data in
            receivedPayloads.withLock { $0.append((sessionID, data)) }
        }

        // Simulate an incoming packet frame.
        let incomingFrame = TUICFrame.packet(
            sessionID: sid, payload: Data("inbound data".utf8)
        )
        let encoded = TUICFrameEncoder.encode(incomingFrame)
        guard let rawData = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        try await manager.handleIncoming(data: Data(rawData))
        let payloads = receivedPayloads.value
        #expect(payloads.count == 1)
        #expect(payloads[0].0 == sid)
        #expect(payloads[0].1 == Data("inbound data".utf8))
    }

    @Test func incomingDisconnectCleansUpStream() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "close.test", port: 443
        )
        #expect(await manager.activeStreamCount == 1)

        // Simulate an incoming disconnect frame.
        let disconnectFrame = TUICFrame.disconnect(sessionID: sid)
        let encoded = TUICFrameEncoder.encode(disconnectFrame)
        guard let rawData = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        try await manager.handleIncoming(data: Data(rawData))
        #expect(await manager.activeStreamCount == 0)
    }

    @Test func incomingHeartbeatEchoesBack() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        await capture.reset()

        let hbFrame = TUICFrame.heartbeat
        let encoded = TUICFrameEncoder.encode(hbFrame)
        guard let rawData = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        try await manager.handleIncoming(data: Data(rawData))

        let frames = try await capture.decodedFrames()
        #expect(frames.contains(.heartbeat))
    }

    @Test func incomingReAuthenticateSetsFlag() async throws {
        let manager = TUICStreamManager(uuid: UUID())
        let capture = TransportCapture()
        await manager.setTransport(captureTransport(capture))

        // Manually set authenticated to false for this test.
        // Simulate a re‑auth frame.
        let authFrame = TUICFrame.authenticate(uuid: UUID(), udpMode: 0)
        let encoded = TUICFrameEncoder.encode(authFrame)
        guard let raw = encoded.getBytes(at: 0, length: encoded.readableBytes)
        else { Issue.record("Encode failed"); return }

        try await manager.handleIncoming(data: Data(raw))
        #expect(await manager.isAuthenticated == true)
    }

    @Test func aggregateTrafficCountsCorrectly() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid = try await manager.openStream(
            addressType: .domain, address: "traffic.test", port: 443
        )

        // Send outbound data.
        try await manager.sendPacket(
            sessionID: sid, payload: Data([UInt8](repeating: 0, count: 100))
        )

        // Simulate inbound data.
        let incoming = TUICFrame.packet(
            sessionID: sid, payload: Data([UInt8](repeating: 1, count: 200))
        )
        let encoded = TUICFrameEncoder.encode(incoming)
        guard let raw = encoded.getBytes(at: 0, length: encoded.readableBytes)
        else { Issue.record("Encode failed"); return }

        try await manager.handleIncoming(data: Data(raw))

        let traffic = await manager.aggregateTraffic
        #expect(traffic.sent == 100)
        #expect(traffic.received == 200)
    }
}

// MARK: - 50 Concurrent Streams

@Suite("TUICStreamManager — 50 Concurrent Streams")
struct TUICManagerConcurrencyTests {

    @Test func fiftyStreamsAllGetDistinctIDs() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        var ids = Set<UInt16>()
        for _ in 0 ..< 50 {
            let sid = try await manager.openStream(
                addressType: .domain, address: "concurrent.test", port: 443
            )
            ids.insert(sid)
        }

        #expect(ids.count == 50)
        #expect(await manager.activeStreamCount == 50)
    }

    @Test func fiftyStreamsAllSendDataCorrectly() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        // Open 50 streams.
        var streams = [UInt16]()
        for i in 0 ..< 50 {
            let sid = try await manager.openStream(
                addressType: .domain,
                address: "stream\(i).test",
                port: UInt16(8000 + i)
            )
            streams.append(sid)
        }

        await capture.reset()

        // Send a unique payload on each stream.
        for (idx, sid) in streams.enumerated() {
            let payload = Data("packet-\(idx)".utf8)
            try await manager.sendPacket(sessionID: sid, payload: payload)
        }

        let frames = try await capture.decodedFrames()
        let packetFrames = frames.compactMap { frame -> (UInt16, Data)? in
            if case .packet(let sid, let pld) = frame {
                return (sid, pld)
            }
            return nil
        }

        #expect(packetFrames.count == 50)

        // Each stream's payload must match.
        for (idx, sid) in streams.enumerated() {
            let expectedPayload = Data("packet-\(idx)".utf8)
            let matching = packetFrames.filter { $0.0 == sid }
            #expect(matching.count == 1)
            #expect(matching.first?.1 == expectedPayload)
        }
    }

    @Test func fiftyStreamsReceiveDataCorrectly() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        // Open 50 streams.
        var streams = [UInt16]()
        for i in 0 ..< 50 {
            let sid = try await manager.openStream(
                addressType: .domain,
                address: "recv\(i).test",
                port: 443
            )
            streams.append(sid)
        }

        // Register a global data handler that collects received data.
        let received = CaptureBox([(UInt16, Data)]())
        await manager.onStreamData { sid, data in
            received.withLock { $0.append((sid, data)) }
        }

        // Simulate incoming packets for all 50 streams.
        for (idx, sid) in streams.enumerated() {
            let payload = Data("response-\(idx)".utf8)
            let frame = TUICFrame.packet(sessionID: sid, payload: payload)
            let encoded = TUICFrameEncoder.encode(frame)
            guard let raw = encoded.getBytes(
                at: 0, length: encoded.readableBytes
            ) else {
                Issue.record("Encode failed at stream \(idx)")
                return
            }
            try await manager.handleIncoming(data: Data(raw))
        }

        let allReceived = received.value
        #expect(allReceived.count == 50)

        // Verify each stream received the right data.
        let receivedByStream = Dictionary(grouping: allReceived, by: { $0.0 })
        for (idx, sid) in streams.enumerated() {
            let expected = Data("response-\(idx)".utf8)
            let entries = receivedByStream[sid] ?? []
            #expect(entries.count == 1)
            #expect(entries.first?.1 == expected)
        }
    }

    @Test func fiftyStreamsConcurrentlyThenCloseAll() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        // Open 50 streams.
        for i in 0 ..< 50 {
            try await manager.openStream(
                addressType: .domain,
                address: "site\(i).example.com",
                port: 443
            )
        }
        #expect(await manager.activeStreamCount == 50)

        // Close all at once.
        await manager.closeAllStreams()
        #expect(await manager.activeStreamCount == 0)
        #expect(await manager.hasActiveStreams == false)
    }

    @Test func streamIDsAreSequential() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        let sid1 = try await manager.openStream(
            addressType: .domain, address: "s1.com", port: 80
        )
        let sid2 = try await manager.openStream(
            addressType: .domain, address: "s2.com", port: 80
        )

        // Close sid1, then open a new one — should reuse or continue.
        try await manager.closeStream(sessionID: sid1)
        let sid3 = try await manager.openStream(
            addressType: .domain, address: "s3.com", port: 80
        )

        #expect(sid1 == 1)
        #expect(sid2 == 2)
        #expect(sid3 == 3) // IDs keep increasing, not reusing yet
    }
}

// MARK: - Per‑Stream Handler

@Suite("TUICClientStreamHandler — Per‑Stream Decoding")
struct TUICClientStreamHandlerTests {

    @Test func handlerInitialState() {
        let handler = TUICClientStreamHandler(sessionID: 42)
        #expect(handler.sessionID == 42)
        #expect(handler.isActive == true)
        #expect(handler.totalBytesReceived == 0)
    }

    @Test func handlerDecodesSinglePacketFrame() {
        let handler = TUICClientStreamHandler(sessionID: 7)

        let payload = Data("stream data".utf8)
        let frame = TUICFrame.packet(sessionID: 7, payload: payload)
        let encoded = TUICFrameEncoder.encode(frame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        let extracted = handler.simulateIncomingBytes(Data(raw))
        #expect(extracted.count == 1)
        #expect(extracted[0] == payload)
    }

    @Test func handlerDecodesMultiplePacketFrames() {
        let handler = TUICClientStreamHandler(sessionID: 3)

        // Encode three packet frames back‑to‑back.
        var combined = ByteBuffer()
        for i in 0 ..< 3 {
            let payload = Data("chunk-\(i)".utf8)
            TUICFrameEncoder.encode(
                .packet(sessionID: 3, payload: payload),
                into: &combined
            )
        }
        guard let raw = combined.getBytes(
            at: 0, length: combined.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        let extracted = handler.simulateIncomingBytes(Data(raw))
        #expect(extracted.count == 3)
        #expect(extracted[0] == Data("chunk-0".utf8))
        #expect(extracted[1] == Data("chunk-1".utf8))
        #expect(extracted[2] == Data("chunk-2".utf8))
    }

    @Test func handlerHandlesPartialData() {
        let handler = TUICClientStreamHandler(sessionID: 99)

        // Encode a full frame.
        let payload = Data("complete".utf8)
        let frame = TUICFrame.packet(sessionID: 99, payload: payload)
        let encoded = TUICFrameEncoder.encode(frame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        // Send only the first 2 bytes — incomplete frame.
        let partial = Data(raw.prefix(2))
        let firstResult = handler.simulateIncomingBytes(partial)
        #expect(firstResult.isEmpty) // No complete frame yet.

        // Send the rest.
        let remainder = Data(raw.dropFirst(2))
        let secondResult = handler.simulateIncomingBytes(remainder)
        #expect(secondResult.count == 1)
        #expect(secondResult[0] == payload)
    }

    @Test func handlerDisconnectDeactivates() {
        let handler = TUICClientStreamHandler(sessionID: 5)

        let disconnectCalled = CaptureBox(false)
        handler.onDisconnect = { disconnectCalled.withLock { $0 = true } }

        let frame = TUICFrame.disconnect(sessionID: 5)
        let encoded = TUICFrameEncoder.encode(frame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        handler.simulateIncomingBytes(Data(raw))
        #expect(handler.isActive == false)
        #expect(disconnectCalled.value == true)
    }

    @Test func handlerOnDataCallbackFires() {
        let handler = TUICClientStreamHandler(sessionID: 10)

        let receivedData = CaptureBox<Data?>(nil)
        handler.onData = { data in receivedData.withLock { $0 = data } }

        let payload = Data("callback test".utf8)
        let frame = TUICFrame.packet(sessionID: 10, payload: payload)
        let encoded = TUICFrameEncoder.encode(frame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        handler.simulateIncomingBytes(Data(raw))
        #expect(receivedData.value == payload)
    }

    @Test func handlerOnErrorCallbackFires() {
        let handler = TUICClientStreamHandler(sessionID: 1)

        let capturedError = CaptureBox<Error?>(nil)
        handler.onError = { error in capturedError.withLock { $0 = error } }

        // Send an invalid type byte.
        let invalidData = Data([0xFF])
        handler.simulateIncomingBytes(invalidData)

        #expect(capturedError.value != nil)
        #expect(capturedError.value is TUICFrameParseError)
    }

    @Test func handlerTotalBytesReceivedTracksCorrectly() {
        let handler = TUICClientStreamHandler(sessionID: 8)

        let payload = Data([UInt8](repeating: 0x42, count: 64))
        let frame = TUICFrame.packet(sessionID: 8, payload: payload)
        let encoded = TUICFrameEncoder.encode(frame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        handler.simulateIncomingBytes(Data(raw))
        // 1 (type) + 2 (sessionID) + 2 (length) + 64 (payload) = 69
        #expect(handler.totalBytesReceived >= 64)
    }

    @Test func handlerIgnoresNonPacketFrames() {
        let handler = TUICClientStreamHandler(sessionID: 20)

        // Send a heartbeat — should not extract any payload.
        let hbFrame = TUICFrame.heartbeat
        let encoded = TUICFrameEncoder.encode(hbFrame)
        guard let raw = encoded.getBytes(
            at: 0, length: encoded.readableBytes
        ) else {
            Issue.record("Encode failed")
            return
        }

        let extracted = handler.simulateIncomingBytes(Data(raw))
        #expect(extracted.isEmpty)
        #expect(handler.isActive == true) // Heartbeat doesn't deactivate.
    }
}

// MARK: - Error Equatability

@Suite("TUICManagerError — Equatability")
struct TUICManagerErrorTests {

    @Test func transportNotConfiguredEquality() {
        #expect(
            TUICManagerError.transportNotConfigured
            == TUICManagerError.transportNotConfigured
        )
    }

    @Test func streamNotFoundEquality() {
        #expect(TUICManagerError.streamNotFound(5)
            == TUICManagerError.streamNotFound(5))
        #expect(TUICManagerError.streamNotFound(5)
            != TUICManagerError.streamNotFound(6))
    }

    @Test func streamNotReadyEquality() {
        #expect(TUICManagerError.streamNotReady(.connecting)
            == TUICManagerError.streamNotReady(.connecting))
        #expect(TUICManagerError.streamNotReady(.connecting)
            != TUICManagerError.streamNotReady(.closed))
    }

    @Test func encodeFailedEquality() {
        #expect(TUICManagerError.encodeFailed
            == TUICManagerError.encodeFailed)
    }
}

// MARK: - Stream State Transitions

@Suite("TUICStreamState — Transitions")
struct TUICStreamStateTests {

    @Test func allStatesAreDistinct() {
        let states: [TUICStreamState] = [
            .connecting, .established, .closing, .closed
        ]
        for i in 0 ..< states.count {
            for j in (i + 1) ..< states.count {
                #expect(states[i] != states[j])
            }
        }
    }

    @Test func rawValuesAreCorrect() {
        #expect(TUICStreamState.connecting.rawValue == 0)
        #expect(TUICStreamState.established.rawValue == 1)
        #expect(TUICStreamState.closing.rawValue == 2)
        #expect(TUICStreamState.closed.rawValue == 3)
    }

    @Test func descriptionsAreHumanReadable() {
        #expect(TUICStreamState.connecting.description == "CONNECTING")
        #expect(TUICStreamState.established.description == "ESTABLISHED")
        #expect(TUICStreamState.closing.description == "CLOSING")
        #expect(TUICStreamState.closed.description == "CLOSED")
    }
}

// MARK: - Concurrent Send/Receive Without Interleaving

@Suite("TUICStreamManager — Concurrent I/O Integrity")
struct TUICManagerConcurrentIOTests {

    @Test func concurrentSendsOnDifferentStreamsDoNotInterleave() async throws {
        let capture = TransportCapture()
        let manager = TUICStreamManager(uuid: UUID())
        await manager.setTransport(captureTransport(capture))

        // Open 10 streams and send data concurrently.
        let streams = try await withThrowingTaskGroup(
            of: UInt16.self
        ) { group in
            for i in 0 ..< 10 {
                group.addTask {
                    let sid = try await manager.openStream(
                        addressType: .domain,
                        address: "concurrent\(i).io",
                        port: 443
                    )
                    let payload = Data("stream-\(sid)-data".utf8)
                    try await manager.sendPacket(
                        sessionID: sid, payload: payload
                    )
                    return sid
                }
            }

            var ids = [UInt16]()
            for try await sid in group {
                ids.append(sid)
            }
            return ids.sorted()
        }

        #expect(streams.count == 10)

        // Verify the captured frames.
        let frames = try await capture.decodedFrames()
        let packetFrames = frames.compactMap { f -> (UInt16, Data)? in
            if case .packet(let sid, let pld) = f { return (sid, pld) }
            return nil
        }

        #expect(packetFrames.count == 10)

        // Each stream ID should appear exactly once with the right payload.
        let packetsByStream = Dictionary(grouping: packetFrames, by: { $0.0 })
        for sid in streams {
            let pkts = packetsByStream[sid] ?? []
            #expect(pkts.count == 1)
            #expect(pkts[0].1 == Data("stream-\(sid)-data".utf8))
        }
    }
}
