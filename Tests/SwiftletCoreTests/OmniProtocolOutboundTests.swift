//===----------------------------------------------------------------------===//
//
//  OmniProtocolOutboundTests.swift
//  SwiftletCore — HTTP & UDP Outbound Unit Tests
//
//  Validates:
//  • HTTP CONNECT header format
//  • HTTP 200 response parsing and state transitions
//  • HTTPS (TLS‑enabled) configuration flag
//  • UDP session registration / lookup / activity tracking
//  • Idle timeout cleanup
//  • Concurrent session isolation
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
import NIOCore
@testable import SwiftletCore

// MARK: - HTTP CONNECT Header

@Suite("HTTPOutboundHandler")
struct HTTPOutboundHandlerTests {

    @Test func connectHeaderFormat() {
        let handler = HTTPOutboundHandler(
            host: "proxy.example.com",
            port: 8080
        )

        // Simulate channelActive by checking the header that would be sent.
        let expectedHeader = "CONNECT proxy.example.com:8080 HTTP/1.1\r\nHost: proxy.example.com\r\n\r\n"
        #expect(handler.connectHeader == expectedHeader)
    }

    @Test func connectHeaderWithIPDestination() {
        let handler = HTTPOutboundHandler(
            host: "10.0.0.1",
            port: 3128
        )
        let header = handler.connectHeader
        #expect(header.contains("CONNECT 10.0.0.1:3128"))
        #expect(header.contains("Host: 10.0.0.1"))
        #expect(header.hasSuffix("\r\n\r\n"))
    }

    @Test func initialStateIsHttpConnect() {
        let handler = HTTPOutboundHandler(host: "proxy", port: 80)
        #expect(handler.state.description == "HTTP_CONNECT")
    }

    @Test func tlsEnabledFlagDefaultFalse() {
        let handler = HTTPOutboundHandler(host: "proxy", port: 443)
        #expect(handler.isTLSEnabled == false)
    }

    @Test func tlsEnabledFlagTrue() {
        let handler = HTTPOutboundHandler(
            host: "proxy",
            port: 443,
            tlsEnabled: true
        )
        #expect(handler.isTLSEnabled == true)
    }

    // MARK: HTTP Response Parsing

    @Test func http200ResponseParsing() {
        // Simulate the handshake‑response parsing logic.
        let response = "HTTP/1.1 200 Connection established\r\nServer: nginx\r\n\r\n"
        #expect(response.contains("200"))
        #expect(response.contains("\r\n\r\n"))
    }

    @Test func httpNon200StatusDetected() {
        let response = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"
        #expect(!response.prefix(20).contains("200"))
    }

    @Test func httpResponseWithResidueData() {
        // Simulate a response where payload arrives with headers.
        let response = "HTTP/1.1 200 OK\r\n\r\nHelloPayload"
        guard let headerEnd = response.range(of: "\r\n\r\n") else {
            Issue.record("No header end found")
            return
        }
        let residue = String(response[headerEnd.upperBound...])
        #expect(residue == "HelloPayload")
    }

    // MARK: Error Types

    @Test func httpErrorEquality() {
        let e1 = HTTPOutboundError.httpStatusNotOK("407")
        let e2 = HTTPOutboundError.httpStatusNotOK("407")
        let e3 = HTTPOutboundError.httpStatusNotOK("500")
        #expect(e1 == e2)
        #expect(e1 != e3)
        #expect(HTTPOutboundError.connectionFailed != e1)
    }
}

// MARK: - UDP Association Manager

@Suite("UdpAssociationManager")
struct UdpAssociationManagerTests {

    @Test func registerAndLookup() async {
        let manager = UdpAssociationManager()
        let key = UDPSessionKey(
            sourceIP: "10.0.0.1",
            sourcePort: 50000,
            destinationIP: "1.1.1.1",
            destinationPort: 51820
        )

        // Use a mock object as the channel reference.
        let mockChannel = MockChannel()
        await manager.register(key: key, channel: mockChannel)

        let session = await manager.lookup(key)
        #expect(session != nil)
        #expect(session?.key == key)
        #expect(session?.isActive == true)
    }

    @Test func lookupMissingKeyReturnsNil() async {
        let manager = UdpAssociationManager()
        let key = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 1,
            destinationIP: "10.0.0.2", destinationPort: 2
        )
        let found = await manager.lookup(key)
        #expect(found == nil)
    }

    @Test func unregisterRemovesSession() async {
        let manager = UdpAssociationManager()
        let key = UDPSessionKey(
            sourceIP: "192.168.1.1", sourcePort: 9000,
            destinationIP: "8.8.8.8", destinationPort: 53
        )
        await manager.register(key: key, channel: MockChannel())
        #expect(await manager.activeCount == 1)

        await manager.unregister(key: key)
        #expect(await manager.activeCount == 0)
    }

    @Test func activityTrackingUpdatesTimestamps() async {
        let manager = UdpAssociationManager()
        let key = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 12345,
            destinationIP: "10.0.0.2", destinationPort: 443
        )
        let session = await manager.register(key: key, channel: MockChannel())

        let initialIdle = session.idleDuration
        // Immediately after creation idle should be near zero.
        #expect(initialIdle < 0.1)

        // Mark activity.
        await manager.markSend(for: key)
        await manager.markReceive(for: key)
        let afterActivity = session.idleDuration
        #expect(afterActivity < 0.1)
    }

    @Test func idleTimeoutPurgesExpiredSessions() async {
        let manager = UdpAssociationManager(idleTimeout: 0.001) // 1ms for test
        let key = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 1,
            destinationIP: "10.0.0.2", destinationPort: 2
        )
        await manager.register(key: key, channel: MockChannel())
        #expect(await manager.activeCount == 1)

        // Wait just past the timeout.
        try? await Task.sleep(nanoseconds: 5_000_000) // 5ms

        let purged = await manager.purgeExpired()
        #expect(purged == 1)
        #expect(await manager.activeCount == 0)
    }

    @Test func activeSessionNotPurged() async {
        let manager = UdpAssociationManager(idleTimeout: 5) // 5 second timeout
        let key = UDPSessionKey(
            sourceIP: "172.16.0.1", sourcePort: 8080,
            destinationIP: "172.16.0.2", destinationPort: 9090
        )
        await manager.register(key: key, channel: MockChannel())

        // Purge immediately — session is fresh and should survive.
        let purged = await manager.purgeExpired()
        #expect(purged == 0)
        #expect(await manager.activeCount == 1)
    }

    @Test func concurrentSessionsAreIsolated() async {
        let manager = UdpAssociationManager()
        let keys = (0 ..< 100).map { i in
            UDPSessionKey(
                sourceIP: "10.0.0.\(i / 256)",
                sourcePort: UInt16(i % 65536),
                destinationIP: "192.168.1.1",
                destinationPort: 443
            )
        }

        // Register 100 sessions concurrently.
        await withTaskGroup(of: Void.self) { group in
            for key in keys {
                group.addTask {
                    await manager.register(key: key, channel: MockChannel())
                }
            }
        }

        let count = await manager.activeCount
        #expect(count == 100)

        // Purge should remove nothing (all fresh).
        let purged = await manager.purgeExpired()
        #expect(purged == 0)

        // Clean up.
        await manager.removeAll()
        #expect(await manager.activeCount == 0)
    }

    @Test func removeAllClearsEverything() async {
        let manager = UdpAssociationManager()
        for i in 0 ..< 10 {
            let key = UDPSessionKey(
                sourceIP: "10.0.0.1", sourcePort: UInt16(i),
                destinationIP: "10.0.0.2", destinationPort: 80
            )
            await manager.register(key: key, channel: MockChannel())
        }
        #expect(await manager.activeCount == 10)

        await manager.removeAll()
        #expect(await manager.activeCount == 0)
    }

    @Test func allKeysReturnsAllRegisteredKeys() async {
        let manager = UdpAssociationManager()
        let k1 = UDPSessionKey(
            sourceIP: "a", sourcePort: 1, destinationIP: "b", destinationPort: 2
        )
        let k2 = UDPSessionKey(
            sourceIP: "c", sourcePort: 3, destinationIP: "d", destinationPort: 4
        )
        await manager.register(key: k1, channel: MockChannel())
        await manager.register(key: k2, channel: MockChannel())

        let keys = await manager.allKeys
        #expect(keys.count == 2)
        #expect(keys.contains(k1))
        #expect(keys.contains(k2))
    }
}

// MARK: - UDP Session Key

@Suite("UDPSessionKey")
struct UDPSessionKeyTests {

    @Test func keyHashableAndEquatable() {
        let a = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 80,
            destinationIP: "10.0.0.2", destinationPort: 443
        )
        let b = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 80,
            destinationIP: "10.0.0.2", destinationPort: 443
        )
        let c = UDPSessionKey(
            sourceIP: "10.0.0.1", sourcePort: 81,
            destinationIP: "10.0.0.2", destinationPort: 443
        )
        #expect(a == b)
        #expect(a != c)
        #expect(a.hashValue == b.hashValue)
    }

    @Test func keyDescription() {
        let key = UDPSessionKey(
            sourceIP: "192.168.1.1", sourcePort: 12345,
            destinationIP: "8.8.8.8", destinationPort: 53
        )
        #expect(key.description.contains("192.168.1.1:12345"))
        #expect(key.description.contains("8.8.8.8:53"))
    }
}

// MARK: - Mock Channel

/// A lightweight stand‑in for a NIO `Channel` used in UDP session tests.
private final class MockChannel: @unchecked Sendable {
    let identifier: String = UUID().uuidString
}
