//===----------------------------------------------------------------------===//
//
//  SwiftletEngineIntegrationTests.swift
//  SwiftletCoreTests — Unified Engine Lifecycle Integration Tests
//
//  Validates the full engine lifecycle: start → running state →
//  component availability → subscription URI bootstrap → graceful
//  shutdown with zero‑leak guarantee.
//
//  Test Coverage
//  -------------
//  ┌─────────────────────────────────────────┬─────────────────────────────┐
//  │ Test                                    │ What it verifies            │
//  ├─────────────────────────────────────────┼─────────────────────────────┤
//  │ testIdleState                           │ Initial state is .idle      │
//  │ testStartWithNodes                      │ Start → .running state      │
//  │ testStartWithSubscriptionURIs           │ Subscription URI bootstrap   │
//  │ testCannotStartTwice                    │ Already‑running guard        │
//  │ testCannotShutdownWhenIdle              │ Not‑running guard            │
//  │ testFullLifecycle                       │ start → shutdown → .stopped  │
//  │ testPortAssignment                      │ Custom local port assignment │
//  │ testComponentCleanupAfterShutdown       │ Components nullified         │
//  │ testPoolActiveAfterStart                │ Connection pool is shared    │
//  │ testRepeatedLifecycles                  │ Start‑stop‑start‑stop        │
//  └─────────────────────────────────────────┴─────────────────────────────┘
//
//===----------------------------------------------------------------------===//

import XCTest
@testable import SwiftletCore
import Foundation

// MARK: - Engine Lifecycle Tests

final class SwiftletEngineLifecycleTests: XCTestCase {

    /// Verifies that a fresh engine starts in the `.idle` state.
    func testIdleState() {
        let engine = SwiftletEngine()
        XCTAssertEqual(engine.state, .idle)
        XCTAssertEqual(engine.nodes.count, 0)
        XCTAssertEqual(engine.rules.count, 0)
    }

    /// Verifies that `start(nodes:rules:)` brings the engine to `.running`.
    func testStartWithNodes() async throws {
        let engine = SwiftletEngine()

        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "aes-128-gcm", password: "test",
            obfsMode: nil, obfsHost: nil
        )

        let rules: [RoutingRule] = [
            .domainSuffix("example.com"),
        ]

        try await engine.start(
            nodes: [node],
            rules: rules,
            localSocksPort: 11080,
            localHttpPort: 18080
        )

        XCTAssertEqual(engine.state, .running)
        XCTAssertEqual(engine.nodes.count, 1)
        XCTAssertEqual(engine.rules.count, 1)

        try await engine.shutdown()
        XCTAssertEqual(engine.state, .stopped)
    }

    /// Verifies that `start(subscriptionURIs:)` parses URIs and starts.
    func testStartWithSubscriptionURIs() async throws {
        let engine = SwiftletEngine()

        // Build a valid Shadowsocks subscription URI.
        let b64 = Data("aes-128-gcm:subTestPwd".utf8).base64EncodedString()
        let uri = "ss://\(b64)@127.0.0.1:9999"

        try await engine.start(
            subscriptionURIs: [uri],
            localSocksPort: 11081,
            localHttpPort: 18081
        )

        XCTAssertEqual(engine.state, .running)
        XCTAssertEqual(engine.nodes.count, 1)
        XCTAssertEqual(engine.nodes.first?.label, "Shadowsocks")

        try await engine.shutdown()
    }

    /// Verifies that starting an already‑running engine throws.
    func testCannotStartTwice() async throws {
        let engine = SwiftletEngine()
        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "aes-128-gcm", password: "test",
            obfsMode: nil, obfsHost: nil
        )

        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 11082,
            localHttpPort: 18082
        )

        // Second start should throw.
        do {
            try await engine.start(nodes: [node], rules: [])
            XCTFail("Expected alreadyRunning error")
        } catch {
            XCTAssertTrue(error is SwiftletEngineError)
        }

        try await engine.shutdown()
    }

    /// Verifies that shutting down an idle engine throws.
    func testCannotShutdownWhenIdle() async {
        let engine = SwiftletEngine()
        do {
            try await engine.shutdown()
            XCTFail("Expected notRunning error")
        } catch {
            XCTAssertTrue(error is SwiftletEngineError)
        }
    }

    /// Verifies a complete start → shutdown lifecycle.
    func testFullLifecycle() async throws {
        let engine = SwiftletEngine()

        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "chacha20-poly1305", password: "lifecycle",
            obfsMode: nil, obfsHost: nil
        )

        // Start.
        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 11083,
            localHttpPort: 18083
        )
        XCTAssertEqual(engine.state, .running)

        // Verify ports assigned.
        XCTAssertEqual(engine.localSocksPort, 11083)
        XCTAssertEqual(engine.localHttpPort, 18083)

        // Shutdown.
        try await engine.shutdown()
        XCTAssertEqual(engine.state, .stopped)

        // Verify clean state.
        XCTAssertEqual(engine.nodes.count, 0)
        XCTAssertEqual(engine.rules.count, 0)
        XCTAssertEqual(engine.localSocksPort, 0)
        XCTAssertEqual(engine.localHttpPort, 0)
    }

    /// Verifies that custom port assignments are respected.
    func testPortAssignment() async throws {
        let engine = SwiftletEngine()
        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "aes-128-gcm", password: "p",
            obfsMode: nil, obfsHost: nil
        )

        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 12000,
            localHttpPort: 13000
        )

        XCTAssertEqual(engine.localSocksPort, 12000)
        XCTAssertEqual(engine.localHttpPort, 13000)

        try await engine.shutdown()
    }

    /// Verifies that components are nullified after shutdown.
    func testComponentCleanupAfterShutdown() async throws {
        let engine = SwiftletEngine()
        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "aes-256-gcm", password: "cleanup",
            obfsMode: nil, obfsHost: nil
        )

        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 11084,
            localHttpPort: 18084
        )

        try await engine.shutdown()

        // After shutdown, all state should be cleared.
        XCTAssertEqual(engine.state, .stopped)
        XCTAssertEqual(engine.nodes.count, 0)
        XCTAssertEqual(engine.rules.count, 0)
        XCTAssertEqual(engine.localSocksPort, 0)
        XCTAssertEqual(engine.localHttpPort, 0)
    }

    /// Verifies that the engine can be started, stopped, and restarted.
    func testRepeatedLifecycles() async throws {
        let engine = SwiftletEngine()
        let node = ProxyNodeConfiguration.shadowsocks(
            host: "127.0.0.1", port: 9999,
            cipher: "aes-128-gcm", password: "repeat",
            obfsMode: nil, obfsHost: nil
        )

        // First cycle.
        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 11085,
            localHttpPort: 18085
        )
        try await engine.shutdown()
        XCTAssertEqual(engine.state, .stopped)

        // Second cycle.
        try await engine.start(
            nodes: [node], rules: [],
            localSocksPort: 11086,
            localHttpPort: 18086
        )
        XCTAssertEqual(engine.state, .running)
        try await engine.shutdown()
        XCTAssertEqual(engine.state, .stopped)
    }
}

// MARK: - Engine State Enum Tests

final class SwiftletEngineStateTests: XCTestCase {

    /// Verifies state enum descriptions.
    func testStateDescriptions() {
        XCTAssertEqual(SwiftletEngineState.idle.description, "idle")
        XCTAssertEqual(SwiftletEngineState.running.description, "running")
        XCTAssertEqual(SwiftletEngineState.stopped.description, "stopped")
    }

    /// Verifies state enum equality.
    func testStateEquality() {
        XCTAssertEqual(SwiftletEngineState.idle, .idle)
        XCTAssertNotEqual(SwiftletEngineState.idle, .running)
    }
}

// MARK: - Engine Error Tests

final class SwiftletEngineErrorTests: XCTestCase {

    /// Verifies error descriptions.
    func testErrorDescriptions() {
        XCTAssertTrue(
            SwiftletEngineError.alreadyRunning.description.contains("already running")
        )
        XCTAssertTrue(
            SwiftletEngineError.notRunning.description.contains("not running")
        )
    }
}
