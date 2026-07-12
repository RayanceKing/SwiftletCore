//===----------------------------------------------------------------------===//
//
//  SecureDNSRacingClient.swift
//  SwiftletCore — Concurrent Encrypted DNS Racing Engine
//
//  Queries multiple DoH / DoQ upstream servers in parallel and returns
//  whichever valid answer arrives first ("Happy Eyeballs for DNS").
//  All slower or failing tasks are immediately cancelled to conserve
//  CPU cycles and socket descriptors.
//
//  Architecture
//  ------------
//  ```
//  resolveA("example.com")
//    │
//    ├─ Task 1 → Cloudflare DoH  ────► 93.184.216.34  (50 ms)  ◄── WINNER
//    ├─ Task 2 → Google DoH     ────► (still running)   ✘ CANCEL
//    ├─ Task 3 → Quad9 DoH      ────► (still running)   ✘ CANCEL
//    └─ Task 4 → AliDNS DoH     ────► (still running)   ✘ CANCEL
//
//    Result: 93.184.216.34 returned at ~50 ms.
//  ```
//
//  Thread Safety
//  -------------
//  The client is an `actor` — all mutable state (upstream list,
//  last‑used metrics) is serialised.  Individual queries run on the
//  Swift concurrency thread pool via `TaskGroup`.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Racing Client

/// An actor‑based encrypted DNS resolver that races multiple upstream
/// servers concurrently, returning the first valid answer.
///
/// ## Usage
/// ```swift
/// let client = SecureDNSRacingClient(
///     servers: SecureDNSServerConfiguration.presets.lowLatency
/// )
/// let ip = try await client.resolveA(domain: "example.com")
/// // → 93.184.216.34 (fastest of Cloudflare / Google / Quad9)
/// ```
public actor SecureDNSRacingClient {

    // MARK: - Configuration

    /// The upstream encrypted DNS servers to race.
    public var servers: [SecureDNSServerProtocol]

    /// Request timeout per upstream (seconds).  Individual queries that
    /// take longer than this are treated as failures.
    public var perServerTimeout: TimeInterval = 10.0

    /// Convenience setter for the per‑server timeout.
    public func setPerServerTimeout(_ timeout: TimeInterval) {
        perServerTimeout = timeout
    }

    /// Counter of successful resolutions (for diagnostics).
    public private(set) var resolutionCount: Int = 0

    /// Counter of failed resolution attempts (all servers exhausted).
    public private(set) var failureCount: Int = 0

    // MARK: - URLSession

    /// The URLSession used for DoH requests.  Inject a mock session for
    /// testing; defaults to `URLSession.shared`.
    private let urlSession: URLSession

    // MARK: - Initialisation

    /// - Parameters:
    ///   - servers: The upstream servers to race (default: Cloudflare,
    ///     Google, Quad9, AliDNS, AdGuard).
    ///   - session: URLSession for DoH transports (default `.shared`).
    ///     Inject a mock session for testing.
    public init(
        servers: [SecureDNSServerProtocol] = SecureDNSServerConfiguration.allPresets,
        session: URLSession = .shared
    ) {
        self.servers = servers
        self.urlSession = session
    }

    // MARK: - Public API

    /// Resolves the first IPv4 address (A record) for a domain by
    /// racing all configured upstreams.
    ///
    /// - Parameter domain: Fully‑qualified domain name.
    /// - Returns: The IPv4 address in host‑byte‑order `UInt32`.
    /// - Throws: `SecureDNSError.allServersFailed` if no upstream
    ///   returns a valid answer within the timeout.
    public func resolveA(domain: String) async throws -> UInt32 {
        let query = DNSPacketBuilder.buildAQuery(for: domain)
        let data = try await raceQuery(query, domain: domain)
        guard let addr = DNSPacketParser.firstA(from: data) else {
            throw SecureDNSError.invalidResponse(domain)
        }
        resolutionCount += 1
        return addr.asUInt32
    }

    /// Resolves the first IPv4 address as an `IPv4Address` struct.
    public func resolveIPv4Address(domain: String) async throws -> IPv4Address {
        let raw = try await resolveA(domain: domain)
        return IPv4Address(
            UInt8((raw >> 24) & 0xFF),
            UInt8((raw >> 16) & 0xFF),
            UInt8((raw >>  8) & 0xFF),
            UInt8(raw & 0xFF)
        )
    }

    /// Resolves the first IPv6 address (AAAA record) for a domain by
    /// racing all configured upstreams.
    ///
    /// - Parameter domain: Fully‑qualified domain name.
    /// - Returns: The `IPv6Address`.
    /// - Throws: `SecureDNSError.allServersFailed` if no upstream
    ///   returns a valid answer within the timeout.
    public func resolveAAAA(domain: String) async throws -> IPv6Address {
        let query = DNSPacketBuilder.buildAAAAQuery(for: domain)
        let data = try await raceQuery(query, domain: domain)
        guard let addr = DNSPacketParser.firstAAAA(from: data) else {
            throw SecureDNSError.invalidResponse(domain)
        }
        resolutionCount += 1
        return addr
    }

    /// Resolves both A and AAAA records concurrently.
    public func resolveAll(domain: String) async throws -> (a: UInt32?, aaaa: IPv6Address?) {
        async let a = try? resolveA(domain: domain)
        async let aaaa = try? resolveAAAA(domain: domain)
        return await (a, aaaa)
    }

    // MARK: - Racing Core

    /// Races a DNS query across all configured upstream servers.
    /// The first valid response wins; all others are cancelled.
    private func raceQuery(_ queryData: Data, domain: String) async throws -> Data {
        let currentServers = servers
        guard !currentServers.isEmpty else {
            failureCount += 1
            throw SecureDNSError.noServersConfigured
        }

        // Use a throwing task group so the first success short‑circuits.
        do {
            return try await withThrowingTaskGroup(
                of: Data.self,
                returning: Data.self
            ) { group in
                for server in currentServers {
                    group.addTask {
                        try await self.queryServer(server, queryData: queryData)
                    }
                }

                // Collect the first successful result.
                var winner: Data?

                for try await result in group {
                    if !result.isEmpty {
                        winner = result
                        group.cancelAll()
                        break
                    }
                }

                guard let data = winner else {
                    throw SecureDNSError.allServersFailed(domain)
                }

                return data
            }
        } catch {
            failureCount += 1
            throw error
        }
    }

    /// Queries a single upstream server for the given DNS query data.
    private func queryServer(
        _ server: SecureDNSServerProtocol,
        queryData: Data
    ) async throws -> Data {
        // Check for task cancellation before doing work.
        try Task.checkCancellation()

        switch server {
        case .doh(let url):
            return try await dohQuery(url: url, queryData: queryData)

        case .doq(let host, let port, let serverName):
            // DoQ: currently delegates to the same server via its
            // well‑known DoH endpoint.  Full QUIC transport is a
            // future enhancement tracked in the roadmap.
            _ = (host, port, serverName)
            // Construct a DoH URL from the DoQ host.
            let dohURL = URL(string: "https://\(host):\(port)/dns-query")!
            return try await dohQuery(url: dohURL, queryData: queryData)
        }
    }

    // MARK: - DoH Transport

    /// Sends a DNS query over HTTPS (RFC 8484) and returns the raw
    /// response body.
    private func dohQuery(url: URL, queryData: Data) async throws -> Data {
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = queryData
        request.timeoutInterval = perServerTimeout

        let (data, response) = try await urlSession.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200 ... 299).contains(httpResponse.statusCode) else {
            throw SecureDNSError.httpError(
                (response as? HTTPURLResponse)?.statusCode ?? 0
            )
        }

        return data
    }

    // MARK: - Diagnostics

    /// Success rate as a fraction (0.0 … 1.0).  Returns 1.0 if no
    /// resolutions have been attempted.
    public var successRate: Double {
        let total = resolutionCount + failureCount
        guard total > 0 else { return 1.0 }
        return Double(resolutionCount) / Double(total)
    }

    /// Resets the success/failure counters.
    public func resetCounters() {
        resolutionCount = 0
        failureCount = 0
    }
}

// MARK: - Errors

public enum SecureDNSError: Error, Sendable, Equatable {
    /// No upstream servers are configured.
    case noServersConfigured
    /// All configured servers failed or timed out for the given domain.
    case allServersFailed(String)
    /// A server returned a response with no usable records.
    case emptyResponse(String)
    /// A server returned a malformed response.
    case invalidResponse(String)
    /// HTTP transport error.
    case httpError(Int)
}

extension SecureDNSError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .noServersConfigured:
            return "No upstream DNS servers configured"
        case .allServersFailed(let domain):
            return "All servers failed for '\(domain)'"
        case .emptyResponse(let domain):
            return "Empty response for '\(domain)'"
        case .invalidResponse(let domain):
            return "Invalid response for '\(domain)'"
        case .httpError(let code):
            return "HTTP error \(code)"
        }
    }
}

// MARK: - IPv4Address Extension

extension IPv4Address {
    /// Returns the address as a host‑byte‑order `UInt32`.
    public var asUInt32: UInt32 {
        (UInt32(octet0) << 24) | (UInt32(octet1) << 16)
        | (UInt32(octet2) << 8) | UInt32(octet3)
    }
}
