//===----------------------------------------------------------------------===//
//
//  AsyncDNSResolver.swift
//  SwiftletCore — Async DNS Client with TTL Cache
//
//  A lightweight, concurrent DNS resolver built on `Network.framework` (UDP)
//  and `URLSession` (DoH).  It supports A and AAAA record lookups, includes
//  a local in‑memory cache with RFC‑compliant TTL countdown, and is driven
//  entirely by Swift's `async/await` structured concurrency.
//
//  Supported transports
//  --------------------
//  • UDP (port 53) — fast, traditional DNS
//  • DoH (port 443) — DNS‑over‑HTTPS, works through restrictive firewalls
//
//===----------------------------------------------------------------------===//

import Foundation
import Network

// MARK: - DNS Record

/// A single resource record returned by a DNS query.
public enum DNSRecord: Sendable, Equatable {
    /// An IPv4 address (A record).
    case a(IPv4Address, ttl: UInt32)
    /// An IPv6 address (AAAA record).
    case aaaa(IPv6Address, ttl: UInt32)
}

// MARK: - DNS Resolver

/// An async DNS resolver that caches results with TTL expiry.
///
/// All mutable state is protected by the actor's serial executor, so
/// callers may issue concurrent `resolveA` / `resolveAAAA` requests
/// without additional synchronisation.
public actor AsyncDNSResolver {

    // MARK: - Configuration

    /// Upstream DNS server address.
    private let upstreamServer: String
    /// Preferred transport.
    private let transport: DNSTransport
    /// Optional secure racing client for high‑priority encrypted DNS.
    /// When set, every resolution attempt will race this client's
    /// upstreams first.  Only if all racing servers fail does the
    /// resolver fall back to the configured `transport`.
    public var secureRacingClient: SecureDNSRacingClient?
    /// If `true` (default), fall back to the legacy transport when
    /// the secure racing client fails.
    public var secureRacingFallback: Bool = true

    /// Convenience setter for the racing client and fallback flag.
    public func setSecureRacingClient(_ client: SecureDNSRacingClient?,
                                       fallback: Bool = true) {
        secureRacingClient = client
        secureRacingFallback = fallback
    }

    public enum DNSTransport: Sendable {
        case udp(port: UInt16 = 53)
        case doh(url: String = "https://1.1.1.1/dns-query")
    }

    // MARK: - Cache

    private struct CacheKey: Hashable, Sendable {
        let domain: String
        let recordType: UInt16  // 1 = A, 28 = AAAA
    }

    private struct CacheEntry: Sendable {
        let records: [DNSRecord]
        let expiresAt: Date
        var isExpired: Bool { Date() > expiresAt }
    }

    private var cache: [CacheKey: CacheEntry] = [:]

    // MARK: - Initialisation

    /// - Parameters:
    ///   - upstream: IP address of the upstream DNS server (default `"1.1.1.1"`).
    ///   - transport: Transport protocol to use (default `.udp`).
    public init(
        upstream: String = "1.1.1.1",
        transport: DNSTransport = .udp()
    ) {
        self.upstreamServer = upstream
        self.transport = transport
    }

    // MARK: - Public API

    /// Resolves the IPv4 address (A record) for the given domain.
    /// - Returns: The first A record, or `nil` if none exists.
    public func resolveA(_ domain: String) async throws -> IPv4Address? {
        let records = try await resolve(domain, recordType: 1) // A = 1
        for record in records {
            if case .a(let addr, _) = record { return addr }
        }
        return nil
    }

    /// Resolves the IPv6 address (AAAA record) for the given domain.
    /// - Returns: The first AAAA record, or `nil` if none exists.
    public func resolveAAAA(_ domain: String) async throws -> IPv6Address? {
        let records = try await resolve(domain, recordType: 28) // AAAA = 28
        for record in records {
            if case .aaaa(let addr, _) = record { return addr }
        }
        return nil
    }

    /// Resolves both A and AAAA records concurrently.
    public func resolveAll(_ domain: String) async throws -> (a: IPv4Address?, aaaa: IPv6Address?) {
        async let a = resolveA(domain)
        async let aaaa = resolveAAAA(domain)
        return try await (a, aaaa)
    }

    /// Evicts all expired entries from the cache.
    public func purgeExpired() {
        cache = cache.filter { !$0.value.isExpired }
    }

    /// Clears the entire cache.
    public func clearCache() {
        cache.removeAll()
    }

    /// Number of cached entries.
    public var cacheSize: Int { cache.count }

    // MARK: - Core Resolution

    /// Returns cached records if available and unexpired; otherwise queries
    /// upstream, caches the result, and returns it.
    private func resolve(_ domain: String, recordType: UInt16) async throws -> [DNSRecord] {
        let key = CacheKey(domain: domain.lowercased(), recordType: recordType)

        // 1. Serve from cache if still fresh.
        if let entry = cache[key], !entry.isExpired {
            return entry.records
        }

        // 2. Try the secure racing client first (fastest of multiple DoH
        //    / DoQ upstreams).  If it succeeds, cache and return.
        if let racing = secureRacingClient {
            do {
                let result: DNSRecord?
                switch recordType {
                case 1:  // A
                    let raw = try await racing.resolveA(domain: domain)
                    let addr = IPv4Address(
                        UInt8((raw >> 24) & 0xFF),
                        UInt8((raw >> 16) & 0xFF),
                        UInt8((raw >>  8) & 0xFF),
                        UInt8(raw & 0xFF)
                    )
                    result = .a(addr, ttl: 300)
                case 28: // AAAA
                    let addr = try await racing.resolveAAAA(domain: domain)
                    result = .aaaa(addr, ttl: 300)
                default:
                    result = nil
                }
                if let record = result {
                    let records = [record]
                    cache[key] = CacheEntry(
                        records: records,
                        expiresAt: Date().addingTimeInterval(300)
                    )
                    return records
                }
            } catch {
                // Racing client failed; fall through to legacy transport
                // only if fallback is enabled.
                guard secureRacingFallback else { throw error }
            }
        }

        // 2. Build the DNS query wire‑format message.
        let queryData = buildDNSQuery(domain: domain, recordType: recordType)

        // 3. Dispatch to the selected transport.
        let responseData: Data
        switch transport {
        case .udp(let port):
            responseData = try await udpQuery(
                server: upstreamServer,
                port: port,
                query: queryData
            )
        case .doh(let url):
            responseData = try await dohQuery(
                url: url,
                query: queryData
            )
        }

        // 4. Parse the response.
        let records = parseDNSResponse(responseData, recordType: recordType)

        // 5. Cache with the minimum TTL from the records (or 60s default).
        let minTTL: UInt32 = records.map { record in
            switch record {
            case .a(_, let ttl): return ttl
            case .aaaa(_, let ttl): return ttl
            }
        }.min() ?? 60

        let entry = CacheEntry(
            records: records,
            expiresAt: Date().addingTimeInterval(TimeInterval(minTTL))
        )
        cache[key] = entry

        return records
    }

    // MARK: - DNS Query Builder

    /// Builds a DNS query message per RFC 1035 §4.1.1.
    private func buildDNSQuery(domain: String, recordType: UInt16) -> Data {
        var data = Data()

        // ---- Header (12 bytes) -------------------------------------------
        let txID = UInt16.random(in: 0 ... UInt16.max)
        data.append(contentsOf: [UInt8(txID >> 8), UInt8(txID & 0xFF)]) // ID
        data.append(contentsOf: [0x01, 0x00]) // Flags: standard query, RD=1
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT = 1
        data.append(contentsOf: [0x00, 0x00]) // ANCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // NSCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // ARCOUNT = 0

        // ---- Question ----------------------------------------------------
        // Encode domain as <length><label>…<0x00>
        for label in domain.lowercased().split(separator: ".") {
            let bytes = label.utf8
            data.append(UInt8(bytes.count))
            data.append(contentsOf: bytes)
        }
        data.append(0x00) // terminating zero‑length label

        // QTYPE
        data.append(contentsOf: [UInt8(recordType >> 8), UInt8(recordType & 0xFF)])
        // QCLASS = IN (1)
        data.append(contentsOf: [0x00, 0x01])

        return data
    }

    // MARK: - UDP Transport

    private func udpQuery(server: String, port: UInt16, query: Data) async throws -> Data {
        let host = NWEndpoint.Host(server)
        let nwPort = NWEndpoint.Port(rawValue: port)!
        let endpoint = NWEndpoint.hostPort(host: host, port: nwPort)
        let connection = NWConnection(to: endpoint, using: .udp)

        return try await withCheckedThrowingContinuation { continuation in
            // Use a small state holder class to avoid capturing non‑Sendable
            // closures across @Sendable boundaries.
            final class QueryState: @unchecked Sendable {
                var hasResumed = false
                func resume(continuation: CheckedContinuation<Data, Error>,
                            with result: Result<Data, Error>,
                            connection: NWConnection) {
                    guard !hasResumed else { return }
                    hasResumed = true
                    connection.cancel()
                    continuation.resume(with: result)
                }
            }
            let state = QueryState()

            connection.stateUpdateHandler = { [state] connState in
                switch connState {
                case .ready:
                    connection.send(content: query, completion: .contentProcessed { error in
                        if let error = error {
                            state.resume(continuation: continuation,
                                         with: .failure(error),
                                         connection: connection)
                            return
                        }
                        connection.receiveMessage { data, _, _, error in
                            if let error = error {
                                state.resume(continuation: continuation,
                                             with: .failure(error),
                                             connection: connection)
                            } else if let data = data {
                                state.resume(continuation: continuation,
                                             with: .success(data),
                                             connection: connection)
                            } else {
                                state.resume(continuation: continuation,
                                             with: .failure(DNSResolverError.noResponse),
                                             connection: connection)
                            }
                        }
                    })
                case .failed(let error):
                    state.resume(continuation: continuation,
                                 with: .failure(error),
                                 connection: connection)
                case .cancelled:
                    state.resume(continuation: continuation,
                                 with: .failure(DNSResolverError.cancelled),
                                 connection: connection)
                default:
                    break
                }
            }
            connection.start(queue: .global())
        }
    }

    // MARK: - DoH Transport

    private func dohQuery(url urlString: String, query: Data) async throws -> Data {
        guard let url = URL(string: urlString) else {
            throw DNSResolverError.invalidURL(urlString)
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/dns-message", forHTTPHeaderField: "Content-Type")
        request.setValue("application/dns-message", forHTTPHeaderField: "Accept")
        request.httpBody = query

        let (data, response) = try await URLSession.shared.data(for: request)

        guard let httpResponse = response as? HTTPURLResponse,
              (200 ... 299).contains(httpResponse.statusCode) else {
            throw DNSResolverError.httpError(
                (response as? HTTPURLResponse)?.statusCode ?? 0
            )
        }

        return data
    }

    // MARK: - DNS Response Parser

    /// Parses the answer section of a DNS response, extracting A / AAAA
    /// records.  Handles DNS name compression (RFC 1035 §4.1.4).
    private func parseDNSResponse(_ data: Data, recordType: UInt16) -> [DNSRecord] {
        guard data.count >= 12 else { return [] }

        // Read header
        let flags    = (UInt16(data[2]) << 8) | UInt16(data[3])
        let ancount  = (UInt16(data[6]) << 8) | UInt16(data[7])

        // Check QR bit (response) and RCODE (no error = 0)
        let isResponse = (flags & 0x8000) != 0
        let rcode      = flags & 0x000F
        guard isResponse, rcode == 0, ancount > 0 else { return [] }

        // Skip past the question section to find the first answer.
        var offset = 12
        offset = skipDomainName(in: data, at: offset)

        // QTYPE (2) + QCLASS (2) = 4 bytes
        offset += 4

        // Parse answer records
        var records: [DNSRecord] = []
        for _ in 0 ..< min(ancount, 16) { // cap at 16 records for safety
            guard offset + 10 <= data.count else { break }

            // NAME (may be compressed)
            offset = skipDomainName(in: data, at: offset)

            guard offset + 10 <= data.count else { break }
            let type  = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
            // CLASS (2 bytes, offset+2, offset+3) — skip
            let ttl   = (UInt32(data[offset + 4]) << 24)
                      | (UInt32(data[offset + 5]) << 16)
                      | (UInt32(data[offset + 6]) <<  8)
                      |  UInt32(data[offset + 7])
            let rdlen = (UInt16(data[offset + 8]) << 8) | UInt16(data[offset + 9])
            offset += 10

            guard offset + Int(rdlen) <= data.count else { break }

            switch type {
            case 1 where rdlen == 4: // A record
                let addr = IPv4Address(
                    data[offset], data[offset + 1],
                    data[offset + 2], data[offset + 3]
                )
                records.append(.a(addr, ttl: ttl))

            case 28 where rdlen == 16: // AAAA record
                let upper = (UInt64(data[offset])     << 56)
                          | (UInt64(data[offset + 1]) << 48)
                          | (UInt64(data[offset + 2]) << 40)
                          | (UInt64(data[offset + 3]) << 32)
                          | (UInt64(data[offset + 4]) << 24)
                          | (UInt64(data[offset + 5]) << 16)
                          | (UInt64(data[offset + 6]) <<  8)
                          |  UInt64(data[offset + 7])
                let lower = (UInt64(data[offset + 8])  << 56)
                          | (UInt64(data[offset + 9])  << 48)
                          | (UInt64(data[offset + 10]) << 40)
                          | (UInt64(data[offset + 11]) << 32)
                          | (UInt64(data[offset + 12]) << 24)
                          | (UInt64(data[offset + 13]) << 16)
                          | (UInt64(data[offset + 14]) <<  8)
                          |  UInt64(data[offset + 15])
                records.append(.aaaa(IPv6Address(upper: upper, lower: lower), ttl: ttl))

            default:
                break
            }

            offset += Int(rdlen)
        }

        return records
    }

    /// Advances `offset` past a DNS domain name, following compression
    /// pointers as needed.
    private func skipDomainName(in data: Data, at offset: Int) -> Int {
        var pos = offset
        var jumped = false
        var jumpEnd = 0

        while pos < data.count {
            let byte = data[pos]
            if byte == 0x00 {
                pos += 1
                break
            }
            // Compression pointer: top 2 bits = 0b11
            if (byte & 0xC0) == 0xC0 {
                guard pos + 1 < data.count else { break }
                let pointer = (UInt16(byte & 0x3F) << 8) | UInt16(data[pos + 1])
                if !jumped {
                    jumpEnd = pos + 2
                }
                pos = Int(pointer)
                jumped = true
            } else {
                // Regular label: byte = length, skip length + label bytes
                pos += 1 + Int(byte)
            }
        }

        return jumped ? jumpEnd : pos
    }
}

// MARK: - DNS Resolver Errors

public enum DNSResolverError: Error, Sendable, Equatable {
    case noResponse
    case cancelled
    case invalidURL(String)
    case httpError(Int)
}
