//===----------------------------------------------------------------------===//
//
//  DNSPacketBuilder.swift
//  SwiftletCore — RFC 1035 DNS Query Builder & Response Parser
//
//  Shared by both `AsyncDNSResolver` and `SecureDNSRacingClient`.
//  Builds wire‑format query messages and extracts A / AAAA records
//  from raw response bytes, including DNS name compression (RFC 1035
//  §4.1.4).
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - DNS Packet Builder

/// Builds DNS query messages in wire format (RFC 1035 §4.1.1).
public enum DNSPacketBuilder {

    /// Builds a DNS query for the given domain and record type.
    ///
    /// - Parameters:
    ///   - domain: Fully‑qualified domain name.
    ///   - recordType: `1` for A (IPv4), `28` for AAAA (IPv6).
    /// - Returns: The raw DNS query bytes.
    public static func buildQuery(domain: String, recordType: UInt16) -> Data {
        var data = Data()

        // ---- Header (12 bytes) ------------------------------------------
        let txID = UInt16.random(in: 0 ... UInt16.max)
        data.append(contentsOf: [UInt8(txID >> 8), UInt8(txID & 0xFF)]) // ID
        data.append(contentsOf: [0x01, 0x00]) // Flags: standard query, RD=1
        data.append(contentsOf: [0x00, 0x01]) // QDCOUNT = 1
        data.append(contentsOf: [0x00, 0x00]) // ANCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // NSCOUNT = 0
        data.append(contentsOf: [0x00, 0x00]) // ARCOUNT = 0

        // ---- Question ---------------------------------------------------
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

    /// Builds an A‑record (IPv4) query.
    public static func buildAQuery(for domain: String) -> Data {
        buildQuery(domain: domain, recordType: 1)
    }

    /// Builds an AAAA‑record (IPv6) query.
    public static func buildAAAAQuery(for domain: String) -> Data {
        buildQuery(domain: domain, recordType: 28)
    }
}

// MARK: - DNS Packet Parser

/// Parses A / AAAA answer records from DNS response wire‑format data.
public enum DNSPacketParser {

    /// A parsed DNS resource record.
    public enum ParsedRecord: Sendable, Equatable {
        /// IPv4 address (A record).
        case a(IPv4Address, ttl: UInt32)
        /// IPv6 address (AAAA record).
        case aaaa(IPv6Address, ttl: UInt32)
    }

    /// Parses the answer section of a DNS response.
    ///
    /// - Parameters:
    ///   - data: Raw DNS response bytes.
    ///   - recordType: Expected type (1 = A, 28 = AAAA).
    /// - Returns: Array of matching resource records (empty on failure).
    public static func parse(_ data: Data, recordType: UInt16) -> [ParsedRecord] {
        guard data.count >= 12 else { return [] }

        // Read header
        let flags   = (UInt16(data[2]) << 8) | UInt16(data[3])
        let ancount = (UInt16(data[6]) << 8) | UInt16(data[7])

        let isResponse = (flags & 0x8000) != 0
        let rcode      = flags & 0x000F
        guard isResponse, rcode == 0, ancount > 0 else { return [] }

        // Skip question section.
        var offset = 12
        offset = skipDomainName(in: data, at: offset)
        offset += 4 // QTYPE + QCLASS

        // Parse answer records.
        var records: [ParsedRecord] = []
        for _ in 0 ..< min(ancount, 16) {
            guard offset + 10 <= data.count else { break }

            offset = skipDomainName(in: data, at: offset)
            guard offset + 10 <= data.count else { break }

            let type  = (UInt16(data[offset]) << 8) | UInt16(data[offset + 1])
            let ttl   = (UInt32(data[offset + 4]) << 24)
                      | (UInt32(data[offset + 5]) << 16)
                      | (UInt32(data[offset + 6]) <<  8)
                      |  UInt32(data[offset + 7])
            let rdlen = (UInt16(data[offset + 8]) << 8) | UInt16(data[offset + 9])
            offset += 10

            guard offset + Int(rdlen) <= data.count else { break }

            switch type {
            case 1 where rdlen == 4: // A
                let addr = IPv4Address(
                    data[offset], data[offset + 1],
                    data[offset + 2], data[offset + 3]
                )
                records.append(.a(addr, ttl: ttl))
            case 28 where rdlen == 16: // AAAA
                let upper = readUInt64(data, at: offset)
                let lower = readUInt64(data, at: offset + 8)
                records.append(.aaaa(IPv6Address(upper: upper, lower: lower), ttl: ttl))
            default:
                break
            }
            offset += Int(rdlen)
        }
        return records
    }

    /// Extracts the first IPv4 address from a parsed A‑record response.
    public static func firstA(from data: Data) -> IPv4Address? {
        for record in parse(data, recordType: 1) {
            if case .a(let addr, _) = record { return addr }
        }
        return nil
    }

    /// Extracts the first IPv6 address from a parsed AAAA‑record response.
    public static func firstAAAA(from data: Data) -> IPv6Address? {
        for record in parse(data, recordType: 28) {
            if case .aaaa(let addr, _) = record { return addr }
        }
        return nil
    }

    // MARK: - Helpers

    private static func skipDomainName(in data: Data, at offset: Int) -> Int {
        var pos = offset
        var jumped = false
        var jumpEnd = 0
        while pos < data.count {
            let byte = data[pos]
            if byte == 0x00 { pos += 1; break }
            if (byte & 0xC0) == 0xC0 {
                guard pos + 1 < data.count else { break }
                let pointer = (UInt16(byte & 0x3F) << 8) | UInt16(data[pos + 1])
                if !jumped { jumpEnd = pos + 2 }
                pos = Int(pointer); jumped = true
            } else {
                pos += 1 + Int(byte)
            }
        }
        return jumped ? jumpEnd : pos
    }

    private static func readUInt64(_ data: Data, at offset: Int) -> UInt64 {
        (UInt64(data[offset])     << 56) | (UInt64(data[offset + 1]) << 48)
        | (UInt64(data[offset + 2]) << 40) | (UInt64(data[offset + 3]) << 32)
        | (UInt64(data[offset + 4]) << 24) | (UInt64(data[offset + 5]) << 16)
        | (UInt64(data[offset + 6]) <<  8) |  UInt64(data[offset + 7])
    }
}
