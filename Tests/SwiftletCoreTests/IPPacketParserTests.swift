//===----------------------------------------------------------------------===//
//
//  IPPacketParserTests.swift
//  SwiftletCore — IP Packet Parser Unit Tests
//
//  Constructs raw hexadecimal byte arrays and verifies that the
//  `IPPacketParser` correctly extracts every relevant field from both
//  IPv4 and IPv6 headers, including edge‑case and error‑path validation.
//
//===----------------------------------------------------------------------===//

import Testing
import Foundation
@testable import SwiftletCore

// MARK: - IPv4 TCP SYN Packet

/// End‑to‑end test: build a valid IPv4 TCP SYN packet by hand, parse it,
/// and assert that every extracted field matches the expected value.
@Test func parseValidIPv4TCPSYNPacket() async throws {

    // ---- Build the mock packet -------------------------------------------
    //
    //  IPv4 header (20 bytes):
    //    Off  Field                 Value        Hex
    //    ---  -----------------     ---------    ----
    //     0   Version / IHL         4 / 5        0x45
    //     1   Type of Service       0            0x00
    //     2   Total Length          60 (0x003C)  0x00 0x3C
    //     4   Identification        0x1234       0x12 0x34
    //     6   Flags / Frag Offset   0            0x00 0x00
    //     8   TTL                   64           0x40
    //     9   Protocol              6  (TCP)     0x06
    //    10   Header Checksum       0x0000       0x00 0x00
    //    12   Source Address        192.168.1.100  0xC0 0xA8 0x01 0x64
    //    16   Destination Address   10.0.0.1       0x0A 0x00 0x00 0x01
    //
    //  Payload: 40 bytes of mock TCP data (all 0xAA for visibility).

    let header: [UInt8] = [
        0x45,                   // Version=4, IHL=5
        0x00,                   // ToS
        0x00, 0x3C,             // Total Length = 60
        0x12, 0x34,             // Identification
        0x00, 0x00,             // Flags + Fragment Offset
        0x40,                   // TTL = 64
        0x06,                   // Protocol = TCP
        0x00, 0x00,             // Header Checksum (unchecked)
        0xC0, 0xA8, 0x01, 0x64, // Source: 192.168.1.100
        0x0A, 0x00, 0x00, 0x01, // Dest:   10.0.0.1
    ]

    let payload = [UInt8](repeating: 0xAA, count: 40) // mock TCP segment
    let packet  = Data(header + payload)

    // ---- Parse -----------------------------------------------------------
    let result = try IPPacketParser.parse(packet)

    // ---- Assert ----------------------------------------------------------
    guard case .ipv4(let h) = result else {
        Issue.record("Expected IPv4 packet, got \(result.version)")
        return
    }

    #expect(h.version == 4)
    #expect(h.ihl == 5)
    #expect(h.headerLength == 20)
    #expect(h.typeOfService == 0)
    #expect(h.totalLength == 60)
    #expect(h.identification == 0x1234)
    #expect(h.flagsAndFragmentOffset == 0)
    #expect(h.ttl == 64)
    #expect(h.protocol == 6)
    #expect(h.protocolNumber == .tcp)
    #expect(h.protocolNumber.isTCP == true)
    #expect(h.protocolNumber.isUDP == false)
    #expect(h.dontFragment == false)
    #expect(h.moreFragments == false)
    #expect(h.fragmentOffset == 0)
    #expect(h.headerChecksum == 0)

    // Addresses
    #expect(h.sourceAddress.description == "192.168.1.100")
    #expect(h.destinationAddress.description == "10.0.0.1")
    #expect(h.sourceAddress == IPv4Address(192, 168, 1, 100))
    #expect(h.destinationAddress == IPv4Address(10, 0, 0, 1))

    // Payload (zero‑copy)
    #expect(h.payloadLength == 40)
    #expect(h.payload.readableBytes == 40)
    // Spot‑check the first and last payload bytes.
    var payloadCopy = h.payload
    #expect(payloadCopy.readInteger(as: UInt8.self) == 0xAA)
    // Seek to the last byte.
    payloadCopy.moveReaderIndex(forwardBy: 38) // 40 - 1 (first read) - 1 (target)
    #expect(payloadCopy.readInteger(as: UInt8.self) == 0xAA)
}

// MARK: - IPv6 TCP Packet

/// Validates parsing of a simple IPv6 header carrying a TCP segment.
@Test func parseValidIPv6TCPPacket() async throws {

    // ---- Build the mock packet -------------------------------------------
    //
    //  IPv6 header (40 bytes):
    //    Off  Field                 Value                      Hex
    //    ---  -----------------     -----------------------    ----
    //     0   Ver/TC/Flow           6 / 0 / 0                  0x60 0x00 0x00 0x00
    //     4   Payload Length        20                         0x00 0x14
    //     6   Next Header           6 (TCP)                    0x06
    //     7   Hop Limit             64                         0x40
    //     8   Source Address        2001:db8::1
    //    24   Destination Address   2001:db8::2
    //
    //  Payload: 20 bytes of mock TCP data.

    var bytes: [UInt8] = []

    // First 32 bits: Version=6, TrafficClass=0, FlowLabel=0
    bytes.append(contentsOf: [0x60, 0x00, 0x00, 0x00])

    // Payload Length = 20
    bytes.append(contentsOf: [0x00, 0x14])

    // Next Header = TCP, Hop Limit = 64
    bytes.append(contentsOf: [0x06, 0x40])

    // Source Address: 2001:db8::1
    //   upper 64 bits = 0x2001_0DB8_0000_0000
    bytes.append(contentsOf: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00])
    //   lower 64 bits = 0x0000_0000_0000_0001
    bytes.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01])

    // Destination Address: 2001:db8::2
    //   upper 64 bits = 0x2001_0DB8_0000_0000
    bytes.append(contentsOf: [0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00])
    //   lower 64 bits = 0x0000_0000_0000_0002
    bytes.append(contentsOf: [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02])

    // Payload: 20 bytes of 0xBB
    bytes.append(contentsOf: [UInt8](repeating: 0xBB, count: 20))

    let packet = Data(bytes)

    // ---- Parse -----------------------------------------------------------
    let result = try IPPacketParser.parse(packet)

    // ---- Assert ----------------------------------------------------------
    guard case .ipv6(let h) = result else {
        Issue.record("Expected IPv6 packet, got \(result.version)")
        return
    }

    #expect(h.version == 6)
    #expect(h.trafficClass == 0)
    #expect(h.flowLabel == 0)
    #expect(h.payloadLength == 20)
    #expect(h.nextHeader == 6)
    #expect(h.nextHeaderNumber == .tcp)
    #expect(h.hopLimit == 64)
    #expect(h.headerLength == 40)

    // Addresses
    #expect(h.sourceAddress.description == "2001:db8::1")
    #expect(h.destinationAddress.description == "2001:db8::2")

    // Payload
    #expect(h.payload.readableBytes == 20)
    var payloadCopy = h.payload
    #expect(payloadCopy.readInteger(as: UInt8.self) == 0xBB)
}

// MARK: - Unified IPPacket Convenience Accessors

/// The convenience accessors on `IPPacket` should delegate correctly.
@Test func ipPacketConvenienceAccessors() async throws {
    let header: [UInt8] = [
        0x45, 0x00, 0x00, 0x14,             // 20-byte datagram, no payload
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0xC0, 0xA8, 0x01, 0x64,
        0x0A, 0x00, 0x00, 0x01,
    ]

    let packet = try IPPacketParser.parse(Data(header))

    #expect(packet.version == .ipv4)
    #expect(packet.protocolNumber == .tcp)
    #expect(packet.payload.readableBytes == 0) // totalLength == 20, no payload
}

// MARK: - Error Paths

/// A buffer shorter than 1 byte should throw `.insufficientData`.
@Test func truncatedToOneByteThrows() async {
    let data = Data([0x45]) // Version + IHL only; no body
    #expect(throws: IPPacketParser.ParseError.insufficientData(needed: 20, available: 1)) {
        _ = try IPPacketParser.parse(data)
    }
}

/// An unknown version nibble (e.g. 0x50 → version 5) should throw.
@Test func invalidIPVersionThrows() async {
    let bytes: [UInt8] = [
        0x50, 0x00, 0x00, 0x14, // version = 5
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    ]
    #expect(throws: IPPacketParser.ParseError.invalidVersion(5)) {
        _ = try IPPacketParser.parse(Data(bytes))
    }
}

/// An IPv4 packet whose IHL field is less than 5 should be rejected.
@Test func invalidIHLThrows() async {
    var bytes = [UInt8](repeating: 0x00, count: 20)
    bytes[0] = 0x44 // Version=4, IHL=4 (< 5, invalid)
    bytes[2] = 0x00; bytes[3] = 0x14 // Total Length = 20

    #expect(throws: IPPacketParser.ParseError.invalidHeaderLength(4)) {
        _ = try IPPacketParser.parse(Data(bytes))
    }
}

/// An IPv4 packet whose total length is less than the header length must
/// be rejected.
@Test func inconsistentTotalLengthThrows() async {
    var bytes = [UInt8](repeating: 0x00, count: 20)
    bytes[0] = 0x45 // Version=4, IHL=5
    bytes[2] = 0x00; bytes[3] = 0x10 // Total Length = 16 (< 20, impossible)

    #expect(throws: IPPacketParser.ParseError.invalidTotalLength(declared: 16, minimum: 20)) {
        _ = try IPPacketParser.parse(Data(bytes))
    }
}

/// Parsing a truncated IPv6 header (fewer than 40 bytes) must throw.
@Test func truncatedIPv6HeaderThrows() async {
    // 39 bytes with a valid version nibble (6), short of the 40‑byte minimum.
    var bytes = [UInt8](repeating: 0x00, count: 39)
    bytes[0] = 0x60 // Version = 6
    let data = Data(bytes)
    #expect(throws: IPPacketParser.ParseError.insufficientData(needed: 40, available: 39)) {
        _ = try IPPacketParser.parse(data)
    }
}

/// The parser should gracefully handle a datagram whose declared total
/// length exceeds the actual available data (truncated payload).
@Test func truncatedPayloadIsAccepted() async throws {
    // Declare Total Length = 60, but only provide 30 bytes.
    var bytes: [UInt8] = [
        0x45, 0x00, 0x00, 0x3C, // Ver=4, IHL=5, Total Length = 60
        0x00, 0x00, 0x00, 0x00,
        0x40, 0x06, 0x00, 0x00,
        0x7F, 0x00, 0x00, 0x01, // 127.0.0.1
        0x7F, 0x00, 0x00, 0x02, // 127.0.0.2
    ]
    // Append only 10 more bytes (total 30, not 60).
    bytes.append(contentsOf: [UInt8](repeating: 0xCC, count: 10))

    // Should NOT throw — the parser clamps to available data.
    let result = try IPPacketParser.parse(Data(bytes))
    guard case .ipv4(let h) = result else {
        Issue.record("Expected IPv4")
        return
    }
    // totalLength still reflects the declared value…
    #expect(h.totalLength == 60)
    // …but the actual payload is clamped.
    #expect(h.payloadLength == 10)
}

// MARK: - IPv4Address / IPv6Address Formatting

@Test func ipv4AddressFormatting() {
    let addr = IPv4Address(192, 168, 1, 100)
    #expect(addr.description == "192.168.1.100")
    #expect(addr == IPv4Address(192, 168, 1, 100))
    #expect(addr != IPv4Address(10, 0, 0, 1))
}

@Test func ipv6AddressFormatting() {
    // 2001:db8::1
    let addr1 = IPv6Address(
        upper: 0x2001_0DB8_0000_0000,
        lower: 0x0000_0000_0000_0001
    )
    #expect(addr1.description == "2001:db8::1")

    // ::1 (loopback)
    let loopback = IPv6Address(upper: 0, lower: 1)
    #expect(loopback.description == "::1")

    // :: (all zeros)
    let zero = IPv6Address(upper: 0, lower: 0)
    #expect(zero.description == "::")

    // fe80::1 (link‑local)
    let linkLocal = IPv6Address(
        upper: 0xFE80_0000_0000_0000,
        lower: 0x0000_0000_0000_0001
    )
    #expect(linkLocal.description == "fe80::1")
}

// MARK: - Hashable & Equatable

@Test func ipAddressesAreHashable() {
    let set: Set<IPv4Address> = [
        IPv4Address(192, 168, 1, 1),
        IPv4Address(10, 0, 0, 1),
        IPv4Address(192, 168, 1, 1), // duplicate
    ]
    #expect(set.count == 2)
}
