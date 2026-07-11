//===----------------------------------------------------------------------===//
//
//  IPHeader.swift
//  SwiftletCore — Layer 3 IP Packet Types
//
//  Type‑safe, Sendable representations of IPv4 and IPv6 packet headers and
//  their associated addresses.  These types are designed for the TUN2Socks
//  stack: they carry the minimal set of routing‑relevant fields while
//  providing a zero‑copy payload slice for the transport‑layer parser.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

// MARK: - IP Version

/// The IP protocol version extracted from the first nibble of a packet.
public enum IPVersion: UInt8, Sendable, Equatable {
    case ipv4 = 4
    case ipv6 = 6
}

// MARK: - IP Protocol Numbers

/// Well‑known IP protocol numbers carried in the IPv4 *Protocol* field or
/// the IPv6 *Next Header* field.
///
/// Only the values relevant to the TCP/UDP relay are defined; all others
/// fall through to `.unknown`.
public enum IPProtocolNumber: RawRepresentable, Sendable, Equatable {
    case tcp       //  6
    case udp       // 17
    case icmp      //  1 (IPv4 only; IPv6 uses 58)
    case unknown(UInt8)

    // MARK: RawRepresentable

    public init(rawValue: UInt8) {
        switch rawValue {
        case  1: self = .icmp
        case  6: self = .tcp
        case 17: self = .udp
        default:  self = .unknown(rawValue)
        }
    }

    public var rawValue: UInt8 {
        switch self {
        case .icmp:           return 1
        case .tcp:            return 6
        case .udp:            return 17
        case .unknown(let v): return v
        }
    }

    /// Convenience accessor to determine if the protocol is TCP.
    public var isTCP: Bool { self == .tcp }
    /// Convenience accessor to determine if the protocol is UDP.
    public var isUDP: Bool { self == .udp }
}

// MARK: - IPv4 Address

/// A 4‑byte IPv4 address stored in network byte order.
///
/// The address is backed by a single `UInt32` so that `Equatable`, `Hashable`,
/// and `Sendable` conformance is trivially synthesised by the compiler.
public struct IPv4Address: Sendable, Equatable, Hashable {

    /// The raw 32‑bit address in network byte order (big‑endian).
    private let _raw: UInt32

    // MARK: Initialisers

    /// Construct an address from four explicit octets in network byte order.
    public init(_ b0: UInt8, _ b1: UInt8, _ b2: UInt8, _ b3: UInt8) {
        self._raw = (UInt32(b0) << 24)
                  | (UInt32(b1) << 16)
                  | (UInt32(b2) <<  8)
                  |  UInt32(b3)
    }

    /// Decode a 32‑bit big‑endian integer read from the wire.
    public init(networkByteOrder value: UInt32) {
        self._raw = value
    }

    // MARK: Octet Accessors

    /// First octet (most significant).
    public var octet0: UInt8 { UInt8(truncatingIfNeeded: _raw >> 24) }
    /// Second octet.
    public var octet1: UInt8 { UInt8(truncatingIfNeeded: _raw >> 16) }
    /// Third octet.
    public var octet2: UInt8 { UInt8(truncatingIfNeeded: _raw >>  8) }
    /// Fourth octet (least significant).
    public var octet3: UInt8 { UInt8(truncatingIfNeeded: _raw) }
}

// MARK: CustomStringConvertible

extension IPv4Address: CustomStringConvertible {
    public var description: String {
        "\(octet0).\(octet1).\(octet2).\(octet3)"
    }
}

// MARK: - IPv6 Address

/// A 16‑byte IPv6 address.
///
/// The address is stored as two 64‑bit halves in network byte order.  This
/// layout makes equality checks fast (two integer comparisons) and keeps
/// the type trivially `Sendable`.
public struct IPv6Address: Sendable, Equatable, Hashable {

    /// The most significant 64 bits in network byte order.
    public let upper: UInt64
    /// The least significant 64 bits in network byte order.
    public let lower: UInt64

    // MARK: Initialisers

    /// Construct an address from its two 64‑bit halves.
    public init(upper: UInt64, lower: UInt64) {
        self.upper = upper
        self.lower = lower
    }

    /// Decode a 16‑byte network‑order address read from the wire.
    public init(networkByteOrder bytes: (UInt64, UInt64)) {
        self.upper = bytes.0
        self.lower = bytes.1
    }
}

// MARK: CustomStringConvertible

extension IPv6Address: CustomStringConvertible {
    /// Returns the canonical colon‑separated hexadecimal representation with
    /// the longest run of zero groups compressed to `::` (RFC 5952).
    public var description: String {
        // Decompose into eight 16‑bit groups in network order.
        let groups: [UInt16] = [
            UInt16(truncatingIfNeeded: upper >> 48),
            UInt16(truncatingIfNeeded: upper >> 32),
            UInt16(truncatingIfNeeded: upper >> 16),
            UInt16(truncatingIfNeeded: upper),
            UInt16(truncatingIfNeeded: lower >> 48),
            UInt16(truncatingIfNeeded: lower >> 32),
            UInt16(truncatingIfNeeded: lower >> 16),
            UInt16(truncatingIfNeeded: lower),
        ]

        // Find the longest run of consecutive zero groups.
        var bestStart = -1, bestLen = 0
        var curStart  = -1, curLen  = 0
        for (i, group) in groups.enumerated() {
            if group == 0 {
                if curStart == -1 { curStart = i }
                curLen += 1
            } else {
                if curLen > bestLen { (bestStart, bestLen) = (curStart, curLen) }
                curStart = -1; curLen = 0
            }
        }
        if curLen > bestLen { (bestStart, bestLen) = (curStart, curLen) }

        // Only compress runs longer than one zero group (RFC 5952 §4.2.2).
        guard bestLen > 1 else {
            return groups.map { String(format: "%x", $0) }.joined(separator: ":")
        }

        let afterEnd = bestStart + bestLen
        var parts: [String] = []

        // Prefix groups (before the zero run).
        for i in 0 ..< bestStart {
            parts.append(String(format: "%x", groups[i]))
        }
        // Placeholder — becomes the `::` in the joined result.
        parts.append("")
        // Suffix groups (after the zero run).
        for i in afterEnd ..< 8 {
            parts.append(String(format: "%x", groups[i]))
        }

        // When the zero run touches a boundary, `joined(separator:)` only
        // produces *one* colon at that boundary because there is no adjacent
        // part on the other side.  Insert an extra empty part so the double‑
        // colon renders correctly at both edges.
        if bestStart == 0 { parts.insert("", at: 0) }
        if afterEnd   == 8 { parts.append("") }

        return parts.joined(separator: ":")
    }
}

// MARK: - IPv4 Header

/// The parsed fields of an IPv4 packet header (RFC 791).
///
/// The `payload` slice is a **zero‑copy** view into the original packet
/// buffer starting immediately after the IPv4 header (including any options).
/// Its length is `totalLength - (ihl * 4)`.
public struct IPv4Header: Sendable {

    // MARK: Fixed‑Header Fields

    /// IP version — always `4` for this type.
    public let version: UInt8
    /// Internet Header Length in 32‑bit words (minimum 5 = 20 bytes).
    public let ihl: UInt8
    /// Type of Service (DSCP + ECN).
    public let typeOfService: UInt8
    /// Total datagram length in bytes (header + payload).
    public let totalLength: UInt16
    /// Fragment identification.
    public let identification: UInt16
    /// Flags (3 bits) + Fragment Offset (13 bits).
    public let flagsAndFragmentOffset: UInt16
    /// Time to Live.
    public let ttl: UInt8
    /// Transport‑layer protocol number.
    public let `protocol`: UInt8
    /// Header checksum (unverified by the parser).
    public let headerChecksum: UInt16

    // MARK: Addresses

    /// Source IPv4 address.
    public let sourceAddress: IPv4Address
    /// Destination IPv4 address.
    public let destinationAddress: IPv4Address

    // MARK: Payload (Zero‑Copy)

    /// A zero‑copy view of the transport‑layer payload (TCP, UDP, etc.).
    /// This `ByteBuffer` shares its underlying storage with the original
    /// packet buffer — no bytes are duplicated.
    public let payload: ByteBuffer

    // MARK: Derived Properties

    /// The IP protocol number as a strongly‑typed enum.
    public var protocolNumber: IPProtocolNumber {
        IPProtocolNumber(rawValue: self.protocol)
    }

    /// Header length in bytes (`ihl * 4`).
    public var headerLength: Int { Int(ihl) * 4 }

    /// Whether the *Don't Fragment* flag is set (bit 1 of the flags field).
    public var dontFragment: Bool {
        (flagsAndFragmentOffset & 0x4000) != 0
    }

    /// Whether the *More Fragments* flag is set (bit 2 of the flags field).
    public var moreFragments: Bool {
        (flagsAndFragmentOffset & 0x2000) != 0
    }

    /// Fragment offset in 8‑byte units (0 for unfragmented datagrams).
    public var fragmentOffset: UInt16 {
        flagsAndFragmentOffset & 0x1FFF
    }

    /// Payload length in bytes.
    public var payloadLength: Int { payload.readableBytes }
}

// MARK: - IPv6 Header

/// The parsed fields of an IPv6 packet header (RFC 8200).
///
/// IPv6 extension headers are **not** parsed — the `nextHeader` field
/// indicates the first extension header or the transport‑layer protocol.
/// The `payload` slice begins immediately after the fixed 40‑byte header;
/// callers must walk the extension‑header chain themselves if needed.
public struct IPv6Header: Sendable {

    // MARK: Fixed‑Header Fields

    /// IP version — always `6` for this type.
    public let version: UInt8
    /// Traffic Class (upper 6 bits) + ECN (lower 2 bits).
    public let trafficClass: UInt8
    /// Flow Label (lower 20 bits of the first 32‑bit word).
    public let flowLabel: UInt32
    /// Length of the payload (extension headers + transport data) in bytes.
    /// Does **not** include the 40‑byte fixed header.
    public let payloadLength: UInt16
    /// Next Header — either a transport protocol number or an IPv6 extension
    /// header type.
    public let nextHeader: UInt8
    /// Hop Limit (analogous to IPv4 TTL).
    public let hopLimit: UInt8

    // MARK: Addresses

    /// Source IPv6 address.
    public let sourceAddress: IPv6Address
    /// Destination IPv6 address.
    public let destinationAddress: IPv6Address

    // MARK: Payload (Zero‑Copy)

    /// A zero‑copy view of the payload starting after the 40‑byte fixed
    /// header.  The slice includes any IPv6 extension headers and the
    /// transport‑layer data.
    public let payload: ByteBuffer

    // MARK: Derived Properties

    /// The next‑header value as a strongly‑typed enum.
    public var nextHeaderNumber: IPProtocolNumber {
        IPProtocolNumber(rawValue: nextHeader)
    }

    /// The fixed header length is always 40 bytes.
    public var headerLength: Int { 40 }
}

// MARK: - Unified IP Packet

/// A parsed IP packet — either IPv4 or IPv6.
///
/// Callers typically match on this enum to extract the source/destination
/// addresses and protocol for routing decisions, then forward the `payload`
/// slice to the transport‑layer parser.
public enum IPPacket: Sendable {
    case ipv4(IPv4Header)
    case ipv6(IPv6Header)

    // MARK: Convenience Accessors

    /// The IP version of the enclosed packet.
    public var version: IPVersion {
        switch self {
        case .ipv4: return .ipv4
        case .ipv6: return .ipv6
        }
    }

    /// The transport‑layer protocol number (TCP, UDP, etc.).
    public var protocolNumber: IPProtocolNumber {
        switch self {
        case .ipv4(let h): return h.protocolNumber
        case .ipv6(let h): return h.nextHeaderNumber
        }
    }

    /// A zero‑copy view of the payload that follows the IP header.
    public var payload: ByteBuffer {
        switch self {
        case .ipv4(let h): return h.payload
        case .ipv6(let h): return h.payload
        }
    }
}
