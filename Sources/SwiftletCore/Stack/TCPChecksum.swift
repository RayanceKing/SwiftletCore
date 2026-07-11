//===----------------------------------------------------------------------===//
//
//  TCPChecksum.swift
//  SwiftletCore — TCP Checksum Computation (RFC 793 §3.1)
//
//  Implements the 16‑bit Internet checksum over the IPv4 or IPv6 pseudo‑
//  header combined with the TCP segment.  The algorithm uses one's‑complement
//  addition with end‑around carry, operating on 16‑bit words.
//
//===----------------------------------------------------------------------===//

// MARK: - TCP Checksum

/// Internet checksum computation for TCP over IPv4 and IPv6.
public enum TCPChecksum {

    // MARK: - IPv4

    /// Computes the TCP checksum for an IPv4 pseudo‑header.
    ///
    /// The pseudo‑header (RFC 793 §3.1) consists of:
    /// ```
    /// +--------+--------+--------+--------+
    /// |          Source Address           |
    /// +--------+--------+--------+--------+
    /// |        Destination Address        |
    /// +--------+--------+--------+--------+
    /// |  zero  |  PTCL  |    TCP Length   |
    /// +--------+--------+--------+--------+
    /// ```
    ///
    /// - Parameters:
    ///   - sourceAddr: IPv4 source address.
    ///   - destAddr: IPv4 destination address.
    ///   - tcpSegment: The complete TCP segment (header + payload) with the
    ///     checksum field zeroed.
    /// - Returns: The 16‑bit one's‑complement checksum.
    public static func computeIPv4(
        sourceAddr: IPv4Address,
        destAddr: IPv4Address,
        tcpSegment: [UInt8]
    ) -> UInt16 {
        let srcUInt32 = ipv4UInt32(from: sourceAddr)
        let dstUInt32 = ipv4UInt32(from: destAddr)

        var sum = checksumAccumulator()

        // --- IPv4 pseudo‑header -------------------------------------------
        sum.add(UInt16(truncatingIfNeeded: srcUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: srcUInt32))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32 >> 16))
        sum.add(UInt16(truncatingIfNeeded: dstUInt32))
        sum.add(UInt16(6))                      // Protocol = TCP
        sum.add(UInt16(tcpSegment.count))       // TCP Length

        // --- TCP segment (header + payload) -------------------------------
        sum.add(bytes: tcpSegment)

        return sum.finalize()
    }

    /// Extracts the raw network‑byte‑order UInt32 from an `IPv4Address`.
    private static func ipv4UInt32(from addr: IPv4Address) -> UInt32 {
        (UInt32(addr.octet0) << 24)
        | (UInt32(addr.octet1) << 16)
        | (UInt32(addr.octet2) <<  8)
        |  UInt32(addr.octet3)
    }

    // MARK: - IPv6

    /// Computes the TCP checksum for an IPv6 pseudo‑header (RFC 8200 §8.1).
    ///
    /// The IPv6 pseudo‑header is:
    /// ```
    /// +---------------------------------------+
    /// |            Source Address             |
    /// |              (16 bytes)               |
    /// +---------------------------------------+
    /// |          Destination Address          |
    /// |              (16 bytes)               |
    /// +-------------------+-------------------+
    /// | Upper‑Layer Pkt   |                   |
    /// |    Length         |     zero          |
    /// +-------------------+-------------------+
    /// |           Next Header (= 6)           |
    /// +---------------------------------------+
    /// ```
    public static func computeIPv6(
        sourceAddr: IPv6Address,
        destAddr: IPv6Address,
        tcpSegment: [UInt8]
    ) -> UInt16 {
        var sum = checksumAccumulator()

        // --- IPv6 pseudo‑header -------------------------------------------
        // Source Address — four 32‑bit words.
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.upper >> 48))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.upper >> 32))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.upper >> 16))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.upper))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.lower >> 48))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.lower >> 32))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.lower >> 16))
        sum.add(UInt16(truncatingIfNeeded: sourceAddr.lower))

        // Destination Address — four 32‑bit words.
        sum.add(UInt16(truncatingIfNeeded: destAddr.upper >> 48))
        sum.add(UInt16(truncatingIfNeeded: destAddr.upper >> 32))
        sum.add(UInt16(truncatingIfNeeded: destAddr.upper >> 16))
        sum.add(UInt16(truncatingIfNeeded: destAddr.upper))
        sum.add(UInt16(truncatingIfNeeded: destAddr.lower >> 48))
        sum.add(UInt16(truncatingIfNeeded: destAddr.lower >> 32))
        sum.add(UInt16(truncatingIfNeeded: destAddr.lower >> 16))
        sum.add(UInt16(truncatingIfNeeded: destAddr.lower))

        // Upper‑Layer Packet Length
        sum.add(UInt16(tcpSegment.count))
        // Next Header (= TCP = 6)
        sum.add(UInt16(6))

        // --- TCP segment --------------------------------------------------
        sum.add(bytes: tcpSegment)

        return sum.finalize()
    }
}

// MARK: - Checksum Accumulator

/// A mutable accumulator for the Internet checksum algorithm.
///
/// Each `add` call performs one's‑complement addition; overflow bits are
/// folded back immediately (end‑around carry) to keep the accumulator
/// bounded to 16 bits per step.
private struct checksumAccumulator {
    private var value: UInt32 = 0

    /// Add a single 16‑bit word.
    mutating func add(_ word: UInt16) {
        value &+= UInt32(word)
    }

    /// Add a 32‑bit value (adds the upper and lower 16‑bit halves separately).
    mutating func add(_ dword: UInt32) {
        value &+= UInt32(UInt16(truncatingIfNeeded: dword >> 16))
        value &+= UInt32(UInt16(truncatingIfNeeded: dword))
    }

    /// Add an array of bytes, treating each consecutive pair as a big‑endian
    /// 16‑bit word.  A trailing odd byte is padded with a zero low‑byte.
    mutating func add(bytes: [UInt8]) {
        var i = 0
        while i + 1 < bytes.count {
            let word = (UInt32(bytes[i]) << 8) | UInt32(bytes[i + 1])
            value &+= word
            i += 2
        }
        // Pad odd trailing byte.
        if i < bytes.count {
            value &+= UInt32(bytes[i]) << 8
        }
    }

    /// Fold all carry bits and return the one's complement.
    mutating func finalize() -> UInt16 {
        while (value >> 16) != 0 {
            value = (value & 0xFFFF) + (value >> 16)
        }
        return ~UInt16(truncatingIfNeeded: value)
    }
}
