//===----------------------------------------------------------------------===//
//
//  PCAPPacketDumper.swift
//  SwiftletCore — Pure‑Memory PCAP Streaming Packet Dumper
//
//  A circular in‑memory buffer that captures raw Layer‑3 IP packets
//  and exports them as a standards‑compliant libpcap file suitable
//  for inspection in Wireshark, tcpdump, or any libpcap‑compatible tool.
//
//  libpcap File Format
//  -------------------
//  ```
//  ┌──────────────────────────────────────────────┐
//  │  Global Header (24 bytes)                     │
//  │  ┌──────┬──────┬──────┬────────────────────┐  │
//  │  │Magic │Major │Minor │ ...                │  │
//  │  │0xa1b2│ 2    │ 4    │                    │  │
//  │  │ c3d4 │      │      │                    │  │
//  │  └──────┴──────┴──────┴────────────────────┘  │
//  ├──────────────────────────────────────────────┤
//  │  Packet Record #1 (16‑byte header + data)     │
//  │  ┌──────────────────┬──────────────────────┐  │
//  │  │ ts_sec (4B)      │ ts_usec (4B)         │  │
//  │  │ incl_len (4B)    │ orig_len (4B)        │  │
//  │  │ packet data …                           │  │
//  │  └──────────────────┴──────────────────────┘  │
//  ├──────────────────────────────────────────────┤
//  │  Packet Record #2 …                            │
//  └──────────────────────────────────────────────┘
//  ```
//
//  Thread Safety
//  -------------
//  `PCAPPacketDumper` is a `final class` marked `@unchecked Sendable`.
//  All buffer mutations happen on the caller's serial execution context
//  (typically the TUN read event loop).  The `dumpActiveBuffersToPCAP()`
//  method reads the buffer synchronously for simplicity.
//
//===----------------------------------------------------------------------===//

import Foundation

// MARK: - Constants

/// Standard libpcap magic number (native byte order: 0xa1b2c3d4).
private let pcapMagicNumber: UInt32 = 0xa1b2_c3d4

/// libpcap major version.
private let pcapMajorVersion: UInt16 = 2

/// libpcap minor version.
private let pcapMinorVersion: UInt16 = 4

/// GMT offset (0 = UTC).
private let pcapGMTToLocal: Int32 = 0

/// Timestamp accuracy (0 = microseconds).
private let pcapAccuracy: UInt32 = 0

/// Maximum snapshot length (65535 = capture everything).
private let pcapMaxSnapLen: UInt32 = 65535

/// Link‑layer type: RAW (101) — raw IP packets with no link‑layer header.
private let pcapLinkType: UInt32 = 101

/// Global header size in bytes.
private let pcapGlobalHeaderSize = 24

/// Per‑packet record header size in bytes.
private let pcapPacketHeaderSize = 16

// MARK: - Packet Record

/// A single captured packet with its timestamp and raw bytes.
internal struct PcapPacketRecord: Sendable {
    /// Seconds component of the capture timestamp.
    let tsSec: UInt32

    /// Microseconds component of the capture timestamp.
    let tsUsec: UInt32

    /// The raw packet data.
    let data: Data

    /// The original packet length (may differ from captured if truncated).
    var originalLength: UInt32 { UInt32(data.count) }

    /// The captured length.
    var capturedLength: UInt32 { UInt32(data.count) }
}

// MARK: - PCAP Packet Dumper

/// An in‑memory circular buffer that captures raw IP packets and can
/// export them as a libpcap‑compliant file.
///
/// ## Usage
/// ```swift
/// let dumper = PCAPPacketDumper(maxPackets: 2048)
/// dumper.capture(packetData: rawIPBytes)
/// // ... later ...
/// let pcapFile = dumper.dumpActiveBuffersToPCAP()
/// try pcapFile.write(to: outputURL)
/// ```
public final class PCAPPacketDumper: @unchecked Sendable {

    // MARK: - Configuration

    /// Whether packet capture is currently enabled.
    public var isEnabled: Bool = false

    /// Maximum number of packets held in the circular buffer.
    public let maxPackets: Int

    // MARK: - Storage

    /// The circular packet buffer.
    private var buffer: [PcapPacketRecord] = []

    /// Write cursor for the circular buffer.
    private var writeIndex: Int = 0

    /// Total packets ever captured (monotonic counter).
    public private(set) var totalCaptured: UInt64 = 0

    /// Whether the circular buffer has wrapped at least once.
    public private(set) var hasWrapped: Bool = false

    // MARK: - Initialisation

    /// - Parameter maxPackets: Maximum number of packets to retain in
    ///   the circular buffer (default 2048).
    public init(maxPackets: Int = 2048) {
        self.maxPackets = max(maxPackets, 1)
        self.buffer.reserveCapacity(self.maxPackets)
    }

    // MARK: - Capture

    /// Captures a raw IP packet into the circular buffer.
    ///
    /// If the buffer is full, the oldest entry is overwritten.
    ///
    /// - Parameter packetData: The raw IP packet bytes (including IP header).
    /// - Parameter timestamp: An optional override timestamp; defaults to
    ///   the current wall‑clock time.
    public func capture(
        packetData: Data,
        timestamp: Date = Date()
    ) {
        guard isEnabled else { return }

        let ts = timestamp.timeIntervalSince1970
        let tsSec  = UInt32(ts)
        let tsUsec = UInt32((ts - Double(tsSec)) * 1_000_000)

        let record = PcapPacketRecord(
            tsSec: tsSec,
            tsUsec: tsUsec,
            data: packetData
        )

        if buffer.count < maxPackets {
            buffer.append(record)
        } else {
            buffer[writeIndex % maxPackets] = record
            hasWrapped = true
        }
        writeIndex = (writeIndex + 1) % maxPackets
        totalCaptured &+= 1
    }

    /// Captures a raw IP packet from a byte array.
    public func capture(bytes: [UInt8], timestamp: Date = Date()) {
        capture(packetData: Data(bytes), timestamp: timestamp)
    }

    // MARK: - PCAP Export

    /// Exports all buffered packets as a complete, standards‑compliant
    /// libpcap file.
    ///
    /// - Returns: A `Data` blob containing the 24‑byte global header
    ///   followed by 16‑byte per‑packet record headers and packet data.
    ///   This blob can be written directly to a `.pcap` file and opened
    ///   in Wireshark.
    public func dumpActiveBuffersToPCAP() -> Data {
        var pcap = Data(capacity: pcapGlobalHeaderSize)

        // ---- Global Header -----------------------------------------------
        pcap.append(contentsOf: withUnsafeBytes(of: pcapMagicNumber.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapMajorVersion.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapMinorVersion.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapGMTToLocal.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapAccuracy.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapMaxSnapLen.littleEndian, Array.init))
        pcap.append(contentsOf: withUnsafeBytes(of: pcapLinkType.littleEndian, Array.init))

        // ---- Packet Records ----------------------------------------------
        let records = orderedRecords()
        for record in records {
            // Per‑packet header.
            pcap.append(contentsOf: withUnsafeBytes(of: record.tsSec.littleEndian, Array.init))
            pcap.append(contentsOf: withUnsafeBytes(of: record.tsUsec.littleEndian, Array.init))
            pcap.append(contentsOf: withUnsafeBytes(of: record.capturedLength.littleEndian, Array.init))
            pcap.append(contentsOf: withUnsafeBytes(of: record.originalLength.littleEndian, Array.init))
            // Packet data.
            pcap.append(record.data)
        }

        return pcap
    }

    // MARK: - Queries

    /// The current number of buffered packets.
    public var bufferedCount: Int { buffer.count }

    /// Returns all buffered records in chronological (insertion) order.
    private func orderedRecords() -> [PcapPacketRecord] {
        guard hasWrapped else {
            return buffer
        }
        // When wrapped, records from `writeIndex` to end are oldest,
        // followed by records from start to `writeIndex - 1`.
        let tail = buffer[writeIndex...]
        let head = buffer[..<writeIndex]
        return Array(tail) + Array(head)
    }

    // MARK: - Management

    /// Clears all buffered packets but keeps the allocated capacity.
    public func clear() {
        buffer.removeAll(keepingCapacity: true)
        writeIndex = 0
        hasWrapped = false
        totalCaptured = 0
    }

    /// Disables capture and clears the buffer.
    public func reset() {
        isEnabled = false
        clear()
    }
}
