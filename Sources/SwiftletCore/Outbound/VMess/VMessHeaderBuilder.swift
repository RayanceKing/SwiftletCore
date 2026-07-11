//===----------------------------------------------------------------------===//
//
//  VMessHeaderBuilder.swift
//  SwiftletCore — VMess Protocol Version 1 Header Builder
//
//  Implements the VMess v1 request header assembly per the V2Ray
//  specification.  Key derivation uses MD5 (UUID + epoch timestamp),
//  and the instruction portion of the header is encrypted with
//  AES‑128‑CFB via CommonCrypto.
//
//  Header layout (before encryption of the instruction block)
//  ----------------------------------------------------------
//  ```
//  [1]  Version           = 0x01
//  [16] Request IV        = random
//  [16] Request Key       = MD5(uuid ‖ ts)
//  [1]  Response Auth     = MD5(requestKey ‖ uuid)[0]
//
//  —— Encrypted with AES‑128‑CFB(key=requestKey, iv=MD5(requestIV ‖ requestKey)) ——
//  [1]  Options           = 0x01 (standard)
//  [1]  Padding Length P
//  [1]  Command           = 0x01 (TCP)
//  [2]  Port              = big‑endian
//  [1]  Address Type      = 0x01 (IPv4) / 0x02 (domain) / 0x03 (IPv6)
//  [n]  Address
//  [P]  Random Padding
//  ```
//
//===----------------------------------------------------------------------===//

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - VMess Header Builder

/// Builds the binary VMess v1 request header frame.
public enum VMessHeaderBuilder {

    // MARK: - Public API

    /// Builds the complete VMess request header for a TCP CONNECT to the
    /// given destination.
    ///
    /// - Parameters:
    ///   - uuid: The user's VMess UUID.
    ///   - address: Destination hostname or IP.
    ///   - port: Destination port.
    ///   - timestamp: Unix epoch timestamp (seconds).  If `nil`, the
    ///     current wall‑clock time is used.
    ///   - paddingLength: Number of random padding bytes (0–255).
    /// - Returns: The complete header frame ready to be flushed as the
    ///   first bytes of the TCP connection.
    public static func build(
        uuid: UUID,
        address: String,
        port: UInt16,
        timestamp: UInt64? = nil,
        paddingLength: UInt8 = 16
    ) -> Data {
        let ts = timestamp ?? UInt64(Date().timeIntervalSince1970)
        let uuidBytes = uuid.toBytes()
        let tsBytes   = ts.toBigEndianBytes()

        // ---- 1. Derive the Request Command Key ---------------------------
        //    requestKey = MD5(uuid ‖ ts)
        var preKeyData = Data()
        preKeyData.append(contentsOf: uuidBytes)
        preKeyData.append(contentsOf: tsBytes)
        let requestKey = Data(Insecure.MD5.hash(data: preKeyData))

        // ---- 2. Generate random Request IV -------------------------------
        let requestIV = generateRandomBytes(count: 16)

        // ---- 3. Response Auth byte ---------------------------------------
        //    responseAuth = MD5(requestKey ‖ uuid)[0]
        var authData = Data()
        authData.append(requestKey)
        authData.append(contentsOf: uuidBytes)
        let responseAuth = Data(Insecure.MD5.hash(data: authData))[0]

        // ---- 4. Build the instruction block (plaintext) ------------------
        var instruction = Data()
        // Options: standard format
        instruction.append(0x01)
        // Padding length
        instruction.append(paddingLength)
        // Command: TCP
        instruction.append(0x01)
        // Port (big‑endian)
        instruction.append(UInt8(port >> 8))
        instruction.append(UInt8(port & 0xFF))
        // Address
        encodeAddress(address, into: &instruction)
        // Random padding
        if paddingLength > 0 {
            instruction.append(contentsOf: generateRandomBytes(count: Int(paddingLength)))
        }

        // ---- 5. Derive encryption IV ------------------------------------
        //    encIV = MD5(requestIV ‖ requestKey)
        var encIVData = Data()
        encIVData.append(requestIV)
        encIVData.append(requestKey)
        let encIV = Data(Insecure.MD5.hash(data: encIVData))

        // ---- 6. AES‑128‑CFB encrypt the instruction block ---------------
        let encryptedInstruction = aes128CFB(
            key: requestKey,
            iv: encIV,
            data: instruction
        )

        // ---- 7. Assemble final header -----------------------------------
        var header = Data()
        header.append(0x01) // Version
        header.append(requestIV)
        header.append(requestKey)
        header.append(responseAuth)
        header.append(encryptedInstruction)

        return header
    }

    /// Returns the derived request command key for a given UUID and
    /// timestamp (useful for testing).
    public static func deriveCommandKey(
        uuid: UUID,
        timestamp: UInt64
    ) -> Data {
        var data = Data()
        data.append(contentsOf: uuid.toBytes())
        data.append(contentsOf: timestamp.toBigEndianBytes())
        return Data(Insecure.MD5.hash(data: data))
    }

    // MARK: - Address Encoding

    private static func encodeAddress(_ address: String, into data: inout Data) {
        if let ipv4 = parseIPv4(address) {
            data.append(0x01) // IPv4
            data.append(contentsOf: ipv4)
        } else if let ipv6 = tryParseIPv6(address) {
            data.append(0x03) // IPv6
            data.append(contentsOf: ipv6)
        } else {
            let domainBytes = Array(address.utf8)
            data.append(0x02) // Domain
            data.append(UInt8(domainBytes.count))
            data.append(contentsOf: domainBytes)
        }
    }

    private static func parseIPv4(_ s: String) -> [UInt8]? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var octets: [UInt8] = []
        for p in parts {
            guard let v = UInt8(p) else { return nil }
            octets.append(v)
        }
        return octets
    }

    private static func tryParseIPv6(_ s: String) -> [UInt8]? {
        var groups = s.split(separator: ":", omittingEmptySubsequences: false)
            .map(String.init)
        if groups.count < 8, let idx = groups.firstIndex(of: "") {
            groups.replaceSubrange(idx ... idx,
                                   with: Array(repeating: "0", count: 8 - (groups.count - 1)))
        }
        guard groups.count == 8 else { return nil }
        var bytes: [UInt8] = []
        for g in groups {
            guard let v = UInt16(g, radix: 16) else { return nil }
            bytes.append(UInt8(v >> 8))
            bytes.append(UInt8(v & 0xFF))
        }
        return bytes.count == 16 ? bytes : nil
    }

    // MARK: - Crypto Helpers

    private static func generateRandomBytes(count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        return Data(bytes)
    }

    /// AES‑128‑CFB encryption via CommonCrypto.
    /// CFB mode is not exposed by CryptoKit; CommonCrypto provides the
    /// canonical implementation available on all Apple platforms.
    private static func aes128CFB(key: Data, iv: Data, data: Data) -> Data {
        precondition(key.count == kCCKeySizeAES128)
        precondition(iv.count == kCCBlockSizeAES128)

        var cryptor: CCCryptorRef?
        let status = CCCryptorCreateWithMode(
            CCOperation(kCCEncrypt),
            CCMode(kCCModeCFB),
            CCAlgorithm(kCCAlgorithmAES),
            CCPadding(ccNoPadding),
            iv.withUnsafeBytes { $0.baseAddress },
            key.withUnsafeBytes { $0.baseAddress },
            key.count,
            nil, 0, 0,
            CCModeOptions(0),
            &cryptor
        )
        guard status == kCCSuccess, let cryptorRef = cryptor else {
            return Data()
        }
        defer { CCCryptorRelease(cryptorRef) }

        let inBytes  = [UInt8](data)
        var outBytes = [UInt8](repeating: 0, count: data.count)
        var dataOutMoved = 0

        let updateStatus = CCCryptorUpdate(
            cryptorRef,
            inBytes,
            inBytes.count,
            &outBytes,
            outBytes.count,
            &dataOutMoved
        )

        guard updateStatus == kCCSuccess else { return Data() }
        return Data(outBytes.prefix(dataOutMoved))
    }
}

// MARK: - Extensions

extension UUID {
    /// Returns the 16 raw bytes of the UUID.
    fileprivate func toBytes() -> [UInt8] {
        let u = uuid
        return [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7,
                u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
    }
}

extension UInt64 {
    /// Returns the 8‑byte big‑endian representation.
    fileprivate func toBigEndianBytes() -> [UInt8] {
        let be = bigEndian
        var bytes: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) {
            bytes.append(UInt8((be >> shift) & 0xFF))
        }
        return bytes
    }
}
