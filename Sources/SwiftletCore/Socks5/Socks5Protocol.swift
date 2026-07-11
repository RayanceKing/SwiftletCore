//===----------------------------------------------------------------------===//
//
//  Socks5Protocol.swift
//  SwiftletCore — SOCKS5 Protocol Definitions (RFC 1928)
//
//  This file contains the complete structural definitions for the SOCKS
//  Protocol Version 5, including all frame types, enums, errors, and the
//  inbound/outbound message type hierarchies consumed by the channel pipeline.
//
//===----------------------------------------------------------------------===//

@preconcurrency import NIOCore

// MARK: - Protocol Constants

/// Wire-level constants defined by RFC 1928.
public enum Socks5Constants {
    /// The SOCKS protocol version (0x05).
    public static let version: UInt8 = 0x05
    /// The reserved field — MUST be 0x00 in all conforming implementations.
    public static let reserved: UInt8 = 0x00
}

// MARK: - Pipeline Handler Names

/// Well‑known names for handlers inserted into the child‑channel pipeline.
/// Callers MUST use these names when adding handlers so the relay
/// reconfiguration logic can locate and remove them deterministically.
public enum Socks5PipelineName {
    public static let decoder = "socks5-decoder"
    public static let encoder = "socks5-encoder"
    public static let handler = "socks5-handler"
    public static let relay   = "socks5-relay"
}

// MARK: - Authentication

/// Authentication methods advertised by the client or selected by the server.
///  - `0x00` — No Authentication Required
///  - `0x01` — GSSAPI
///  - `0x02` — Username / Password
///  - `0xFF` — No Acceptable Methods (server‑only rejection signal)
public enum Socks5AuthMethod: UInt8, Sendable, Equatable, CaseIterable {
    case noAuthentication   = 0x00
    case gssapi             = 0x01
    case usernamePassword   = 0x02
    /// Server‑only: signals that none of the client‑offered methods are supported.
    case noAcceptable       = 0xFF
}

// MARK: - Commands

/// SOCKS5 request commands (RFC 1928 §4).
public enum Socks5Command: UInt8, Sendable, Equatable {
    case connect        = 0x01
    case bind           = 0x02
    case udpAssociate   = 0x03
}

// MARK: - Address Types

/// Address type indicators used in SOCKS5 requests and replies (RFC 1928 §5).
public enum Socks5AddressType: UInt8, Sendable, Equatable {
    case ipv4       = 0x01
    case domainName = 0x03
    case ipv6       = 0x04
}

// MARK: - Reply Codes

/// Reply codes sent by the server in response to a CONNECT / BIND / UDP request
/// (RFC 1928 §6).
public enum Socks5Reply: UInt8, Sendable, Equatable {
    case succeeded                  = 0x00
    case generalFailure             = 0x01
    case connectionNotAllowed       = 0x02
    case networkUnreachable         = 0x03
    case hostUnreachable            = 0x04
    case connectionRefused          = 0x05
    case ttlExpired                 = 0x06
    case commandNotSupported        = 0x07
    case addressTypeNotSupported    = 0x08
}

// MARK: - Address Target

/// A fully‑resolved destination target extracted from a SOCKS5 request.
/// Addresses are stored in their human‑readable string form so they can be
/// passed directly to `ClientBootstrap.connect(host:port:)`.
public enum Socks5Target: Sendable, Equatable {
    /// IPv4 address (e.g. `"192.168.1.1"`) and port.
    case ipv4(address: String, port: Int)
    /// Fully‑qualified domain name and port.
    case domain(name: String, port: Int)
    /// IPv6 address (e.g. `"::1"`) and port.
    case ipv6(address: String, port: Int)
}

// MARK: - Protocol Messages (Parsed)

/// A SOCKS5 client greeting: the list of authentication methods the client
/// is willing to negotiate.
public struct Socks5Greeting: Sendable, Equatable {
    /// Offered methods in the order the client sent them.
    public let methods: [Socks5AuthMethod]

    public init(methods: [Socks5AuthMethod]) {
        self.methods = methods
    }
}

/// A SOCKS5 client request carrying the command and destination.
public struct Socks5Request: Sendable, Equatable {
    /// The requested command (CONNECT, BIND, or UDP ASSOCIATE).
    public let command: Socks5Command
    /// The destination target host and port.
    public let target: Socks5Target

    public init(command: Socks5Command, target: Socks5Target) {
        self.command = command
        self.target = target
    }
}

/// A SOCKS5 server response sent after the outbound connection has been
/// established (or has failed).
public struct Socks5Response: Sendable, Equatable {
    /// The reply code indicating success or the reason for failure.
    public let reply: Socks5Reply
    /// Server‑bound address (BND.ADDR). Defaults to `"0.0.0.0"`.
    public let bindHost: String
    /// Server‑bound port (BND.PORT). Defaults to `0`.
    public let bindPort: UInt16

    public init(
        reply: Socks5Reply,
        bindHost: String = "0.0.0.0",
        bindPort: UInt16 = 0
    ) {
        self.reply = reply
        self.bindHost = bindHost
        self.bindPort = bindPort
    }
}

// MARK: - Pipeline Message Enums

/// Messages flowing **into** the `Socks5InboundHandler` after being decoded
/// from the wire by `Socks5Decoder`.
public enum Socks5InboundMessage: Sendable {
    case greeting(Socks5Greeting)
    case request(Socks5Request)
}

/// Messages flowing **out of** the `Socks5InboundHandler` toward the client
/// through the `Socks5Encoder`.
public enum Socks5OutboundMessage: Sendable {
    /// Server → Client: method‑selection message (2 bytes).
    case methodSelection(Socks5AuthMethod)
    /// Server → Client: request reply.
    case response(Socks5Response)
}

// MARK: - Errors

/// Errors produced during SOCKS5 protocol parsing and connection handling.
public enum Socks5Error: Error, Sendable {
    /// The VER byte is not 0x05.
    case invalidVersion(UInt8)
    /// The CMD byte does not map to a known `Socks5Command`.
    case invalidCommand(UInt8)
    /// The command is valid but not supported by this server (e.g. BIND).
    case unsupportedCommand(Socks5Command)
    /// The RSV field is not 0x00.
    case invalidReservedField(UInt8)
    /// The ATYP byte is not a recognised `Socks5AddressType`.
    case invalidAddressType(UInt8)
    /// The domain‑name length byte is 0 or exceeds 255.
    case invalidDomainLength(Int)
    /// The client did not offer any authentication method the server accepts.
    case noAcceptableAuthMethod
    /// The upstream connection could not be established.
    case connectionFailed(reply: Socks5Reply, underlying: Error?)

    /// A human‑readable description suitable for logging.
    public var localizedDescription: String {
        switch self {
        case .invalidVersion(let v):
            return "Invalid SOCKS version: \(v) (expected 0x05)"
        case .invalidCommand(let c):
            return "Invalid SOCKS command: 0x\(String(c, radix: 16))"
        case .unsupportedCommand(let cmd):
            return "Unsupported SOCKS command: \(cmd)"
        case .invalidReservedField(let r):
            return "Invalid RSV field: 0x\(String(r, radix: 16)) (expected 0x00)"
        case .invalidAddressType(let a):
            return "Invalid ATYP: 0x\(String(a, radix: 16))"
        case .invalidDomainLength(let len):
            return "Invalid domain name length: \(len) (expected 1–255)"
        case .noAcceptableAuthMethod:
            return "Client offered no acceptable authentication method"
        case .connectionFailed(let reply, let error):
            let base = "Upstream connection failed: \(reply)"
            if let error = error {
                return "\(base) — \(String(describing: error))"
            }
            return base
        }
    }
}
