//===----------------------------------------------------------------------===//
//
//  SwiftletCore.swift
//  SwiftletCore — Module Entry Point
//
//  This file serves as the public API surface for the SwiftletCore package.
//  Importing `SwiftletCore` re‑exports the entire SOCKS5 Inbound Engine
//  and, in future milestones, the TUN2Socks stack, the Router, and the
//  Outbound tunnel implementations.
//
//===----------------------------------------------------------------------===//

// ---------------------------------------------------------------------------
// SOCKS5 Inbound Engine (Milestone 1)
// ---------------------------------------------------------------------------
//
// `Socks5Server` is the primary entry point — bind it to a local port and
// it will accept SOCKS5 CONNECT requests, establish upstream TCP connections,
// and relay data bidirectionally.
//
// All protocol types are public so callers can implement custom handlers,
// logging, or analytics without re‑parsing wire‑format data.
//
// @_exported import is deliberately avoided — each type is re‑exported
// individually to keep the module surface explicit and auditable.
// ---------------------------------------------------------------------------

// These re‑exports ensure that `import SwiftletCore` makes all SOCKS5 types
// available without requiring a separate `import SwiftletCore.Socks5`.

@_exported import NIOCore
@_exported import NIOPosix
