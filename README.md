# SwiftletCore

使用 Swift 编写的纯血统网络代理内核。基于 Apple SwiftNIO 异步事件驱动框架，专为 iOS/visionOS `PacketTunnelProvider` 网络扩展设计，利用编译期 ARC 替代 GC 延迟，内存占用控制在 5MB–8MB。

---

## 架构总览

```
┌──────────────────────────────────────────────────────────────┐
│                     Inbound (入站)                            │
│  Socks5/        ← SOCKS5 协议服务器 (RFC 1928)                │
│  HTTP/          ← HTTP CONNECT 代理服务器 (RFC 7231)          │
│  NE/            ← VIF 双栈虚拟接口配置器 (IPv4+IPv6+DNS+MTU)   │
├──────────────────────────────────────────────────────────────┤
│                     Stack (协议栈)                            │
│  IPHeader/      ← IPv4/IPv6 零拷贝数据包解析器                 │
│  TCPHeader/     ← TCP 段解析器 + SYN-ACK 构建器               │
│  TCPChecksum    ← TCP 校验和计算 (IPv4/IPv6)                  │
│  TCPSession     ← 4元组会话跟踪 + NAT 表                      │
│  TUN2Socks      ← 虚拟 TCP 3次握手 + SOCKS5 桥接              │
│  TUN2Udp         ← UDP 会话 NAT 桥接 + 回复包组装               │
├──────────────────────────────────────────────────────────────┤
│                     Router (路由)                             │
│  TrieNode       ← 域名后缀 Trie 树 (Radix Tree)              │
│  RoutingRule    ← 多维规则 (域名/CIDR/UserAgent/ASN/逻辑)     │
│  IPRadixTree    ← 位图 Radix Tree (O(32) IPv4 最长前缀)       │
│  AsyncDNS       ← UDP + DoH 异步 DNS 解析器 (TTL 缓存)       │
│  RoutingEngine  ← 中央路由决策引擎 (Actor + 上下文路由)       │
├──────────────────────────────────────────────────────────────┤
│                    Outbound (出站)                            │
│  Shadowsocks/   ← AEAD 加密 (AES-GCM / ChaCha20-Poly1305)    │
│  ShadowsocksR/  ← SSR 协议 + 混淆插件 (auth_aes128 / tls1.2) │
│  Trojan/        ← Trojan-TLS 出站协议                         │
│  TLS/           ← REALITY TLS ClientHello 修改器 + ShadowTLS  │
│  VLESS/         ← VLESS-REALITY + WebSocket 出站引擎          │
│  WireGuard/     ← Noise_IKpsk2 握手 + Type 4 Transport AEAD   │
│  VMess/         ← VMess v1 协议 (MD5 + AES-128-CFB)          │
│  Hysteria2/     ← QUIC 帧 + Salamander 混淆引擎               │
│  TUIC/           ← TUIC v5 二进制帧 + 流多路分解器              │
│  Snell/          ← Snell v4 PSK 协议 + AES‑128‑GCM 会话加密     │
│  gRPC/           ← gRPC 5 字节帧编解码 + HTTP/2 流合成          │
│  AnyTLS/        ← 对称字节混淆引擎 (XOR + xorshift32)         │
│  Obfs/           ← Simple-Obfs HTTP/TLS 流伪装引擎             │
│  HTTP/          ← HTTP CONNECT 出站隧道                       │
│  UDP/           ← UDP 会话关联管理器 (WireGuard / Hysteria2)   │
└──────────────────────────────────────────────────────────────┘
```

---

## 支持的协议

### 入站协议 (Inbound)

| 协议 | 模块 | 说明 |
|------|------|------|
| **SOCKS5** | `Inbound/Socks5/` | 完整 RFC 1928 实现，支持 `NO AUTH` (0x00) 认证和 `CONNECT` (0x01) 命令，IPv4 / IPv6 / 域名地址类型，异步双向流转发 |
| **HTTP CONNECT** | `Inbound/HTTP/` | HTTP 代理服务器，解析 `CONNECT host:port` 请求，返回 `HTTP/1.1 200`，转入零拷贝原始流转发 |
| **VIF Configurator** | `Inbound/NE/` | Apple NetworkExtension 双栈虚拟接口 | IPv4 `198.18.0.1/16` + IPv6 `fd00:a:b:c::1/64`，全局默认路由（`0.0.0.0/0` + `::/0`），DNS 劫持，MTU 1420 |

### Layer 3/4 协议 (Stack)

| 协议 | 模块 | 说明 |
|------|------|------|
| **IPv4** | `Stack/IPHeader.swift` | RFC 791 头部解析，零拷贝 `ByteBuffer` 切片，IHL / Total Length / Protocol / 分片标志 |
| **IPv6** | `Stack/IPHeader.swift` | RFC 8200 头部解析，Payload Length / Next Header / Hop Limit / Flow Label |
| **TCP** | `Stack/TCPHeader.swift` | RFC 793 段解析器，SYN / SYN-ACK / RST / FIN-ACK 构建器，Data Offset + Flags + 校验和 |
| **TCP Checksum** | `Stack/TCPChecksum.swift` | IPv4 伪头部 + IPv6 伪头部 16 位 Internet 补码校验和 |
| **TUN2Socks** | `Stack/TUN2SocksBridge.swift` | 用户空间 TCP 虚拟握手 (SYN → SYN-ACK)，4元组 NAT 会话表，IP 包 → SOCKS5 桥接 |
| **TUN2Udp** | `Stack/TUN2UdpBridge.swift` | UDP 数据包解析（8 字节头），4 元组 NAT 会话注册表，IPv4 伪头部 UDP 校验和，反向回复包组装 |

### 路由引擎 (Router)

| 组件 | 模块 | 说明 |
|------|------|------|
| **Domain Trie** | `Router/TrieNode.swift` | 域名后缀 Trie 树，最长匹配优先，O(labels) 查找，10k 规则 < 10µs/次 |
| **CIDR Matcher** | `Router/RoutingRule.swift` | IPv4 最长前缀匹配，O(32) 查找，支持 `/0` 到 `/32` |
| **IP Radix Tree** | `Router/IPRadixTree.swift` | IPv4/IPv6 位图压缩前缀树，O(32/128) 单次查找，10k 规则插入+查找 < 100ms |
| **Keyword Matcher** | `Router/TrieNode.swift` | 域名关键词线性扫描 |
| **Async DNS** | `Router/AsyncDNSResolver.swift` | UDP (端口 53) + DoH (DNS over HTTPS) 双传输，TTL 缓存，A / AAAA 并发查询 |
| **Routing Engine** | `Router/RoutingEngine.swift` | Actor 中央决策引擎，优先级：域名后缀 → 关键词 → UserAgent/ASN/逻辑 → CIDR → 默认 |

### 出站协议 (Outbound)

| 协议 | 模块 | 加密 / 认证方式 | 说明 |
|------|------|-----------------|------|
| **Shadowsocks** | `Outbound/Shadowsocks/` | `aes-128-gcm` / `aes-256-gcm` / `chacha20-poly1305` | CryptoKit 硬件 AEAD，HKDF-SHA1 密钥派生，0x3FFF 分块，Salt + Nonce + Tag |
| **ShadowsocksR** | `Outbound/ShadowsocksR/` | AES‑CFB / ChaCha20 + 协议插件 + 混淆插件 | SSR 协议插件层 (`origin`, `auth_aes128_sha1`, `auth_chain_a`) + 混淆插件层 (`plain`, `http_simple`, `tls1.2_ticket_auth`)，支持 `ssr://` Base64 URI 解析 |
| **Trojan** | `Outbound/Trojan/` | TLS 1.3 + SHA-224 | SHA-224 密码哈希 (56 字节 hex)，SOCKS5 地址编码，TLS 加密通道 |
| **REALITY** | `Outbound/TLS/` | 原始 TLS 1.3 字节修改 | ClientHello 解析/序列化，Auth Key + Padding 扩展注入，SNI 替换，长度重算 |
| **ShadowTLS v3** | `Outbound/ShadowTLS/` | TLS 1.3 握手劫持 + HMAC-SHA256 挑战注入 | 三阶段状态机 + v3 挑战令牌：HMAC(password, ClientHello.random).prefix(8) 注入 Session ID，ServerHello 响应验证 |
| **VLESS-REALITY** | `Outbound/VLESS/` | VLESS v0 + REALITY | UUID 认证 (16 字节)，REALITY 握手，三阶段状态机 (handshake → request → streaming) |
| **VLESS-WebSocket** | `Outbound/VLESS/` | RFC 6455 Binary Frame | WebSocket 帧编解码，Client→Server XOR 掩码，7/16/64 bit 扩展长度，零拷贝透传 |
| **VMess v1** | `Outbound/VMess/` | MD5 + AES-128-CFB | UUID + 时间戳动态密钥，加密指令块 (端口/地址/填充)，反重放 |
| **WireGuard** | `Outbound/WireGuard/` | Curve25519 ECDH + HKDF-SHA256 + ChaCha20-Poly1305 | Noise_IKpsk2_25519 握手 (Type 1/2)，Type 4 Transport Data 加密/解密，零拷贝 ByteBuffer 封装 |
| **Hysteria 2** | `Outbound/Hysteria2/` | QUIC Varints + 自定义帧 + Salamander XOR 混淆 | Type 0x401 TCP/0x402 UDP 请求帧，0x403 数据帧，Salamander 动态填充防 DPI |
| **TUIC v5** | `Outbound/TUIC/` | 原始 QUIC 流二进制帧 + Actor 多路复用 | 5 种帧类型编解码，零拷贝 ByteBuffer，边界安全 nil‑on‑partial 流解码器，Actor 并发流管理器（开流/发包/关流），50 路并发隔离 |
| **Snell v4** | `Outbound/Snell/` | PSK + HKDF-SHA256 + AES-128-GCM | 16 字节 Nonce → 会话密钥派生，加密元数据帧 (addrType + address + port + command)，握手验证 + 流式 AEAD 加解密 |
| **gRPC Transport** | `Outbound/gRPC/` | HTTP/2 流多路复用 + 5 字节 gRPC 帧 | gRPCFrameCodec (0x00 + 4B BE 长度)，HTTP/2 流合成 (:method=POST, :path=/{svc}/Tun)，支持 VMess/VLESS/Trojan+gRPC 组合 |
| **Simple-Obfs** | `Outbound/Obfs/` | HTTP/TLS 流伪装 | HTTP 模式前置 GET 请求头 + 剥离 HTTP 响应头，TLS 模式前置 ClientHello + 剥离握手记录至 Application Data |
| **Streaming HTTP Obfs** | `Outbound/Obfs/` | HTTP POST 流式分块编码/解码 | 每块代理数据独立包装为 HTTP POST（动态 Content-Length），入站 HTTP 响应流式解帧（Header 扫描 → 精确 Body 切片），支持 VMess+HTTP / VLESS+HTTP / Trojan+HTTP 组合 |
| **AnyTLS** | `Outbound/AnyTLS/` | XOR + xorshift32 PRNG | 对称混淆，种子 → 密钥流，原地 XOR 突变，双重 XOR = 还原 |
| **HTTP CONNECT** | `Outbound/HTTP/` | HTTP/1.1 CONNECT 隧道 | `CONNECT host:port` 请求 + 200 响应解析，可选 TLS 嵌套 (`isTLSEnabled`) |
| **UDP Association** | `Outbound/UDP/` | Actor 并发会话管理 | 4元组 UDP 会话跟踪，30s 空闲超时自动清理，支持 WireGuard / Hysteria2 |

---

## 依赖

| 库 | 用途 |
|----|------|
| [swift-nio](https://github.com/apple/swift-nio) | 异步事件驱动网络框架 (NIOCore + NIOPosix) |
| [swift-nio-ssl](https://github.com/apple/swift-nio-ssl) | TLS 支持 (Trojan / HTTPS 协议) |
| `CryptoKit` (系统) | AEAD (Shadowsocks / WireGuard)，Curve25519 ECDH + HKDF-SHA256 (WireGuard Noise)，MD5 (VMess)，SHA-1 HMAC (HKDF) |
| `CommonCrypto` (系统) | SHA-224 (Trojan)，AES-128-CFB (VMess) |
| `Network.framework` (系统) | UDP / DoH DNS 传输 (AsyncDNSResolver) |
| `Security.framework` (系统) | `SecRandomCopyBytes` 安全随机数 |

---

## 编译 & 测试

```bash
# 编译
swift build

# 运行全部测试
swift test
```

### 平台要求

| 平台 | 最低版本 |
|------|----------|
| iOS | 15.0 |
| macOS | 12.0 |
| tvOS | 15.0 |
| visionOS | 1.0 |

### 测试覆盖

```
795+ tests | 158+ suites | 0 warnings

入站:
  SOCKS5:               1 test
  HTTP Inbound:        13 tests
  VIF Configurator:    36 tests

协议栈:
  IP Parser:           12 tests
  TUN2Socks:            4 tests
  TUN2Udp:             28 tests (UDP 解析 + 校验和 + NAT + 回复组装)

路由:
  Router:              42 tests (Trie/CIDR/RadixTree/UserAgent/ASN/逻辑规则 + 10k 性能基准)

出站:
  Shadowsocks:         10 tests
  ShadowsocksR:        15 tests (URI 解析 + 协议/混淆插件 + 状态机)
  Trojan:              10 tests
  REALITY / ShadowTLS: 51 tests (TLS 修改 8 + ShadowTLS v3 43)
  VLESS-REALITY:       13 tests
  VLESS-WebSocket:      8 tests
  VMess v1:            16 tests
  WireGuard:           61 tests (Noise 21 + Transport Data 40)
  Hysteria 2:          38 tests (帧/QUIC/Salamander/UDP)
  TUIC v5:            130 tests (帧编解码 84 + 多路复用 46)
  Snell v4:            30 tests (密钥派生 + AEAD + 握手 + 元数据帧)
  gRPC Transport:      24 tests (帧编解码 + 分段 + 配置 + 订阅解析)
  Simple-Obfs:         27 tests
  Streaming HTTP Obfs: 32 tests (POST 包装 + 响应解帧 + OutboundProtocol 工厂)
  AnyTLS:               8 tests
  HTTP Outbound:        9 tests
  UDP Association:      9 tests

集成:
  Ecosystem Pipeline:   1 test
  Outbound Connection Pool: 26 tests
  Subscription Parser:  70 tests
  Secure DNS:           36 tests (竞速 + 配置 + 数据包)
  Legacy:               3 tests
  Omni Protocol:        5 tests (HTTP + UDP 联动)
```
