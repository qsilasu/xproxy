# XProxy Design Spec

## Overview

XProxy is a Go-native proxy toolkit library providing three capabilities:

1. **Unified proxy interface** — wrap sing-box core, expose `DialContext` / `Listen` / `Info` / `Statistics`
2. **Proxy URL codec** — bi-directional encode/decode of proxy URLs (`ss://`, `vmess://`, `vless://`, etc.)
3. **Subscription format conversion** — parse and generate mainstream subscription formats (Clash, Surge, sing-box, Base64, SIP002)

Pure library, not a service. Users `go get` and import the packages they need.

## Architecture

```
xproxy/
├── node/            # Shared types, zero external deps
│   └── types.go     #   Node, Protocol, Subscription, TransportConfig, TLSConfig
├── url/             # Proxy URL codec, zero external deps
│   ├── url.go       #   Clean + Parse + Generate
│   ├── ss.go        #   Shadowsocks SIP002 / legacy
│   ├── vmess.go     #   VMess (base64 JSON body)
│   ├── vless.go     #   VLESS query-string encoding
│   ├── trojan.go    #   Trojan / trojan-go
│   ├── hysteria2.go #   Hysteria2
│   ├── tuic.go      #   TUIC
│   ├── socks.go     #   SOCKS5 / SOCKS4
│   ├── http.go      #   HTTP / HTTPS
│   ├── wireguard.go #   WireGuard
│   └── others.go    #   SSH, ShadowTLS, AnyTLS
├── sub/             # Subscription format conversion, dep: yaml.v3
│   ├── sub.go       #   Format enum + Parse/Generate/ParseURL
│   ├── clash.go     #   Clash / Clash Meta YAML
│   ├── surge.go     #   Surge 4+ conf
│   ├── singbox.go   #   sing-box JSON config
│   ├── base64.go    #   Base64-encoded URI blob
│   ├── ss.go        #   Shadowsocks SIP002 URI list
│   ├── raw.go       #   Newline-delimited proxy URLs
│   └── detect.go    #   Auto format detection for ParseURL
└── proxy/           # Unified proxy interface, dep: sagernet/sing-box
    ├── proxy.go     #   Proxy interface + New()
    └── singbox/     #   sing-box backend adapter
        ├── ss.go
        ├── vmess.go
        ├── vless.go
        └── ...
```

### Dependency Graph

```
node/          zero external deps
  ├── url/     zero external deps (depends on node/)
  ├── sub/     yaml.v3 (depends on node/)
  └── proxy/   sagernet/sing-box GPLv3 (depends on node/)
```

Users import only what they need:
- Want just URL codec? `import ".../url"` — no sing-box, no yaml
- Want format conversion? `import ".../sub"` — no sing-box
- Want proxy connections? `import ".../proxy"` — includes sing-box

## Package: node/

Shared types. Zero external dependencies. All other packages depend on this.

### Protocol Enum

```go
type Protocol string
const (
    ProtoSS        Protocol = "shadowsocks"
    ProtoVMess     Protocol = "vmess"
    ProtoVLESS     Protocol = "vless"
    ProtoTrojan    Protocol = "trojan"
    ProtoHysteria2 Protocol = "hysteria2"
    ProtoTUIC      Protocol = "tuic"
    ProtoHTTP      Protocol = "http"
    ProtoHTTPS     Protocol = "https"
    ProtoSOCKS5    Protocol = "socks5"
    ProtoWireGuard Protocol = "wireguard"
    ProtoSSH       Protocol = "ssh"
    ProtoShadowTLS Protocol = "shadowtls"
    ProtoAnyTLS    Protocol = "anytls"
)
```

### Node

```go
type Node struct {
    Name     string
    Protocol Protocol
    Address  string
    Port     int

    // Protocol-specific configs (only one non-nil per protocol)
    Shadowsocks *SSConfig
    VMess       *VMessConfig
    VLESS       *VLESSConfig
    Trojan      *TrojanConfig
    Hysteria2   *Hysteria2Config
    TUIC        *TUICConfig
    WireGuard   *WireGuardConfig

    Transport *TransportConfig
    TLS       *TLSConfig

    Tags   []string
    Extras map[string]string
}
```

Each protocol has its own typed config struct. Only one is non-nil per node, enforced by construction. `Extras` captures kv pairs not explicitly modeled.

### TransportConfig

```go
type TransportType string
const (
    TransportTCP   TransportType = "tcp"
    TransportWS    TransportType = "ws"
    TransportGRPC  TransportType = "grpc"
    TransportHTTP2 TransportType = "h2"
    TransportQUIC  TransportType = "quic"
)

type TransportConfig struct {
    Type    TransportType
    Path    string
    Host    string
    Headers map[string]string
}
```

### TLSConfig

```go
type TLSConfig struct {
    Enable     bool
    ServerName string
    Insecure   bool
    ALPN       []string
    Fingerprint string  // uTLS fingerprint
}
```

### Subscription

```go
type Subscription struct {
    SourceURL string
    Nodes     []Node
    Groups    []ProxyGroup
    Rules     []Rule
    UpdatedAt time.Time
}

type ProxyGroup struct {
    Name     string
    Type     string   // select, url-test, fallback, load-balance
    Proxies  []string // proxy names (references Node.Name)
    URL      string   // url-test target
    Interval int      // check interval in seconds
}

type Rule struct {
    Type    string
    Content string
    Proxy   string   // target proxy or group name
}
```

## Package: proxy/

Wraps sing-box core. Provides a unified `Proxy` interface. Stateful — callers must `Close()`.

### Proxy Interface

```go
type Proxy interface {
    DialContext(ctx context.Context, network, addr string) (net.Conn, error)
    Listen(ctx context.Context, network, addr string) (net.Listener, error)
    Info() Info
    Statistics() Statistics
    Close() error
}

type Info struct {
    Name     string
    Protocol node.Protocol
    Address  string
    Port     int
}

type Statistics struct {
    UploadBytes   int64
    DownloadBytes int64
    StartedAt     time.Time
}
```

### Constructor

```go
func New(n node.Node) (Proxy, error)
func Must(p Proxy, err error) Proxy
```

### Sing-box Adapter Pattern

`New()` dispatches to protocol-specific adapters:

```
New(Node) → switch Protocol →
  ssAdapter(Node.Shadowsocks) → sing-box outbound → Proxy
  vmessAdapter(Node.VMess)     → sing-box outbound → Proxy
  vlessAdapter(Node.VLESS)     → sing-box outbound → Proxy
  ...
```

Each adapter translates `node.Node` fields into sing-box's internal option struct. `Listen()` uses sing-box inbound path.

## Package: url/

Proxy URL codec. Zero external dependencies, depends only on `node/` and Go stdlib.

### API

```go
func Parse(rawURL string) (*node.Node, error)
func MustParse(rawURL string) *node.Node
func Generate(n *node.Node) (string, error)
func Clean(rawURL string) string
func ParseURL(rawURL string) (*node.Node, error)  // Clean + Parse
```

### Supported URL Schemes

| Scheme                       | Parse | Generate |
| ---------------------------- | ----- | -------- |
| `ss://` (SIP002 + legacy)    | Yes   | Yes      |
| `vmess://`                   | Yes   | Yes      |
| `vless://`                   | Yes   | Yes      |
| `trojan://` / `trojan-go://` | Yes   | Yes      |
| `hysteria2://`               | Yes   | Yes      |
| `tuic://`                    | Yes   | Yes      |
| `socks5://` / `socks4://`    | Yes   | Yes      |
| `http://` / `https://`       | Yes   | Yes      |
| `wireguard://`               | Yes   | Yes      |
| `ssh://`                     | Yes   | Yes      |
| `shadowtls://`               | Yes   | Yes      |
| `anytls://`                  | Yes   | Yes      |

### Parse Pipeline (inspired by singproxy)

```
1. Scheme dispatch → route to protocol-specific parser
2. Clean phase:
   - Isolate fragment (#name)
   - Strip junk params (ps, remarks, tag)
   - Protocol-specific brute-force fixes
3. net/url.Parse standard parsing
4. Post-parse: fill defaults, validate required fields
```

`Clean()` is public so callers can debug dirty URLs without full parsing.

## Package: sub/

Subscription format conversion. Depends on `node/`, `gopkg.in/yaml.v3`, and Go stdlib.

### API

```go
type Format string
const (
    FmtClash   Format = "clash"
    FmtSurge   Format = "surge"
    FmtSingBox Format = "singbox"
    FmtSS      Format = "ss"
    FmtBase64  Format = "base64"
    FmtRaw     Format = "raw"
)

func Parse(input []byte, format Format) (*node.Subscription, error)
func ParseURL(ctx context.Context, url string) (*node.Subscription, error)
func Generate(sub *node.Subscription, format Format) ([]byte, error)
```

### Format Capability Matrix

| Format                  | Parse (input) | Generate (output) | Priority |
| ----------------------- | ------------- | ----------------- | -------- |
| Clash / Clash Meta YAML | Yes           | Yes               | P0       |
| sing-box JSON           | Yes           | Yes               | P0       |
| Base64 blob             | Yes           | Yes               | P0       |
| SIP002 URI list         | Yes           | Yes               | P0       |
| Surge 4+ conf           | Yes           | Yes               | P1       |
| Raw URL list            | Yes           | Yes               | P1       |

### ParseURL Flow

```
ParseURL(ctx, url) →
  1. HTTP GET (with ctx)
  2. Response sniffing:
     - Content-Type header
     - First bytes pattern match
  3. Decode wrapper (base64 or gzip or plain)
  4. Format auto-detect
  5. Parse(decoded, detectedFormat)
```

### Conversion Flow

Format conversion is pure function composition:

```
Input → Parse(input, sourceFormat) → node.Subscription
  → user may modify/filter Nodes
  → Generate(sub, targetFormat) → Output
```

## Error Handling

### Error Types

```go
type ParseError struct {
    Input  string
    Format string
    Err    error
}
func (e *ParseError) Error() string
func (e *ParseError) Unwrap() error

type NodeError struct {
    Index int
    Raw   string
    Err   error
}
func (e *NodeError) Error() string
func (e *NodeError) Unwrap() error
```

### Multi-Node Parsing

When parsing multiple nodes (subscriptions), individual node failures are collected alongside successes:

```go
type NodeListResult struct {
    Nodes  []node.Node
    Errors []NodeError
}
```

Go standard library error convention applies: callers check errors via return values. `Must*()` variants available for trusted input.

## Testing Strategy

- **node/**: unit tests for type construction, zero-value safety
- **url/**: per-protocol parse/generate round-trip tests (`n == Parse(Generate(n))`), dirty URL fixture tests from known-problematic subscription sources
- **sub/**: per-format parse/generate round-trip tests, fixture-based tests against real subscription outputs (Clash, Surge, sing-box), format auto-detection tests
- **proxy/**: integration tests with sing-box loopback (echo server → proxy → assert connectivity), per-protocol smoke tests

## Scope Boundaries

### In scope
- Proxy URL parse/generate (12+ schemes)
- Subscription format convert (6 formats)
- Unified proxy interface with Dial/Listen/Info/Statistics
- Node validation (required field checks)
- URL cleaning for malformed inputs
- Concurrent-safe proxy usage

### Out of scope
- Protocol wire implementations (delegated to sing-box)
- HTTP service / REST API
- Gist auto-upload
- Custom ruleset management
- GUI or CLI tooling
- Quality-of-life features beyond what's specified (no scope creep)

## Dependency Summary

| Package  | External Dependencies | License Risk |
| -------- | --------------------- | ------------ |
| `node/`  | None                  | —            |
| `url/`   | None                  | —            |
| `sub/`   | `gopkg.in/yaml.v3`    | MIT          |
| `proxy/` | `sagernet/sing-box`   | GPLv3        |

## References

- [sing-box](https://github.com/SagerNet/sing-box) — universal proxy platform (GPLv3)
- [singproxy](https://github.com/izomsoftware/singproxy) — sing-box wrapper with dirty URL parsing (MIT)
- [subconverter](https://github.com/tindy2013/subconverter) — subscription format converter (C++, GPLv3)
