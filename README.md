# XProxy

Go-native proxy toolkit library. Four packages in a layered architecture — import only what you need.

## Packages

| Package  | Purpose                                                      | Dependencies        |
| -------- | ------------------------------------------------------------ | ------------------- |
| `node/`  | Shared types: `Node`, `Subscription`, `Protocol` enum        | zero                |
| `url/`   | Bi-directional proxy URL codec (parse & generate)            | `node/`             |
| `sub/`   | Subscription format conversion + auto-detection + HTTP fetch | `node/`, `yaml.v3`  |
| `proxy/` | Unified `Proxy` interface wrapping sing-box runtime          | `node/`, `sing-box` |

## Quick Start

```go
// Parse a proxy URL
n, _ := url.Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#MyNode")

// Generate a proxy URL
s, _ := url.Generate(n)

// Convert subscription formats
sub, _ := sub.ParseURL(ctx, "https://mysub.com/clash.yaml")
clashYAML, _ := sub.Generate(sub, sub.FmtClash)

// Fetch subscription through a proxy
p, _ := proxy.New(socks5Node)
client := &http.Client{Transport: &http.Transport{DialContext: p.DialContext}}
sub, _ := sub.ParseURLWithClient(ctx, "https://mysub.com/all", client)

// Connect through a proxy
conn, _ := p.DialContext(ctx, "tcp", "example.com:443")

// Create a transparent TCP forwarder
ln, _ := p.Listen(ctx, "tcp", ":1080")
// Accepted connections are automatically forwarded through the proxy
```

## Protocol Support

### URL Codec (`url/`)

| Protocol                      | Parse | Generate |
| ----------------------------- | ----- | -------- |
| Shadowsocks (SIP002 + legacy) | Yes   | Yes      |
| VMess                         | Yes   | Yes      |
| VLESS                         | Yes   | Yes      |
| Trojan / Trojan-Go            | Yes   | Yes      |
| Hysteria2                     | Yes   | Yes      |
| TUIC                          | Yes   | Yes      |
| SOCKS5 / SOCKS4               | Yes   | Yes      |
| HTTP / HTTPS                  | Yes   | Yes      |
| WireGuard                     | Yes   | Yes      |
| SSH                           | Yes   | Yes      |
| ShadowTLS                     | Yes   | Yes      |
| AnyTLS                        | Yes   | Yes      |

### Proxy Adapter (`proxy/`)

Wraps [sing-box](https://github.com/SagerNet/sing-box) for runtime connections.

| Protocol     | DialContext |
| ------------ | ----------- |
| Shadowsocks  | Yes         |
| VMess        | Yes         |
| VLESS        | Yes         |
| Trojan       | Yes         |
| Hysteria2    | Yes         |
| SOCKS5       | Yes         |
| HTTP / HTTPS | Yes         |
| TUIC         | Yes         |
| SSH          | Yes         |
| ShadowTLS    | Yes         |
| AnyTLS       | Yes         |
| Direct       | Yes         |

### Subscription Formats (`sub/`)

| Format                  | Parse | Generate | Auto-Detect |
| ----------------------- | ----- | -------- | ----------- |
| Clash / Clash Meta YAML | Yes   | Yes      | Yes         |
| Surge 4+ conf           | Yes   | Yes      | Yes         |
| sing-box JSON           | Yes   | Yes      | Yes         |
| Base64-encoded URI blob | Yes   | Yes      | Yes         |
| SIP002 URI list         | Yes   | Yes      | Yes         |
| Raw URL list            | Yes   | Yes      | Yes         |

## Performance

Apple M1 Pro, single-thread:

| Operation           | Latency | Allocs  |
| ------------------- | ------- | ------- |
| Parse SS            | 2.7 μs  | 720 B   |
| Parse VMess         | 5.2 μs  | 1,424 B |
| Parse VLESS         | 3.0 μs  | 1,912 B |
| Generate SS         | 353 ns  | 288 B   |
| Parse + Generate SS | 1.5 μs  | 1,008 B |
| Detect format       | 248 ns  | 304 B   |
| Batch parse 100 SS  | 119 μs  | 72 KB   |

## E2E Testing

Real-world proxy URL parsing tested against 4 active sources (30,000+ URLs):

| Source    | Update    | VMess  | VLESS | Trojan | SS    |
| --------- | --------- | ------ | ----- | ------ | ----- |
| tgparse   | scheduled | 99.2%  | 99.9% | 100%   | 98.1% |
| epodonios | 5 min     | 69.7%* | 100%  | 99.7%  | 96.9% |
| v2go      | 6 h       | 100%   | 100%  | 100%   | 99.9% |

*epodonios VMess has corrupted base64 in source data.

Fetch fixtures: `bash tests/fetch_fixtures.sh`

## License

MIT
