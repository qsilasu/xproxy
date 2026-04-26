package node

import (
	"fmt"
	"time"
)

// Protocol identifies the proxy protocol.
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
	ProtoDirect    Protocol = "direct"
)

// TransportType identifies the transport layer protocol.
type TransportType string

const (
	TransportTCP   TransportType = "tcp"
	TransportWS    TransportType = "ws"
	TransportGRPC  TransportType = "grpc"
	TransportHTTP2 TransportType = "h2"
	TransportQUIC  TransportType = "quic"
)

// Node is the unified proxy node representation.
type Node struct {
	Name     string
	Protocol Protocol
	Address  string
	Port     int

	// Protocol-specific configs — only one non-nil per Node.
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

// SSConfig holds Shadowsocks-specific parameters.
type SSConfig struct {
	Method   string
	Password string
}

// VMessConfig holds VMess-specific parameters.
type VMessConfig struct {
	UUID     string
	AlterID  int
	Security string
}

// VLESSConfig holds VLESS-specific parameters.
type VLESSConfig struct {
	UUID   string
	Flow   string
	Packet string
}

// TrojanConfig holds Trojan-specific parameters.
type TrojanConfig struct {
	Password string
	Flow     string
}

// Hysteria2Config holds Hysteria2-specific parameters.
type Hysteria2Config struct {
	Password string
	Obfs     string
	UpMbps   int
	DownMbps int
}

// TUICConfig holds TUIC-specific parameters.
type TUICConfig struct {
	UUID              string
	Password          string
	CongestionControl string
}

// WireGuardConfig holds WireGuard-specific parameters.
type WireGuardConfig struct {
	PrivateKey   string
	PublicKey    string
	PreSharedKey string
	MTU          int
	Reserved     []int
}

// TransportConfig holds transport layer configuration.
type TransportConfig struct {
	Type    TransportType
	Path    string
	Host    string
	Headers map[string]string
}

// TLSConfig holds TLS configuration.
type TLSConfig struct {
	Enable      bool
	ServerName  string
	Insecure    bool
	ALPN        []string
	Fingerprint string
}

// Subscription holds a parsed subscription.
type Subscription struct {
	SourceURL string
	Nodes     []Node
	Groups    []ProxyGroup
	Rules     []Rule
	UpdatedAt time.Time
}

// ProxyGroup represents a client proxy group.
type ProxyGroup struct {
	Name     string
	Type     string   // select, url-test, fallback, load-balance
	Proxies  []string // proxy names (references Node.Name)
	URL      string   // url-test target
	Interval int      // check interval in seconds
}

// Rule represents a routing rule.
type Rule struct {
	Type    string
	Content string
	Proxy   string // target proxy or group name
}

// NodeError records a single node parsing failure within a multi-node input.
type NodeError struct {
	Index int
	Raw   string
	Err   error
}

func (e *NodeError) Error() string {
	return fmt.Sprintf("node[%d] %q: %v", e.Index, e.Raw, e.Err)
}

func (e *NodeError) Unwrap() error {
	return e.Err
}

// NodeListResult captures partial success when parsing multiple nodes.
type NodeListResult struct {
	Nodes  []Node
	Errors []NodeError
}
