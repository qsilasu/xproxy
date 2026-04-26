package sub

import (
	"github.com/qsilasu/xproxy/node"
	"gopkg.in/yaml.v3"
)

type clashConfig struct {
	Proxies     []clashProxy `yaml:"proxies"`
	ProxyGroups []clashGroup `yaml:"proxy-groups"`
	Rules       []string     `yaml:"rules"`
}

type clashProxy struct {
	Name           string         `yaml:"name"`
	Type           string         `yaml:"type"`
	Server         string         `yaml:"server"`
	Port           int            `yaml:"port"`
	Cipher         string         `yaml:"cipher,omitempty"`
	Password       string         `yaml:"password,omitempty"`
	UUID           string         `yaml:"uuid,omitempty"`
	AlterID        int            `yaml:"alterId,omitempty"`
	Network        string         `yaml:"network,omitempty"`
	WSOpts         *clashWSOpts   `yaml:"ws-opts,omitempty"`
	GRPCOpts       *clashGRPCOpts `yaml:"grpc-opts,omitempty"`
	H2Opts         *clashH2Opts   `yaml:"h2-opts,omitempty"`
	SNI            string         `yaml:"sni,omitempty"`
	SkipCertVerify bool           `yaml:"skip-cert-verify,omitempty"`
	Fingerprint    string         `yaml:"fingerprint,omitempty"`
	Extra          map[string]any `yaml:",inline"`
}

type clashWSOpts struct {
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers,omitempty"`
}

type clashGRPCOpts struct {
	GRPCServiceName string `yaml:"grpc-service-name"`
}

type clashH2Opts struct {
	Host []string `yaml:"host"`
	Path string   `yaml:"path"`
}

type clashGroup struct {
	Name     string   `yaml:"name"`
	Type     string   `yaml:"type"`
	Proxies  []string `yaml:"proxies"`
	URL      string   `yaml:"url,omitempty"`
	Interval int      `yaml:"interval,omitempty"`
}

func parseClash(input []byte) (*node.Subscription, error) {
	var cfg clashConfig
	if err := yaml.Unmarshal(input, &cfg); err != nil {
		return nil, err
	}

	sub := &node.Subscription{}
	for _, p := range cfg.Proxies {
		n := clashProxyToNode(p)
		sub.Nodes = append(sub.Nodes, n)
	}
	for _, g := range cfg.ProxyGroups {
		sub.Groups = append(sub.Groups, node.ProxyGroup{
			Name:     g.Name,
			Type:     g.Type,
			Proxies:  g.Proxies,
			URL:      g.URL,
			Interval: g.Interval,
		})
	}
	for _, r := range cfg.Rules {
		sub.Rules = append(sub.Rules, parseClashRule(r))
	}
	return sub, nil
}

func clashProxyToNode(p clashProxy) node.Node {
	n := node.Node{
		Name:    p.Name,
		Address: p.Server,
		Port:    p.Port,
		Extras:  make(map[string]string),
	}

	switch p.Type {
	case "ss":
		n.Protocol = node.ProtoSS
		n.Shadowsocks = &node.SSConfig{
			Method:   p.Cipher,
			Password: p.Password,
		}
	case "vmess":
		n.Protocol = node.ProtoVMess
		n.VMess = &node.VMessConfig{
			UUID:     p.UUID,
			AlterID:  p.AlterID,
			Security: p.Cipher,
		}
	case "vless":
		n.Protocol = node.ProtoVLESS
		n.VLESS = &node.VLESSConfig{UUID: p.UUID}
	case "trojan":
		n.Protocol = node.ProtoTrojan
		n.Trojan = &node.TrojanConfig{Password: p.Password}
	case "hysteria2":
		n.Protocol = node.ProtoHysteria2
		n.Hysteria2 = &node.Hysteria2Config{
			Password: p.Password,
			Obfs:     p.Cipher,
		}
	}

	if p.Network != "" && p.Network != "tcp" {
		n.Transport = clashTransportFromProxy(p)
	}

	if p.SNI != "" || p.SkipCertVerify {
		n.TLS = &node.TLSConfig{
			Enable:      true,
			ServerName:  p.SNI,
			Insecure:    p.SkipCertVerify,
			Fingerprint: p.Fingerprint,
		}
	}

	return n
}

func clashTransportFromProxy(p clashProxy) *node.TransportConfig {
	tc := &node.TransportConfig{}
	switch p.Network {
	case "ws":
		tc.Type = node.TransportWS
		if p.WSOpts != nil {
			tc.Path = p.WSOpts.Path
			if p.WSOpts.Headers != nil {
				tc.Host = p.WSOpts.Headers["Host"]
			}
		}
	case "grpc":
		tc.Type = node.TransportGRPC
		if p.GRPCOpts != nil {
			tc.Path = p.GRPCOpts.GRPCServiceName
		}
	case "h2":
		tc.Type = node.TransportHTTP2
		if p.H2Opts != nil {
			tc.Path = p.H2Opts.Path
			if len(p.H2Opts.Host) > 0 {
				tc.Host = p.H2Opts.Host[0]
			}
		}
	}
	return tc
}

func parseClashRule(rule string) node.Rule {
	parts := splitRule(rule)
	if len(parts) >= 3 {
		return node.Rule{
			Type:    parts[0],
			Content: parts[1],
			Proxy:   parts[2],
		}
	}
	return node.Rule{Type: rule}
}

func splitRule(s string) []string {
	var parts []string
	current := ""
	inQuote := false
	for _, c := range s {
		switch c {
		case '"':
			inQuote = !inQuote
		case ',':
			if !inQuote {
				parts = append(parts, current)
				current = ""
				continue
			}
			current += string(c)
		default:
			current += string(c)
		}
	}
	parts = append(parts, current)
	return parts
}

func generateClash(sub *node.Subscription) ([]byte, error) {
	var cfg clashConfig
	for _, n := range sub.Nodes {
		cfg.Proxies = append(cfg.Proxies, nodeToClashProxy(n))
	}
	for _, g := range sub.Groups {
		cfg.ProxyGroups = append(cfg.ProxyGroups, clashGroup{
			Name:     g.Name,
			Type:     g.Type,
			Proxies:  g.Proxies,
			URL:      g.URL,
			Interval: g.Interval,
		})
	}
	for _, r := range sub.Rules {
		cfg.Rules = append(cfg.Rules, r.Type+","+r.Content+","+r.Proxy)
	}
	return yaml.Marshal(cfg)
}

func nodeToClashProxy(n node.Node) clashProxy {
	p := clashProxy{
		Name:   n.Name,
		Server: n.Address,
		Port:   n.Port,
	}
	switch n.Protocol {
	case node.ProtoSS:
		p.Type = "ss"
		if n.Shadowsocks != nil {
			p.Cipher = n.Shadowsocks.Method
			p.Password = n.Shadowsocks.Password
		}
	case node.ProtoVMess:
		p.Type = "vmess"
		if n.VMess != nil {
			p.UUID = n.VMess.UUID
			p.AlterID = n.VMess.AlterID
			p.Cipher = n.VMess.Security
		}
	case node.ProtoTrojan:
		p.Type = "trojan"
		if n.Trojan != nil {
			p.Password = n.Trojan.Password
		}
	default:
		p.Type = string(n.Protocol)
	}
	if n.Transport != nil {
		p.Network = string(n.Transport.Type)
		switch n.Transport.Type {
		case node.TransportWS:
			p.WSOpts = &clashWSOpts{
				Path: n.Transport.Path,
			}
			if n.Transport.Host != "" {
				p.WSOpts.Headers = map[string]string{"Host": n.Transport.Host}
			}
		case node.TransportGRPC:
			p.GRPCOpts = &clashGRPCOpts{GRPCServiceName: n.Transport.Path}
		}
	}
	if n.TLS != nil && n.TLS.Enable {
		p.SNI = n.TLS.ServerName
		p.SkipCertVerify = n.TLS.Insecure
		p.Fingerprint = n.TLS.Fingerprint
	}
	return p
}
