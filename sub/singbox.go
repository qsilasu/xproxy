package sub

import (
	"encoding/json"

	"github.com/qsilasu/xproxy/node"
)

type singboxConfig struct {
	Outbounds []singboxOutbound `json:"outbounds"`
}

type singboxOutbound struct {
	Tag        string            `json:"tag"`
	Type       string            `json:"type"`
	Server     string            `json:"server"`
	ServerPort int               `json:"server_port"`
	Method     string            `json:"method,omitempty"`
	Password   string            `json:"password,omitempty"`
	UUID       string            `json:"uuid,omitempty"`
	Security   string            `json:"security,omitempty"`
	Flow       string            `json:"flow,omitempty"`
	Transport  *singboxTransport `json:"transport,omitempty"`
	TLS        *singboxTLS       `json:"tls,omitempty"`
}

type singboxTransport struct {
	Type    string            `json:"type"`
	Path    string            `json:"path,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
}

type singboxTLS struct {
	Enabled    bool   `json:"enabled"`
	ServerName string `json:"server_name,omitempty"`
	Insecure   bool   `json:"insecure,omitempty"`
}

func parseSingBox(input []byte) (*node.Subscription, error) {
	var cfg singboxConfig
	if err := json.Unmarshal(input, &cfg); err != nil {
		return nil, err
	}
	sub := &node.Subscription{}
	for _, o := range cfg.Outbounds {
		n := singboxToNode(o)
		sub.Nodes = append(sub.Nodes, n)
	}
	return sub, nil
}

func singboxToNode(o singboxOutbound) node.Node {
	n := node.Node{
		Name:    o.Tag,
		Address: o.Server,
		Port:    o.ServerPort,
		Extras:  make(map[string]string),
	}

	switch o.Type {
	case "shadowsocks":
		n.Protocol = node.ProtoSS
		n.Shadowsocks = &node.SSConfig{
			Method:   o.Method,
			Password: o.Password,
		}
	case "vmess":
		n.Protocol = node.ProtoVMess
		n.VMess = &node.VMessConfig{
			UUID:     o.UUID,
			Security: o.Security,
		}
	case "vless":
		n.Protocol = node.ProtoVLESS
		n.VLESS = &node.VLESSConfig{
			UUID: o.UUID,
			Flow: o.Flow,
		}
	case "trojan":
		n.Protocol = node.ProtoTrojan
		n.Trojan = &node.TrojanConfig{
			Password: o.Password,
		}
	case "hysteria2":
		n.Protocol = node.ProtoHysteria2
		n.Hysteria2 = &node.Hysteria2Config{
			Password: o.Password,
		}
	}

	if o.Transport != nil {
		n.Transport = &node.TransportConfig{
			Type: mapSBTransport(o.Transport.Type),
			Path: o.Transport.Path,
		}
		if o.Transport.Headers != nil {
			n.Transport.Host = o.Transport.Headers["Host"]
		}
	}

	if o.TLS != nil && o.TLS.Enabled {
		n.TLS = &node.TLSConfig{
			Enable:     true,
			ServerName: o.TLS.ServerName,
			Insecure:   o.TLS.Insecure,
		}
	}

	return n
}

func generateSingBox(sub *node.Subscription) ([]byte, error) {
	var cfg singboxConfig
	for _, n := range sub.Nodes {
		cfg.Outbounds = append(cfg.Outbounds, nodeToSingbox(n))
	}
	return json.MarshalIndent(cfg, "", "  ")
}

func nodeToSingbox(n node.Node) singboxOutbound {
	o := singboxOutbound{
		Tag:        n.Name,
		Server:     n.Address,
		ServerPort: n.Port,
	}
	switch n.Protocol {
	case node.ProtoSS:
		o.Type = "shadowsocks"
		if n.Shadowsocks != nil {
			o.Method = n.Shadowsocks.Method
			o.Password = n.Shadowsocks.Password
		}
	case node.ProtoVMess:
		o.Type = "vmess"
		if n.VMess != nil {
			o.UUID = n.VMess.UUID
			o.Security = n.VMess.Security
		}
	case node.ProtoVLESS:
		o.Type = "vless"
		if n.VLESS != nil {
			o.UUID = n.VLESS.UUID
			o.Flow = n.VLESS.Flow
		}
	case node.ProtoTrojan:
		o.Type = "trojan"
		if n.Trojan != nil {
			o.Password = n.Trojan.Password
		}
	default:
		o.Type = string(n.Protocol)
	}

	if n.Transport != nil {
		o.Transport = &singboxTransport{
			Type: string(n.Transport.Type),
			Path: n.Transport.Path,
		}
		if n.Transport.Host != "" {
			o.Transport.Headers = map[string]string{"Host": n.Transport.Host}
		}
	}

	if n.TLS != nil && n.TLS.Enable {
		o.TLS = &singboxTLS{
			Enabled:    true,
			ServerName: n.TLS.ServerName,
			Insecure:   n.TLS.Insecure,
		}
	}

	return o
}

func mapSBTransport(t string) node.TransportType {
	switch t {
	case "ws":
		return node.TransportWS
	case "grpc":
		return node.TransportGRPC
	case "http":
		return node.TransportHTTP2
	default:
		return node.TransportTCP
	}
}
