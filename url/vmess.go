package url

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

type vmessJSON struct {
	V    any    `json:"v"`
	PS   string `json:"ps"`
	Add  string `json:"add"`
	Port any    `json:"port"`
	ID   string `json:"id"`
	AID  any    `json:"aid"`
	SCY  string `json:"scy"`
	Net  string `json:"net"`
	Type string `json:"type"`
	Host string `json:"host"`
	Path string `json:"path"`
	TLS  string `json:"tls"`
	SNI  string `json:"sni"`
	ALPN string `json:"alpn"`
	FP   string `json:"fp"`
}

func parseVMess(rest string) (*node.Node, error) {
	cleaned := strings.TrimRight(rest, " \t\n\r?&")
	if qIdx := strings.Index(cleaned, "?"); qIdx >= 0 {
		cleaned = cleaned[:qIdx]
	}

	// Try standard decode first, then clean non-base64 chars.
	decoded, err := base64.RawURLEncoding.DecodeString(cleaned)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(cleaned)
	}
	if err != nil {
		cleaned = cleanBase64(cleaned)
		decoded, err = base64.RawURLEncoding.DecodeString(cleaned)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(cleaned)
		}
		if err != nil {
			return nil, fmt.Errorf("vmess: base64 decode: %w", err)
		}
	}

	var v vmessJSON
	if err := json.Unmarshal(decoded, &v); err != nil {
		return nil, fmt.Errorf("vmess: json decode: %w", err)
	}

	n := &node.Node{
		Name:     v.PS,
		Protocol: node.ProtoVMess,
		Address:  v.Add,
		Port:     toInt(v.Port),
		VMess: &node.VMessConfig{
			UUID:     v.ID,
			AlterID:  toInt(v.AID),
			Security: v.SCY,
		},
		Extras: make(map[string]string),
	}

	transportType := mapVMessNet(v.Net, v.Type)
	if transportType != node.TransportTCP || v.Net != "" {
		n.Transport = &node.TransportConfig{
			Type: transportType,
			Path: v.Path,
			Host: v.Host,
		}
	}

	if v.TLS == "tls" || v.TLS == "1" {
		n.TLS = &node.TLSConfig{
			Enable:     true,
			ServerName: v.SNI,
		}
		if v.FP != "" {
			n.TLS.Fingerprint = v.FP
		}
		if v.ALPN != "" {
			n.TLS.ALPN = strings.Split(v.ALPN, ",")
		}
		if v.SNI == "" {
			n.TLS.Insecure = true
		}
	}

	return n, nil
}

func generateVMess(n *node.Node) (string, error) {
	if n.VMess == nil {
		return "", fmt.Errorf("vmess: VMess config is nil")
	}
	v := vmessJSON{
		V:    "2",
		PS:   n.Name,
		Add:  n.Address,
		Port: n.Port,
		ID:   n.VMess.UUID,
		AID:  n.VMess.AlterID,
		SCY:  n.VMess.Security,
	}

	if n.Transport != nil {
		v.Net = string(n.Transport.Type)
		v.Type = string(n.Transport.Type)
		v.Host = n.Transport.Host
		v.Path = n.Transport.Path
	}

	if n.TLS != nil && n.TLS.Enable {
		v.TLS = "tls"
		v.SNI = n.TLS.ServerName
		if n.TLS.Fingerprint != "" {
			v.FP = n.TLS.Fingerprint
		}
	}

	body, err := json.Marshal(v)
	if err != nil {
		return "", fmt.Errorf("vmess: json encode: %w", err)
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(body), nil
}

func mapVMessNet(net, typ string) node.TransportType {
	switch {
	case net == "ws":
		return node.TransportWS
	case net == "grpc" || typ == "gun":
		return node.TransportGRPC
	case net == "h2":
		return node.TransportHTTP2
	case net == "quic":
		return node.TransportQUIC
	default:
		return node.TransportTCP
	}
}

func toInt(v any) int {
	switch val := v.(type) {
	case float64:
		return int(val)
	case string:
		n, _ := strconv.Atoi(val)
		return n
	case int:
		return val
	default:
		return 0
	}
}

// cleanBase64 strips characters that are not valid base64.
func cleanBase64(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') || c == '+' || c == '/' ||
			c == '-' || c == '_' || c == '=' {
			b.WriteRune(c)
		}
	}
	return b.String()
}
