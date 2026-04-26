package url

import (
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseTUIC(rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("tuic: %w", err)
	}
	n := &node.Node{
		Protocol: node.ProtoTUIC,
		Address:  host,
		Port:     port,
		Extras:   make(map[string]string),
	}
	extractName(rest, n)
	return n, nil
}

func generateTUIC(n *node.Node) (string, error) {
	base := fmt.Sprintf("tuic://%s", net.JoinHostPort(n.Address, fmt.Sprint(n.Port)))
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base, nil
}

func parseSSH(rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}
	n := &node.Node{
		Protocol: node.ProtoSSH,
		Address:  host,
		Port:     port,
		Extras:   make(map[string]string),
	}
	if atIdx := strings.Index(rest, "@"); atIdx >= 0 && atIdx < strings.Index(rest, host) {
		n.Extras["user"] = rest[:atIdx]
	}
	extractName(rest, n)
	return n, nil
}

func generateSSH(n *node.Node) (string, error) {
	var user string
	if n.Extras != nil {
		user = n.Extras["user"]
	}
	base := "ssh://"
	if user != "" {
		base += user + "@"
	}
	base += net.JoinHostPort(n.Address, fmt.Sprint(n.Port))
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base, nil
}

func parseShadowTLS(rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("shadowtls: %w", err)
	}
	n := &node.Node{
		Protocol: node.ProtoShadowTLS,
		Address:  host,
		Port:     port,
		Extras:   make(map[string]string),
	}
	extractName(rest, n)
	return n, nil
}

func generateShadowTLS(n *node.Node) (string, error) {
	base := fmt.Sprintf("shadowtls://%s", net.JoinHostPort(n.Address, fmt.Sprint(n.Port)))
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base, nil
}

func parseAnyTLS(rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	n := &node.Node{
		Protocol: node.ProtoAnyTLS,
		Address:  host,
		Port:     port,
		Extras:   make(map[string]string),
	}
	extractName(rest, n)
	return n, nil
}

func generateAnyTLS(n *node.Node) (string, error) {
	base := fmt.Sprintf("anytls://%s", net.JoinHostPort(n.Address, fmt.Sprint(n.Port)))
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base, nil
}

// --- Shared helpers ---

func parseProxyWithUserinfo(rest string, proto node.Protocol, build func(userinfo string, params url.Values) (*node.Node, error)) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")

	var fragment string
	fIdx := strings.LastIndex(rest, "#")
	if fIdx >= 0 {
		fragment = rest[fIdx+1:]
		rest = rest[:fIdx]
	}

	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("%s: missing @ in URL", proto)
	}

	userinfo := rest[:atIdx]
	hostPart := rest[atIdx+1:]

	host, port, err := splitHostPort(hostPart)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", proto, err)
	}

	var queryStr string
	if qIdx := strings.Index(hostPart, "?"); qIdx >= 0 {
		queryStr = hostPart[qIdx+1:]
	}
	params, _ := url.ParseQuery(queryStr)

	n, err := build(userinfo, params)
	if err != nil {
		return nil, err
	}
	n.Address = host
	n.Port = port
	if fragment != "" {
		n.Name = fragment
	}
	return n, nil
}

func applyCommonParams(n *node.Node, params url.Values) {
	if typ := params.Get("type"); typ != "" {
		n.Transport = &node.TransportConfig{
			Type: mapTransportType(typ),
			Path: params.Get("path"),
			Host: params.Get("host"),
		}
	}
	if sec := params.Get("security"); sec == "tls" || sec == "reality" {
		n.TLS = &node.TLSConfig{
			Enable:      true,
			ServerName:  params.Get("sni"),
			Fingerprint: params.Get("fp"),
		}
		if sec == "reality" {
			n.TLS.ALPN = []string{"h2", "http/1.1"}
		}
	}
	if sni := params.Get("sni"); sni != "" && n.TLS == nil {
		n.TLS = &node.TLSConfig{
			Enable:     true,
			ServerName: sni,
		}
	}
}

func buildCommonParams(params url.Values, n *node.Node) {
	if n.Transport != nil {
		params.Set("type", string(n.Transport.Type))
		if n.Transport.Path != "" {
			params.Set("path", n.Transport.Path)
		}
		if n.Transport.Host != "" {
			params.Set("host", n.Transport.Host)
		}
	}
	if n.TLS != nil && n.TLS.Enable {
		params.Set("security", "tls")
		if n.TLS.ServerName != "" {
			params.Set("sni", n.TLS.ServerName)
		}
	}
}

func buildProxyURL(scheme, userinfo string, n *node.Node, params url.Values) string {
	base := fmt.Sprintf("%s://%s@%s", scheme, userinfo, net.JoinHostPort(n.Address, fmt.Sprint(n.Port)))
	if len(params) > 0 {
		base += "?" + params.Encode()
	}
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base
}

func extractName(rest string, n *node.Node) {
	if fIdx := strings.LastIndex(rest, "#"); fIdx >= 0 {
		n.Name = rest[fIdx+1:]
	}
}

func mapTransportType(typ string) node.TransportType {
	switch typ {
	case "ws":
		return node.TransportWS
	case "grpc", "gun":
		return node.TransportGRPC
	case "h2", "http":
		return node.TransportHTTP2
	case "quic":
		return node.TransportQUIC
	default:
		return node.TransportTCP
	}
}
