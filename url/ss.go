package url

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseSS(rest string) (*node.Node, error) {
	if rest == "" {
		return nil, fmt.Errorf("ss: empty URL body")
	}

	var fragment string
	if idx := strings.LastIndex(rest, "#"); idx >= 0 {
		fragment = rest[idx+1:]
		rest = rest[:idx]
	}

	atIdx := strings.LastIndex(rest, "@")
	if atIdx < 0 {
		return parseSSLegacy(rest, fragment)
	}

	userinfo := rest[:atIdx]
	hostPort := rest[atIdx+1:]

	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	method, password, err := decodeSSUserinfo(userinfo)
	if err != nil {
		return nil, fmt.Errorf("ss: %w", err)
	}

	n := &node.Node{
		Protocol: node.ProtoSS,
		Name:     fragment,
		Address:  host,
		Port:     port,
		Shadowsocks: &node.SSConfig{
			Method:   method,
			Password: password,
		},
		Extras: make(map[string]string),
	}

	if qIdx := strings.Index(hostPort, "?"); qIdx >= 0 {
		query := hostPort[qIdx+1:]
		params, _ := url.ParseQuery(query)
		for k, v := range params {
			if len(v) > 0 {
				n.Extras[k] = v[0]
			}
		}
	}

	return n, nil
}

func parseSSLegacy(rest, fragment string) (*node.Node, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(rest)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(rest)
		if err != nil {
			return nil, fmt.Errorf("ss legacy: base64 decode: %w", err)
		}
	}
	parts := string(decoded)
	atIdx := strings.LastIndex(parts, "@")
	if atIdx < 0 {
		return nil, fmt.Errorf("ss legacy: missing @ in decoded payload")
	}
	userinfo := parts[:atIdx]
	hostPort := parts[atIdx+1:]

	colonIdx := strings.Index(userinfo, ":")
	if colonIdx < 0 {
		return nil, fmt.Errorf("ss legacy: missing : in userinfo")
	}
	method := userinfo[:colonIdx]
	password := userinfo[colonIdx+1:]

	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("ss legacy: %w", err)
	}

	return &node.Node{
		Protocol: node.ProtoSS,
		Name:     fragment,
		Address:  host,
		Port:     port,
		Shadowsocks: &node.SSConfig{
			Method:   method,
			Password: password,
		},
		Extras: make(map[string]string),
	}, nil
}

func decodeSSUserinfo(raw string) (method, password string, err error) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		decoded, err = base64.StdEncoding.DecodeString(raw)
	}
	if err == nil {
		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) == 2 && parts[0] != "" {
			return parts[0], parts[1], nil
		}
		if len(parts) == 1 && looksLikePassword(parts[0]) {
			// Only password, use default method.
			return "chacha20-ietf-poly1305", parts[0], nil
		}
	}

	// Base64 decode failed or content is not method:password.
	// Try treating raw as a plain-text password (common in v2go data).
	if looksLikePassword(raw) {
		return "chacha20-ietf-poly1305", raw, nil
	}

	return "", "", fmt.Errorf("decode userinfo: %w", err)
}

func looksLikePassword(s string) bool {
	if len(s) < 4 {
		return false
	}
	// UUID, hex string, or alphanumeric with common separators.
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}

func generateSS(n *node.Node) (string, error) {
	if n.Shadowsocks == nil {
		return "", fmt.Errorf("ss: Shadowsocks config is nil")
	}
	userinfo := base64.RawURLEncoding.EncodeToString(
		[]byte(n.Shadowsocks.Method + ":" + n.Shadowsocks.Password),
	)
	result := fmt.Sprintf("ss://%s@%s", userinfo, net.JoinHostPort(n.Address, fmt.Sprint(n.Port)))
	if n.Name != "" {
		result += "#" + n.Name
	}
	return result, nil
}

func splitHostPort(s string) (host string, port int, err error) {
	if qIdx := strings.Index(s, "?"); qIdx >= 0 {
		s = s[:qIdx]
	}
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	portNum := 0
	if p != "" {
		fmt.Sscanf(p, "%d", &portNum)
	}
	return h, portNum, nil
}
