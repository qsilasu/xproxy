package url

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

// ParseError wraps a URL parsing failure.
type ParseError struct {
	Input string
	Err   error
}

func (e *ParseError) Error() string {
	return fmt.Sprintf("url: parse %q: %v", e.Input, e.Err)
}

func (e *ParseError) Unwrap() error {
	return e.Err
}

// Clean applies general-purpose fixes to a malformed proxy URL.
func Clean(rawURL string) string {
	s := strings.TrimSpace(rawURL)

	// Strip control characters.
	s = strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' {
			return -1
		}
		return r
	}, s)

	// Strip known junk query parameters (before fragment extraction).
	s = stripJunkParams(s)

	return s
}

// Parse converts a proxy URL string to a Node.
func Parse(rawURL string) (*node.Node, error) {
	cleaned := Clean(rawURL)
	scheme, rest, ok := splitScheme(cleaned)
	if !ok {
		return nil, &ParseError{Input: rawURL, Err: fmt.Errorf("no scheme in URL")}
	}

	// Protocol-specific pre-cleaning.
	rest = cleanByProtocol(scheme, rest)

	switch scheme {
	case "ss":
		return parseSS(rest)
	case "vmess":
		return parseVMess(rest)
	case "vless":
		return parseVLESS(rest)
	case "trojan", "trojan-go":
		return parseTrojan(scheme, rest)
	case "hysteria", "hysteria2":
		return parseHysteria2(scheme, rest)
	case "tuic":
		return parseTUIC(rest)
	case "socks5", "socks4", "socks":
		return parseSOCKS(scheme, rest)
	case "http", "https":
		return parseHTTP(scheme, rest)
	case "wireguard":
		return parseWireGuard(rest)
	case "ssh":
		return parseSSH(rest)
	case "shadowtls":
		return parseShadowTLS(rest)
	case "anytls", "atls":
		return parseAnyTLS(rest)
	default:
		return nil, &ParseError{Input: rawURL, Err: fmt.Errorf("unsupported scheme: %s", scheme)}
	}
}

func cleanByProtocol(scheme, rest string) string {
	switch scheme {
	case "vmess":
		return cleanVMessBody(rest)
	}
	return rest
}

func cleanVMessBody(rest string) string {
	if qIdx := strings.Index(rest, "?"); qIdx >= 0 {
		rest = rest[:qIdx]
	}
	if ampIdx := strings.Index(rest, "&remarks="); ampIdx >= 0 {
		rest = rest[:ampIdx]
	}
	if ampIdx := strings.Index(rest, "&tag="); ampIdx >= 0 {
		rest = rest[:ampIdx]
	}
	return rest
}

// MustParse is like Parse but panics on error.
func MustParse(rawURL string) *node.Node {
	n, err := Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return n
}

// ParseURL is a convenience that does Clean + Parse.
func ParseURL(rawURL string) (*node.Node, error) {
	return Parse(rawURL)
}

// Generate converts a Node back to its proxy URL string.
func Generate(n *node.Node) (string, error) {
	if n == nil {
		return "", fmt.Errorf("url: cannot generate URL from nil Node")
	}
	switch n.Protocol {
	case node.ProtoSS:
		return generateSS(n)
	case node.ProtoVMess:
		return generateVMess(n)
	case node.ProtoVLESS:
		return generateVLESS(n)
	case node.ProtoTrojan:
		return generateTrojan(n)
	case node.ProtoSOCKS5:
		return generateSOCKS(n)
	case node.ProtoHTTP:
		return generateHTTP(n)
	case node.ProtoHTTPS:
		return generateHTTPS(n)
	case node.ProtoHysteria2:
		return generateHysteria2(n)
	case node.ProtoTUIC:
		return generateTUIC(n)
	case node.ProtoWireGuard:
		return generateWireGuard(n)
	case node.ProtoSSH:
		return generateSSH(n)
	case node.ProtoShadowTLS:
		return generateShadowTLS(n)
	case node.ProtoAnyTLS:
		return generateAnyTLS(n)
	default:
		return "", fmt.Errorf("url: generate not implemented for protocol %q", n.Protocol)
	}
}

func splitScheme(raw string) (scheme, rest string, ok bool) {
	idx := strings.Index(raw, "://")
	if idx < 0 {
		return "", raw, false
	}
	return raw[:idx], raw[idx+3:], true
}

func stripJunkParams(s string) string {
	junkKeys := []string{"remarks", "tag", "remark", "comment", "ps"}
	u, err := url.Parse(s)
	if err != nil {
		return s
	}
	q := u.Query()
	for _, k := range junkKeys {
		q.Del(k)
	}
	u.RawQuery = q.Encode()
	return u.String()
}
