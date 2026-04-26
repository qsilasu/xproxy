package url

import (
	"fmt"
	"net"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseSOCKS(scheme, rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")

	// Handle socks://user:pass@host:port format
	if atIdx := strings.Index(rest, "@"); atIdx >= 0 {
		rest = rest[atIdx+1:]
	}

	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}
	proto := node.ProtoSOCKS5
	if scheme == "socks4" {
		proto = node.Protocol("socks4")
	}
	n := &node.Node{
		Protocol: proto,
		Address:  host,
		Port:     port,
		Extras:   make(map[string]string),
	}
	extractName(rest, n)
	return n, nil
}

func generateSOCKS(n *node.Node) (string, error) {
	scheme := "socks5"
	if n.Protocol == "socks4" {
		scheme = "socks4"
	}
	return fmt.Sprintf("%s://%s", scheme, net.JoinHostPort(n.Address, fmt.Sprint(n.Port))), nil
}
