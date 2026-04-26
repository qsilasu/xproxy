package url

import (
	"fmt"
	"net"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseHTTP(scheme, rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	host, port, err := splitHostPort(rest)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	var proto node.Protocol
	switch scheme {
	case "http":
		proto = node.ProtoHTTP
	default:
		proto = node.ProtoHTTPS
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

func generateHTTP(n *node.Node) (string, error) {
	return fmt.Sprintf("http://%s", net.JoinHostPort(n.Address, fmt.Sprint(n.Port))), nil
}

func generateHTTPS(n *node.Node) (string, error) {
	return fmt.Sprintf("https://%s", net.JoinHostPort(n.Address, fmt.Sprint(n.Port))), nil
}
