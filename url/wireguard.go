package url

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseWireGuard(rest string) (*node.Node, error) {
	rest = strings.TrimPrefix(rest, "//")
	qIdx := strings.Index(rest, "?")
	if qIdx < 0 {
		return nil, fmt.Errorf("wireguard: missing query params")
	}
	hostPort := rest[:qIdx]
	query := rest[qIdx+1:]
	host, port, err := splitHostPort(hostPort)
	if err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	params, _ := url.ParseQuery(query)
	n := &node.Node{
		Protocol:  node.ProtoWireGuard,
		Address:   host,
		Port:      port,
		WireGuard: &node.WireGuardConfig{},
		Extras:    make(map[string]string),
	}
	if pk := params.Get("publickey"); pk != "" {
		n.WireGuard.PublicKey = pk
	}
	if sk := params.Get("privatekey"); sk != "" {
		n.WireGuard.PrivateKey = sk
	}
	if psk := params.Get("presharedkey"); psk != "" {
		n.WireGuard.PreSharedKey = psk
	}
	if m := params.Get("mtu"); m != "" {
		n.WireGuard.MTU, _ = strconv.Atoi(m)
	}
	if res := params.Get("reserved"); res != "" {
		decoded, _ := base64.StdEncoding.DecodeString(res)
		for _, b := range decoded {
			n.WireGuard.Reserved = append(n.WireGuard.Reserved, int(b))
		}
	}
	return n, nil
}

func generateWireGuard(n *node.Node) (string, error) {
	params := url.Values{}
	if n.WireGuard != nil {
		if n.WireGuard.PublicKey != "" {
			params.Set("publickey", n.WireGuard.PublicKey)
		}
		if n.WireGuard.PrivateKey != "" {
			params.Set("privatekey", n.WireGuard.PrivateKey)
		}
		if n.WireGuard.PreSharedKey != "" {
			params.Set("presharedkey", n.WireGuard.PreSharedKey)
		}
		if n.WireGuard.MTU > 0 {
			params.Set("mtu", strconv.Itoa(n.WireGuard.MTU))
		}
		if len(n.WireGuard.Reserved) > 0 {
			buf := make([]byte, len(n.WireGuard.Reserved))
			for i, v := range n.WireGuard.Reserved {
				buf[i] = byte(v)
			}
			params.Set("reserved", base64.StdEncoding.EncodeToString(buf))
		}
	}
	base := fmt.Sprintf("wireguard://%s?%s",
		net.JoinHostPort(n.Address, fmt.Sprint(n.Port)), params.Encode())
	if n.Name != "" {
		base += "#" + n.Name
	}
	return base, nil
}
