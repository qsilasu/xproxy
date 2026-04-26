package sub

import (
	"strconv"
	"strings"

	"github.com/qsilasu/xproxy/node"
)

func parseSurge(input []byte) (*node.Subscription, error) {
	sub := &node.Subscription{}
	lines := strings.Split(string(input), "\n")
	section := ""

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}

		switch section {
		case "[Proxy]":
			n := parseSurgeProxy(line)
			sub.Nodes = append(sub.Nodes, n)
		case "[Proxy Group]":
			g := parseSurgeGroup(line)
			sub.Groups = append(sub.Groups, g)
		case "[Rule]":
			sub.Rules = append(sub.Rules, parseSurgeRule(line))
		}
	}
	return sub, nil
}

func parseSurgeProxy(line string) node.Node {
	// Surge format: name = type, server, port, options...
	// Use LastIndex because names may contain " = ".
	idx := strings.LastIndex(line, " = ")
	if idx < 0 {
		return node.Node{}
	}
	name := strings.TrimSpace(line[:idx])
	fields := strings.Split(line[idx+3:], ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	if len(fields) < 3 {
		return node.Node{Name: name}
	}

	n := node.Node{
		Name:   name,
		Extras: make(map[string]string),
	}
	typ := fields[0]
	n.Address = fields[1]
	if port, err := strconv.Atoi(fields[2]); err == nil {
		n.Port = port
	}

	switch typ {
	case "ss":
		n.Protocol = node.ProtoSS
		n.Shadowsocks = &node.SSConfig{}
		for _, f := range fields[3:] {
			if strings.HasPrefix(f, "encrypt-method=") {
				n.Shadowsocks.Method = strings.TrimPrefix(f, "encrypt-method=")
			}
			if strings.HasPrefix(f, "password=") {
				n.Shadowsocks.Password = strings.TrimPrefix(f, "password=")
			}
		}
	case "trojan":
		n.Protocol = node.ProtoTrojan
		n.Trojan = &node.TrojanConfig{}
		for _, f := range fields[3:] {
			if strings.HasPrefix(f, "password=") {
				n.Trojan.Password = strings.TrimPrefix(f, "password=")
			}
			if f == "tls=true" {
				n.TLS = &node.TLSConfig{Enable: true}
			}
			if strings.HasPrefix(f, "sni=") {
				if n.TLS == nil {
					n.TLS = &node.TLSConfig{Enable: true}
				}
				n.TLS.ServerName = strings.TrimPrefix(f, "sni=")
			}
		}
	case "http":
		n.Protocol = node.ProtoHTTP
	case "https":
		n.Protocol = node.ProtoHTTPS
	}

	return n
}

func parseSurgeGroup(line string) node.ProxyGroup {
	idx := strings.LastIndex(line, " = ")
	if idx < 0 {
		return node.ProxyGroup{}
	}
	name := strings.TrimSpace(line[:idx])
	fields := strings.Split(line[idx+3:], ",")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}

	g := node.ProxyGroup{Name: name}
	if len(fields) > 0 {
		g.Type = fields[0]
	}
	for _, f := range fields[1:] {
		if strings.HasPrefix(f, "url=") {
			g.URL = strings.TrimPrefix(f, "url=")
		} else if strings.HasPrefix(f, "interval=") {
			g.Interval, _ = strconv.Atoi(strings.TrimPrefix(f, "interval="))
		} else {
			g.Proxies = append(g.Proxies, f)
		}
	}
	return g
}

func parseSurgeRule(line string) node.Rule {
	parts := strings.Split(line, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	r := node.Rule{}
	if len(parts) >= 2 {
		r.Type = parts[0]
		r.Content = parts[1]
		if len(parts) >= 3 {
			r.Proxy = parts[2]
		}
	}
	return r
}

func generateSurge(sub *node.Subscription) ([]byte, error) {
	var lines []string

	lines = append(lines, "[Proxy]")
	for _, n := range sub.Nodes {
		lines = append(lines, nodeToSurgeLine(n))
	}

	if len(sub.Groups) > 0 {
		lines = append(lines, "", "[Proxy Group]")
		for _, g := range sub.Groups {
			lines = append(lines, groupToSurgeLine(g))
		}
	}

	if len(sub.Rules) > 0 {
		lines = append(lines, "", "[Rule]")
		for _, r := range sub.Rules {
			lines = append(lines, r.Type+","+r.Content+","+r.Proxy)
		}
	}

	return []byte(strings.Join(lines, "\n")), nil
}

func nodeToSurgeLine(n node.Node) string {
	var parts []string
	switch n.Protocol {
	case node.ProtoSS:
		parts = append(parts, "ss")
		parts = append(parts, n.Address)
		parts = append(parts, strconv.Itoa(n.Port))
		if n.Shadowsocks != nil {
			parts = append(parts, "encrypt-method="+n.Shadowsocks.Method)
			parts = append(parts, "password="+n.Shadowsocks.Password)
		}
	case node.ProtoTrojan:
		parts = append(parts, "trojan")
		parts = append(parts, n.Address)
		parts = append(parts, strconv.Itoa(n.Port))
		if n.Trojan != nil {
			parts = append(parts, "password="+n.Trojan.Password)
		}
		if n.TLS != nil && n.TLS.Enable {
			parts = append(parts, "tls=true")
			if n.TLS.ServerName != "" {
				parts = append(parts, "sni="+n.TLS.ServerName)
			}
		}
	default:
		parts = append(parts, string(n.Protocol))
		parts = append(parts, n.Address)
		parts = append(parts, strconv.Itoa(n.Port))
	}
	return n.Name + " = " + strings.Join(parts, ", ")
}

func groupToSurgeLine(g node.ProxyGroup) string {
	parts := []string{g.Type}
	parts = append(parts, g.Proxies...)
	if g.URL != "" {
		parts = append(parts, "url="+g.URL)
	}
	if g.Interval > 0 {
		parts = append(parts, "interval="+strconv.Itoa(g.Interval))
	}
	return g.Name + " = " + strings.Join(parts, ", ")
}
