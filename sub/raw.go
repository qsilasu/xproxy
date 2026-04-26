package sub

import (
	"strings"

	"github.com/qsilasu/xproxy/node"
	"github.com/qsilasu/xproxy/url"
)

func parseRaw(input []byte) (*node.Subscription, error) {
	lines := strings.Split(string(input), "\n")
	sub := &node.Subscription{}
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		n, err := url.Parse(line)
		if err != nil {
			continue
		}
		sub.Nodes = append(sub.Nodes, *n)
	}
	return sub, nil
}

func generateRaw(sub *node.Subscription) ([]byte, error) {
	var lines []string
	for _, n := range sub.Nodes {
		u, err := url.Generate(&n)
		if err != nil {
			continue
		}
		lines = append(lines, u)
	}
	return []byte(strings.Join(lines, "\n")), nil
}
