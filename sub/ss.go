package sub

import (
	"strings"

	"github.com/qsilasu/xproxy/node"
	"github.com/qsilasu/xproxy/url"
)

func parseSSList(input []byte) (*node.Subscription, error) {
	return parseRaw(input)
}

func generateSSList(sub *node.Subscription) ([]byte, error) {
	var lines []string
	for _, n := range sub.Nodes {
		if n.Protocol == node.ProtoSS {
			u, err := url.Generate(&n)
			if err != nil {
				continue
			}
			lines = append(lines, u)
		}
	}
	return []byte(strings.Join(lines, "\n")), nil
}
