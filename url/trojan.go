package url

import (
	"fmt"
	"net/url"

	"github.com/qsilasu/xproxy/node"
)

func parseTrojan(_ /* scheme */, rest string) (*node.Node, error) {
	return parseProxyWithUserinfo(rest, node.ProtoTrojan, func(password string, params url.Values) (*node.Node, error) {
		n := &node.Node{
			Protocol: node.ProtoTrojan,
			Trojan: &node.TrojanConfig{
				Password: password,
			},
			Extras: make(map[string]string),
		}
		applyCommonParams(n, params)
		return n, nil
	})
}

func generateTrojan(n *node.Node) (string, error) {
	if n.Trojan == nil {
		return "", fmt.Errorf("trojan: Trojan config is nil")
	}
	params := url.Values{}
	buildCommonParams(params, n)
	return buildProxyURL("trojan", n.Trojan.Password, n, params), nil
}
