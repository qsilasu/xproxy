package url

import (
	"fmt"
	"net/url"

	"github.com/qsilasu/xproxy/node"
)

func parseVLESS(rest string) (*node.Node, error) {
	return parseProxyWithUserinfo(rest, node.ProtoVLESS, func(uuid string, params url.Values) (*node.Node, error) {
		n := &node.Node{
			Protocol: node.ProtoVLESS,
			VLESS: &node.VLESSConfig{
				UUID: uuid,
			},
			Extras: make(map[string]string),
		}
		if flow := params.Get("flow"); flow != "" {
			n.VLESS.Flow = flow
		}
		applyCommonParams(n, params)
		return n, nil
	})
}

func generateVLESS(n *node.Node) (string, error) {
	if n.VLESS == nil {
		return "", fmt.Errorf("vless: VLESS config is nil")
	}
	params := url.Values{}
	if n.VLESS.Flow != "" {
		params.Set("flow", n.VLESS.Flow)
	}
	buildCommonParams(params, n)
	return buildProxyURL("vless", n.VLESS.UUID, n, params), nil
}
