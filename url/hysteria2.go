package url

import (
	"fmt"
	"net/url"
	"strconv"

	"github.com/qsilasu/xproxy/node"
)

func parseHysteria2(_ /* scheme */, rest string) (*node.Node, error) {
	return parseProxyWithUserinfo(rest, node.ProtoHysteria2, func(password string, params url.Values) (*node.Node, error) {
		n := &node.Node{
			Protocol: node.ProtoHysteria2,
			Hysteria2: &node.Hysteria2Config{
				Password: password,
			},
			Extras: make(map[string]string),
		}
		if obfs := params.Get("obfs"); obfs != "" {
			n.Hysteria2.Obfs = obfs
		}
		if up := params.Get("upmbps"); up != "" {
			n.Hysteria2.UpMbps, _ = strconv.Atoi(up)
		}
		if down := params.Get("downmbps"); down != "" {
			n.Hysteria2.DownMbps, _ = strconv.Atoi(down)
		}
		applyCommonParams(n, params)
		return n, nil
	})
}

func generateHysteria2(n *node.Node) (string, error) {
	if n.Hysteria2 == nil {
		return "", fmt.Errorf("hysteria2: config is nil")
	}
	params := url.Values{}
	if n.Hysteria2.Obfs != "" {
		params.Set("obfs", n.Hysteria2.Obfs)
	}
	buildCommonParams(params, n)
	return buildProxyURL("hysteria2", n.Hysteria2.Password, n, params), nil
}
