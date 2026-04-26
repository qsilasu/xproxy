package sub

import "testing"

const clashYAMLFixture = `
proxies:
  - name: "ss-node"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "mypassword"
  - name: "vmess-ws"
    type: vmess
    server: 5.6.7.8
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
    network: ws
    ws-opts:
      path: /ws
      headers:
        Host: example.com
proxy-groups:
  - name: "auto-group"
    type: url-test
    proxies:
      - ss-node
      - vmess-ws
    url: http://www.gstatic.com/generate_204
    interval: 300
rules:
  - DOMAIN-SUFFIX,google.com,auto-group
  - MATCH,auto-group
`

func TestParseClash(t *testing.T) {
	sub, err := Parse([]byte(clashYAMLFixture), FmtClash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sub.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(sub.Nodes))
	}
	if sub.Nodes[0].Name != "ss-node" {
		t.Errorf("expected first node 'ss-node', got %q", sub.Nodes[0].Name)
	}
	if sub.Nodes[0].Shadowsocks == nil {
		t.Fatal("first node should be Shadowsocks")
	}
	if sub.Nodes[0].Shadowsocks.Method != "aes-256-gcm" {
		t.Errorf("expected aes-256-gcm, got %q", sub.Nodes[0].Shadowsocks.Method)
	}
	if len(sub.Groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(sub.Groups))
	}
	if len(sub.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(sub.Rules))
	}
}

func TestGenerateClashRoundTrip(t *testing.T) {
	sub1, err := Parse([]byte(clashYAMLFixture), FmtClash)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := Generate(sub1, FmtClash)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}
	sub2, err := Parse(out, FmtClash)
	if err != nil {
		t.Fatalf("round-trip parse error: %v", err)
	}
	if len(sub2.Nodes) != len(sub1.Nodes) {
		t.Errorf("round-trip node count mismatch: %d vs %d", len(sub1.Nodes), len(sub2.Nodes))
	}
}
