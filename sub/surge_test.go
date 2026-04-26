package sub

import "testing"

const surgeConfFixture = `
[Proxy]
ss-node = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=secret
trojan-node = trojan, 5.6.7.8, 443, password=mypass, tls=true, sni=example.com
http-proxy = http, 9.10.11.12, 8080

[Proxy Group]
auto = url-test, ss-node, trojan-node, http-proxy, url=http://www.gstatic.com/generate_204, interval=300

[Rule]
DOMAIN-SUFFIX,google.com,auto
FINAL,auto
`

func TestParseSurge(t *testing.T) {
	sub, err := Parse([]byte(surgeConfFixture), FmtSurge)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sub.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(sub.Nodes))
	}
	if sub.Nodes[0].Name != "ss-node" {
		t.Errorf("expected 'ss-node', got %q", sub.Nodes[0].Name)
	}
	if len(sub.Groups) != 1 {
		t.Errorf("expected 1 group, got %d", len(sub.Groups))
	}
	if len(sub.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(sub.Rules))
	}
}
