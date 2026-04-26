package url

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestParseSSSIP002(t *testing.T) {
	n, err := Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzd29yZA@1.2.3.4:8388#MySS")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoSS {
		t.Errorf("expected shadowsocks, got %q", n.Protocol)
	}
	if n.Name != "MySS" {
		t.Errorf("expected name 'MySS', got %q", n.Name)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected address '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 8388 {
		t.Errorf("expected port 8388, got %d", n.Port)
	}
	if n.Shadowsocks == nil {
		t.Fatal("Shadowsocks config should not be nil")
	}
	if n.Shadowsocks.Method != "chacha20-ietf-poly1305" {
		t.Errorf("expected chacha20-ietf-poly1305, got %q", n.Shadowsocks.Method)
	}
	if n.Shadowsocks.Password != "password" {
		t.Errorf("expected 'password', got %q", n.Shadowsocks.Password)
	}
}

func TestParseSSSIP002WithPlugin(t *testing.T) {
	n, err := Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388/?plugin=obfs-local%3Bobfs%3Dhttp#Node")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Shadowsocks == nil {
		t.Fatal("Shadowsocks config should not be nil")
	}
	if n.Extras == nil {
		t.Fatal("Extras should not be nil")
	}
	if n.Extras["plugin"] == "" {
		t.Error("plugin should be in extras")
	}
}

func TestParseSSLegacy(t *testing.T) {
	n, err := Parse("ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNzQDEuMi4zLjQ6ODM4OA#Legacy")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 8388 {
		t.Errorf("expected 8388, got %d", n.Port)
	}
}

func TestParseSSRoundTrip(t *testing.T) {
	original := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#TestNode"
	n, err := Parse(original)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	generated, err := Generate(n)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}
	n2, err := Parse(generated)
	if err != nil {
		t.Fatalf("unexpected parse error on generated URL %q: %v", generated, err)
	}
	if n2.Address != n.Address || n2.Port != n.Port {
		t.Errorf("round-trip mismatch: %s:%d vs %s:%d",
			n.Address, n.Port, n2.Address, n2.Port)
	}
	if n2.Shadowsocks.Method != n.Shadowsocks.Method {
		t.Errorf("method mismatch: %q vs %q", n.Shadowsocks.Method, n2.Shadowsocks.Method)
	}
}
