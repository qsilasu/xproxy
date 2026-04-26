package url

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestGenerateTUIC(t *testing.T) {
	n := &node.Node{
		Name:     "tuic-node",
		Protocol: node.ProtoTUIC,
		Address:  "1.2.3.4",
		Port:     8443,
	}
	got, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expect := "tuic://1.2.3.4:8443#tuic-node"
	if got != expect {
		t.Errorf("expected %q, got %q", expect, got)
	}
}

func TestGenerateWireGuard(t *testing.T) {
	n := &node.Node{
		Name:     "wg-node",
		Protocol: node.ProtoWireGuard,
		Address:  "10.0.0.1",
		Port:     51820,
		WireGuard: &node.WireGuardConfig{
			PublicKey:  "base64pubkey",
			PrivateKey: "base64privkey",
			MTU:        1420,
		},
	}
	got, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if !contains(got, "wireguard://") {
		t.Errorf("expected wireguard scheme, got %q", got)
	}
	if !contains(got, "publickey=base64pubkey") {
		t.Errorf("missing publickey, got %q", got)
	}
	if !contains(got, "privatekey=base64privkey") {
		t.Errorf("missing privatekey, got %q", got)
	}
	if !contains(got, "mtu=1420") {
		t.Errorf("missing mtu, got %q", got)
	}
}

func TestGenerateSSH(t *testing.T) {
	n := &node.Node{
		Name:     "ssh-node",
		Protocol: node.ProtoSSH,
		Address:  "5.6.7.8",
		Port:     22,
		Extras:   map[string]string{"user": "root"},
	}
	got, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expect := "ssh://root@5.6.7.8:22#ssh-node"
	if got != expect {
		t.Errorf("expected %q, got %q", expect, got)
	}
}

func TestGenerateShadowTLS(t *testing.T) {
	n := &node.Node{
		Name:     "stls-node",
		Protocol: node.ProtoShadowTLS,
		Address:  "9.10.11.12",
		Port:     443,
	}
	got, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expect := "shadowtls://9.10.11.12:443#stls-node"
	if got != expect {
		t.Errorf("expected %q, got %q", expect, got)
	}
}

func TestGenerateAnyTLS(t *testing.T) {
	n := &node.Node{
		Name:     "atls-node",
		Protocol: node.ProtoAnyTLS,
		Address:  "13.14.15.16",
		Port:     8443,
	}
	got, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	expect := "anytls://13.14.15.16:8443#atls-node"
	if got != expect {
		t.Errorf("expected %q, got %q", expect, got)
	}
}

func TestGenerateRoundTrip_TUIC(t *testing.T) {
	original := "tuic://1.2.3.4:8443#test"
	n, err := Parse(original)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gen, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if gen != original {
		t.Errorf("round-trip: %q → %q", original, gen)
	}
}

func TestGenerateRoundTrip_ShadowTLS(t *testing.T) {
	original := "shadowtls://1.2.3.4:443#test"
	n, err := Parse(original)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gen, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if gen != original {
		t.Errorf("round-trip: %q → %q", original, gen)
	}
}

func TestGenerateRoundTrip_AnyTLS(t *testing.T) {
	original := "anytls://1.2.3.4:8443#test"
	n, err := Parse(original)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gen, err := Generate(n)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if gen != original {
		t.Errorf("round-trip: %q → %q", original, gen)
	}
}
