package url

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestParseVLESS(t *testing.T) {
	raw := "vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?encryption=none&security=tls&type=ws&path=%2Fws#MyVLESS"
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoVLESS {
		t.Errorf("expected vless, got %q", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 443 {
		t.Errorf("expected 443, got %d", n.Port)
	}
	if n.VLESS == nil {
		t.Fatal("VLESS config should not be nil")
	}
	if n.VLESS.UUID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("UUID mismatch")
	}
	if n.Transport == nil || n.Transport.Type != node.TransportWS {
		t.Error("expected ws transport")
	}
	if n.Name != "MyVLESS" {
		t.Errorf("expected name 'MyVLESS', got %q", n.Name)
	}
}

func TestParseTrojan(t *testing.T) {
	raw := "trojan://mypassword@1.2.3.4:443?security=tls#MyTrojan"
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoTrojan {
		t.Errorf("expected trojan, got %q", n.Protocol)
	}
	if n.Trojan == nil {
		t.Fatal("Trojan config should not be nil")
	}
	if n.Trojan.Password != "mypassword" {
		t.Errorf("expected password 'mypassword', got %q", n.Trojan.Password)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", n.Address)
	}
}

func TestParseSOCKS5(t *testing.T) {
	raw := "socks5://1.2.3.4:1080#MySOCKS"
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoSOCKS5 {
		t.Errorf("expected socks5, got %q", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 1080 {
		t.Errorf("expected 1080, got %d", n.Port)
	}
}

func TestParseHTTP(t *testing.T) {
	raw := "http://1.2.3.4:8080#MyHTTP"
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoHTTP {
		t.Errorf("expected http, got %q", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 8080 {
		t.Errorf("expected 8080, got %d", n.Port)
	}
}
