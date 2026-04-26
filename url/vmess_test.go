package url

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestParseVMess(t *testing.T) {
	raw := "vmess://eyJ2IjoiMiIsInBzIjoiTXlWTWVzcyIsImFkZCI6IjEuMi4zLjQiLCJwb3J0Ijo0NDMsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8iLCJuZXQiOiJ3cyJ9"
	n, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.Protocol != node.ProtoVMess {
		t.Errorf("expected vmess, got %q", n.Protocol)
	}
	if n.Address != "1.2.3.4" {
		t.Errorf("expected address '1.2.3.4', got %q", n.Address)
	}
	if n.Port != 443 {
		t.Errorf("expected port 443, got %d", n.Port)
	}
	if n.VMess == nil {
		t.Fatal("VMess config should not be nil")
	}
	if n.VMess.UUID != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("unexpected UUID: %q", n.VMess.UUID)
	}
	if n.Transport == nil || n.Transport.Type != node.TransportWS {
		t.Error("expected ws transport")
	}
}

func TestParseVMessRoundTrip(t *testing.T) {
	original := "vmess://eyJ2IjoiMiIsInBzIjoiTXlWTWVzcyIsImFkZCI6IjEuMi4zLjQiLCJwb3J0Ijo0NDMsImlkIjoiMTExMTExMTEtMTExMS0xMTExLTExMTEtMTExMTExMTExMTExIiwiYWlkIjoiMCIsInNjeSI6ImF1dG8ifQ"
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
		t.Fatalf("round-trip parse error: %v", err)
	}
	if n2.VMess.UUID != n.VMess.UUID {
		t.Errorf("UUID mismatch: %q vs %q", n.VMess.UUID, n2.VMess.UUID)
	}
}
