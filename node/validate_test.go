package node

import "testing"

func TestNodeValidate_ValidSS(t *testing.T) {
	n := &Node{
		Name:     "valid-ss",
		Protocol: ProtoSS,
		Address:  "1.2.3.4",
		Port:     8388,
		Shadowsocks: &SSConfig{
			Method:   "aes-256-gcm",
			Password: "secret",
		},
	}
	if err := n.Validate(); err != nil {
		t.Errorf("expected valid, got %v", err)
	}
}

func TestNodeValidate_MissingAddress(t *testing.T) {
	n := &Node{Protocol: ProtoSOCKS5, Port: 1080}
	err := n.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	ve, ok := err.(*ValidateError)
	if !ok {
		t.Fatalf("expected *ValidateError, got %T", err)
	}
	if len(ve.Errors) != 1 {
		t.Errorf("expected 1 error, got %d", len(ve.Errors))
	}
}

func TestNodeValidate_InvalidPort(t *testing.T) {
	n := &Node{Protocol: ProtoSOCKS5, Address: "1.2.3.4", Port: 0}
	err := n.Validate(); if err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestNodeValidate_SSMissingMethod(t *testing.T) {
	n := &Node{
		Protocol: ProtoSS,
		Address:  "1.2.3.4",
		Port:     8388,
		Shadowsocks: &SSConfig{
			Password: "secret",
		},
	}
	err := n.Validate()
	if err == nil {
		t.Fatal("expected error")
	}
	ve := err.(*ValidateError)
	if len(ve.Errors) != 1 {
		t.Errorf("expected 1 error, got %d: %v", len(ve.Errors), ve)
	}
}

func TestNodeValidate_VMessMissingUUID(t *testing.T) {
	n := &Node{
		Protocol: ProtoVMess,
		Address:  "1.2.3.4",
		Port:     443,
		VMess:    &VMessConfig{},
	}
	err := n.Validate(); if err == nil {
		t.Fatal("expected error for empty UUID")
	}
}

func TestNodeValidate_MultipleErrors(t *testing.T) {
	n := &Node{
		Protocol: ProtoSS,
	}
	err := n.Validate(); if err == nil {
		t.Fatal("expected error")
	}
	ve := err.(*ValidateError)
	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 errors, got %d: %v", len(ve.Errors), ve)
	}
}

func TestNodeValidate_ValidSOCKS5(t *testing.T) {
	n := &Node{
		Protocol: ProtoSOCKS5,
		Address:  "1.2.3.4",
		Port:     1080,
	}
	if err := n.Validate(); err != nil {
		t.Errorf("expected valid SOCKS5, got %v", err)
	}
}
