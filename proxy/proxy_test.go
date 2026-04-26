package proxy

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestNewValidatesAddress(t *testing.T) {
	_, err := New(node.Node{
		Name:     "test",
		Protocol: node.ProtoSOCKS5,
		Address:  "",
		Port:     1080,
	})
	if err == nil {
		t.Fatal("expected error for empty address")
	}
}

func TestNewValidatesPort(t *testing.T) {
	_, err := New(node.Node{
		Name:     "test",
		Protocol: node.ProtoSOCKS5,
		Address:  "1.2.3.4",
		Port:     0,
	})
	if err == nil {
		t.Fatal("expected error for port 0")
	}
}

func TestNewSuccess(t *testing.T) {
	p, err := New(node.Node{
		Name:     "test",
		Protocol: node.ProtoSOCKS5,
		Address:  "1.2.3.4",
		Port:     1080,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer p.Close()

	info := p.Info()
	if info.Name != "test" {
		t.Errorf("expected name 'test', got %q", info.Name)
	}
	if info.Protocol != node.ProtoSOCKS5 {
		t.Errorf("expected socks5, got %q", info.Protocol)
	}
}

func TestMustPanics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid node")
		}
	}()
	Must(New(node.Node{}))
}
