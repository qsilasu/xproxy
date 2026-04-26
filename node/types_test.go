package node

import (
	"testing"
	"time"
)

func TestNodeZeroValue(t *testing.T) {
	var n Node
	if n.Protocol != "" {
		t.Errorf("zero value Protocol should be empty, got %q", n.Protocol)
	}
	if n.Port != 0 {
		t.Errorf("zero value Port should be 0, got %d", n.Port)
	}
}

func TestNodeProtocolSpecificConfig(t *testing.T) {
	n := Node{
		Name:     "test-node",
		Protocol: ProtoSS,
		Address:  "1.2.3.4",
		Port:     8388,
		Shadowsocks: &SSConfig{
			Method:   "aes-256-gcm",
			Password: "secret",
		},
	}
	if n.Shadowsocks == nil {
		t.Fatal("Shadowsocks config should not be nil")
	}
	if n.Shadowsocks.Method != "aes-256-gcm" {
		t.Errorf("expected aes-256-gcm, got %q", n.Shadowsocks.Method)
	}
	if n.VMess != nil {
		t.Error("VMess config should be nil when protocol is SS")
	}
}

func TestSubscriptionEmptyNodes(t *testing.T) {
	sub := Subscription{
		SourceURL: "https://example.com/sub",
		UpdatedAt: time.Now(),
	}
	if len(sub.Nodes) != 0 {
		t.Errorf("expected 0 nodes, got %d", len(sub.Nodes))
	}
}

func TestTransportConfigDefaults(t *testing.T) {
	tc := TransportConfig{}
	if tc.Type != "" {
		t.Errorf("zero value Type should be empty, got %q", tc.Type)
	}
	if tc.Headers != nil {
		t.Error("zero value Headers should be nil")
	}
}
