package sub

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestFormatConstants(t *testing.T) {
	if FmtClash != "clash" {
		t.Errorf("expected 'clash', got %q", FmtClash)
	}
	if FmtBase64 != "base64" {
		t.Errorf("expected 'base64', got %q", FmtBase64)
	}
}

func TestParseUnknownFormat(t *testing.T) {
	_, err := Parse([]byte("dummy content"), Format("unknown"))
	if err == nil {
		t.Fatal("expected error for unknown format")
	}
}

func TestGenerateEmptySubscription(t *testing.T) {
	sub := &node.Subscription{
		SourceURL: "https://example.com",
	}
	out, err := Generate(sub, FmtBase64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Empty subscription (no nodes) produces empty base64 output
	if out == nil {
		t.Error("expected non-nil output for empty subscription")
	}
}
