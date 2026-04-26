package url

import (
	"testing"

	"github.com/qsilasu/xproxy/node"
)

func TestParseUnsupportedScheme(t *testing.T) {
	_, err := Parse("notaproxy://user@host:80")
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
	perr, ok := err.(*ParseError)
	if !ok {
		t.Fatalf("expected *ParseError, got %T", err)
	}
	if perr.Input != "notaproxy://user@host:80" {
		t.Errorf("expected input preserved, got %q", perr.Input)
	}
}

func TestMustParsePanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for invalid URL")
		}
	}()
	MustParse("!!!invalid")
}

func TestMustParseValid(t *testing.T) {
	n := MustParse("socks5://1.2.3.4:1080")
	if n.Protocol != node.ProtoSOCKS5 {
		t.Errorf("expected socks5, got %q", n.Protocol)
	}
}

func TestCleanTrimsWhitespace(t *testing.T) {
	dirty := "  ss://Y2hhY2hhMjA@1.2.3.4:8388#Node  "
	cleaned := Clean(dirty)
	if len(cleaned) > 0 && cleaned[0] == ' ' {
		t.Errorf("whitespace not trimmed: %q", cleaned)
	}
}

func TestCleanStripsJunkParams(t *testing.T) {
	dirty := "ss://Y2hhY2hhMjA@1.2.3.4:8388?remarks=dirty&tag=bad#Node"
	cleaned := Clean(dirty)
	if contains(cleaned, "remarks") {
		t.Errorf("remarks param should be stripped, got %q", cleaned)
	}
}

func contains(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
