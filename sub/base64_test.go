package sub

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestParseBase64(t *testing.T) {
	raw := "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwYXNz@1.2.3.4:8388#Node1\nvmess://eyJ2IjoiMiIsInBzIjoiVk1lc3MiLCJhZGQiOiI1LjYuNy44IiwicG9ydCI6NDQzLCJpZCI6IjExMTExMTExLTExMTEtMTExMS0xMTExLTExMTExMTExMTExMSIsImFpZCI6MCwic2N5IjoiYXV0byJ9"
	encoded := base64.StdEncoding.EncodeToString([]byte(raw))
	sub, err := Parse([]byte(encoded), FmtBase64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sub.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(sub.Nodes))
	}
	if sub.Nodes[0].Protocol != "shadowsocks" {
		t.Errorf("first node should be ss, got %q", sub.Nodes[0].Protocol)
	}
}

func TestGenerateBase64(t *testing.T) {
	sub, err := Parse([]byte("ss://Y2hhY2hhMjA@1.2.3.4:8388\nss://YWVzLTI1Ni1nY206cGFzc0A1LjYuNy44OjgzODg="), FmtRaw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	out, err := Generate(sub, FmtBase64)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.HasPrefix(string(out), "c3M6Ly") {
		t.Errorf("output should be base64-encoded, got prefix %q", string(out)[:10])
	}
}
