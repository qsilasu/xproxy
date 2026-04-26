package sub

import "testing"

const singboxJSONFixture = `{
  "outbounds": [
    {
      "tag": "ss-out",
      "type": "shadowsocks",
      "server": "1.2.3.4",
      "server_port": 8388,
      "method": "aes-256-gcm",
      "password": "secret"
    },
    {
      "tag": "vmess-out",
      "type": "vmess",
      "server": "5.6.7.8",
      "server_port": 443,
      "uuid": "11111111-1111-1111-1111-111111111111",
      "security": "auto",
      "transport": {
        "type": "ws",
        "path": "/ws",
        "headers": {"Host": "example.com"}
      }
    }
  ]
}`

func TestParseSingBox(t *testing.T) {
	sub, err := Parse([]byte(singboxJSONFixture), FmtSingBox)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(sub.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(sub.Nodes))
	}
	if sub.Nodes[0].Name != "ss-out" {
		t.Errorf("expected 'ss-out', got %q", sub.Nodes[0].Name)
	}
	if sub.Nodes[0].Shadowsocks == nil {
		t.Fatal("first node should be Shadowsocks")
	}
}

func TestGenerateSingBoxRoundTrip(t *testing.T) {
	sub, _ := Parse([]byte(singboxJSONFixture), FmtSingBox)
	out, err := Generate(sub, FmtSingBox)
	if err != nil {
		t.Fatalf("unexpected generate error: %v", err)
	}
	sub2, err := Parse(out, FmtSingBox)
	if err != nil {
		t.Fatalf("round-trip parse error: %v", err)
	}
	if len(sub2.Nodes) != len(sub.Nodes) {
		t.Errorf("round-trip count mismatch: %d vs %d", len(sub.Nodes), len(sub2.Nodes))
	}
}
