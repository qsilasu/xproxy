package sub

import "testing"

func TestDetectClash(t *testing.T) {
	f := Detect([]byte(`proxies:
  - name: ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass
`))
	if f != FmtClash {
		t.Errorf("expected clash, got %q", f)
	}
}

func TestDetectSingBox(t *testing.T) {
	f := Detect([]byte(`{
  "outbounds": [
    {"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388}
  ]
}`))
	if f != FmtSingBox {
		t.Errorf("expected singbox, got %q", f)
	}
}

func TestDetectSurge(t *testing.T) {
	f := Detect([]byte(`[Proxy]
ss-node = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=secret
`))
	if f != FmtSurge {
		t.Errorf("expected surge, got %q", f)
	}
}

func TestDetectBase64(t *testing.T) {
	// base64 of "ss://Y2hhY2hhMjA@1.2.3.4:8388#Node1\nvmess://..."
	encoded := "c3M6Ly9ZMmhoWTJoaE1qQTZNVll4TWpNdU5DNDRPREF3TXpnNE9DSWdhV1JpUFNJdE1URXhNVEV4TVRFdE1URXhNUzB4TVRFeExURXhNU0F0TVRFeE1URXhNVEV4TVRFeElpd2dZV1JrUFNJMUxqWXVOeTRJU0l3aWUzSmxjM05sSWpvaVRYbFdUV1Z6Y3lJc0ltRmtJanA3SWpJd2V6SnViY2lJc0ltZHBiQ0k2SWpFeE1URXhNVEV4TVMweE1URXhMVEV4TVRFdE1URXhNUzB4TVRFeE1URXhNVEV4TVNJc0ltOXlaWFFpT2lJME5ETWlMQ0pwWkNJNklqRXhNVEV4TVRFeE1TMHhNVEV4TFRFeE1URXRNVEV4TFMweE1URXhNVEV4TVRFeE1TSXNJbUZwWkNJNk1Dd2ljMk41SWpvaVlYVjBieUo5"
	f := Detect([]byte(encoded))
	if f != FmtSS {
		t.Errorf("expected ss, got %q", f)
	}
}

func TestDetectRaw(t *testing.T) {
	f := Detect([]byte("ss://Y2hhY2hhMjA@1.2.3.4:8388#Node1\nvmess://eyJ2IjoiMiJ9"))
	if f != FmtRaw {
		t.Errorf("expected raw for mixed URLs, got %q", f)
	}
}

func TestDetectEmpty(t *testing.T) {
	f := Detect([]byte(""))
	if f != FmtRaw {
		t.Errorf("expected raw for empty, got %q", f)
	}
}
