package tests

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/qsilasu/xproxy/sub"
)

// loadFixtureFile reads a fixture file from fixtures/{source}/{name}.txt.
func loadFixtureFile(t *testing.T, source, name string) []byte {
	t.Helper()
	path := filepath.Join(fixturesDir, source, name+".txt")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("fixture not available: %s (run fetch_fixtures.sh)", path)
	}
	return data
}

// --- Base64 round-trip per source ---

func TestSub_Base64RoundTrip(t *testing.T) {
	sources := []struct{ source, name string }{
		{"tgparse", "vmess"},
		{"epodonios", "vmess"},
		{"v2go", "vmess"},
	}
	for _, s := range sources {
		data := loadFixtureFile(t, s.source, s.name)
		if len(data) == 0 {
			continue
		}
		s1, err := sub.Parse(data, sub.FmtRaw)
		if err != nil {
			t.Errorf("%s/%s: parse raw: %v", s.source, s.name, err)
			continue
		}

		encoded, err := sub.Generate(s1, sub.FmtBase64)
		if err != nil {
			t.Errorf("%s/%s: generate base64: %v", s.source, s.name, err)
			continue
		}

		s2, err := sub.Parse(encoded, sub.FmtBase64)
		if err != nil {
			t.Errorf("%s/%s: parse base64 round-trip: %v", s.source, s.name, err)
			continue
		}

		if len(s2.Nodes) != len(s1.Nodes) {
			t.Errorf("%s/%s: base64 round-trip %d → %d nodes",
				s.source, s.name, len(s1.Nodes), len(s2.Nodes))
		} else {
			t.Logf("%s/%s: base64 round-trip %d nodes OK", s.source, s.name, len(s1.Nodes))
		}
	}
}

// --- Clash round-trip per source ---

func TestSub_ClashRoundTrip(t *testing.T) {
	sources := []struct{ source, name string }{
		{"tgparse", "vmess"},
		{"epodonios", "vmess"},
		{"v2go", "vmess"},
	}
	for _, s := range sources {
		data := loadFixtureFile(t, s.source, s.name)
		if len(data) == 0 {
			continue
		}
		s1, err := sub.Parse(data, sub.FmtRaw)
		if err != nil {
			t.Errorf("%s/%s: parse: %v", s.source, s.name, err)
			continue
		}
		limit := min(50, len(s1.Nodes))
		s1.Nodes = s1.Nodes[:limit]

		out, err := sub.Generate(s1, sub.FmtClash)
		if err != nil {
			t.Errorf("%s/%s: generate clash: %v", s.source, s.name, err)
			continue
		}
		s2, err := sub.Parse(out, sub.FmtClash)
		if err != nil {
			t.Errorf("%s/%s: parse clash: %v", s.source, s.name, err)
			continue
		}
		if len(s2.Nodes) != limit {
			t.Errorf("%s/%s: clash round-trip %d → %d", s.source, s.name, limit, len(s2.Nodes))
		} else {
			t.Logf("%s/%s: clash round-trip %d OK", s.source, s.name, limit)
		}
	}
}

// --- Sing-box round-trip per source ---

func TestSub_SingBoxRoundTrip(t *testing.T) {
	sources := []struct{ source, name string }{
		{"tgparse", "vmess"},
		{"epodonios", "vmess"},
		{"v2go", "vmess"},
	}
	for _, s := range sources {
		data := loadFixtureFile(t, s.source, s.name)
		if len(data) == 0 {
			continue
		}
		s1, err := sub.Parse(data, sub.FmtRaw)
		if err != nil {
			t.Errorf("%s/%s: parse: %v", s.source, s.name, err)
			continue
		}
		limit := min(50, len(s1.Nodes))
		s1.Nodes = s1.Nodes[:limit]

		out, err := sub.Generate(s1, sub.FmtSingBox)
		if err != nil {
			t.Errorf("%s/%s: generate singbox: %v", s.source, s.name, err)
			continue
		}
		s2, err := sub.Parse(out, sub.FmtSingBox)
		if err != nil {
			t.Errorf("%s/%s: parse singbox: %v", s.source, s.name, err)
			continue
		}
		if len(s2.Nodes) != limit {
			t.Errorf("%s/%s: singbox round-trip %d → %d", s.source, s.name, limit, len(s2.Nodes))
		} else {
			t.Logf("%s/%s: singbox round-trip %d OK", s.source, s.name, limit)
		}
	}
}

// --- Surge round-trip per source ---

func TestSub_SurgeRoundTrip(t *testing.T) {
	sources := []struct{ source, name string }{
		{"tgparse", "ss"},
		{"epodonios", "ss"},
		{"v2go", "ss"},
	}
	for _, s := range sources {
		data := loadFixtureFile(t, s.source, s.name)
		if len(data) == 0 {
			continue
		}
		s1, err := sub.Parse(data, sub.FmtRaw)
		if err != nil {
			t.Errorf("%s/%s: parse: %v", s.source, s.name, err)
			continue
		}
		if len(s1.Nodes) == 0 {
			continue
		}

		out, err := sub.Generate(s1, sub.FmtSurge)
		if err != nil {
			t.Errorf("%s/%s: generate surge: %v", s.source, s.name, err)
			continue
		}
		outStr := string(out)
		if !strings.Contains(outStr, "[Proxy]") {
			t.Errorf("%s/%s: surge output missing [Proxy] section", s.source, s.name)
		}

		s2, err := sub.Parse(out, sub.FmtSurge)
		if err != nil {
			t.Errorf("%s/%s: parse surge: %v", s.source, s.name, err)
			continue
		}
		if len(s2.Nodes) != len(s1.Nodes) {
			t.Errorf("%s/%s: surge round-trip %d → %d", s.source, s.name, len(s1.Nodes), len(s2.Nodes))
		} else {
			t.Logf("%s/%s: surge round-trip %d OK", s.source, s.name, len(s1.Nodes))
		}
	}
}

// --- Cross-format conversion using Epodonios data ---

func TestSub_CrossFormat(t *testing.T) {
	data := loadFixtureFile(t, "epodonios", "ss")
	if len(data) == 0 {
		t.Skip("no epodonios/ss data")
	}
	s, err := sub.Parse(data, sub.FmtRaw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	limit := min(10, len(s.Nodes))
	s.Nodes = s.Nodes[:limit]

	formats := []struct {
		name string
		fmt  sub.Format
	}{
		{"clash", sub.FmtClash},
		{"surge", sub.FmtSurge},
		{"singbox", sub.FmtSingBox},
		{"base64", sub.FmtBase64},
		{"ss", sub.FmtSS},
		{"raw", sub.FmtRaw},
	}

	for _, src := range formats {
		for _, dst := range formats {
			if src.fmt == dst.fmt {
				continue
			}
			srcOut, err := sub.Generate(s, src.fmt)
			if err != nil {
				t.Errorf("%s→%s: generate src: %v", src.name, dst.name, err)
				continue
			}
			s2, err := sub.Parse(srcOut, src.fmt)
			if err != nil {
				t.Errorf("%s→%s: re-parse src: %v", src.name, dst.name, err)
				continue
			}
			dstOut, err := sub.Generate(s2, dst.fmt)
			if err != nil {
				t.Errorf("%s→%s: generate dst: %v", src.name, dst.name, err)
				continue
			}
			_, err = sub.Parse(dstOut, dst.fmt)
			if err != nil {
				t.Errorf("%s→%s: parse dst: %v", src.name, dst.name, err)
				continue
			}
		}
	}
	t.Log("cross-format: all 30 pairs OK")
}

// --- Auto-detect tests ---

const testClashYAML = `
proxies:
  - name: "ss-node"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "mypassword"
  - name: "vmess-ws"
    type: vmess
    server: 5.6.7.8
    port: 443
    uuid: 11111111-1111-1111-1111-111111111111
    alterId: 0
    cipher: auto
proxy-groups:
  - name: "auto-group"
    type: url-test
    proxies:
      - ss-node
      - vmess-ws
rules:
  - DOMAIN-SUFFIX,google.com,auto-group
`

func TestSub_ConvertURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(testClashYAML))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	out, err := sub.Convert(ctx, srv.URL, sub.FmtSingBox)
	if err != nil {
		t.Fatalf("Convert: %v", err)
	}
	s2, err := sub.Parse(out, sub.FmtSingBox)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	if len(s2.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(s2.Nodes))
	}
	t.Log("Convert OK: clash → singbox via URL")
}

func TestSub_ParseURL_Gzip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		gw.Write([]byte(testClashYAML))
		gw.Close()
		w.Write(buf.Bytes())
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	s, err := sub.ParseURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ParseURL gzip: %v", err)
	}
	if len(s.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(s.Nodes))
	}
	t.Log("gzip decompression OK")
}

func TestSub_AutoDetect(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect sub.Format
	}{
		{"clash", "proxies:\n  - name: test\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n", sub.FmtClash},
		{"singbox", `{"outbounds":[{"type":"shadowsocks","server":"1.2.3.4","server_port":8388}]}`, sub.FmtSingBox},
		{"surge", "[Proxy]\nnode = ss, 1.2.3.4, 8388, encrypt-method=aes-256-gcm, password=pass\n", sub.FmtSurge},
		{"raw", "ss://Y2hhY2hhMjA@1.2.3.4:8388\nvmess://eyJ2IjoiMiJ9\n", sub.FmtRaw},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sub.Detect([]byte(tc.input))
			if got != tc.expect {
				t.Errorf("expected %q, got %q", tc.expect, got)
			}
		})
	}
}
