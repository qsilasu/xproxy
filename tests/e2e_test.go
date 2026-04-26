package tests

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/qsilasu/xproxy/node"
	"github.com/qsilasu/xproxy/url"
)

const fixturesDir = "fixtures"

// readLines reads non-empty, non-comment lines from fixtures/{source}/{name}.txt.
func readLines(t *testing.T, source, name string) []string {
	t.Helper()
	path := filepath.Join(fixturesDir, source, name+".txt")
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("fixture not available: %s (run fetch_fixtures.sh)", path)
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return lines
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// E2E URL parse test helper — parses all lines, reports pass rate.
func testParseProtocol(t *testing.T, source, name string, wantProto node.Protocol, needField func(*node.Node) bool) {
	lines := readLines(t, source, name)
	if len(lines) == 0 {
		t.Fatal("no fixture data loaded")
	}
	t.Logf("source=%s/%s total=%d", source, name, len(lines))

	var parsed, failed int
	for _, line := range lines {
		n, err := url.Parse(line)
		if err != nil {
			failed++
			if failed <= 5 {
				t.Logf("  FAIL %s: %v", truncate(line, 80), err)
			}
			continue
		}
		parsed++
		if n.Protocol != wantProto {
			t.Errorf("%s/%s: expected %q, got %q: %s", source, name, wantProto, n.Protocol, truncate(line, 60))
		}
		if n.Address == "" {
			t.Errorf("%s/%s: empty address: %s", source, name, truncate(line, 60))
		}
		if n.Port == 0 {
			t.Errorf("%s/%s: zero port: %s", source, name, truncate(line, 60))
		}
		if needField != nil && !needField(n) {
			t.Errorf("%s/%s: required field missing: %s", source, name, truncate(line, 60))
		}
	}
	rate := float64(parsed) / float64(parsed+failed) * 100
	t.Logf("  result: parsed=%d failed=%d rate=%.1f%%", parsed, failed, rate)
}

func ssFields(n *node.Node) bool { return n.Shadowsocks != nil && n.Shadowsocks.Method != "" }
func vmFields(n *node.Node) bool { return n.VMess != nil && n.VMess.UUID != "" }
func vlFields(n *node.Node) bool { return n.VLESS != nil && n.VLESS.UUID != "" }
func tjFields(n *node.Node) bool { return n.Trojan != nil && n.Trojan.Password != "" }

// --- TGParse ---

func TestE2E_TGParse_SS(t *testing.T) { testParseProtocol(t, "tgparse", "ss", node.ProtoSS, ssFields) }
func TestE2E_TGParse_VMess(t *testing.T) {
	testParseProtocol(t, "tgparse", "vmess", node.ProtoVMess, vmFields)
}
func TestE2E_TGParse_VLESS(t *testing.T) {
	testParseProtocol(t, "tgparse", "vless", node.ProtoVLESS, vlFields)
}
func TestE2E_TGParse_Trojan(t *testing.T) {
	testParseProtocol(t, "tgparse", "trojan", node.ProtoTrojan, tjFields)
}

// --- Epodonios ---

func TestE2E_Epodonios_VMess(t *testing.T) {
	testParseProtocol(t, "epodonios", "vmess", node.ProtoVMess, vmFields)
}
func TestE2E_Epodonios_VLESS(t *testing.T) {
	testParseProtocol(t, "epodonios", "vless", node.ProtoVLESS, vlFields)
}
func TestE2E_Epodonios_Trojan(t *testing.T) {
	testParseProtocol(t, "epodonios", "trojan", node.ProtoTrojan, tjFields)
}
func TestE2E_Epodonios_SS(t *testing.T) {
	testParseProtocol(t, "epodonios", "ss", node.ProtoSS, ssFields)
}

// --- V2go ---

func TestE2E_V2go_VMess(t *testing.T) {
	testParseProtocol(t, "v2go", "vmess", node.ProtoVMess, vmFields)
}
func TestE2E_V2go_VLESS(t *testing.T) {
	testParseProtocol(t, "v2go", "vless", node.ProtoVLESS, vlFields)
}
func TestE2E_V2go_Trojan(t *testing.T) {
	testParseProtocol(t, "v2go", "trojan", node.ProtoTrojan, tjFields)
}
func TestE2E_V2go_SS(t *testing.T) { testParseProtocol(t, "v2go", "ss", node.ProtoSS, ssFields) }

// --- Miladtahanian ---

func TestE2E_Milad_Mixed(t *testing.T) {
	lines := readLines(t, "miladtahanian", "mixed")
	if len(lines) == 0 {
		t.Fatal("no fixture data")
	}
	var parsed, failed int
	protos := map[string]int{}
	for _, line := range lines {
		n, err := url.Parse(line)
		if err != nil {
			failed++
			continue
		}
		parsed++
		protos[string(n.Protocol)]++
	}
	t.Logf("  total=%d parsed=%d failed=%d protocols=%v", len(lines), parsed, failed, protos)
}

// --- Cross-source consistency ---

func TestE2E_CrossSource_ProtocolDetection(t *testing.T) {
	// Every VMess source should consistently detect as ProtoVMess
	sources := []struct{ source, name string }{
		{"tgparse", "vmess"},
		{"epodonios", "vmess"},
		{"v2go", "vmess"},
	}
	for _, s := range sources {
		lines := readLines(t, s.source, s.name)
		if len(lines) == 0 {
			continue
		}
		// Check first 20
		for i, line := range lines {
			if i >= 20 {
				break
			}
			n, err := url.Parse(line)
			if err != nil {
				// Real-world data includes malformed URLs — skip them.
				continue
			}
			if n.Protocol != node.ProtoVMess {
				t.Errorf("%s/%s[%d]: expected vmess, got %q", s.source, s.name, i, n.Protocol)
			}
		}
	}
}

// --- SS Round-trip across all sources ---

func TestE2E_CrossSource_SS_RoundTrip(t *testing.T) {
	sources := []string{"tgparse", "epodonios", "v2go"}
	for _, src := range sources {
		lines := readLines(t, src, "ss")
		if len(lines) == 0 {
			continue
		}
		var ok int
		for _, line := range lines {
			n, err := url.Parse(line)
			if err != nil {
				continue
			}
			gen, err := url.Generate(n)
			if err != nil {
				t.Logf("%s/ss: generate fail: %v", src, err)
				continue
			}
			n2, err := url.Parse(gen)
			if err != nil {
				t.Logf("%s/ss: re-parse fail: %s → %v", src, truncate(gen, 60), err)
				continue
			}
			if n2.Address != n.Address || n2.Port != n.Port {
				continue
			}
			ok++
		}
		t.Logf("%s/ss: round-trip ok=%d", src, ok)
	}
}
