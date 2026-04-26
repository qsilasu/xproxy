package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/qsilasu/xproxy/node"
	"github.com/qsilasu/xproxy/proxy"
	"github.com/qsilasu/xproxy/url"
)

const (
	smokeSamplePerFile = 10
	smokeWorkers       = 50
	smokeTimeout       = 5 * time.Second
	smokeTarget        = "http://www.google.com/robots.txt" // small text, reliable
)

// benchResult holds comprehensive per-node metrics.
type benchResult struct {
	Source   string
	Protocol string
	Name     string
	Address  string
	RawURL   string

	Status     string // "ok" or error summary
	Err        string
	ConnectLat time.Duration // TCP dial latency
	FirstByte  time.Duration // time to first response byte
	TotalLat   time.Duration // total round-trip
	BytesRead  int64
	SpeedKBs   float64
}

func readLinesOrEmpty(source, name string) []string {
	path := filepath.Join(fixturesDir, source, name+".txt")
	f, err := os.Open(path)
	if err != nil {
		return nil
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
	return lines
}

func benchmarkNode(source, rawURL string) benchResult {
	r := benchResult{Source: source, RawURL: rawURL, Status: "parse_error"}

	// 1. Parse.
	n, err := url.Parse(rawURL)
	if err != nil {
		r.Err = fmt.Sprintf("parse: %v", err)
		return r
	}
	r.Protocol = string(n.Protocol)
	r.Name = n.Name
	r.Address = n.Address

	// 2. Validate.
	if n.Protocol == node.ProtoWireGuard {
		r.Err = "wireguard: no sing-box outbound"
		r.Status = "skip"
		return r
	}
	if err := n.Validate(); err != nil {
		r.Err = fmt.Sprintf("validate: %v", err)
		return r
	}

	// 3. Create proxy.
	r.Status = "create_error"
	p, err := proxy.New(*n)
	if err != nil {
		r.Err = fmt.Sprintf("create: %v", err)
		return r
	}
	defer p.Close()

	// 4. Dial through proxy with HTTP.
	r.Status = "dial_error"
	ctx, cancel := context.WithTimeout(context.Background(), smokeTimeout)
	defer cancel()

	dialStart := time.Now()
	conn, err := p.DialContext(ctx, "tcp", "www.google.com:80")
	if err != nil {
		r.Err = fmt.Sprintf("dial: %v", err)
		return r
	}
	r.ConnectLat = time.Since(dialStart)
	defer conn.Close()

	// Set deadline so stalled proxies don't hang the test.
	conn.SetDeadline(time.Now().Add(smokeTimeout))

	// 5. HTTP GET — measure first-byte and total.
	reqStart := time.Now()
	fmt.Fprintf(conn, "GET /robots.txt HTTP/1.0\r\nHost: www.google.com\r\nUser-Agent: XProxy-Smoke/1.0\r\n\r\n")

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		r.Err = fmt.Sprintf("http: %v", err)
		return r
	}
	r.FirstByte = time.Since(reqStart)
	defer resp.Body.Close()

	// 6. Read body, count bytes including headers for speed calc.
	body, err := io.ReadAll(resp.Body)
	r.TotalLat = time.Since(reqStart)
	if err != nil {
		r.Err = fmt.Sprintf("read: %v", err)
		return r
	}
	// Include header overhead in speed (status line + headers + body).
	headerBytes := len(resp.Proto) + 4 + len(resp.Status) + 2 // "HTTP/1.0 200 OK\r\n"
	for k, vv := range resp.Header {
		for _, v := range vv {
			headerBytes += len(k) + 2 + len(v) + 2 // "Key: value\r\n"
		}
	}
	headerBytes += 2 // final \r\n
	r.BytesRead = int64(len(body) + headerBytes)
	if r.TotalLat > 0 {
		r.SpeedKBs = float64(r.BytesRead) / 1024.0 / r.TotalLat.Seconds()
	}

	// 7. Check response.
	if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNoContent {
		r.Status = "ok"
	} else {
		r.Status = fmt.Sprintf("http_%d", resp.StatusCode)
	}
	return r
}

// --- collection + reporting ---

func collectAndReport(t *testing.T, sources []string) []benchResult {
	t.Helper()

	type nodeEntry struct {
		source string
		raw    string
	}
	var entries []nodeEntry
	for _, src := range sources {
		for _, name := range []string{"vmess", "vless", "trojan", "ss", "socks", "mixed"} {
			lines := readLinesOrEmpty(src, name)
			n := smokeSamplePerFile
			if len(lines) < n {
				n = len(lines)
			}
			for _, line := range lines[:n] {
				entries = append(entries, nodeEntry{source: src, raw: line})
			}
		}
	}
	if len(entries) == 0 {
		t.Skip("no fixture nodes available")
	}
	total := len(entries)
	t.Logf("testing %d nodes (target=%s timeout=%v workers=%d)", total, smokeTarget, smokeTimeout, smokeWorkers)

	jobs := make(chan nodeEntry, total)
	for _, e := range entries {
		jobs <- e
	}
	close(jobs)

	results := make(chan benchResult, total)
	var wg sync.WaitGroup
	var done atomic.Int64

	for w := 0; w < smokeWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for entry := range jobs {
				results <- benchmarkNode(entry.source, entry.raw)
				n := done.Add(1)
				if n%20 == 0 {
					t.Logf("  progress: %d/%d", n, total)
				}
			}
		}()
	}
	wg.Wait()
	close(results)

	var all []benchResult
	for r := range results {
		all = append(all, r)
	}
	return all
}

func printReport(t *testing.T, all []benchResult) {
	t.Helper()

	// --- Summary table ---
	t.Logf("")
	t.Logf("╔══════════════════════════════════════════════════════════════╗")
	t.Logf("║              XProxy Node Bench Report                        ║")
	t.Logf("╠══════════════════════════════════════════════════════════════╣")
	t.Logf("║  target: %-50s ║", smokeTarget)
	t.Logf("║  total: %-4d  workers: %-2d  timeout: %-4v                ║", len(all), smokeWorkers, smokeTimeout)
	t.Logf("╚══════════════════════════════════════════════════════════════╝")
	t.Logf("")

	// --- Per-protocol aggregate ---
	type protoStats struct {
		total, ok        int
		connSum          time.Duration
		firstByteSum     time.Duration
		totalSum         time.Duration
		bytesSum         int64
		connMin, connMax time.Duration
	}
	byProto := map[string]*protoStats{}

	for _, r := range all {
		if _, ok := byProto[r.Protocol]; !ok {
			byProto[r.Protocol] = &protoStats{}
		}
		ps := byProto[r.Protocol]
		ps.total++
		if r.Status == "ok" {
			ps.ok++
			ps.connSum += r.ConnectLat
			ps.firstByteSum += r.FirstByte
			ps.totalSum += r.TotalLat
			ps.bytesSum += r.BytesRead

			if ps.connMin == 0 || r.ConnectLat < ps.connMin {
				ps.connMin = r.ConnectLat
			}
			if r.ConnectLat > ps.connMax {
				ps.connMax = r.ConnectLat
			}
		}
	}

	t.Logf("┌─ Per Protocol ───────────────────────────────────────────────┐")
	t.Logf("│ %-12s %4s %4s  %9s %9s %9s %9s │", "protocol", "ok", "total", "connect", "first_byte", "total", "speed")
	t.Logf("├───────────────────────────────────────────────────────────────┤")
	for proto, ps := range byProto {
		if ps.ok == 0 {
			t.Logf("│ %-12s %4d %4d  %9s %9s %9s %9s │", proto, ps.ok, ps.total, "-", "-", "-", "-")
			continue
		}
		avgConn := ps.connSum / time.Duration(ps.ok)
		avgFB := ps.firstByteSum / time.Duration(ps.ok)
		avgTotal := ps.totalSum / time.Duration(ps.ok)
		speed := float64(ps.bytesSum) / 1024.0 / ps.totalSum.Seconds()
		t.Logf("│ %-12s %4d %4d  %9v %9v %9v %8.1fKB/s │", proto, ps.ok, ps.total, avgConn, avgFB, avgTotal, speed)
	}
	t.Logf("└───────────────────────────────────────────────────────────────┘")
	t.Logf("")

	// --- Top 10 fastest ---
	sort.Slice(all, func(i, j int) bool {
		if all[i].Status != all[j].Status {
			return all[i].Status == "ok"
		}
		return all[i].TotalLat < all[j].TotalLat
	})

	t.Logf("┌─ Top 10 Fastest (OK nodes) ──────────────────────────────────┐")
	t.Logf("│ %-2s %-20s %-12s %9s %9s %9s │", "#", "node", "protocol", "connect", "http", "speed")
	shown := 0
	for _, r := range all {
		if r.Status != "ok" {
			break
		}
		shown++
		if shown > 10 {
			break
		}
		t.Logf("│ %-2d %-20s %-12s %9v %9v %8.1fKB/s │",
			shown, truncate(r.Name, 20), r.Protocol, r.ConnectLat, r.TotalLat, r.SpeedKBs)
	}
	t.Logf("└───────────────────────────────────────────────────────────────┘")
	t.Logf("")

	// --- Failure summary ---
	failCount := 0
	errDist := map[string]int{}
	for _, r := range all {
		if r.Status != "ok" {
			failCount++
			cat := r.Status
			if strings.HasPrefix(r.Err, "dial:") {
				cat = r.Status + "/" + simplifyDialErr(r.Err)
			}
			errDist[cat]++
		}
	}

	t.Logf("┌─ Failure Distribution ──────────────────────────────────────┐")
	for cat, count := range errDist {
		t.Logf("│ %-50s %4d │", cat, count)
	}
	t.Logf("└─────────────────────────────────────────────────────────────┘")

	okCount := len(all) - failCount
	t.Logf("")
	t.Logf("  ✓ %d/%d nodes reachable (%.1f%%)", okCount, len(all), float64(okCount)/float64(len(all))*100)
}

func simplifyDialErr(err string) string {
	if strings.Contains(err, "connection refused") {
		return "refused"
	}
	if strings.Contains(err, "timeout") || strings.Contains(err, "deadline") {
		return "timeout"
	}
	if strings.Contains(err, "no route to host") {
		return "no_route"
	}
	return "other"
}

// --- tests ---

func TestProxy_Bench_All(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bench in short mode")
	}
	all := collectAndReport(t, []string{"tgparse", "epodonios", "v2go", "miladtahanian"})
	printReport(t, all)
}

func TestProxy_Bench_TGParse(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bench in short mode")
	}
	all := collectAndReport(t, []string{"tgparse"})
	printReport(t, all)
}
