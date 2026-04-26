package tests

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/qsilasu/xproxy/node"
	"github.com/qsilasu/xproxy/proxy"
)

// --- test servers ---

// startHTTPTarget starts a simple HTTP server.
func startHTTPTarget(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("hello from target"))
	})}
	go srv.Serve(ln)
	return ln.Addr().String(), func() { srv.Close(); ln.Close() }
}

// startEchoServer returns a TCP echo server address.
func startEchoServer(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// startMinimalHTTPProxy starts a basic HTTP CONNECT proxy for testing.
func startMinimalHTTPProxy(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleHTTPConnect(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleHTTPConnect(client net.Conn) {
	defer client.Close()
	br := bufio.NewReader(client)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		return
	}
	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		client.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer target.Close()
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(target, client) }()
	go func() { defer wg.Done(); io.Copy(client, target) }()
	wg.Wait()
}

// startSOCKS5Server starts a minimal SOCKS5 proxy for testing.
func startSOCKS5Server(t *testing.T) (addr string, closeFn func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5Server(conn)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func handleSOCKS5Server(client net.Conn) {
	defer client.Close()
	buf := make([]byte, 263)

	n, err := client.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return
	}
	client.Write([]byte{0x05, 0x00})

	n, err = client.Read(buf)
	if err != nil || n < 10 || buf[0] != 0x05 || buf[1] != 0x01 {
		return
	}
	var dstHost string
	var dstPort int
	switch buf[3] {
	case 0x01:
		dstHost = net.IP(buf[4:8]).String()
		dstPort = int(buf[8])<<8 | int(buf[9])
	case 0x03:
		domainLen := int(buf[4])
		dstHost = string(buf[5 : 5+domainLen])
		dstPort = int(buf[5+domainLen])<<8 | int(buf[6+domainLen])
	default:
		return
	}
	target, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dstHost, dstPort))
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	done := make(chan struct{}, 2)
	go func() { io.Copy(target, client); done <- struct{}{} }()
	go func() { io.Copy(client, target); done <- struct{}{} }()
	<-done
}

// socks5Connect dials a target through a SOCKS5 proxy.
func socks5Connect(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	conn.Write([]byte{0x05, 0x01, 0x00})
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		conn.Close()
		return nil, err
	}
	host, portStr, _ := net.SplitHostPort(targetAddr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}
	req = append(req, []byte(host)...)
	req = append(req, byte(port>>8), byte(port&0xFF))
	conn.Write(req)
	resp := make([]byte, 10)
	if _, err := conn.Read(resp); err != nil {
		conn.Close()
		return nil, err
	}
	if resp[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect failed: code %d", resp[1])
	}
	return conn, nil
}

// httpGET helper: sends minimal HTTP/1.0 GET through a connection and returns body.
func httpGET(t *testing.T, conn net.Conn, host string) string {
	t.Helper()
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body)
}

func mustPort(addr string) int {
	_, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)
	return port
}

// --- outbound tests ---

func TestProxy_Direct_DialAndHTTP(t *testing.T) {
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "direct-http",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     mustPort(targetAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	body := httpGET(t, conn, targetAddr)
	if body != "hello from target" {
		t.Errorf("expected 'hello from target', got %q", body)
	}

	stats := p.Statistics()
	if stats.UploadBytes == 0 || stats.DownloadBytes == 0 {
		t.Error("traffic stats should be non-zero after connection")
	}
}

func TestProxy_SOCKS5_Outbound(t *testing.T) {
	socksAddr, socksClose := startSOCKS5Server(t)
	defer socksClose()
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "socks5-out",
		Protocol: node.ProtoSOCKS5,
		Address:  "127.0.0.1",
		Port:     mustPort(socksAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	body := httpGET(t, conn, targetAddr)
	if body != "hello from target" {
		t.Errorf("expected 'hello from target', got %q", body)
	}
}

func TestProxy_HTTP_Outbound(t *testing.T) {
	proxyAddr, proxyClose := startMinimalHTTPProxy(t)
	defer proxyClose()
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "http-out",
		Protocol: node.ProtoHTTP,
		Address:  "127.0.0.1",
		Port:     mustPort(proxyAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	body := httpGET(t, conn, targetAddr)
	if body != "hello from target" {
		t.Errorf("expected 'hello from target', got %q", body)
	}
}

func TestProxy_UnreachableHost(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "unreachable",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     1, // closed/unused port
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, err = p.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected error for unreachable host")
	}
}

func TestProxy_ContextCancellation(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "cancel-test",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     8080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = p.DialContext(ctx, "tcp", "127.0.0.1:8080")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

// --- concurrent ---

func TestProxy_Concurrent_Dial(t *testing.T) {
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "concurrent",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     mustPort(targetAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	ctx := context.Background()

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := p.DialContext(ctx, "tcp", targetAddr)
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			body := httpGET(t, conn, targetAddr)
			if body != "hello from target" {
				errs <- fmt.Errorf("bad body: %q", body)
			}
		}()
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent dial error: %v", err)
	}

	stats := p.Statistics()
	if stats.UploadBytes == 0 || stats.DownloadBytes == 0 {
		t.Error("stats should accumulate across concurrent dials")
	}
	t.Logf("concurrent 10: upload=%d download=%d", stats.UploadBytes, stats.DownloadBytes)
}

// --- listener tests ---

func TestProxy_Listen_TransparentForward(t *testing.T) {
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "listen-fwd",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     mustPort(targetAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ln, err := p.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	lnAddr := ln.Addr().String()

	// Accept in background
	acceptCh := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			acceptCh <- conn
		}
	}()

	// Dial the listener
	client, err := net.Dial("tcp", lnAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()

	// Wait for accept
	select {
	case <-acceptCh:
	case <-time.After(3 * time.Second):
		t.Fatal("accept timeout")
	}
	time.Sleep(50 * time.Millisecond) // let pipes settle

	// Write HTTP request through the listener → forwarded to target
	body := httpGET(t, client, targetAddr)
	if body != "hello from target" {
		t.Errorf("expected 'hello from target', got %q", body)
	}
}

func TestProxy_ListenSOCKS5_ServerMode(t *testing.T) {
	targetAddr, targetClose := startHTTPTarget(t)
	defer targetClose()

	p, err := proxy.New(node.Node{
		Name:     "socks5-srv",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     mustPort(targetAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ln, err := p.ListenSOCKS5(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenSOCKS5: %v", err)
	}
	defer ln.Close()

	socksAddr := ln.Addr().String()

	// Accept in background (handshake happens here)
	acceptCh := make(chan net.Conn, 1)
	go func() {
		conn, _ := ln.Accept()
		if conn != nil {
			acceptCh <- conn
		}
	}()

	// Connect through SOCKS5
	conn, err := socks5Connect(socksAddr, targetAddr)
	if err != nil {
		t.Fatalf("socks5 connect: %v", err)
	}
	defer conn.Close()

	<-acceptCh

	body := httpGET(t, conn, targetAddr)
	if body != "hello from target" {
		t.Errorf("expected 'hello from target', got %q", body)
	}
}

// --- metadata tests ---

func TestProxy_Info(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "info-test",
		Protocol: node.ProtoSOCKS5,
		Address:  "10.0.0.1",
		Port:     1080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	info := p.Info()
	if info.Name != "info-test" {
		t.Errorf("name: %q", info.Name)
	}
	if info.Protocol != node.ProtoSOCKS5 {
		t.Errorf("protocol: %q", info.Protocol)
	}
	if info.Address != "10.0.0.1" {
		t.Errorf("address: %q", info.Address)
	}
	if info.Port != 1080 {
		t.Errorf("port: %d", info.Port)
	}
}

func TestProxy_Close(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "close-test",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     8080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("first Close: %v", err)
	}
	if err := p.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
}

func TestProxy_StatisticsInitial(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "stats-init",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     8080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	stats := p.Statistics()
	if stats.StartedAt.IsZero() {
		t.Error("StartedAt should not be zero")
	}
	if stats.UploadBytes != 0 || stats.DownloadBytes != 0 {
		t.Error("initial stats should be zero")
	}
}

func TestProxy_EchoLargeData(t *testing.T) {
	echoAddr, echoClose := startEchoServer(t)
	defer echoClose()

	p, err := proxy.New(node.Node{
		Name:     "echo-data",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     mustPort(echoAddr),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Send 64KB of data and verify echo
	payload := strings.Repeat("0123456789", 6554) // ~65KB
	go func() {
		conn.Write([]byte(payload))
	}()

	buf := make([]byte, len(payload))
	n, err := io.ReadFull(conn, buf)
	if err != nil {
		t.Fatalf("read full: %v (read %d/%d)", err, n, len(payload))
	}
	if n != len(payload) {
		t.Errorf("expected %d bytes, got %d", len(payload), n)
	}

	stats := p.Statistics()
	t.Logf("echo 65KB: upload=%d download=%d", stats.UploadBytes, stats.DownloadBytes)
}

func TestProxy_Listen_CloseStopsAccept(t *testing.T) {
	p, err := proxy.New(node.Node{
		Name:     "listen-close",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     8080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ln, err := p.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	lnAddr := ln.Addr().String()

	// Close should stop the listener
	p.Close()

	// Try to Accept — should return an error since listener is closed
	_, err = ln.Accept()
	if err == nil {
		t.Error("expected error from Accept after Close")
	}

	// Try to dial — should fail since listener is closed
	_, err = net.Dial("tcp", lnAddr)
	if err == nil {
		t.Error("expected error dialing closed listener")
	}
}
