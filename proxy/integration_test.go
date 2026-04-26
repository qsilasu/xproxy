package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/qsilasu/xproxy/node"
)

func TestDialContextDirect(t *testing.T) {
	// Start a local HTTP server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()
	host, portStr, _ := net.SplitHostPort(addr)
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("pong"))
	})}
	go srv.Serve(ln)
	defer srv.Close()

	// Create a direct proxy pointing to the local server.
	p, err := New(node.Node{
		Name:     "test-direct",
		Protocol: node.ProtoDirect,
		Address:  host,
		Port:     port,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	// Dial through the proxy.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := p.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Send an HTTP request through the connection.
	req, _ := http.NewRequest("GET", "/", nil)
	if err := req.Write(conn); err != nil {
		t.Fatalf("write request: %v", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "pong" {
		t.Errorf("expected 'pong', got %q", body)
	}
}

func TestDialContextContextCancellation(t *testing.T) {
	p, err := New(node.Node{
		Name:     "test-cancel",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     1, // port 1 is typically closed
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err = p.DialContext(ctx, "tcp", "127.0.0.1:1")
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestStatisticsCountsTraffic(t *testing.T) {
	p, err := New(node.Node{
		Name:     "test-stats",
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

func TestListen(t *testing.T) {
	p, err := New(node.Node{
		Name:     "test-listen",
		Protocol: node.ProtoDirect,
		Address:  "127.0.0.1",
		Port:     8080,
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

	addr := ln.Addr().String()

	// Dial the listener.
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial listener: %v", err)
	}
	conn.Close()

	// Accept the connection on the listener side.
	client, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	client.Close()
}

func TestInfo(t *testing.T) {
	p, err := New(node.Node{
		Name:     "test-info",
		Protocol: node.ProtoSOCKS5,
		Address:  "192.168.1.1",
		Port:     1080,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer p.Close()

	info := p.Info()
	if info.Name != "test-info" {
		t.Errorf("expected name 'test-info', got %q", info.Name)
	}
	if info.Protocol != node.ProtoSOCKS5 {
		t.Errorf("expected socks5, got %q", info.Protocol)
	}
	if info.Address != "192.168.1.1" {
		t.Errorf("expected address, got %q", info.Address)
	}
	if info.Port != 1080 {
		t.Errorf("expected 1080, got %d", info.Port)
	}
}
