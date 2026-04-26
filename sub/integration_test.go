package sub

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestParseURLClash(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/yaml")
		w.Write([]byte(clashYAMLFixture))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := ParseURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if sub.SourceURL != srv.URL {
		t.Errorf("expected source %q, got %q", srv.URL, sub.SourceURL)
	}
	if len(sub.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(sub.Nodes))
	}
}

func TestParseURLSurge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(surgeConfFixture))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := ParseURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if len(sub.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(sub.Nodes))
	}
}

func TestParseURLSingBox(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(singboxJSONFixture))
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	sub, err := ParseURL(ctx, srv.URL)
	if err != nil {
		t.Fatalf("ParseURL: %v", err)
	}
	if len(sub.Nodes) != 2 {
		t.Errorf("expected 2 nodes, got %d", len(sub.Nodes))
	}
}

func TestParseURLContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := ParseURL(ctx, "http://127.0.0.1:1/never-reachable")
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}
