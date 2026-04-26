package proxy

import (
	"context"
	"net"
	"time"

	"github.com/qsilasu/xproxy/node"
)

// Proxy is a unified proxy connection interface.
type Proxy interface {
	// DialContext connects to the target address through the proxy.
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)

	// Listen creates a listener for incoming proxy connections.
	// Accepted connections are transparently forwarded to the configured target.
	Listen(ctx context.Context, network, addr string) (net.Listener, error)

	// ListenSOCKS5 creates a SOCKS5 proxy server. Incoming connections
	// are handled via the SOCKS5 protocol — the target address is read
	// from the CONNECT request and dialed through the outbound.
	ListenSOCKS5(ctx context.Context, network, addr string) (net.Listener, error)

	// Info returns proxy metadata.
	Info() Info

	// Statistics returns traffic counters since the proxy was created.
	Statistics() Statistics

	// Close releases all resources held by the proxy.
	Close() error
}

// Info holds proxy metadata.
type Info struct {
	Name     string
	Protocol node.Protocol
	Address  string
	Port     int
}

// Statistics holds cumulative traffic counters.
type Statistics struct {
	UploadBytes   int64
	DownloadBytes int64
	StartedAt     time.Time
}

// New creates a Proxy from a Node. The returned Proxy must be closed after use.
func New(n node.Node) (Proxy, error) {
	return newAdapter(n)
}

// Must is like New but panics on error. For use with trusted configurations.
func Must(p Proxy, err error) Proxy {
	if err != nil {
		panic(err)
	}
	return p
}
