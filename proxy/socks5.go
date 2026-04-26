package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

// socks5Server handles SOCKS5 CONNECT requests and forwards them through an outbound.
type socks5Server struct {
	outbound adapterOutbound
}

// ListenSOCKS5 creates a SOCKS5 proxy server that forwards connections
// through the proxy outbound. The returned listener handles the SOCKS5
// protocol handshake automatically — callers only need to Accept() to
// get ready-to-use proxied connections.
//
// Unlike Listen() which transparently forwards to a fixed target,
// ListenSOCKS5() reads the target address from the SOCKS5 CONNECT request
// and dials that address through the outbound.
func (a *adapter) ListenSOCKS5(ctx context.Context, network, addr string) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: socks5 listen %s: %w", addr, err)
	}

	a.listeners = append(a.listeners, ln)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return &socks5Listener{
		Listener: ln,
		server:   &socks5Server{outbound: a.outbound},
	}, nil
}

type socks5Listener struct {
	net.Listener
	server *socks5Server
}

func (l *socks5Listener) Accept() (net.Conn, error) {
	client, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}

	// Handle SOCKS5 handshake.
	conn, err := l.server.handshake(client)
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("proxy: socks5 handshake: %w", err)
	}
	return conn, nil
}

func (s *socks5Server) handshake(client net.Conn) (net.Conn, error) {
	buf := make([]byte, 263)

	// 1. Read auth methods: [ver=5, nmethods, methods...]
	n, err := client.Read(buf)
	if err != nil || n < 3 || buf[0] != 0x05 {
		return nil, fmt.Errorf("invalid auth request")
	}
	// Reply: no auth required.
	if _, err := client.Write([]byte{0x05, 0x00}); err != nil {
		return nil, err
	}

	// 2. Read request: [ver=5, cmd, rsv, atyp, dst...]
	n, err = client.Read(buf)
	if err != nil || n < 10 || buf[0] != 0x05 {
		return nil, fmt.Errorf("invalid connect request")
	}
	if buf[1] != 0x01 { // CONNECT only
		client.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("unsupported command: %d", buf[1])
	}

	// Parse destination address.
	dstAddr, err := parseSOCKS5Addr(buf[3:n])
	if err != nil {
		client.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, err
	}

	// Dial target through the outbound.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target, err := s.outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(dstAddr))
	if err != nil {
		client.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return nil, fmt.Errorf("dial %s: %w", dstAddr, err)
	}

	// Reply with success (bind addr = zeros).
	if _, err := client.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		target.Close()
		return nil, err
	}

	// Bidirectional copy between client and target.
	go func() {
		defer target.Close()
		io.Copy(target, client)
	}()
	go func() {
		defer client.Close()
		io.Copy(client, target)
	}()

	return client, nil
}

func parseSOCKS5Addr(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("address too short")
	}
	switch data[0] { // ATYP
	case 0x01: // IPv4
		if len(data) < 7 {
			return "", fmt.Errorf("IPv4 address too short")
		}
		host := net.IP(data[1:5]).String()
		port := int(data[5])<<8 | int(data[6])
		return net.JoinHostPort(host, fmt.Sprint(port)), nil
	case 0x03: // Domain
		if len(data) < 2 {
			return "", fmt.Errorf("domain address too short")
		}
		domainLen := int(data[1])
		if len(data) < 2+domainLen+2 {
			return "", fmt.Errorf("domain address truncated")
		}
		host := string(data[2 : 2+domainLen])
		port := int(data[2+domainLen])<<8 | int(data[3+domainLen])
		return net.JoinHostPort(host, fmt.Sprint(port)), nil
	case 0x04: // IPv6
		if len(data) < 19 {
			return "", fmt.Errorf("IPv6 address too short")
		}
		host := net.IP(data[1:17]).String()
		port := int(data[17])<<8 | int(data[18])
		return net.JoinHostPort(host, fmt.Sprint(port)), nil
	default:
		return "", fmt.Errorf("unsupported address type: %d", data[0])
	}
}
