package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"time"

	"github.com/qsilasu/xproxy/node"
	singbox "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
)

type adapter struct {
	info      Info
	start     Statistics
	outbound  adapterOutbound
	listeners []net.Listener
	closeFn   func() error

	upload   atomic.Int64
	download atomic.Int64
}

type adapterOutbound interface {
	DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error)
	ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error)
}

func newAdapter(n node.Node) (Proxy, error) {
	if n.Address == "" {
		return nil, fmt.Errorf("proxy: node address is required")
	}
	if n.Port <= 0 || n.Port > 65535 {
		return nil, fmt.Errorf("proxy: node port %d is out of range", n.Port)
	}

	outOpt, err := nodeToOutbound(n)
	if err != nil {
		return nil, fmt.Errorf("proxy: %w", err)
	}

	ctx := include.Context(context.Background())

	b, err := singbox.New(singbox.Options{
		Context: ctx,
		Options: option.Options{
			Outbounds: []option.Outbound{outOpt},
			Route:     &option.RouteOptions{},
			DNS:       &option.DNSOptions{},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("proxy: create box: %w", err)
	}

	if err := b.PreStart(); err != nil {
		b.Close()
		return nil, fmt.Errorf("proxy: prestart: %w", err)
	}

	out := b.Outbound().Default()

	now := time.Now()
	a := &adapter{
		info: Info{
			Name:     n.Name,
			Protocol: n.Protocol,
			Address:  n.Address,
			Port:     n.Port,
		},
		start:    Statistics{StartedAt: now},
		outbound: out,
		closeFn:  b.Close,
	}

	return a, nil
}

func (a *adapter) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	conn, err := a.outbound.DialContext(ctx, network, M.ParseSocksaddr(addr))
	if err != nil {
		return nil, err
	}
	return &statsConn{Conn: conn, a: a}, nil
}

func (a *adapter) Listen(ctx context.Context, network, addr string) (net.Listener, error) {
	ln, err := net.Listen(network, addr)
	if err != nil {
		return nil, fmt.Errorf("proxy: listen %s: %w", addr, err)
	}

	a.listeners = append(a.listeners, ln)

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return &proxyListener{
		Listener: ln,
		outbound: a.outbound,
		target:   net.JoinHostPort(a.info.Address, fmt.Sprint(a.info.Port)),
	}, nil
}

// proxyListener transparently forwards accepted connections through the proxy outbound.
type proxyListener struct {
	net.Listener
	outbound adapterOutbound
	target   string
}

func (l *proxyListener) Accept() (net.Conn, error) {
	client, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	target, err := l.outbound.DialContext(ctx, "tcp", M.ParseSocksaddr(l.target))
	if err != nil {
		client.Close()
		return nil, fmt.Errorf("proxy: forward dial %s: %w", l.target, err)
	}

	// Bidirectional copy: client↔target.
	// When one side closes, the other side gets closed via defer.
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

func (a *adapter) Info() Info {
	return a.info
}

func (a *adapter) Statistics() Statistics {
	return Statistics{
		UploadBytes:   a.upload.Load(),
		DownloadBytes: a.download.Load(),
		StartedAt:     a.start.StartedAt,
	}
}

func (a *adapter) Close() error {
	for _, ln := range a.listeners {
		ln.Close()
	}
	if a.closeFn != nil {
		fn := a.closeFn
		a.closeFn = nil
		return fn()
	}
	return nil
}

// nodeToOutbound converts a node.Node to a sing-box option.Outbound.
func nodeToOutbound(n node.Node) (option.Outbound, error) {
	base := option.Outbound{
		Tag: n.Name,
	}

	switch n.Protocol {
	case node.ProtoSS:
		base.Type = "shadowsocks"
		base.Options = buildSSOptions(n)
	case node.ProtoVMess:
		base.Type = "vmess"
		base.Options = buildVMessOptions(n)
	case node.ProtoVLESS:
		base.Type = "vless"
		base.Options = buildVLESSOptions(n)
	case node.ProtoTrojan:
		base.Type = "trojan"
		base.Options = buildTrojanOptions(n)
	case node.ProtoHysteria2:
		base.Type = "hysteria2"
		base.Options = buildHysteria2Options(n)
	case node.ProtoSOCKS5:
		base.Type = "socks"
		base.Options = buildSOCKS5Options(n)
	case node.ProtoHTTP:
		base.Type = "http"
		base.Options = buildHTTPOptions(n)
	case node.ProtoHTTPS:
		base.Type = "http"
		base.Options = buildHTTPSOptions(n)
	case node.ProtoTUIC:
		base.Type = "tuic"
		base.Options = buildTUICOptions(n)
	case node.ProtoSSH:
		base.Type = "ssh"
		base.Options = buildSSHOptions(n)
	case node.ProtoShadowTLS:
		base.Type = "shadowtls"
		base.Options = buildShadowTLSOptions(n)
	case node.ProtoAnyTLS:
		base.Type = "anytls"
		base.Options = buildAnyTLSOptions(n)
	case node.ProtoDirect:
		base.Type = "direct"
		base.Options = &option.DirectOutboundOptions{}
	default:
		return option.Outbound{}, fmt.Errorf("unsupported protocol: %q", n.Protocol)
	}

	return base, nil
}

func buildSSOptions(n node.Node) *option.ShadowsocksOutboundOptions {
	o := &option.ShadowsocksOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.Shadowsocks != nil {
		o.Method = n.Shadowsocks.Method
		o.Password = n.Shadowsocks.Password
	}
	if n.Extras != nil {
		if plugin, ok := n.Extras["plugin"]; ok {
			o.Plugin = plugin
			o.PluginOptions = n.Extras["plugin_opts"]
		}
	}
	return o
}

func buildVMessOptions(n node.Node) *option.VMessOutboundOptions {
	o := &option.VMessOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.VMess != nil {
		o.UUID = n.VMess.UUID
		o.AlterId = n.VMess.AlterID
		o.Security = n.VMess.Security
	}
	if n.TLS != nil && n.TLS.Enable && n.Transport == nil {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	if n.Transport != nil {
		o.Transport = buildTransportOptions(n)
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildVLESSOptions(n node.Node) *option.VLESSOutboundOptions {
	o := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.VLESS != nil {
		o.UUID = n.VLESS.UUID
		o.Flow = n.VLESS.Flow
	}
	if n.Transport != nil {
		o.Transport = buildTransportOptions(n)
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildTrojanOptions(n node.Node) *option.TrojanOutboundOptions {
	o := &option.TrojanOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.Trojan != nil {
		o.Password = n.Trojan.Password
	}
	if n.Transport != nil {
		o.Transport = buildTransportOptions(n)
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildHysteria2Options(n node.Node) *option.Hysteria2OutboundOptions {
	o := &option.Hysteria2OutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.Hysteria2 != nil {
		o.Password = n.Hysteria2.Password
		o.UpMbps = n.Hysteria2.UpMbps
		o.DownMbps = n.Hysteria2.DownMbps
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildSOCKS5Options(n node.Node) *option.SOCKSOutboundOptions {
	return &option.SOCKSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
		Version: "5",
	}
}

func buildHTTPOptions(n node.Node) *option.HTTPOutboundOptions {
	return &option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
}

func buildHTTPSOptions(n node.Node) *option.HTTPOutboundOptions {
	o := &option.HTTPOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildTLSOptions(n node.Node) *option.OutboundTLSOptions {
	if n.TLS == nil {
		return nil
	}
	return &option.OutboundTLSOptions{
		Enabled:    n.TLS.Enable,
		ServerName: n.TLS.ServerName,
		Insecure:   n.TLS.Insecure,
	}
}

func buildTUICOptions(n node.Node) *option.TUICOutboundOptions {
	o := &option.TUICOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.TUIC != nil {
		o.UUID = n.TUIC.UUID
		o.Password = n.TUIC.Password
		o.CongestionControl = n.TUIC.CongestionControl
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildSSHOptions(n node.Node) *option.SSHOutboundOptions {
	o := &option.SSHOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.Extras != nil {
		if user, ok := n.Extras["user"]; ok {
			o.User = user
		}
		if password, ok := n.Extras["password"]; ok {
			o.Password = password
		}
	}
	return o
}

func buildShadowTLSOptions(n node.Node) *option.ShadowTLSOutboundOptions {
	o := &option.ShadowTLSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	return o
}

func buildAnyTLSOptions(n node.Node) *option.AnyTLSOutboundOptions {
	o := &option.AnyTLSOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     n.Address,
			ServerPort: uint16(n.Port),
		},
	}
	if n.TLS != nil && n.TLS.Enable {
		o.OutboundTLSOptionsContainer = option.OutboundTLSOptionsContainer{
			TLS: buildTLSOptions(n),
		}
	}
	if n.Extras != nil {
		if pass, ok := n.Extras["password"]; ok {
			o.Password = pass
		}
	}
	return o
}

func buildTransportOptions(n node.Node) *option.V2RayTransportOptions {
	if n.Transport == nil {
		return nil
	}
	t := &option.V2RayTransportOptions{}
	switch n.Transport.Type {
	case node.TransportWS:
		t.Type = "ws"
		t.WebsocketOptions = option.V2RayWebsocketOptions{
			Path: n.Transport.Path,
		}
		if n.Transport.Host != "" {
			t.WebsocketOptions.Headers = badoption.HTTPHeader{
				"Host": {n.Transport.Host},
			}
		}
	case node.TransportGRPC:
		t.Type = "grpc"
		t.GRPCOptions = option.V2RayGRPCOptions{
			ServiceName: n.Transport.Path,
		}
	case node.TransportHTTP2:
		t.Type = "http"
		t.HTTPOptions = option.V2RayHTTPOptions{
			Path: n.Transport.Path,
		}
		if n.Transport.Host != "" {
			t.HTTPOptions.Host = badoption.Listable[string]{n.Transport.Host}
		}
	}
	return t
}

// statsConn wraps net.Conn to count bytes transferred.
type statsConn struct {
	net.Conn
	a *adapter
}

func (c *statsConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	c.a.download.Add(int64(n))
	return n, err
}

func (c *statsConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	c.a.upload.Add(int64(n))
	return n, err
}
