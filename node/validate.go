package node

import "fmt"

// ValidateError holds one or more validation failures for a Node.
type ValidateError struct {
	Errors []string
}

func (e *ValidateError) Error() string {
	if len(e.Errors) == 1 {
		return e.Errors[0]
	}
	s := fmt.Sprintf("%d validation errors:", len(e.Errors))
	for _, err := range e.Errors {
		s += "\n  - " + err
	}
	return s
}

// Validate checks that the Node has all required fields for its protocol.
// Returns nil if valid, or a *ValidateError describing all issues.
func (n *Node) Validate() error {
	var errs []string

	if n.Address == "" {
		errs = append(errs, "address is required")
	}
	if n.Port <= 0 || n.Port > 65535 {
		errs = append(errs, fmt.Sprintf("port %d is out of range (1-65535)", n.Port))
	}

	switch n.Protocol {
	case ProtoSS:
		if n.Shadowsocks == nil {
			errs = append(errs, "shadowsocks config is required")
		} else {
			if n.Shadowsocks.Method == "" {
				errs = append(errs, "shadowsocks method is required")
			}
			if n.Shadowsocks.Password == "" {
				errs = append(errs, "shadowsocks password is required")
			}
		}
	case ProtoVMess:
		if n.VMess == nil {
			errs = append(errs, "vmess config is required")
		} else if n.VMess.UUID == "" {
			errs = append(errs, "vmess uuid is required")
		}
	case ProtoVLESS:
		if n.VLESS == nil {
			errs = append(errs, "vless config is required")
		} else if n.VLESS.UUID == "" {
			errs = append(errs, "vless uuid is required")
		}
	case ProtoTrojan:
		if n.Trojan == nil {
			errs = append(errs, "trojan config is required")
		} else if n.Trojan.Password == "" {
			errs = append(errs, "trojan password is required")
		}
	case ProtoHysteria2:
		if n.Hysteria2 == nil {
			errs = append(errs, "hysteria2 config is required")
		} else if n.Hysteria2.Password == "" {
			errs = append(errs, "hysteria2 password is required")
		}
	case ProtoTUIC:
		if n.TUIC == nil {
			errs = append(errs, "tuic config is required")
		} else if n.TUIC.UUID == "" && n.TUIC.Password == "" {
			errs = append(errs, "tuic uuid or password is required")
		}
	case ProtoWireGuard:
		if n.WireGuard == nil {
			errs = append(errs, "wireguard config is required")
		} else if n.WireGuard.PublicKey == "" && n.WireGuard.PrivateKey == "" {
			errs = append(errs, "wireguard public key or private key is required")
		}
	}

	if len(errs) > 0 {
		return &ValidateError{Errors: errs}
	}
	return nil
}
