package sub

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
)

// Detect tries to identify the subscription format from content.
// It samples the first few lines and checks for format-specific markers.
func Detect(input []byte) Format {
	if len(input) == 0 {
		return FmtRaw
	}

	trimmed := bytes.TrimSpace(input)

	// Check for Base64 encoding first: valid base64 of substantial length
	if isBase64(trimmed) {
		decoded, err := base64.RawURLEncoding.DecodeString(string(trimmed))
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(string(trimmed))
		}
		if err == nil && len(decoded) > 0 {
			// Recursively detect the decoded content
			return Detect(decoded)
		}
	}

	// Check for sing-box JSON: has "outbounds" or "inbounds" as JSON keys
	if bytes.Contains(trimmed, []byte(`"outbounds"`)) ||
		bytes.Contains(trimmed, []byte(`"inbounds"`)) {
		if json.Valid(trimmed) {
			return FmtSingBox
		}
	}

	// Check for Clash YAML: contains "proxies:" as a top-level key
	firstLines := firstLines(trimmed, 5)
	if strings.Contains(firstLines, "\nproxies:") ||
		strings.HasPrefix(firstLines, "proxies:") {
		return FmtClash
	}
	// Also check YAML-style proxy list
	if strings.Contains(firstLines, "type: ss") ||
		strings.Contains(firstLines, "type: vmess") ||
		strings.Contains(firstLines, "type: trojan") {
		return FmtClash
	}

	// Check for Surge conf: contains [Proxy] section header
	if strings.Contains(firstLines, "[Proxy]") {
		return FmtSurge
	}

	// Check if it's all/primarily ss:// URLs
	if isSSList(trimmed) {
		return FmtSS
	}

	// Default: treat as raw proxy URL list
	return FmtRaw
}

func isBase64(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	// Base64 chars: A-Za-z0-9+/= and URL-safe variants
	for _, b := range data {
		if b >= 'A' && b <= 'Z' {
			continue
		}
		if b >= 'a' && b <= 'z' {
			continue
		}
		if b >= '0' && b <= '9' {
			continue
		}
		if b == '+' || b == '/' || b == '-' || b == '_' || b == '=' {
			continue
		}
		// Non-base64 character found; allow whitespace
		if b == '\n' || b == '\r' || b == ' ' || b == '\t' {
			continue
		}
		return false
	}
	return true
}

func firstLines(data []byte, n int) string {
	lines := strings.SplitN(string(data), "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}

func isSSList(data []byte) bool {
	s := string(bytes.TrimSpace(data))
	lines := strings.Split(s, "\n")
	ssCount := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "ss://") {
			ssCount++
		} else if strings.HasPrefix(line, "vmess://") ||
			strings.HasPrefix(line, "trojan://") ||
			strings.HasPrefix(line, "vless://") {
			// Mixed protocols, not pure SS list
			return false
		}
	}
	return ssCount > 0
}
