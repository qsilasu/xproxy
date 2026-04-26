package sub

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/qsilasu/xproxy/node"
)

var httpClient = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		ResponseHeaderTimeout: 15 * time.Second,
	},
}

// SetHTTPClient replaces the HTTP client used by ParseURL.
func SetHTTPClient(c *http.Client) { httpClient = c }

// Format identifies a subscription format.
type Format string

const (
	FmtClash   Format = "clash"
	FmtSurge   Format = "surge"
	FmtSingBox Format = "singbox"
	FmtSS      Format = "ss"
	FmtBase64  Format = "base64"
	FmtRaw     Format = "raw"
)

// Parse parses subscription content of the given format.
func Parse(input []byte, format Format) (*node.Subscription, error) {
	switch format {
	case FmtClash:
		return parseClash(input)
	case FmtSurge:
		return parseSurge(input)
	case FmtSingBox:
		return parseSingBox(input)
	case FmtSS:
		return parseSSList(input)
	case FmtBase64:
		return parseBase64(input)
	case FmtRaw:
		return parseRaw(input)
	default:
		return nil, fmt.Errorf("sub: unsupported format: %q", format)
	}
}

// Generate converts a Subscription to the target format.
func Generate(sub *node.Subscription, format Format) ([]byte, error) {
	switch format {
	case FmtClash:
		return generateClash(sub)
	case FmtSurge:
		return generateSurge(sub)
	case FmtSingBox:
		return generateSingBox(sub)
	case FmtSS:
		return generateSSList(sub)
	case FmtBase64:
		return generateBase64(sub)
	case FmtRaw:
		return generateRaw(sub)
	default:
		return nil, fmt.Errorf("sub: unsupported format: %q", format)
	}
}

// ParseURL fetches and parses a subscription from a remote URL.
// It auto-detects the format from the response body.
func ParseURL(ctx context.Context, url string) (*node.Subscription, error) {
	return ParseURLWithClient(ctx, url, httpClient)
}

// ParseURLWithClient fetches and parses a subscription using a custom HTTP client.
// This allows fetching through a proxy by setting the client's transport.
//
// Example:
//
//	p, _ := proxy.New(socks5Node)
//	client := &http.Client{
//	    Transport: &http.Transport{DialContext: p.DialContext},
//	}
//	sub, _ := sub.ParseURLWithClient(ctx, "https://example.com/sub", client)
func ParseURLWithClient(ctx context.Context, url string, client *http.Client) (*node.Subscription, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("sub: %w", err)
	}

	req.Header.Set("User-Agent", "XProxy/1.0")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sub: fetch %q: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sub: read response: %w", err)
	}

	// Decompress gzip if needed.
	if len(body) >= 2 && body[0] == 0x1f && body[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err == nil {
			decompressed, err := io.ReadAll(gr)
			gr.Close()
			if err == nil {
				body = decompressed
			}
		}
	}

	detectedFormat := Detect(body)
	sub, err := Parse(body, detectedFormat)
	if err != nil {
		return nil, fmt.Errorf("sub: parse as %s: %w", detectedFormat, err)
	}
	sub.SourceURL = url
	return sub, nil
}

// Convert fetches a subscription from a URL and converts it to the target format.
// Shortcut for ParseURL + Generate.
func Convert(ctx context.Context, url string, target Format) ([]byte, error) {
	sub, err := ParseURL(ctx, url)
	if err != nil {
		return nil, err
	}
	return Generate(sub, target)
}

// ConvertWithClient fetches a subscription through a custom HTTP client
// and converts it to the target format.
func ConvertWithClient(ctx context.Context, url string, client *http.Client, target Format) ([]byte, error) {
	sub, err := ParseURLWithClient(ctx, url, client)
	if err != nil {
		return nil, err
	}
	return Generate(sub, target)
}
