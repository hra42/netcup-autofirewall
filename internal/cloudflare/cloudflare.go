// Package cloudflare fetches Cloudflare's published edge IP ranges, used to allow
// inbound HTTPS traffic from Cloudflare's proxy network.
package cloudflare

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

const (
	ipsV4URL = "https://www.cloudflare.com/ips-v4"
	ipsV6URL = "https://www.cloudflare.com/ips-v6"
)

// Ranges holds Cloudflare's edge CIDR ranges, separated by address family.
type Ranges struct {
	V4 []string
	V6 []string
}

var client = &http.Client{Timeout: 10 * time.Second}

// FetchRanges downloads and parses Cloudflare's IPv4 and IPv6 range lists.
func FetchRanges(ctx context.Context) (*Ranges, error) {
	v4, err := fetchList(ctx, ipsV4URL)
	if err != nil {
		return nil, fmt.Errorf("fetching Cloudflare IPv4 ranges: %w", err)
	}
	v6, err := fetchList(ctx, ipsV6URL)
	if err != nil {
		return nil, fmt.Errorf("fetching Cloudflare IPv6 ranges: %w", err)
	}
	if len(v4) == 0 && len(v6) == 0 {
		return nil, fmt.Errorf("Cloudflare returned no IP ranges")
	}
	return &Ranges{V4: v4, V6: v6}, nil
}

// fetchList downloads a newline-separated CIDR list, validating each entry.
func fetchList(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: unexpected status %s", url, resp.Status)
	}

	var cidrs []string
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 64*1024))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if _, _, err := net.ParseCIDR(line); err != nil {
			return nil, fmt.Errorf("%s: invalid CIDR %q: %w", url, line, err)
		}
		cidrs = append(cidrs, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading %s: %w", url, err)
	}
	return cidrs, nil
}
