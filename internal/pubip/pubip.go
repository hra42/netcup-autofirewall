// Package pubip detects the machine's public IPv4 and IPv6 addresses by querying
// a self-hosted echo endpoint (see cmd/echo-server), forcing the respective
// address family per request. No third-party service is contacted.
package pubip

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultUserAgent is sent on echo requests. The echo server only serves
// requests carrying this User-Agent, so casual scanners hitting the public
// endpoint are turned away. It is not a secret (it ships in the source); use a
// custom User-Agent on both sides for stronger gating.
const DefaultUserAgent = "netcup-autofirewall/echo-client"

const requestTimeout = 5 * time.Second

// Detect returns the public IPv4 and IPv6 addresses as seen by the echo endpoint
// at echoURL. userAgent is sent with each request (defaults to DefaultUserAgent
// when empty). IPv6 is best-effort: if it cannot be determined, v6 is returned
// empty with no error. An error is returned only when IPv4 detection fails.
//
// This is a convenience wrapper over Resolve with an EchoSource in ModeDual;
// use Resolve directly to select a different source or address-family mode.
func Detect(ctx context.Context, echoURL, userAgent string) (v4, v6 string, err error) {
	res, err := Resolve(ctx, EchoSource{URL: echoURL, UserAgent: userAgent}, ModeDual)
	if err != nil {
		return "", "", err
	}
	return res.V4, res.V6, nil
}

// detectFamily queries echoURL over the given network family ("tcp4" or "tcp6")
// and returns the validated public IP it reports. The reply must be a routable
// global-unicast address of the matching family — this rejects, for example,
// Cloudflare's synthetic pseudo-IPv4 (in the reserved 240.0.0.0/4 range) that it
// substitutes for IPv6-only clients, which would otherwise poison the v6 result.
func detectFamily(ctx context.Context, network, echoURL, userAgent string) (string, error) {
	client := &http.Client{
		Timeout: requestTimeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
				d := net.Dialer{Timeout: requestTimeout}
				return d.DialContext(ctx, network, addr)
			},
		},
	}

	// Ask the echo server for the family we dialed, so it can return the real
	// IPv6 even when Cloudflare's Pseudo IPv4 rewrote CF-Connecting-IP.
	reqURL, err := withFamily(echoURL, network)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/plain")

	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 128))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: unexpected status %s: %s", echoURL, resp.Status, strings.TrimSpace(string(body)))
	}

	raw := strings.TrimSpace(string(body))
	ip := net.ParseIP(raw)
	if ip == nil {
		return "", fmt.Errorf("%s: not an IP: %q", echoURL, raw)
	}
	if !isRoutablePublic(ip) {
		return "", fmt.Errorf("%s: not a routable public address: %s", echoURL, raw)
	}
	// Enforce the family we dialed: a tcp6 request that comes back with an IPv4
	// address (e.g. a proxy's pseudo-IPv4 for a v6-only client) is not a usable
	// IPv6 result and must not be reported as one.
	isV4 := ip.To4() != nil
	if network == "tcp4" && !isV4 {
		return "", fmt.Errorf("%s: expected IPv4 but got %s", echoURL, raw)
	}
	if network == "tcp6" && isV4 {
		return "", fmt.Errorf("%s: expected IPv6 but got IPv4 %s", echoURL, raw)
	}
	return ip.String(), nil
}

// withFamily adds a ?family=4 or ?family=6 query parameter to echoURL based on
// the dialed network ("tcp4" or "tcp6").
func withFamily(echoURL, network string) (string, error) {
	u, err := url.Parse(echoURL)
	if err != nil {
		return "", fmt.Errorf("invalid echo URL %q: %w", echoURL, err)
	}
	q := u.Query()
	switch network {
	case "tcp4":
		q.Set("family", "4")
	case "tcp6":
		q.Set("family", "6")
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// isRoutablePublic reports whether ip is a globally routable public unicast
// address, rejecting private, loopback, link-local, and other reserved ranges
// (including the IPv4 240.0.0.0/4 reserved block used for pseudo-IPv4).
func isRoutablePublic(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 240.0.0.0/4 (reserved, incl. Cloudflare pseudo-IPv4) and
		// 100.64.0.0/10 (CGNAT shared address space) are not public.
		if v4[0] >= 240 {
			return false
		}
		if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
			return false
		}
	}
	return true
}
