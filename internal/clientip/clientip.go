// Package clientip extracts the originating client IP from an HTTP request,
// accounting for reverse proxies such as Cloudflare.
package clientip

import (
	"net"
	"net/http"
	"strings"
)

// Family selects which address family the caller wants extracted.
type Family int

const (
	Any Family = iota // best available, any family
	V4                // IPv4 only
	V6                // IPv6 only
)

// FromRequest returns the originating client IP for r, restricted to want.
//
// It reads Cloudflare's headers, which matter here because when "Pseudo IPv4" is
// active (an IPv6 client reaching an IPv4-only origin) Cloudflare rewrites
// CF-Connecting-IP to a synthetic 240.0.0.0/4 address while preserving the real
// IPv6 in CF-Connecting-IPv6. So for want==V6 we read CF-Connecting-IPv6, and for
// want==V4/Any we read CF-Connecting-IP, then fall back to X-Forwarded-For and
// RemoteAddr. Candidates not matching want are skipped. Returns "" if none match.
//
// Header values are only meaningful behind a trusted proxy that sets them; when
// exposed directly they are attacker-controlled. Since this endpoint only reports
// the caller their own IP, a forged header merely makes the caller lie to
// themselves, so no trust boundary is crossed here.
func FromRequest(r *http.Request, want Family) string {
	var candidates []string

	if want == V6 {
		// Prefer the header that carries the real IPv6 under Pseudo IPv4.
		candidates = append(candidates,
			r.Header.Get("CF-Connecting-IPv6"),
			r.Header.Get("CF-Connecting-IP"),
		)
	} else {
		candidates = append(candidates, r.Header.Get("CF-Connecting-IP"))
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		candidates = append(candidates, strings.TrimSpace(strings.Split(xff, ",")[0]))
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		candidates = append(candidates, host)
	} else {
		candidates = append(candidates, r.RemoteAddr)
	}

	for _, c := range candidates {
		ip := parse(c)
		if ip == "" || !matchesFamily(ip, want) {
			continue
		}
		return ip
	}
	return ""
}

// FamilyFromString maps a request-supplied value ("4"/"6"/"") to a Family.
func FamilyFromString(s string) Family {
	switch s {
	case "4":
		return V4
	case "6":
		return V6
	default:
		return Any
	}
}

func matchesFamily(ipStr string, want Family) bool {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	isV4 := ip.To4() != nil
	switch want {
	case V4:
		return isV4
	case V6:
		return !isV4
	default:
		return true
	}
}

// parse validates s as an IP and returns its canonical string form, or "".
func parse(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return ""
	}
	return ip.String()
}
