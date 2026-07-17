package pubip

import (
	"net"
	"testing"
)

func TestIsRoutablePublic(t *testing.T) {
	cases := []struct {
		ip   string
		want bool
	}{
		{"203.0.113.10", true}, // public IPv4 (RFC 5737 doc range)
		{"2001:db8::1", true},  // public IPv6 (RFC 3849 doc range)
		{"240.0.0.1", false},   // reserved 240/4 (e.g. Cloudflare pseudo-IPv4)
		{"100.64.0.1", false},  // CGNAT shared space
		{"10.0.0.1", false},    // private
		{"192.168.1.1", false}, // private
		{"127.0.0.1", false},   // loopback
		{"169.254.1.1", false}, // link-local
		{"fd00::1", false},     // unique local (private v6)
		{"fe80::1", false},     // link-local v6
	}
	for _, c := range cases {
		ip := net.ParseIP(c.ip)
		if ip == nil {
			t.Fatalf("bad test IP %q", c.ip)
		}
		if got := isRoutablePublic(ip); got != c.want {
			t.Errorf("isRoutablePublic(%s) = %v, want %v", c.ip, got, c.want)
		}
	}
}
