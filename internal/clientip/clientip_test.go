package clientip

import (
	"net/http"
	"testing"
)

func req(headers map[string]string, remote string) *http.Request {
	r := &http.Request{Header: http.Header{}, RemoteAddr: remote}
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

func TestFromRequest_PseudoIPv4(t *testing.T) {
	// Cloudflare Pseudo IPv4 active: CF-Connecting-IP is a synthetic 240/4
	// address, real IPv6 is in CF-Connecting-IPv6.
	h := map[string]string{
		"CF-Connecting-IP":   "240.0.0.1",
		"CF-Connecting-IPv6": "2001:db8::1",
	}
	r := req(h, "10.0.0.1:1234") // RemoteAddr is Traefik, unreliable

	if got := FromRequest(r, V6); got != "2001:db8::1" {
		t.Errorf("V6 = %q, want real IPv6 from CF-Connecting-IPv6", got)
	}
	// V4 request still gets the (pseudo) v4 from CF-Connecting-IP; the pubip
	// layer separately rejects 240/4, so this just confirms family selection.
	if got := FromRequest(r, V4); got != "240.0.0.1" {
		t.Errorf("V4 = %q, want CF-Connecting-IP", got)
	}
}

func TestFromRequest_NormalV4(t *testing.T) {
	r := req(map[string]string{"CF-Connecting-IP": "203.0.113.10"}, "10.0.0.1:1")
	if got := FromRequest(r, V4); got != "203.0.113.10" {
		t.Errorf("V4 = %q", got)
	}
	// No v6 available anywhere -> empty for V6.
	if got := FromRequest(r, V6); got != "" {
		t.Errorf("V6 = %q, want empty", got)
	}
}

func TestFromRequest_DirectNoProxy(t *testing.T) {
	// No CF headers: fall back to RemoteAddr.
	r := req(nil, "203.0.113.7:5555")
	if got := FromRequest(r, Any); got != "203.0.113.7" {
		t.Errorf("Any = %q, want RemoteAddr host", got)
	}
}

func TestFamilyFromString(t *testing.T) {
	if FamilyFromString("4") != V4 || FamilyFromString("6") != V6 || FamilyFromString("") != Any {
		t.Fatal("FamilyFromString mapping wrong")
	}
}
