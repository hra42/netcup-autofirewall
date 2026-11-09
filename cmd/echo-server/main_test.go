package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandlerChecksAgentAndPreservesCloudflareIP(t *testing.T) {
	h := handler("expected-agent")
	for _, tc := range []struct {
		name, agent, ip string
		status          int
		body            string
	}{
		{"wrong agent", "other", "203.0.113.9", http.StatusForbidden, "forbidden\n"},
		{"cloudflare IP", "expected-agent", "203.0.113.9", http.StatusOK, "203.0.113.9\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.Header.Set("User-Agent", tc.agent)
			req.Header.Set("CF-Connecting-IP", tc.ip)
			res := httptest.NewRecorder()
			h.ServeHTTP(res, req)
			if res.Code != tc.status || res.Body.String() != tc.body {
				t.Fatalf("got status %d and body %q", res.Code, res.Body.String())
			}
		})
	}
}
