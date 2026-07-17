// Command echo-server is a tiny HTTP service that returns the caller's public IP
// as plain text. Run it on a machine reachable by the netcup-autofirewall CLI
// (e.g. behind Cloudflare on 443) to detect your public IP without contacting
// any third-party service.
//
// It reports the originating client IP from CF-Connecting-IP / X-Forwarded-For /
// RemoteAddr (in that order), so it works behind Cloudflare and when exposed
// directly. Access is gated by User-Agent: only requests carrying the expected
// User-Agent are served; everything else gets 403, keeping casual scanners out.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/hra42/netcup-autofirewall/internal/clientip"
	"github.com/hra42/netcup-autofirewall/internal/pubip"
)

func main() {
	addr := flag.String("addr", envOr("ECHO_ADDR", ":8080"), "listen address (host:port)")
	userAgent := flag.String("user-agent", envOr("ECHO_USER_AGENT", pubip.DefaultUserAgent),
		"only serve requests carrying this exact User-Agent")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/", handler(*userAgent))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	log.Printf("echo-server listening on %s (gating User-Agent %q)", *addr, *userAgent)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("echo-server: %v", err)
	}
}

// handler returns the caller's IP as plain text, but only for requests whose
// User-Agent matches wantUA.
func handler(wantUA string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("User-Agent") != wantUA {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		// The client may request a specific family via ?family=4 or ?family=6;
		// this lets it get the real IPv6 even when Cloudflare's Pseudo IPv4 has
		// rewritten CF-Connecting-IP.
		want := clientip.FamilyFromString(r.URL.Query().Get("family"))
		ip := clientip.FromRequest(r, want)
		if ip == "" {
			http.Error(w, "could not determine client IP", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		fmt.Fprintln(w, ip)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
