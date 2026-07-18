package pubip

import (
	"context"
	"errors"
	"net"
	"testing"
)

// stubResolver returns a lookupIP func serving the given addresses per network
// ("ip4"/"ip6"). A network absent from the map yields a not-found DNSError,
// mimicking a hostname with no record of that family.
func stubResolver(byNetwork map[string][]string) func(context.Context, string, string) ([]net.IP, error) {
	return func(_ context.Context, network, host string) ([]net.IP, error) {
		raw, ok := byNetwork[network]
		if !ok {
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		}
		var ips []net.IP
		for _, s := range raw {
			ips = append(ips, net.ParseIP(s))
		}
		return ips, nil
	}
}

func TestDNSSourceLookup(t *testing.T) {
	tests := []struct {
		name    string
		records map[string][]string
		family  Family
		want    string
		wantErr bool
	}{
		{
			name:    "A record only, v4 requested",
			records: map[string][]string{"ip4": {"203.0.113.7"}},
			family:  FamilyV4,
			want:    "203.0.113.7",
		},
		{
			name:    "A record only, v6 requested yields nothing",
			records: map[string][]string{"ip4": {"203.0.113.7"}},
			family:  FamilyV6,
			want:    "",
		},
		{
			name:    "AAAA record only, v6 requested",
			records: map[string][]string{"ip6": {"2001:db8::1"}},
			family:  FamilyV6,
			want:    "2001:db8::1",
		},
		{
			name:    "both families present",
			records: map[string][]string{"ip4": {"203.0.113.7"}, "ip6": {"2001:db8::1"}},
			family:  FamilyV4,
			want:    "203.0.113.7",
		},
		{
			name:    "no records at all",
			records: map[string][]string{},
			family:  FamilyV4,
			want:    "",
		},
		{
			// A router that registered its LAN side must not become a rule.
			name:    "private address is skipped",
			records: map[string][]string{"ip4": {"192.168.1.1"}},
			family:  FamilyV4,
			want:    "",
		},
		{
			name:    "first public address wins over a private one",
			records: map[string][]string{"ip4": {"10.0.0.1", "203.0.113.7"}},
			family:  FamilyV4,
			want:    "203.0.113.7",
		},
		{
			name:    "CGNAT address is skipped",
			records: map[string][]string{"ip4": {"100.64.0.1"}},
			family:  FamilyV4,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := DNSSource{Hostname: "home.example.org", lookupIP: stubResolver(tt.records)}
			got, err := src.Lookup(context.Background(), tt.family)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("Lookup = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDNSSourceLookupPropagatesRealErrors(t *testing.T) {
	boom := errors.New("server misbehaving")
	src := DNSSource{
		Hostname: "home.example.org",
		lookupIP: func(context.Context, string, string) ([]net.IP, error) { return nil, boom },
	}
	if _, err := src.Lookup(context.Background(), FamilyV4); !errors.Is(err, boom) {
		t.Fatalf("error = %v, want it to wrap %v", err, boom)
	}
}

func TestDNSSourceLookupNoHostname(t *testing.T) {
	if _, err := (DNSSource{}).Lookup(context.Background(), FamilyV4); err == nil {
		t.Fatal("expected an error when no hostname is configured")
	}
}

func TestResolve(t *testing.T) {
	const v4, v6 = "203.0.113.7", "2001:db8::1"

	tests := []struct {
		name           string
		records        map[string][]string
		mode           Mode
		wantV4, wantV6 string
		wantErr        bool
	}{
		// Dual: v4 required, v6 best-effort.
		{name: "dual/both", records: map[string][]string{"ip4": {v4}, "ip6": {v6}}, mode: ModeDual, wantV4: v4, wantV6: v6},
		{name: "dual/v4 only", records: map[string][]string{"ip4": {v4}}, mode: ModeDual, wantV4: v4},
		{name: "dual/v6 only errors", records: map[string][]string{"ip6": {v6}}, mode: ModeDual, wantErr: true},
		{name: "dual/neither errors", records: map[string][]string{}, mode: ModeDual, wantErr: true},

		// V4Only: v6 never looked up.
		{name: "v4only/both ignores v6", records: map[string][]string{"ip4": {v4}, "ip6": {v6}}, mode: ModeV4Only, wantV4: v4},
		{name: "v4only/v4 only", records: map[string][]string{"ip4": {v4}}, mode: ModeV4Only, wantV4: v4},
		{name: "v4only/v6 only errors", records: map[string][]string{"ip6": {v6}}, mode: ModeV4Only, wantErr: true},

		// V6Only: the DS-Lite case; v4 never looked up.
		{name: "v6only/both ignores v4", records: map[string][]string{"ip4": {v4}, "ip6": {v6}}, mode: ModeV6Only, wantV6: v6},
		{name: "v6only/v6 only", records: map[string][]string{"ip6": {v6}}, mode: ModeV6Only, wantV6: v6},
		{name: "v6only/v4 only errors", records: map[string][]string{"ip4": {v4}}, mode: ModeV6Only, wantErr: true},

		// Auto: succeeds if either family resolves.
		{name: "auto/both", records: map[string][]string{"ip4": {v4}, "ip6": {v6}}, mode: ModeAuto, wantV4: v4, wantV6: v6},
		{name: "auto/v4 only", records: map[string][]string{"ip4": {v4}}, mode: ModeAuto, wantV4: v4},
		{name: "auto/v6 only", records: map[string][]string{"ip6": {v6}}, mode: ModeAuto, wantV6: v6},
		{name: "auto/neither errors", records: map[string][]string{}, mode: ModeAuto, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := DNSSource{Hostname: "home.example.org", lookupIP: stubResolver(tt.records)}
			res, err := Resolve(context.Background(), src, tt.mode)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.V4 != tt.wantV4 {
				t.Errorf("V4 = %q, want %q", res.V4, tt.wantV4)
			}
			if res.V6 != tt.wantV6 {
				t.Errorf("V6 = %q, want %q", res.V6, tt.wantV6)
			}
		})
	}
}

// A mode must not pay the latency of looking up a family it does not want.
func TestResolveSkipsUnwantedFamilies(t *testing.T) {
	tests := []struct {
		mode    Mode
		skipped string
	}{
		{ModeV4Only, "ip6"},
		{ModeV6Only, "ip4"},
	}

	for _, tt := range tests {
		t.Run(tt.mode.String(), func(t *testing.T) {
			var queried []string
			src := DNSSource{
				Hostname: "home.example.org",
				lookupIP: func(_ context.Context, network, _ string) ([]net.IP, error) {
					queried = append(queried, network)
					return []net.IP{net.ParseIP("203.0.113.7"), net.ParseIP("2001:db8::1")}, nil
				},
			}
			if _, err := Resolve(context.Background(), src, tt.mode); err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for _, q := range queried {
				if q == tt.skipped {
					t.Errorf("mode %s queried %s, want it skipped", tt.mode, tt.skipped)
				}
			}
		})
	}
}

func TestParseMode(t *testing.T) {
	tests := []struct {
		in      string
		want    Mode
		wantErr bool
	}{
		{in: "", want: ModeDual},
		{in: "dual", want: ModeDual},
		{in: "DUAL", want: ModeDual},
		{in: " auto ", want: ModeAuto},
		{in: "v4only", want: ModeV4Only},
		{in: "v4", want: ModeV4Only},
		{in: "v6only", want: ModeV6Only},
		{in: "v6", want: ModeV6Only},
		{in: "nonsense", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := ParseMode(tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %q", tt.in)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseMode(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
