package config

import (
	"os"
	"path/filepath"
	"testing"
)

// loadFrom writes raw JSON to a temp file and loads it, exercising the same
// defaulting path a real config file takes.
func loadFrom(t *testing.T, raw string) *Config {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("loading config: %v", err)
	}
	return cfg
}

func TestIPSourceDefaulting(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "empty config defaults to echo",
			raw:  `{}`,
			want: IPSourceEcho,
		},
		{
			name: "echo URL only stays echo",
			raw:  `{"echoUrl": "https://echo.example.org"}`,
			want: IPSourceEcho,
		},
		{
			// A user who configured only a DynDNS name means to use it.
			name: "dns hostname alone implies the dns source",
			raw:  `{"dnsHostname": "home.example.org"}`,
			want: IPSourceDNS,
		},
		{
			// Ambiguous: both configured, so fall back to the echo default
			// rather than silently switching an existing setup.
			name: "both configured keeps echo",
			raw:  `{"dnsHostname": "home.example.org", "echoUrl": "https://echo.example.org"}`,
			want: IPSourceEcho,
		},
		{
			name: "explicit source always wins",
			raw:  `{"ipSource": "dns", "echoUrl": "https://echo.example.org", "dnsHostname": "home.example.org"}`,
			want: IPSourceDNS,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := loadFrom(t, tt.raw).IPSource; got != tt.want {
				t.Errorf("IPSource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDefaultsApplied(t *testing.T) {
	cfg := loadFrom(t, `{}`)

	checks := []struct {
		name      string
		got, want string
	}{
		{"PolicyName", cfg.PolicyName, DefaultPolicyName},
		{"CloudflarePolicyName", cfg.CloudflarePolicyName, DefaultCloudflarePolicyName},
		{"WireGuardPolicyName", cfg.WireGuardPolicyName, DefaultWireGuardPolicyName},
		{"OpenVPNPolicyName", cfg.OpenVPNPolicyName, DefaultOpenVPNPolicyName},
		{"SSHPort", cfg.SSHPort, DefaultSSHPort},
		{"WireGuardPort", cfg.WireGuardPort, DefaultWireGuardPort},
		{"OpenVPNPort", cfg.OpenVPNPort, DefaultOpenVPNPort},
		{"OpenVPNProtocol", cfg.OpenVPNProtocol, DefaultOpenVPNProtocol},
		{"Schedule", cfg.Schedule, DefaultSchedule},
		{"IPMode", cfg.IPMode, DefaultIPMode},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %q, want %q", c.name, c.got, c.want)
		}
	}

	// Prefix lengths intentionally stay zero: the firewall package maps zero to
	// its own defaults, so there is a single source of truth for them.
	if cfg.IPv4PrefixLen != 0 || cfg.IPv6PrefixLen != 0 {
		t.Errorf("prefix lengths = %d/%d, want 0/0 (resolved by the firewall package)",
			cfg.IPv4PrefixLen, cfg.IPv6PrefixLen)
	}
}

// Egress defaults to "auto": attaching an egress rule flips the interface's
// implicit egress rule to DROP_ALL, so the rules are only emitted where the
// interface already restricts outbound traffic and they are actually needed.
func TestEgressMode(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    string
		wantErr bool
	}{
		{name: "unset defaults to auto", raw: `{}`, want: VPNEgressAuto},
		{name: "explicit auto", raw: `{"vpnEgress": "auto"}`, want: VPNEgressAuto},
		{name: "always", raw: `{"vpnEgress": "always"}`, want: VPNEgressAlways},
		{name: "never", raw: `{"vpnEgress": "never"}`, want: VPNEgressNever},
		{name: "case insensitive", raw: `{"vpnEgress": "ALWAYS"}`, want: VPNEgressAlways},
		// Earlier versions wrote a JSON boolean here; a config written by one of
		// those must still parse rather than failing at unmarshal time.
		{name: "legacy bool true maps to always", raw: `{"vpnEgress": true}`, want: VPNEgressAlways},
		{name: "legacy bool false maps to never", raw: `{"vpnEgress": false}`, want: VPNEgressNever},
		{name: "quoted true maps to always", raw: `{"vpnEgress": "true"}`, want: VPNEgressAlways},
		{name: "quoted false maps to never", raw: `{"vpnEgress": "false"}`, want: VPNEgressNever},
		{name: "unknown value errors", raw: `{"vpnEgress": "sometimes"}`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := loadFrom(t, tt.raw).EgressMode()
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
				t.Errorf("EgressMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPerTargetOverrides(t *testing.T) {
	cfg := loadFrom(t, `{
		"wireguard": true,
		"openvpn": false,
		"targets": [
			{"serverId": 1, "mac": "aa:aa"},
			{"serverId": 2, "mac": "bb:bb", "wireguard": false, "openvpn": true}
		]
	}`)

	targets := cfg.Targets()
	if len(targets) != 2 {
		t.Fatalf("target count = %d, want 2", len(targets))
	}

	// Target 1 inherits the top-level toggles.
	if !cfg.WireGuardFor(targets[0]) {
		t.Error("target 0 should inherit wireguard=true")
	}
	if cfg.OpenVPNFor(targets[0]) {
		t.Error("target 0 should inherit openvpn=false")
	}

	// Target 2 overrides both.
	if cfg.WireGuardFor(targets[1]) {
		t.Error("target 1 overrides wireguard to false")
	}
	if !cfg.OpenVPNFor(targets[1]) {
		t.Error("target 1 overrides openvpn to true")
	}

	// The aggregates drive whether a shared policy is upserted at all.
	if !cfg.AnyWireGuard() {
		t.Error("AnyWireGuard should be true (target 0 has it)")
	}
	if !cfg.AnyOpenVPN() {
		t.Error("AnyOpenVPN should be true (target 1 overrides it on)")
	}
}

func TestTargetsFromServerIDAndMAC(t *testing.T) {
	cfg := loadFrom(t, `{"serverId": 42, "mac": "aa:bb:cc:dd:ee:ff"}`)
	targets := cfg.Targets()
	if len(targets) != 1 {
		t.Fatalf("target count = %d, want 1 synthesized target", len(targets))
	}
	if targets[0].ServerID != 42 || targets[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("target = %+v, want serverId 42 / mac aa:bb:cc:dd:ee:ff", targets[0])
	}

	if got := loadFrom(t, `{}`).Targets(); len(got) != 0 {
		t.Errorf("Targets() with nothing configured = %+v, want empty", got)
	}
}
