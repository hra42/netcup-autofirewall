// Package config handles loading and persisting the CLI's configuration file,
// which holds the long-lived refresh token and the target server details.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultPolicyName is the name of the SSH policy this tool owns.
const DefaultPolicyName = "ssh-autofirewall"

// DefaultCloudflarePolicyName is the name of the Cloudflare HTTPS policy.
const DefaultCloudflarePolicyName = "cloudflare-https"

// DefaultWireGuardPolicyName is the name of the WireGuard policy.
const DefaultWireGuardPolicyName = "wireguard"

// DefaultSSHPort is used when no SSH port is configured.
const DefaultSSHPort = "22"

// DefaultWireGuardPort is used when no WireGuard port is configured.
const DefaultWireGuardPort = "51820"

// DefaultOpenVPNPolicyName is the name of the OpenVPN policy.
const DefaultOpenVPNPolicyName = "openvpn"

// DefaultOpenVPNPort is used when no OpenVPN port is configured.
const DefaultOpenVPNPort = "1194"

// DefaultOpenVPNProtocol is used when no OpenVPN protocol is configured.
const DefaultOpenVPNProtocol = "UDP"

// DefaultSchedule is the cron expression the run daemon uses by default
// (every 15 minutes).
const DefaultSchedule = "*/15 * * * *"

// IP source kinds for Config.IPSource.
const (
	// IPSourceEcho queries the self-hosted echo endpoint (see cmd/echo-server).
	IPSourceEcho = "echo"
	// IPSourceDNS resolves a hostname, typically an existing DynDNS name.
	IPSourceDNS = "dns"
)

// DefaultIPMode requires IPv4 and treats IPv6 as best-effort, matching the
// behavior from before address-family modes existed.
const DefaultIPMode = "dual"

// Target identifies one server interface to manage, with optional per-target
// overrides of the Cloudflare/WireGuard/OpenVPN modes. When an override is nil
// the top-level config default applies; when set it wins for that target. This
// lets, e.g., the host that serves the echo endpoint always keep HTTPS (443)
// open, or only one host run the VPN.
type Target struct {
	ServerID   int    `json:"serverId"`
	MAC        string `json:"mac"`
	Cloudflare *bool  `json:"cloudflare,omitempty"`
	WireGuard  *bool  `json:"wireguard,omitempty"`
	OpenVPN    *bool  `json:"openvpn,omitempty"`
}

// CloudflareFor reports whether Cloudflare mode applies to target t.
func (c *Config) CloudflareFor(t Target) bool {
	if t.Cloudflare != nil {
		return *t.Cloudflare
	}
	return c.Cloudflare
}

// WireGuardFor reports whether WireGuard mode applies to target t.
func (c *Config) WireGuardFor(t Target) bool {
	if t.WireGuard != nil {
		return *t.WireGuard
	}
	return c.WireGuard
}

// AnyCloudflare reports whether Cloudflare mode is enabled for any target, so
// the shared policy is upserted when at least one target needs it.
func (c *Config) AnyCloudflare() bool {
	for _, t := range c.Targets() {
		if c.CloudflareFor(t) {
			return true
		}
	}
	return false
}

// AnyWireGuard reports whether WireGuard mode is enabled for any target.
func (c *Config) AnyWireGuard() bool {
	for _, t := range c.Targets() {
		if c.WireGuardFor(t) {
			return true
		}
	}
	return false
}

// OpenVPNFor reports whether OpenVPN mode applies to target t.
func (c *Config) OpenVPNFor(t Target) bool {
	if t.OpenVPN != nil {
		return *t.OpenVPN
	}
	return c.OpenVPN
}

// AnyOpenVPN reports whether OpenVPN mode is enabled for any target.
func (c *Config) AnyOpenVPN() bool {
	for _, t := range c.Targets() {
		if c.OpenVPNFor(t) {
			return true
		}
	}
	return false
}

// VPN egress modes for Config.VPNEgress.
const (
	// VPNEgressAuto emits egress rules only where they are needed, i.e. where
	// the interface's implicit egress rule is already restrictive.
	VPNEgressAuto = "auto"
	// VPNEgressAlways always emits them. Note this flips a permissive implicit
	// egress rule to DROP_ALL, requiring egress rules for all other traffic.
	VPNEgressAlways = "always"
	// VPNEgressNever never emits them.
	VPNEgressNever = "never"
)

// DefaultVPNEgress only adds egress rules where they do something.
const DefaultVPNEgress = VPNEgressAuto

// DefaultEgressAllowPolicyName is the name of the allow-all-egress policy.
const DefaultEgressAllowPolicyName = "egress-allow-all"

// EgressAllowAllEnabled reports whether the allow-all-egress policy is attached
// alongside any egress rules this tool emits. Defaults to true: without it,
// emitting an egress rule flips the interface to DROP_ALL and cuts off all other
// outbound traffic.
func (c *Config) EgressAllowAllEnabled() bool {
	if c.EgressAllowAll != nil {
		return *c.EgressAllowAll
	}
	return true
}

// VPNEgressMode is the vpnEgress setting. It decodes from a string, and also
// from the boolean that versions before the auto mode wrote, so upgrading does
// not fail to parse an existing config.
type VPNEgressMode string

// UnmarshalJSON implements json.Unmarshaler.
func (m *VPNEgressMode) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*m = VPNEgressMode(s)
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err == nil {
		if b {
			*m = VPNEgressAlways
		} else {
			*m = VPNEgressNever
		}
		return nil
	}
	return fmt.Errorf("vpnEgress must be %q, %q or %q", VPNEgressAuto, VPNEgressAlways, VPNEgressNever)
}

// EgressMode returns the configured VPN egress mode, accepting the legacy
// boolean spellings that earlier versions wrote.
func (c *Config) EgressMode() (string, error) {
	switch strings.ToLower(strings.TrimSpace(string(c.VPNEgress))) {
	case "", VPNEgressAuto:
		return VPNEgressAuto, nil
	case VPNEgressAlways, "true":
		return VPNEgressAlways, nil
	case VPNEgressNever, "false":
		return VPNEgressNever, nil
	default:
		return "", fmt.Errorf("unknown vpnEgress %q (want %q, %q or %q)",
			c.VPNEgress, VPNEgressAuto, VPNEgressAlways, VPNEgressNever)
	}
}

// Config is the persisted configuration. The refresh token is a long-lived
// credential, so the file is written with 0600 permissions.
type Config struct {
	RefreshToken string `json:"refreshToken,omitempty"`
	UserID       int    `json:"userId,omitempty"`

	// A single target may be given via ServerID/MAC, or several via TargetList.
	// Use the Targets() method to get the effective list.
	ServerID   int      `json:"serverId,omitempty"`
	MAC        string   `json:"mac,omitempty"`
	TargetList []Target `json:"targets,omitempty"`

	SSHPort    string `json:"sshPort,omitempty"`
	PolicyName string `json:"policyName,omitempty"`

	// Prefix lengths applied to the detected addresses before they become
	// firewall sources. The defaults (32/128) allow exactly the detected host.
	// Set IPv6PrefixLen to 64 when the detected IPv6 tracks your router and you
	// connect from varying hosts behind it, mirroring how a single IPv4 already
	// fronts the whole home network.
	IPv4PrefixLen int `json:"ipv4PrefixLen,omitempty"`
	IPv6PrefixLen int `json:"ipv6PrefixLen,omitempty"`

	// EchoURL is the self-hosted echo endpoint used to detect the public IP
	// (see cmd/echo-server). EchoUserAgent gates access to that endpoint.
	EchoURL       string `json:"echoUrl,omitempty"`
	EchoUserAgent string `json:"echoUserAgent,omitempty"`

	// IPSource selects where the public address comes from: "echo" (the
	// self-hosted endpoint above) or "dns" (resolving DNSHostname, typically an
	// existing DynDNS name). Defaults to "dns" when only DNSHostname is set.
	IPSource    string `json:"ipSource,omitempty"`
	DNSHostname string `json:"dnsHostname,omitempty"`
	// DNSServer, when set, is queried directly instead of the system resolver.
	// Aim it at the DynDNS provider's nameserver to bypass caches, which would
	// otherwise serve stale answers between apply runs.
	DNSServer string `json:"dnsServer,omitempty"`

	// IPMode selects which address families are looked up and required:
	// "dual" (default; IPv4 required, IPv6 best-effort), "v6only" (DS-Lite),
	// "v4only", or "auto" (whichever family resolves).
	IPMode string `json:"ipMode,omitempty"`

	// Cloudflare mode: allow HTTPS (443) from Cloudflare's edge ranges.
	Cloudflare           bool   `json:"cloudflare,omitempty"`
	CloudflarePolicyName string `json:"cloudflarePolicyName,omitempty"`

	// WireGuard mode: allow UDP (default 51820) from any source.
	WireGuard           bool   `json:"wireguard,omitempty"`
	WireGuardPort       string `json:"wireguardPort,omitempty"`
	WireGuardPolicyName string `json:"wireguardPolicyName,omitempty"`

	// OpenVPN mode: allow the OpenVPN port (default UDP 1194) from any source.
	// Unlike WireGuard, OpenVPN can run over TCP, so the protocol is settable.
	OpenVPN           bool   `json:"openvpn,omitempty"`
	OpenVPNPort       string `json:"openvpnPort,omitempty"`
	OpenVPNProtocol   string `json:"openvpnProtocol,omitempty"`
	OpenVPNPolicyName string `json:"openvpnPolicyName,omitempty"`

	// VPNEgress emits an egress ACCEPT for replies leaving the VPN port, needed
	// because the netcup firewall is not stateful for UDP.
	//
	// Defaults to "auto": emit only when the interface's implicit egress rule is
	// already restrictive, i.e. exactly when the rule is actually needed.
	// Attaching *any* egress rule flips that implicit rule from ACCEPT_ALL to
	// DROP_ALL, which would otherwise silently cut off all outbound TCP —
	// so emitting it unconditionally does far more than it appears to.
	// Use "always" or "never" to override.
	VPNEgress VPNEgressMode `json:"vpnEgress,omitempty"`

	// EgressAllowAll attaches a policy permitting all outbound traffic whenever
	// this tool emits any egress rule. Attaching an egress rule flips the
	// interface's implicit egress rule to DROP_ALL, so without this the host
	// silently loses outbound connectivity. Defaults to true; set false only if
	// you manage the interface's egress rules yourself.
	EgressAllowAll *bool `json:"egressAllowAll,omitempty"`

	// EgressAllowProtocols lists the protocols the allow-all policy covers.
	// Defaults to TCP, UDP, ICMP and ICMPv6 — ICMP is included because a VPN
	// needs path MTU discovery, without which large packets hang inside the
	// tunnel. Set this to narrow the set.
	EgressAllowProtocols []string `json:"egressAllowProtocols,omitempty"`

	// EgressAllowPolicyName is the name of that policy.
	EgressAllowPolicyName string `json:"egressAllowPolicyName,omitempty"`

	// Schedule is the cron expression used by the `run` daemon.
	Schedule string `json:"schedule,omitempty"`
}

// DefaultPath returns the config file path, honoring $XDG_CONFIG_HOME.
func DefaultPath() (string, error) {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolving home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "netcup-autofirewall", "config.json"), nil
}

// Load reads the config from path. A missing file yields a zero-value Config
// (with defaults applied) and no error, so first-run flows work.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return withDefaults(&Config{}), nil
		}
		return nil, fmt.Errorf("reading config %s: %w", path, err)
	}

	// Warn on overly permissive perms for a file holding a credential.
	if info, statErr := os.Stat(path); statErr == nil {
		if info.Mode().Perm()&0o077 != 0 {
			fmt.Fprintf(os.Stderr, "warning: %s is group/world accessible (%o); consider chmod 600\n",
				path, info.Mode().Perm())
		}
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config %s: %w", path, err)
	}
	return withDefaults(&cfg), nil
}

// Targets returns the effective list of interfaces to manage: the explicit
// Targets list if set, otherwise a single target built from ServerID/MAC (if
// present). Returns an empty slice when nothing is configured.
func (c *Config) Targets() []Target {
	if len(c.TargetList) > 0 {
		return c.TargetList
	}
	if c.ServerID != 0 && c.MAC != "" {
		return []Target{{ServerID: c.ServerID, MAC: c.MAC}}
	}
	return nil
}

// Save writes the config to path (0600), creating parent directories as needed.
func Save(path string, cfg *Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing config %s: %w", path, err)
	}
	return nil
}

func withDefaults(cfg *Config) *Config {
	if cfg.PolicyName == "" {
		cfg.PolicyName = DefaultPolicyName
	}
	if cfg.CloudflarePolicyName == "" {
		cfg.CloudflarePolicyName = DefaultCloudflarePolicyName
	}
	if cfg.WireGuardPolicyName == "" {
		cfg.WireGuardPolicyName = DefaultWireGuardPolicyName
	}
	if cfg.SSHPort == "" {
		cfg.SSHPort = DefaultSSHPort
	}
	if cfg.WireGuardPort == "" {
		cfg.WireGuardPort = DefaultWireGuardPort
	}
	if cfg.OpenVPNPolicyName == "" {
		cfg.OpenVPNPolicyName = DefaultOpenVPNPolicyName
	}
	if cfg.OpenVPNPort == "" {
		cfg.OpenVPNPort = DefaultOpenVPNPort
	}
	if cfg.OpenVPNProtocol == "" {
		cfg.OpenVPNProtocol = DefaultOpenVPNProtocol
	}
	if cfg.EgressAllowPolicyName == "" {
		cfg.EgressAllowPolicyName = DefaultEgressAllowPolicyName
	}
	if cfg.Schedule == "" {
		cfg.Schedule = DefaultSchedule
	}
	if cfg.IPSource == "" {
		// A user who configured only a DynDNS name means to use it; requiring a
		// second key to say so would be redundant. An explicit ipSource wins.
		if cfg.DNSHostname != "" && cfg.EchoURL == "" {
			cfg.IPSource = IPSourceDNS
		} else {
			cfg.IPSource = IPSourceEcho
		}
	}
	if cfg.IPMode == "" {
		cfg.IPMode = DefaultIPMode
	}
	return cfg
}
