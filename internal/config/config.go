// Package config handles loading and persisting the CLI's configuration file,
// which holds the long-lived refresh token and the target server details.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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

// DefaultSchedule is the cron expression the run daemon uses by default
// (every 15 minutes).
const DefaultSchedule = "*/15 * * * *"

// Target identifies one server interface to manage, with optional per-target
// overrides of the Cloudflare/WireGuard modes. When an override is nil the
// top-level config default applies; when set it wins for that target. This lets,
// e.g., the host that serves the echo endpoint always keep HTTPS (443) open.
type Target struct {
	ServerID   int    `json:"serverId"`
	MAC        string `json:"mac"`
	Cloudflare *bool  `json:"cloudflare,omitempty"`
	WireGuard  *bool  `json:"wireguard,omitempty"`
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

	// EchoURL is the self-hosted echo endpoint used to detect the public IP
	// (see cmd/echo-server). EchoUserAgent gates access to that endpoint.
	EchoURL       string `json:"echoUrl,omitempty"`
	EchoUserAgent string `json:"echoUserAgent,omitempty"`

	// Cloudflare mode: allow HTTPS (443) from Cloudflare's edge ranges.
	Cloudflare           bool   `json:"cloudflare,omitempty"`
	CloudflarePolicyName string `json:"cloudflarePolicyName,omitempty"`

	// WireGuard mode: allow UDP (default 51820) from any source.
	WireGuard           bool   `json:"wireguard,omitempty"`
	WireGuardPort       string `json:"wireguardPort,omitempty"`
	WireGuardPolicyName string `json:"wireguardPolicyName,omitempty"`

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
	if cfg.Schedule == "" {
		cfg.Schedule = DefaultSchedule
	}
	return cfg
}
