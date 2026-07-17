// Package firewall builds the SSH allow/deny rule set for the autofirewall
// policy from the detected public IP addresses.
package firewall

import (
	"fmt"
	"net"

	"github.com/hra42/netcup-autofirewall/internal/scp"
)

// BuildSSHRules returns the ingress TCP rules that allow SSH from the given
// public IPv4/IPv6 (either may be empty) and drop SSH from everyone else.
//
// The result is: one ACCEPT rule per provided address (as /32 or /128), plus a
// catch-all DROP for the SSH port. The DROP is placed last so the more specific
// ACCEPTs take precedence. At least one of v4/v6 must be non-empty.
func BuildSSHRules(v4, v6, sshPort string) ([]scp.FirewallRule, error) {
	if sshPort == "" {
		return nil, fmt.Errorf("ssh port is empty")
	}
	if v4 == "" && v6 == "" {
		return nil, fmt.Errorf("no public IP addresses provided")
	}

	var rules []scp.FirewallRule

	if v4 != "" {
		if net.ParseIP(v4).To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %q", v4)
		}
		rules = append(rules, acceptRule(v4+"/32", sshPort, "allow SSH from current public IPv4"))
	}
	if v6 != "" {
		ip := net.ParseIP(v6)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %q", v6)
		}
		rules = append(rules, acceptRule(v6+"/128", sshPort, "allow SSH from current public IPv6"))
	}

	// Catch-all DROP for the SSH port; empty sources = any.
	rules = append(rules, scp.FirewallRule{
		Direction:        scp.DirectionIngress,
		Protocol:         scp.ProtocolTCP,
		Action:           scp.ActionDrop,
		Description:      "deny SSH from all other IPs",
		DestinationPorts: sshPort,
	})

	return rules, nil
}

func acceptRule(source, sshPort, desc string) scp.FirewallRule {
	return scp.FirewallRule{
		Direction:        scp.DirectionIngress,
		Protocol:         scp.ProtocolTCP,
		Action:           scp.ActionAccept,
		Description:      desc,
		Sources:          []string{source},
		DestinationPorts: sshPort,
	}
}

// HTTPSPort is the destination port allowed for Cloudflare traffic.
const HTTPSPort = "443"

// BuildCloudflareHTTPSRules returns ingress ACCEPT rules allowing HTTPS (443)
// from Cloudflare's edge ranges. IPv4 and IPv6 CIDRs are kept in separate rules
// so each rule's sources stay single-family (the API forbids mixing families in
// one rule's sources when destinations are also set). Since the interface's
// implicit ingress rule becomes DROP_ALL once any policy is attached, no
// explicit DROP is needed here. At least one family must be non-empty.
func BuildCloudflareHTTPSRules(v4CIDRs, v6CIDRs []string) ([]scp.FirewallRule, error) {
	if len(v4CIDRs) == 0 && len(v6CIDRs) == 0 {
		return nil, fmt.Errorf("no Cloudflare IP ranges provided")
	}

	var rules []scp.FirewallRule
	if len(v4CIDRs) > 0 {
		rules = append(rules, scp.FirewallRule{
			Direction:        scp.DirectionIngress,
			Protocol:         scp.ProtocolTCP,
			Action:           scp.ActionAccept,
			Description:      "allow HTTPS from Cloudflare (IPv4)",
			Sources:          v4CIDRs,
			DestinationPorts: HTTPSPort,
		})
	}
	if len(v6CIDRs) > 0 {
		rules = append(rules, scp.FirewallRule{
			Direction:        scp.DirectionIngress,
			Protocol:         scp.ProtocolTCP,
			Action:           scp.ActionAccept,
			Description:      "allow HTTPS from Cloudflare (IPv6)",
			Sources:          v6CIDRs,
			DestinationPorts: HTTPSPort,
		})
	}
	return rules, nil
}

// DefaultWireGuardPort is the default UDP port allowed for WireGuard.
const DefaultWireGuardPort = "51820"

// BuildWireGuardRules returns an ingress ACCEPT rule allowing WireGuard traffic
// on the given UDP port from any source. WireGuard authenticates peers
// cryptographically, so exposing the port to any IP is the normal configuration
// (peers roam and use dynamic addresses). Empty sources = any.
func BuildWireGuardRules(port string) ([]scp.FirewallRule, error) {
	if port == "" {
		return nil, fmt.Errorf("wireguard port is empty")
	}
	return []scp.FirewallRule{{
		Direction:        scp.DirectionIngress,
		Protocol:         scp.ProtocolUDP,
		Action:           scp.ActionAccept,
		Description:      "allow WireGuard (UDP)",
		DestinationPorts: port,
	}}, nil
}
