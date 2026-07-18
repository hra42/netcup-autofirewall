// Package firewall builds the SSH allow/deny rule set for the autofirewall
// policy from the detected public IP addresses.
package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/hra42/netcup-autofirewall/internal/scp"
)

// Default prefix lengths: a single host address per family.
const (
	DefaultV4PrefixLen = 32
	DefaultV6PrefixLen = 128
)

// MinPrefixLen guards against a typo that would open the port to a large slice
// of the internet — writing 6 instead of 64, say. Anyone genuinely wanting a
// wider allow-list should not be using this tool.
const MinPrefixLen = 8

// SSHRuleOptions controls how detected addresses become source CIDRs.
//
// A prefix length shorter than the full address width widens the rule to the
// surrounding network. That is the right choice when the detected address
// tracks a router — the whole home network then reaches SSH, mirroring how IPv4
// NAT already presents every device behind one address. Zero values mean the
// defaults (a single host: /32 and /128).
type SSHRuleOptions struct {
	SSHPort     string
	V4PrefixLen int
	V6PrefixLen int
}

// BuildSSHRules returns the ingress TCP rules that allow SSH from the given
// public IPv4/IPv6 (either may be empty), using single-host sources (/32 and
// /128). Use BuildSSHRulesOpts to widen those.
func BuildSSHRules(v4, v6, sshPort string) ([]scp.FirewallRule, error) {
	return BuildSSHRulesOpts(v4, v6, SSHRuleOptions{SSHPort: sshPort})
}

// BuildSSHRulesOpts returns the ingress TCP rules that allow SSH from the given
// public IPv4/IPv6 (either may be empty).
//
// The result is one ACCEPT rule per provided address, masked to the configured
// prefix. At least one of v4/v6 must be non-empty.
//
// No explicit DROP is emitted: attaching any policy flips the interface's
// implicit ingress rule to DROP_ALL, so everything not accepted is already
// denied. An explicit DROP on the SSH port would additionally override ACCEPTs
// in other policies, which is worse than redundant.
func BuildSSHRulesOpts(v4, v6 string, opt SSHRuleOptions) ([]scp.FirewallRule, error) {
	if opt.SSHPort == "" {
		return nil, fmt.Errorf("ssh port is empty")
	}
	if v4 == "" && v6 == "" {
		return nil, fmt.Errorf("no public IP addresses provided")
	}

	v4Bits, v6Bits := opt.V4PrefixLen, opt.V6PrefixLen
	if v4Bits == 0 {
		v4Bits = DefaultV4PrefixLen
	}
	if v6Bits == 0 {
		v6Bits = DefaultV6PrefixLen
	}

	var rules []scp.FirewallRule

	if v4 != "" {
		ip := net.ParseIP(v4)
		if ip == nil || ip.To4() == nil {
			return nil, fmt.Errorf("invalid IPv4 address: %q", v4)
		}
		source, err := maskToPrefix(ip, v4Bits)
		if err != nil {
			return nil, err
		}
		rules = append(rules, acceptRule(source, opt.SSHPort,
			fmt.Sprintf("allow SSH from current public IPv4 (/%d)", v4Bits)))
	}
	if v6 != "" {
		ip := net.ParseIP(v6)
		if ip == nil || ip.To4() != nil {
			return nil, fmt.Errorf("invalid IPv6 address: %q", v6)
		}
		source, err := maskToPrefix(ip, v6Bits)
		if err != nil {
			return nil, err
		}
		rules = append(rules, acceptRule(source, opt.SSHPort,
			fmt.Sprintf("allow SSH from current public IPv6 (/%d)", v6Bits)))
	}

	return rules, nil
}

// maskToPrefix returns the network CIDR containing ip at the given prefix
// length, e.g. maskToPrefix(2001:db8:1:2:3:4:5:6, 64) == "2001:db8:1:2::/64".
//
// The host bits are zeroed: emitting an unmasked address with a short prefix
// would leave the API to normalize or reject it, and the client cannot tell
// which happened.
func maskToPrefix(ip net.IP, bits int) (string, error) {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return "", fmt.Errorf("invalid address: %v", ip)
	}
	addr = addr.Unmap()
	if bits > addr.BitLen() {
		return "", fmt.Errorf("prefix length /%d is too long for %s (max /%d)", bits, addr, addr.BitLen())
	}
	if bits < MinPrefixLen {
		return "", fmt.Errorf("prefix length /%d is too short (minimum /%d); "+
			"this would allow a large portion of the internet", bits, MinPrefixLen)
	}
	return netip.PrefixFrom(addr, bits).Masked().String(), nil
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

// BuildWireGuardRules returns the rules allowing WireGuard on the given UDP
// port. WireGuard is UDP-only by protocol design.
func BuildWireGuardRules(port string) ([]scp.FirewallRule, error) {
	return BuildVPNRules("WireGuard", scp.ProtocolUDP, port, false)
}

// BuildVPNRules returns the rules opening a VPN port for the named service.
//
// VPN protocols authenticate peers cryptographically and peers roam between
// dynamic addresses, so exposing the port to any source is the normal
// configuration. Empty sources = any.
//
// When includeEgress is set, an egress ACCEPT for replies leaving the VPN port
// is emitted alongside each ingress rule. This is required because the netcup
// firewall is not stateful for UDP: unless the interface's implicit egress rule
// is ACCEPT_ALL, replies are dropped on the way out and the tunnel never
// establishes, even though the ingress rule looks correct.
func BuildVPNRules(name, protocol, port string, includeEgress bool) ([]scp.FirewallRule, error) {
	if port == "" {
		return nil, fmt.Errorf("%s port is empty", name)
	}
	proto, err := normalizeProtocol(protocol)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", name, err)
	}

	rules := []scp.FirewallRule{{
		Direction:        scp.DirectionIngress,
		Protocol:         proto,
		Action:           scp.ActionAccept,
		Description:      fmt.Sprintf("allow %s (%s)", name, proto),
		DestinationPorts: port,
	}}

	if includeEgress {
		rules = append(rules, scp.FirewallRule{
			Direction: scp.DirectionEgress,
			Protocol:  proto,
			Action:    scp.ActionAccept,
			// Replies leave *from* the VPN port, so this matches on the source
			// port rather than the destination.
			Description: fmt.Sprintf("allow %s replies (%s)", name, proto),
			SourcePorts: port,
		})
	}

	return rules, nil
}

// DefaultEgressAllowProtocols covers ordinary application traffic.
var DefaultEgressAllowProtocols = []string{scp.ProtocolTCP, scp.ProtocolUDP}

// VPNEgressAllowProtocols adds ICMP/ICMPv6 on top of the defaults.
//
// A VPN needs path MTU discovery: without ICMP, the "packet too big" responses
// that size the tunnel never arrive, so large packets hang while small ones
// succeed — a failure that looks like an application bug rather than a firewall
// rule. Since the egress allowance only exists because a VPN forced the
// interface into DROP_ALL, ICMP belongs with it.
var VPNEgressAllowProtocols = []string{
	scp.ProtocolTCP, scp.ProtocolUDP, scp.ProtocolICMP, scp.ProtocolICMPv6,
}

// BuildEgressAllowRules returns blanket egress ACCEPT rules, one per protocol.
//
// Attaching any egress rule flips the interface's implicit egress rule from
// ACCEPT_ALL to DROP_ALL, after which every outbound flow needs an explicit
// rule. These rules restore the permissive behavior as something the tool
// controls, rather than depending on an implicit default that silently changes
// the moment an egress rule appears.
func BuildEgressAllowRules(protocols []string) ([]scp.FirewallRule, error) {
	if len(protocols) == 0 {
		return nil, fmt.Errorf("no egress protocols given")
	}
	var rules []scp.FirewallRule
	for _, p := range protocols {
		proto, err := normalizeEgressProtocol(p)
		if err != nil {
			return nil, err
		}
		rules = append(rules, scp.FirewallRule{
			Direction:   scp.DirectionEgress,
			Protocol:    proto,
			Action:      scp.ActionAccept,
			Description: fmt.Sprintf("allow all outbound %s", proto),
		})
	}
	return rules, nil
}

// normalizeEgressProtocol accepts the four protocols the API models, since an
// egress allowance may legitimately need ICMP as well as TCP/UDP.
func normalizeEgressProtocol(protocol string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case scp.ProtocolTCP:
		return scp.ProtocolTCP, nil
	case scp.ProtocolUDP:
		return scp.ProtocolUDP, nil
	case "ICMP":
		return scp.ProtocolICMP, nil
	case "ICMPV6":
		return scp.ProtocolICMPv6, nil
	default:
		return "", fmt.Errorf("unsupported egress protocol %q (want TCP, UDP, ICMP or ICMPv6)", protocol)
	}
}

// normalizeProtocol maps a user-supplied protocol to the API's spelling,
// defaulting to UDP. Only UDP and TCP are meaningful for a VPN listener.
func normalizeProtocol(protocol string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(protocol)) {
	case "", scp.ProtocolUDP:
		return scp.ProtocolUDP, nil
	case scp.ProtocolTCP:
		return scp.ProtocolTCP, nil
	default:
		return "", fmt.Errorf("unsupported protocol %q (want %q or %q)", protocol, scp.ProtocolUDP, scp.ProtocolTCP)
	}
}
