package firewall

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/hra42/netcup-autofirewall/internal/scp"
)

// assertSingleFamily reports an error unless every CIDR in sources belongs to
// the same address family.
func assertSingleFamily(sources []string) error {
	var sawV4, sawV6 bool
	for _, s := range sources {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("source %q is not a CIDR: %w", s, err)
		}
		if p.Addr().Is4() {
			sawV4 = true
		} else {
			sawV6 = true
		}
	}
	if sawV4 && sawV6 {
		return fmt.Errorf("sources mix IPv4 and IPv6: %v", sources)
	}
	return nil
}

func TestBuildSSHRules(t *testing.T) {
	tests := []struct {
		name        string
		v4, v6      string
		sshPort     string
		wantErr     bool
		wantSources []string // sources of the ACCEPT rules, in order
	}{
		{
			name:        "v4 only",
			v4:          "203.0.113.7",
			sshPort:     "22",
			wantSources: []string{"203.0.113.7/32"},
		},
		{
			name:        "v6 only",
			v6:          "2001:db8::1",
			sshPort:     "22",
			wantSources: []string{"2001:db8::1/128"},
		},
		{
			name:        "both families",
			v4:          "203.0.113.7",
			v6:          "2001:db8::1",
			sshPort:     "2222",
			wantSources: []string{"203.0.113.7/32", "2001:db8::1/128"},
		},
		{name: "neither address", sshPort: "22", wantErr: true},
		{name: "empty port", v4: "203.0.113.7", wantErr: true},
		{name: "v6 passed as v4", v4: "2001:db8::1", sshPort: "22", wantErr: true},
		{name: "v4 passed as v6", v6: "203.0.113.7", sshPort: "22", wantErr: true},
		{name: "garbage v4", v4: "not-an-ip", sshPort: "22", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := BuildSSHRules(tt.v4, tt.v6, tt.sshPort)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got rules: %+v", rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			// One ACCEPT per address; the interface's implicit DROP_ALL denies
			// the rest, so no explicit DROP is emitted.
			if got, want := len(rules), len(tt.wantSources); got != want {
				t.Fatalf("rule count = %d, want %d: %+v", got, want, rules)
			}

			for i, want := range tt.wantSources {
				r := rules[i]
				if r.Action != scp.ActionAccept {
					t.Errorf("rule %d action = %q, want %q", i, r.Action, scp.ActionAccept)
				}
				if len(r.Sources) != 1 || r.Sources[0] != want {
					t.Errorf("rule %d sources = %v, want [%s]", i, r.Sources, want)
				}
				if r.Direction != scp.DirectionIngress {
					t.Errorf("rule %d direction = %q, want %q", i, r.Direction, scp.DirectionIngress)
				}
				if r.Protocol != scp.ProtocolTCP {
					t.Errorf("rule %d protocol = %q, want %q", i, r.Protocol, scp.ProtocolTCP)
				}
				if r.DestinationPorts != tt.sshPort {
					t.Errorf("rule %d destination ports = %q, want %q", i, r.DestinationPorts, tt.sshPort)
				}
			}

			// No explicit DROP: it would be redundant with the interface's
			// implicit DROP_ALL, and would also override ACCEPTs that other
			// policies define on the same port.
			for i, r := range rules {
				if r.Action == scp.ActionDrop {
					t.Errorf("rule %d is a DROP (%q); the implicit rule handles denial", i, r.Description)
				}
			}
		})
	}
}

func TestMaskToPrefix(t *testing.T) {
	tests := []struct {
		name    string
		ip      string
		bits    int
		want    string
		wantErr bool
	}{
		{name: "v6 host", ip: "2001:db8:1:2:3:4:5:6", bits: 128, want: "2001:db8:1:2:3:4:5:6/128"},
		{name: "v6 masked to /64", ip: "2001:db8:1:2:3:4:5:6", bits: 64, want: "2001:db8:1:2::/64"},
		{name: "v6 masked to /48", ip: "2001:db8:1:2:3:4:5:6", bits: 48, want: "2001:db8:1::/48"},
		{name: "v4 host", ip: "203.0.113.7", bits: 32, want: "203.0.113.7/32"},
		{name: "v4 masked to /24", ip: "203.0.113.7", bits: 24, want: "203.0.113.0/24"},
		{name: "v4 prefix too long", ip: "203.0.113.7", bits: 64, wantErr: true},
		{name: "v6 prefix too long", ip: "2001:db8::1", bits: 129, wantErr: true},
		{name: "prefix below minimum", ip: "2001:db8::1", bits: 6, wantErr: true},
		{name: "negative prefix", ip: "203.0.113.7", bits: -1, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := maskToPrefix(net.ParseIP(tt.ip), tt.bits)
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
				t.Errorf("maskToPrefix(%s, %d) = %q, want %q", tt.ip, tt.bits, got, tt.want)
			}
		})
	}
}

func TestBuildSSHRulesOptsPrefixes(t *testing.T) {
	tests := []struct {
		name        string
		opt         SSHRuleOptions
		wantSources []string
		wantErr     bool
	}{
		{
			name:        "zero values mean single hosts",
			opt:         SSHRuleOptions{SSHPort: "22"},
			wantSources: []string{"203.0.113.7/32", "2001:db8:1:2:3:4:5:6/128"},
		},
		{
			name:        "v6 widened to the /64 prefix",
			opt:         SSHRuleOptions{SSHPort: "22", V6PrefixLen: 64},
			wantSources: []string{"203.0.113.7/32", "2001:db8:1:2::/64"},
		},
		{
			name:        "both families widened",
			opt:         SSHRuleOptions{SSHPort: "22", V4PrefixLen: 24, V6PrefixLen: 56},
			wantSources: []string{"203.0.113.0/24", "2001:db8:1::/56"},
		},
		{
			name:    "typo'd short prefix is rejected",
			opt:     SSHRuleOptions{SSHPort: "22", V6PrefixLen: 6},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := BuildSSHRulesOpts("203.0.113.7", "2001:db8:1:2:3:4:5:6", tt.opt)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got rules: %+v", rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			for i, want := range tt.wantSources {
				if len(rules[i].Sources) != 1 || rules[i].Sources[0] != want {
					t.Errorf("rule %d sources = %v, want [%s]", i, rules[i].Sources, want)
				}
			}
		})
	}
}

func TestBuildCloudflareHTTPSRules(t *testing.T) {
	v4 := []string{"198.51.100.0/24", "203.0.113.0/24"}
	v6 := []string{"2001:db8::/32"}

	tests := []struct {
		name           string
		v4CIDRs        []string
		v6CIDRs        []string
		wantErr        bool
		wantRuleCount  int
		wantAllSources []string
	}{
		{name: "v4 only", v4CIDRs: v4, wantRuleCount: 1, wantAllSources: v4},
		{name: "v6 only", v6CIDRs: v6, wantRuleCount: 1, wantAllSources: v6},
		{name: "both families", v4CIDRs: v4, v6CIDRs: v6, wantRuleCount: 2, wantAllSources: append(append([]string{}, v4...), v6...)},
		{name: "neither", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := BuildCloudflareHTTPSRules(tt.v4CIDRs, tt.v6CIDRs)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got rules: %+v", rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != tt.wantRuleCount {
				t.Fatalf("rule count = %d, want %d", len(rules), tt.wantRuleCount)
			}

			var got []string
			for i, r := range rules {
				if r.Action != scp.ActionAccept {
					t.Errorf("rule %d action = %q, want %q", i, r.Action, scp.ActionAccept)
				}
				if r.DestinationPorts != HTTPSPort {
					t.Errorf("rule %d ports = %q, want %q", i, r.DestinationPorts, HTTPSPort)
				}
				// The API forbids mixing address families in one rule's sources
				// when destinations are also set, so each rule must be single-family.
				if err := assertSingleFamily(r.Sources); err != nil {
					t.Errorf("rule %d: %v", i, err)
				}
				got = append(got, r.Sources...)
			}
			if len(got) != len(tt.wantAllSources) {
				t.Errorf("total sources = %v, want %v", got, tt.wantAllSources)
			}
		})
	}
}

func TestBuildWireGuardRules(t *testing.T) {
	t.Run("port set", func(t *testing.T) {
		rules, err := BuildWireGuardRules("51820")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("rule count = %d, want 1", len(rules))
		}
		r := rules[0]
		if r.Direction != scp.DirectionIngress {
			t.Errorf("direction = %q, want %q", r.Direction, scp.DirectionIngress)
		}
		if r.Protocol != scp.ProtocolUDP {
			t.Errorf("protocol = %q, want %q", r.Protocol, scp.ProtocolUDP)
		}
		if r.Action != scp.ActionAccept {
			t.Errorf("action = %q, want %q", r.Action, scp.ActionAccept)
		}
		if r.DestinationPorts != "51820" {
			t.Errorf("destination ports = %q, want %q", r.DestinationPorts, "51820")
		}
		// Peers roam, so the port is open to any source.
		if len(r.Sources) != 0 {
			t.Errorf("sources = %v, want empty (any)", r.Sources)
		}
	})

	t.Run("empty port", func(t *testing.T) {
		if _, err := BuildWireGuardRules(""); err == nil {
			t.Fatal("expected an error for an empty port")
		}
	})
}

// The allow-all-egress policy exists to counteract the implicit rule flipping to
// DROP_ALL: every rule must be an unrestricted egress ACCEPT.
func TestBuildEgressAllowRules(t *testing.T) {
	// A VPN needs ICMP for path MTU discovery, so the VPN set carries it.
	t.Run("VPN set covers TCP, UDP and ICMP", func(t *testing.T) {
		rules, err := BuildEgressAllowRules(VPNEgressAllowProtocols)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{scp.ProtocolTCP, scp.ProtocolUDP, scp.ProtocolICMP, scp.ProtocolICMPv6}
		if len(rules) != len(want) {
			t.Fatalf("rule count = %d, want %d", len(rules), len(want))
		}
		for i, w := range want {
			if rules[i].Protocol != w {
				t.Errorf("rule %d protocol = %q, want %q", i, rules[i].Protocol, w)
			}
		}
	})

	t.Run("defaults cover TCP and UDP", func(t *testing.T) {
		rules, err := BuildEgressAllowRules(DefaultEgressAllowProtocols)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("rule count = %d, want 2", len(rules))
		}
		for i, r := range rules {
			if r.Direction != scp.DirectionEgress {
				t.Errorf("rule %d direction = %q, want %q", i, r.Direction, scp.DirectionEgress)
			}
			if r.Action != scp.ActionAccept {
				t.Errorf("rule %d action = %q, want %q", i, r.Action, scp.ActionAccept)
			}
			// Any port restriction here would defeat the purpose.
			if r.SourcePorts != "" || r.DestinationPorts != "" {
				t.Errorf("rule %d ports = src %q/dst %q, want both empty (any)",
					i, r.SourcePorts, r.DestinationPorts)
			}
			if len(r.Sources) != 0 || len(r.Destinations) != 0 {
				t.Errorf("rule %d restricts addresses, want unrestricted", i)
			}
		}
		if rules[0].Protocol != scp.ProtocolTCP || rules[1].Protocol != scp.ProtocolUDP {
			t.Errorf("protocols = %q/%q, want TCP/UDP", rules[0].Protocol, rules[1].Protocol)
		}
	})

	t.Run("ICMP can be added for path MTU discovery", func(t *testing.T) {
		rules, err := BuildEgressAllowRules([]string{"ICMP", "icmpv6"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("rule count = %d, want 2", len(rules))
		}
		if rules[0].Protocol != scp.ProtocolICMP || rules[1].Protocol != scp.ProtocolICMPv6 {
			t.Errorf("protocols = %q/%q, want ICMP/ICMPv6", rules[0].Protocol, rules[1].Protocol)
		}
	})

	t.Run("empty list errors", func(t *testing.T) {
		if _, err := BuildEgressAllowRules(nil); err == nil {
			t.Fatal("expected an error for an empty protocol list")
		}
	})

	t.Run("unknown protocol errors", func(t *testing.T) {
		if _, err := BuildEgressAllowRules([]string{"banana"}); err == nil {
			t.Fatal("expected an error for an unknown protocol")
		}
	})
}

func TestBuildVPNRulesProtocols(t *testing.T) {
	tests := []struct {
		name      string
		protocol  string
		wantProto string
		wantErr   bool
	}{
		{name: "explicit UDP", protocol: "UDP", wantProto: scp.ProtocolUDP},
		{name: "explicit TCP", protocol: "TCP", wantProto: scp.ProtocolTCP},
		{name: "lowercase is normalized", protocol: "tcp", wantProto: scp.ProtocolTCP},
		{name: "empty defaults to UDP", protocol: "", wantProto: scp.ProtocolUDP},
		{name: "unsupported protocol", protocol: "ICMP", wantErr: true},
		{name: "nonsense protocol", protocol: "banana", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := BuildVPNRules("OpenVPN", tt.protocol, "1194", false)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got rules: %+v", rules)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != 1 {
				t.Fatalf("rule count = %d, want 1 (ingress only)", len(rules))
			}
			if rules[0].Protocol != tt.wantProto {
				t.Errorf("protocol = %q, want %q", rules[0].Protocol, tt.wantProto)
			}
		})
	}
}

// The netcup firewall is not stateful for UDP, so replies leaving the VPN port
// need their own egress ACCEPT — matched on the source port, not the destination.
func TestBuildVPNRulesEgress(t *testing.T) {
	t.Run("egress enabled", func(t *testing.T) {
		rules, err := BuildVPNRules("WireGuard", scp.ProtocolUDP, "51820", true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 2 {
			t.Fatalf("rule count = %d, want 2 (ingress + egress)", len(rules))
		}

		ingress, egress := rules[0], rules[1]
		if ingress.Direction != scp.DirectionIngress {
			t.Errorf("rule 0 direction = %q, want %q", ingress.Direction, scp.DirectionIngress)
		}
		if ingress.DestinationPorts != "51820" || ingress.SourcePorts != "" {
			t.Errorf("ingress ports = src %q/dst %q, want src \"\"/dst \"51820\"",
				ingress.SourcePorts, ingress.DestinationPorts)
		}

		if egress.Direction != scp.DirectionEgress {
			t.Errorf("rule 1 direction = %q, want %q", egress.Direction, scp.DirectionEgress)
		}
		if egress.Action != scp.ActionAccept {
			t.Errorf("egress action = %q, want %q", egress.Action, scp.ActionAccept)
		}
		// Replies leave FROM the VPN port.
		if egress.SourcePorts != "51820" {
			t.Errorf("egress source ports = %q, want %q", egress.SourcePorts, "51820")
		}
		if egress.DestinationPorts != "" {
			t.Errorf("egress destination ports = %q, want empty", egress.DestinationPorts)
		}
		if egress.Protocol != scp.ProtocolUDP {
			t.Errorf("egress protocol = %q, want %q", egress.Protocol, scp.ProtocolUDP)
		}
	})

	t.Run("egress disabled yields ingress only", func(t *testing.T) {
		rules, err := BuildVPNRules("WireGuard", scp.ProtocolUDP, "51820", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(rules) != 1 {
			t.Fatalf("rule count = %d, want 1", len(rules))
		}
		if rules[0].Direction != scp.DirectionIngress {
			t.Errorf("direction = %q, want %q", rules[0].Direction, scp.DirectionIngress)
		}
	})

	t.Run("empty port", func(t *testing.T) {
		if _, err := BuildVPNRules("OpenVPN", scp.ProtocolUDP, "", true); err == nil {
			t.Fatal("expected an error for an empty port")
		}
	})
}
