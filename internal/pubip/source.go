package pubip

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// Family is an IP address family.
type Family int

const (
	// FamilyV4 is IPv4.
	FamilyV4 Family = iota
	// FamilyV6 is IPv6.
	FamilyV6
)

func (f Family) String() string {
	if f == FamilyV6 {
		return "IPv6"
	}
	return "IPv4"
}

// network returns the Go network string for this family, using the given
// prefix ("tcp" for dialing, "ip" for DNS lookups).
func (f Family) network(prefix string) string {
	if f == FamilyV6 {
		return prefix + "6"
	}
	return prefix + "4"
}

// Source resolves the machine's current public address for one address family.
//
// A "" result with a nil error means the source has no address of that family
// (e.g. a DynDNS name with no AAAA record). That is distinct from an error,
// which means the lookup itself failed and the result is unknown.
type Source interface {
	Lookup(ctx context.Context, family Family) (string, error)
	// Describe returns a short human-readable identification of the source,
	// used in status output and error messages.
	Describe() string
}

// EchoSource resolves addresses by querying a self-hosted echo endpoint (see
// cmd/echo-server), forcing the address family per request.
type EchoSource struct {
	URL       string
	UserAgent string
}

// Lookup implements Source.
func (s EchoSource) Lookup(ctx context.Context, family Family) (string, error) {
	if s.URL == "" {
		return "", fmt.Errorf("no echo endpoint configured (set --echo-url or echoUrl in config)")
	}
	ua := s.UserAgent
	if ua == "" {
		ua = DefaultUserAgent
	}
	return detectFamily(ctx, family.network("tcp"), s.URL, ua)
}

// Describe implements Source.
func (s EchoSource) Describe() string { return fmt.Sprintf("echo endpoint %s", s.URL) }

// DNSSource resolves addresses by looking up a hostname — typically a DynDNS
// name that already tracks the user's connection. This avoids having to deploy
// the echo server at all.
//
// Server, when set, is the DNS server to query directly (host or host:port,
// default port 53). Pointing this at the DynDNS provider's authoritative
// nameserver bypasses intermediate caches, which matters because a resolver
// caching longer than the apply interval yields silently stale firewall rules.
type DNSSource struct {
	Hostname string
	Server   string

	// lookupIP overrides the resolver in tests. Nil means use the real one.
	lookupIP func(ctx context.Context, network, host string) ([]net.IP, error)
}

// Lookup implements Source.
func (s DNSSource) Lookup(ctx context.Context, family Family) (string, error) {
	if s.Hostname == "" {
		return "", fmt.Errorf("no DNS hostname configured (set --dns-hostname or dnsHostname in config)")
	}

	lookup := s.lookupIP
	if lookup == nil {
		lookup = s.resolver().LookupIP
	}

	network := family.network("ip")
	ips, err := lookup(ctx, network, s.Hostname)
	if err != nil {
		// No record of this family is a legitimate "nothing here", not a
		// failure: an IPv4-only DynDNS name simply has no AAAA.
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return "", nil
		}
		return "", fmt.Errorf("resolving %s (%s): %w", s.Hostname, network, err)
	}

	// A DynDNS record can legitimately point somewhere unusable — a router that
	// registered its LAN side, for instance. Such an address must never become a
	// firewall rule, so skip it rather than trusting the record blindly.
	for _, ip := range ips {
		if isRoutablePublic(ip) {
			return ip.String(), nil
		}
	}
	return "", nil
}

// Describe implements Source.
func (s DNSSource) Describe() string {
	if s.Server != "" {
		return fmt.Sprintf("DNS name %s (via %s)", s.Hostname, s.Server)
	}
	return fmt.Sprintf("DNS name %s", s.Hostname)
}

// resolver returns the system resolver, or one aimed at s.Server when set.
func (s DNSSource) resolver() *net.Resolver {
	if s.Server == "" {
		return net.DefaultResolver
	}
	addr := s.Server
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "53")
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: requestTimeout}
			return d.DialContext(ctx, network, addr)
		},
	}
}

// Mode selects which address families are looked up and which are required.
type Mode int

const (
	// ModeDual looks up both families; IPv4 is required and IPv6 is
	// best-effort. This is the default and matches historical behavior.
	ModeDual Mode = iota
	// ModeV4Only looks up IPv4 only, and requires it.
	ModeV4Only
	// ModeV6Only looks up IPv6 only, and requires it. This is the mode for
	// DS-Lite connections, which have no public IPv4 at all.
	ModeV6Only
	// ModeAuto looks up both families and succeeds if either resolves.
	ModeAuto
)

// ParseMode converts a config/flag string to a Mode.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "dual":
		return ModeDual, nil
	case "v4only", "v4":
		return ModeV4Only, nil
	case "v6only", "v6":
		return ModeV6Only, nil
	case "auto":
		return ModeAuto, nil
	default:
		return 0, fmt.Errorf("unknown ip mode %q (want \"dual\", \"auto\", \"v4only\" or \"v6only\")", s)
	}
}

func (m Mode) String() string {
	switch m {
	case ModeV4Only:
		return "v4only"
	case ModeV6Only:
		return "v6only"
	case ModeAuto:
		return "auto"
	default:
		return "dual"
	}
}

// wants reports whether mode m looks up the given family.
func (m Mode) wants(f Family) bool {
	switch m {
	case ModeV4Only:
		return f == FamilyV4
	case ModeV6Only:
		return f == FamilyV6
	default:
		return true
	}
}

// Result holds the resolved public addresses. Either field may be empty.
type Result struct {
	V4, V6 string
}

// Resolve looks up the address families required by mode from src and validates
// that everything the mode requires was found.
//
// Families the mode does not want are never looked up, so a DS-Lite user in
// ModeV6Only pays no IPv4 timeout. Under ModeDual an IPv6 failure is tolerated
// (v6 comes back empty); under ModeAuto a failure of either family is tolerated
// as long as the other resolves.
func Resolve(ctx context.Context, src Source, mode Mode) (Result, error) {
	var res Result
	var v4Err, v6Err error

	if mode.wants(FamilyV4) {
		res.V4, v4Err = src.Lookup(ctx, FamilyV4)
	}
	if mode.wants(FamilyV6) {
		res.V6, v6Err = src.Lookup(ctx, FamilyV6)
	}

	switch mode {
	case ModeV4Only:
		if err := required(FamilyV4, res.V4, v4Err, src); err != nil {
			return Result{}, err
		}
	case ModeV6Only:
		if err := required(FamilyV6, res.V6, v6Err, src); err != nil {
			return Result{}, err
		}
	case ModeAuto:
		if res.V4 == "" && res.V6 == "" {
			return Result{}, fmt.Errorf("no public address found via %s: IPv4: %v; IPv6: %v",
				src.Describe(), errOrNone(v4Err), errOrNone(v6Err))
		}
	default: // ModeDual
		if err := required(FamilyV4, res.V4, v4Err, src); err != nil {
			return Result{}, fmt.Errorf("%w (use --ip-mode v6only on a DS-Lite connection, "+
				"or --ip-mode auto to proceed with whichever family resolves)", err)
		}
	}

	return res, nil
}

// required turns a missing-but-required family into an error.
func required(f Family, addr string, err error, src Source) error {
	if err != nil {
		return fmt.Errorf("detecting public %s via %s: %w", f, src.Describe(), err)
	}
	if addr == "" {
		return fmt.Errorf("no public %s found via %s", f, src.Describe())
	}
	return nil
}

func errOrNone(err error) string {
	if err == nil {
		return "no address"
	}
	return err.Error()
}
