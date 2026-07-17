// Command netcup-autofirewall locks a NetCup server's firewall down to SSH from
// the current machine's public IP only, keeping the rule current across runs.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/go-co-op/gocron/v2"

	"github.com/hra42/netcup-autofirewall/internal/auth"
	"github.com/hra42/netcup-autofirewall/internal/cloudflare"
	"github.com/hra42/netcup-autofirewall/internal/config"
	"github.com/hra42/netcup-autofirewall/internal/firewall"
	"github.com/hra42/netcup-autofirewall/internal/pubip"
	"github.com/hra42/netcup-autofirewall/internal/scp"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	var err error
	switch cmd {
	case "login":
		err = cmdLogin(ctx, args)
	case "apply":
		err = cmdApply(ctx, args)
	case "run":
		err = cmdRun(ctx, args)
	case "status":
		err = cmdStatus(ctx, args)
	case "logout":
		err = cmdLogout(ctx, args)
	case "-h", "--help", "help":
		usage()
		return
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `netcup-autofirewall — restrict SSH to your current public IP via NetCup SCP

Usage:
  netcup-autofirewall login    Authenticate (device flow) and store a refresh token
  netcup-autofirewall apply    Detect public IP, upsert the SSH policy, attach it
                               (--cf: also allow HTTPS from Cloudflare;
                                --wg: also allow WireGuard on UDP 51820)
  netcup-autofirewall run      Run apply now, then on a cron schedule (daemon)
  netcup-autofirewall status   Show detected IPs and current firewall state (read-only)
  netcup-autofirewall logout   Revoke the refresh token and clear stored credentials

Run "netcup-autofirewall <command> -h" for command flags.
`)
}

// commonFlags holds config-overriding flags shared by the mutating commands.
type commonFlags struct {
	configPath    string
	serverID      int
	mac           string
	sshPort       string
	policyName    string
	echoURL       string
	echoUserAgent string
}

func addCommonFlags(fs *flag.FlagSet, cf *commonFlags) {
	fs.StringVar(&cf.configPath, "config", "", "path to config file (default: $XDG_CONFIG_HOME/netcup-autofirewall/config.json)")
	fs.IntVar(&cf.serverID, "server-id", 0, "SCP server id (overrides config)")
	fs.StringVar(&cf.mac, "mac", "", "network interface MAC (overrides config)")
	fs.StringVar(&cf.sshPort, "ssh-port", "", "SSH port to allow (overrides config; default 22)")
	fs.StringVar(&cf.policyName, "policy-name", "", "firewall policy name (overrides config)")
	fs.StringVar(&cf.echoURL, "echo-url", "", "self-hosted echo endpoint for public-IP detection (overrides config)")
	fs.StringVar(&cf.echoUserAgent, "echo-user-agent", "", "User-Agent sent to the echo endpoint (overrides config)")
}

// resolveConfig loads the config and applies flag overrides. It returns the
// effective config and the resolved config path (for saving back).
func resolveConfig(cf *commonFlags) (*config.Config, string, error) {
	path := cf.configPath
	if path == "" {
		p, err := config.DefaultPath()
		if err != nil {
			return nil, "", err
		}
		path = p
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, "", err
	}
	if cf.serverID != 0 {
		cfg.ServerID = cf.serverID
	}
	if cf.mac != "" {
		cfg.MAC = cf.mac
	}
	if cf.sshPort != "" {
		cfg.SSHPort = cf.sshPort
	}
	if cf.policyName != "" {
		cfg.PolicyName = cf.policyName
	}
	if cf.echoURL != "" {
		cfg.EchoURL = cf.echoURL
	}
	if cf.echoUserAgent != "" {
		cfg.EchoUserAgent = cf.echoUserAgent
	}
	return cfg, path, nil
}

// authClient refreshes the access token and returns an SCP client. If the
// refresh rotated the refresh token, it is persisted back to configPath.
func authClient(ctx context.Context, cfg *config.Config, configPath string) (*scp.Client, error) {
	if cfg.RefreshToken == "" {
		return nil, fmt.Errorf("not authenticated; run \"netcup-autofirewall login\" first")
	}
	tok, err := auth.Refresh(ctx, cfg.RefreshToken)
	if err != nil {
		return nil, err
	}
	if tok.RefreshToken != "" && tok.RefreshToken != cfg.RefreshToken {
		cfg.RefreshToken = tok.RefreshToken
		if err := config.Save(configPath, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "warning: could not persist rotated refresh token: %v\n", err)
		}
	}
	return scp.NewClient(tok.AccessToken), nil
}

// ensureUserID resolves and caches the SCP user id if not already known.
func ensureUserID(ctx context.Context, client *scp.Client, cfg *config.Config, configPath string) error {
	if cfg.UserID != 0 {
		return nil
	}
	id, err := client.GetUserID(ctx)
	if err != nil {
		return err
	}
	cfg.UserID = id
	if err := config.Save(configPath, cfg); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not persist user id: %v\n", err)
	}
	return nil
}

func cmdLogin(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := resolveConfig(&cf)
	if err != nil {
		return err
	}

	da, err := auth.StartDeviceAuth(ctx)
	if err != nil {
		return err
	}

	fmt.Println("To authenticate, open this URL in your browser and approve access:")
	fmt.Printf("\n    %s\n\n", da.VerificationURIComplete)
	fmt.Printf("(user code: %s)\n\n", da.UserCode)
	fmt.Println("Waiting for authorization...")

	tok, err := auth.PollToken(ctx, da)
	if err != nil {
		return err
	}
	if tok.RefreshToken == "" {
		return fmt.Errorf("no refresh token returned; ensure the offline_access grant was approved")
	}
	cfg.RefreshToken = tok.RefreshToken

	// Resolve the user id now while we hold a fresh access token.
	client := scp.NewClient(tok.AccessToken)
	if id, err := client.GetUserID(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "warning: could not resolve user id now (will retry on apply): %v\n", err)
	} else {
		cfg.UserID = id
	}

	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Printf("Authenticated. Credentials stored in %s\n", path)
	if cfg.UserID != 0 {
		fmt.Printf("SCP user id: %d\n", cfg.UserID)
	}
	return nil
}

func cmdApply(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("apply", flag.ExitOnError)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	yes := fs.Bool("yes", false, "skip the confirmation prompt")
	cfMode := fs.Bool("cf", false, "also allow HTTPS (443) from Cloudflare's edge ranges")
	wgMode := fs.Bool("wg", false, "also allow WireGuard (UDP 51820) from any source")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := resolveConfig(&cf)
	if err != nil {
		return err
	}
	// --cf / --wg, when passed, override the config toggle for this run.
	if flagPassed(fs, "cf") {
		cfg.Cloudflare = *cfMode
	}
	if flagPassed(fs, "wg") {
		cfg.WireGuard = *wgMode
	}
	if err := requireTarget(cfg); err != nil {
		return err
	}

	return runApply(ctx, cfg, path, *yes)
}

func cmdRun(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	schedule := fs.String("schedule", "", "cron expression for recurring applies (overrides config; default \"*/15 * * * *\")")
	cfMode := fs.Bool("cf", false, "also allow HTTPS (443) from Cloudflare's edge ranges")
	wgMode := fs.Bool("wg", false, "also allow WireGuard (UDP 51820) from any source")
	once := fs.Bool("once", false, "run a single apply and exit (no scheduling)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := resolveConfig(&cf)
	if err != nil {
		return err
	}
	if flagPassed(fs, "cf") {
		cfg.Cloudflare = *cfMode
	}
	if flagPassed(fs, "wg") {
		cfg.WireGuard = *wgMode
	}
	if *schedule != "" {
		cfg.Schedule = *schedule
	}
	if err := requireTarget(cfg); err != nil {
		return err
	}

	// apply runs one cycle; scheduled runs never prompt.
	apply := func() {
		fmt.Printf("\n=== apply @ %s ===\n", time.Now().Format(time.RFC3339))
		if err := runApply(ctx, cfg, path, true); err != nil {
			fmt.Fprintf(os.Stderr, "apply failed: %v\n", err)
		}
	}

	// Run immediately on start so the firewall is correct without waiting for the
	// first scheduled tick.
	apply()

	if *once {
		return nil
	}

	sched, err := gocron.NewScheduler()
	if err != nil {
		return fmt.Errorf("creating scheduler: %w", err)
	}
	if _, err := sched.NewJob(
		gocron.CronJob(cfg.Schedule, false),
		gocron.NewTask(apply),
	); err != nil {
		return fmt.Errorf("scheduling job with cron %q: %w", cfg.Schedule, err)
	}

	sched.Start()
	fmt.Printf("Scheduled: cron %q. Press Ctrl-C to stop.\n", cfg.Schedule)

	// Block until interrupted, then shut the scheduler down cleanly.
	<-ctx.Done()
	fmt.Println("\nShutting down scheduler...")
	if err := sched.Shutdown(); err != nil {
		return fmt.Errorf("scheduler shutdown: %w", err)
	}
	return nil
}

// runApply performs one full apply cycle: detect the public IP, upsert and
// attach the SSH policy, and reconcile the optional Cloudflare/WireGuard
// policies. When skipConfirm is false it prompts interactively before mutating.
// This is the reusable core shared by the apply command and the run daemon.
func runApply(ctx context.Context, cfg *config.Config, path string, skipConfirm bool) error {
	targets := cfg.Targets()
	if len(targets) == 0 {
		return fmt.Errorf("no targets configured (set serverId+mac or a targets list)")
	}

	// 1. Detect public IPs.
	v4, v6, err := pubip.Detect(ctx, cfg.EchoURL, cfg.EchoUserAgent)
	if err != nil {
		return err
	}
	if v6 == "" {
		fmt.Fprintln(os.Stderr, "warning: no public IPv6 detected; allowing IPv4 only")
	}

	// 2. Build SSH rules (shared across targets).
	rules, err := firewall.BuildSSHRules(v4, v6, cfg.SSHPort)
	if err != nil {
		return err
	}

	// 3. Confirm (interactive runs only).
	fmt.Println("About to restrict SSH access on:")
	for _, t := range targets {
		fmt.Printf("  server %d interface %s\n", t.ServerID, t.MAC)
	}
	fmt.Printf("  ssh port  : %s\n", cfg.SSHPort)
	fmt.Println("Allowing SSH only from:")
	fmt.Printf("  IPv4: %s\n", orNone(v4))
	fmt.Printf("  IPv6: %s\n", orNone(v6))
	fmt.Println("All other source IPs will be denied on the SSH port.")
	if !skipConfirm {
		if !confirm("Proceed?") {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// 4. Authenticate.
	client, err := authClient(ctx, cfg, path)
	if err != nil {
		return err
	}
	if err := ensureUserID(ctx, client, cfg, path); err != nil {
		return err
	}

	// 5. Upsert the user-scoped policies once (they are shared across targets).
	sshPolicyID, created, err := client.UpsertPolicy(ctx, cfg.UserID, cfg.PolicyName,
		"Managed by netcup-autofirewall: SSH allowed from current public IP only.", rules)
	if err != nil {
		return err
	}
	fmt.Printf("%s SSH policy %q (id %d).\n", createdWord(created), cfg.PolicyName, sshPolicyID)

	// Upsert the optional policies if any target needs them.
	cfPolicyID, err := upsertCloudflarePolicy(ctx, client, cfg)
	if err != nil {
		return err
	}
	wgPolicyID, err := upsertWireGuardPolicy(ctx, client, cfg)
	if err != nil {
		return err
	}

	// 6. Reconcile each target's attachments. A failure on one target does not
	// abort the others.
	var firstErr error
	for _, t := range targets {
		if err := reconcileTarget(ctx, client, cfg, t, sshPolicyID, cfPolicyID, wgPolicyID); err != nil {
			fmt.Fprintf(os.Stderr, "target server %d (%s): %v\n", t.ServerID, t.MAC, err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// reconcileTarget brings one interface to the desired state in a single write:
// the SSH policy (and enabled Cloudflare/WireGuard policies) attached, disabled
// ones detached, all other policies preserved. Combining these into one write
// avoids the SCP API's 409 "write already running" from back-to-back writes.
func reconcileTarget(ctx context.Context, client *scp.Client, cfg *config.Config, t config.Target, sshPolicyID, cfPolicyID, wgPolicyID int) error {
	fmt.Printf("\nTarget: server %d interface %s\n", t.ServerID, t.MAC)

	ensurePresent := []int{sshPolicyID}
	var ensureAbsent []string

	if cfg.CloudflareFor(t) {
		ensurePresent = append(ensurePresent, cfPolicyID)
	} else {
		ensureAbsent = append(ensureAbsent, cfg.CloudflarePolicyName)
	}
	if cfg.WireGuardFor(t) {
		ensurePresent = append(ensurePresent, wgPolicyID)
	} else {
		ensureAbsent = append(ensureAbsent, cfg.WireGuardPolicyName)
	}

	res, err := client.ReconcileInterface(ctx, t.ServerID, t.MAC, ensurePresent, ensureAbsent)
	if err != nil {
		return err
	}
	warnImplicit(res.Firewall)
	if !res.Changed {
		fmt.Println("  already in desired state; no change.")
		return nil
	}
	fmt.Println("  updated interface policies.")
	if res.Task != nil {
		fmt.Printf("  firewall update task: %s (state: %s)\n", res.Task.UUID, orNone(res.Task.State))
	}
	return nil
}

// upsertCloudflarePolicy creates/updates the cloudflare-https policy when the
// mode is enabled and returns its id (0 when disabled).
func upsertCloudflarePolicy(ctx context.Context, client *scp.Client, cfg *config.Config) (int, error) {
	if !cfg.AnyCloudflare() {
		return 0, nil
	}
	ranges, err := cloudflare.FetchRanges(ctx)
	if err != nil {
		return 0, err
	}
	rules, err := firewall.BuildCloudflareHTTPSRules(ranges.V4, ranges.V6)
	if err != nil {
		return 0, err
	}
	id, created, err := client.UpsertPolicy(ctx, cfg.UserID, cfg.CloudflarePolicyName,
		"Managed by netcup-autofirewall: allow HTTPS (443) from Cloudflare edge ranges.", rules)
	if err != nil {
		return 0, err
	}
	fmt.Printf("%s Cloudflare policy %q (id %d; %d v4 + %d v6 ranges).\n",
		createdWord(created), cfg.CloudflarePolicyName, id, len(ranges.V4), len(ranges.V6))
	return id, nil
}

// upsertWireGuardPolicy creates/updates the wireguard policy when the mode is
// enabled and returns its id (0 when disabled).
func upsertWireGuardPolicy(ctx context.Context, client *scp.Client, cfg *config.Config) (int, error) {
	if !cfg.AnyWireGuard() {
		return 0, nil
	}
	rules, err := firewall.BuildWireGuardRules(cfg.WireGuardPort)
	if err != nil {
		return 0, err
	}
	id, created, err := client.UpsertPolicy(ctx, cfg.UserID, cfg.WireGuardPolicyName,
		"Managed by netcup-autofirewall: allow WireGuard (UDP) from any source.", rules)
	if err != nil {
		return 0, err
	}
	fmt.Printf("%s WireGuard policy %q (id %d; UDP %s).\n",
		createdWord(created), cfg.WireGuardPolicyName, id, cfg.WireGuardPort)
	return id, nil
}

func createdWord(created bool) string {
	if created {
		return "Created"
	}
	return "Updated"
}

func cmdStatus(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := resolveConfig(&cf)
	if err != nil {
		return err
	}

	v4, v6, ipErr := pubip.Detect(ctx, cfg.EchoURL, cfg.EchoUserAgent)
	fmt.Println("Detected public IP:")
	if ipErr != nil {
		fmt.Printf("  (detection failed: %v)\n", ipErr)
	} else {
		fmt.Printf("  IPv4: %s\n", orNone(v4))
		fmt.Printf("  IPv6: %s\n", orNone(v6))
	}

	if err := requireTarget(cfg); err != nil {
		fmt.Printf("\n%v\n", err)
		return nil
	}

	client, err := authClient(ctx, cfg, path)
	if err != nil {
		return err
	}
	if err := ensureUserID(ctx, client, cfg, path); err != nil {
		return err
	}

	managed := []string{cfg.PolicyName, cfg.CloudflarePolicyName, cfg.WireGuardPolicyName}
	for _, t := range cfg.Targets() {
		fmt.Printf("\nInterface firewall (server %d, %s):\n", t.ServerID, t.MAC)
		fw, err := client.GetFirewall(ctx, t.ServerID, t.MAC)
		if err != nil {
			fmt.Printf("  error reading firewall: %v\n", err)
			continue
		}
		fmt.Printf("  active            : %t\n", fw.Active)
		fmt.Printf("  ingress implicit  : %s\n", orNone(fw.IngressImplicitRule))
		fmt.Printf("  egress implicit   : %s\n", orNone(fw.EgressImplicitRule))
		fmt.Printf("  user policies     : %s\n", policyNames(fw.UserPolicies))
		fmt.Printf("  copied policies   : %s\n", policyNames(fw.CopiedPolicies))
		for _, name := range managed {
			printManagedPolicy(fw, name)
		}
		warnImplicit(fw)
	}
	return nil
}

// printManagedPolicy prints the rules of the named policy if it is attached, or
// a note that it is not.
func printManagedPolicy(fw *scp.ServerFirewall, name string) {
	for _, p := range fw.UserPolicies {
		if p.Name == name {
			fmt.Printf("\nPolicy %q (id %d) is attached with %d rule(s):\n", p.Name, p.ID, len(p.Rules))
			for _, r := range p.Rules {
				fmt.Printf("  - %s %s %s sources=%s dports=%s\n",
					r.Direction, r.Protocol, r.Action, summarizeSources(r.Sources), orAny2(r.DestinationPorts))
			}
			return
		}
	}
	fmt.Printf("\nPolicy %q is not attached to this interface.\n", name)
}

func cmdLogout(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	var cf commonFlags
	addCommonFlags(fs, &cf)
	if err := fs.Parse(args); err != nil {
		return err
	}

	cfg, path, err := resolveConfig(&cf)
	if err != nil {
		return err
	}
	if cfg.RefreshToken == "" {
		fmt.Println("No stored credentials.")
		return nil
	}
	if err := auth.Revoke(ctx, cfg.RefreshToken); err != nil {
		fmt.Fprintf(os.Stderr, "warning: revoke failed (clearing local credentials anyway): %v\n", err)
	}
	cfg.RefreshToken = ""
	cfg.UserID = 0
	if err := config.Save(path, cfg); err != nil {
		return err
	}
	fmt.Println("Logged out; refresh token revoked and cleared.")
	return nil
}

// flagPassed reports whether the named flag was explicitly set on the command line.
func flagPassed(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// requireTarget ensures at least one target (serverId+MAC, or a targets list) is
// configured.
func requireTarget(cfg *config.Config) error {
	if len(cfg.Targets()) == 0 {
		return fmt.Errorf("missing required target: set --server-id and --mac, or a \"targets\" list in the config")
	}
	return nil
}

func warnImplicit(fw *scp.ServerFirewall) {
	if fw != nil && fw.IngressImplicitRule == scp.ImplicitAcceptAll {
		fmt.Fprintln(os.Stderr,
			"note: interface ingress implicit rule is ACCEPT_ALL — ports other than SSH remain open to all IPs.")
	}
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil {
		return false
	}
	line = strings.ToLower(strings.TrimSpace(line))
	return line == "y" || line == "yes"
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

// summarizeSources renders a source list, collapsing long lists (e.g. Cloudflare
// ranges) to the first few plus a count so status output stays readable.
func summarizeSources(ss []string) string {
	if len(ss) == 0 {
		return "any"
	}
	const max = 3
	if len(ss) <= max {
		return strings.Join(ss, ",")
	}
	return fmt.Sprintf("%s,… (%d total)", strings.Join(ss[:max], ","), len(ss))
}

func orAny2(s string) string {
	if s == "" {
		return "any"
	}
	return s
}

func policyNames(policies []scp.FirewallPolicy) string {
	if len(policies) == 0 {
		return "(none)"
	}
	names := make([]string, len(policies))
	for i, p := range policies {
		names[i] = fmt.Sprintf("%s(#%d)", p.Name, p.ID)
	}
	return strings.Join(names, ", ")
}
