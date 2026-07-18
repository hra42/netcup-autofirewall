# netcup-autofirewall

A small Go CLI that restricts **SSH access on a NetCup server to your current
public IP** using NetCup's Server Control Panel (SCP) API. On each run it detects
your public IPv4/IPv6, writes them into a firewall policy named
`ssh-autofirewall`, and attaches that policy to the target interface —
**alongside** any policies already there, never replacing them.

The policy contains one ingress `ACCEPT` on the SSH port per detected address:

1. from your current public IPv4 (`/32`)
2. from your current public IPv6 (`/128`, widenable to your whole prefix)

Everyone else is denied without an explicit rule: attaching any policy flips the
interface's implicit ingress rule to `DROP_ALL`, so whatever is not accepted is
already blocked.

Re-running `apply` after your IP changes updates the same policy in place, so it
never accumulates stale policies.

Optionally it also manages policies for [Cloudflare-only HTTPS](#cloudflare-mode)
and for [WireGuard / OpenVPN](#vpn-mode-wireguard--openvpn), each a separate
policy you can turn on and off independently.

Public-IP detection never involves a third-party service. Use either:

- a **DynDNS hostname** you already maintain (`--dns-hostname`) — nothing to
  deploy, and most people running a VPN already have one; or
- a tiny self-hosted **`echo-server`** (included, `--echo-url`), typically behind
  Cloudflare on 443, which the CLI asks "what's my IP?".

## Install

```sh
go build -o netcup-autofirewall .          # the CLI
go build -o echo-server ./cmd/echo-server  # the IP echo server
```

Requires Go 1.26+.

## Containers

Both binaries ship as container images (multi-stage build → `scratch`, tiny and
static). Examples use `docker`; `podman` works with the same commands, and the
`Containerfile`s are OCI-compatible with any builder.

### echo-server image

```sh
docker build -t netcup-echo-server -f Containerfile.echo-server .
docker run -d -p 8080:8080 --name echo netcup-echo-server
```

Terminate TLS on 443 in front of it (Cloudflare or a reverse proxy) and forward
to `:8080`. Configure via env: `ECHO_ADDR` (listen address) and `ECHO_USER_AGENT`
(the gating User-Agent). A `compose.yaml` is included:

```sh
docker compose up -d       # or podman compose up -d
```

### CLI image

```sh
docker build -t netcup-autofirewall -f Containerfile.cli .
```

The CLI stores its refresh token in a config file, so mount a volume at `/config`
(the image sets `XDG_CONFIG_HOME=/config`) to persist credentials across runs:

```sh
# one-time interactive login (prints a URL you approve in a browser):
docker run -it -v netcup-cfg:/config netcup-autofirewall login

# unattended apply (e.g. from a host cron/timer):
docker run --rm -v netcup-cfg:/config netcup-autofirewall apply --yes
```

The CA bundle is baked in, so HTTPS to the NetCup API and your echo endpoint
works from the `scratch` image.

## Usage

### 1. Authenticate (one time)

```sh
netcup-autofirewall login
```

This runs the OAuth2 device flow: it prints a URL, you open it in a browser, log
in, and approve access (make sure the `offline_access` grant is approved). The
resulting long-lived refresh token is stored in the config file (mode `0600`).

### 2. Choose an IP source

The CLI needs to learn your current public IP. Pick **one** of two sources.

#### Option A: a DynDNS hostname (nothing to deploy)

If you already keep a DynDNS record pointing at your connection — most people
running a VPN do — reuse it. No echo server required:

```sh
netcup-autofirewall apply --dns-hostname home.example.org
```

The A record becomes your IPv4 and the AAAA record your IPv6. Setting
`--dns-hostname` alone switches the source to DNS; nothing else to configure.
Addresses that are not globally routable (a router that registered its LAN
address, say) are skipped rather than written into a rule.

**Beware resolver caching.** If a caching resolver holds the old answer longer
than your apply interval, you get stale rules. Point the lookup straight at your
provider's nameserver to bypass caches:

```sh
netcup-autofirewall apply --dns-hostname home.example.org --dns-server ns1.dyndns-provider.net
```

#### Option B: the self-hosted echo server

Run your own `echo-server` on a machine the CLI can reach — a good choice is
another server of yours behind Cloudflare on 443, which also breaks the
chicken-and-egg problem (the locked-down box can always reach a *different* box
on 443).

```sh
# on the echo host:
./echo-server --addr :8080        # or ECHO_ADDR=:8080
```

Put it behind a reverse proxy / Cloudflare terminating TLS on 443 and forwarding
to `:8080`, with **both** an A and AAAA DNS record so IPv4 and IPv6 detection
both work. The server reports the caller's IP from `CF-Connecting-IP` (Cloudflare
sets this), then `X-Forwarded-For`, then the direct connection.

**Access is gated by User-Agent.** Only requests carrying the expected
User-Agent are served; everything else gets `403`. This keeps casual scanners
out. It is obfuscation, not authentication (the default UA is in the source) — to
gate more strongly, set a private User-Agent on both sides:

```sh
./echo-server --user-agent "my-secret-ua"          # server (or ECHO_USER_AGENT)
netcup-autofirewall apply --echo-user-agent "my-secret-ua" ...   # client
```

`GET /healthz` is always open (no UA required) for uptime checks.

### 3. Configure the target

The CLI needs the **server id** and the **interface MAC** (both from the SCP web
UI), plus your chosen IP source:

```sh
# with a DynDNS name:
netcup-autofirewall apply \
  --server-id 67890 --mac aa:bb:cc:dd:ee:ff \
  --dns-hostname home.example.org

# or with an echo server:
netcup-autofirewall apply \
  --server-id 67890 --mac aa:bb:cc:dd:ee:ff \
  --echo-url https://ip.example.com/
```

All of these persist in the config file, so future runs need no flags.

### 4. Apply

```sh
netcup-autofirewall apply           # prompts for confirmation
netcup-autofirewall apply --yes     # no prompt (for cron/launchd)
```

`apply` detects your public IP via the configured source, shows exactly which
source CIDRs will be allowed, asks for confirmation, then upserts and attaches
the policy.

### Address families (incl. DS-Lite)

By default IPv4 is required and IPv6 is a bonus. That fails outright on a
**DS-Lite** connection, which has no public IPv4 at all. Pick a mode with
`--ip-mode` (or `"ipMode"` in the config):

| Mode | Behavior |
|------|----------|
| `dual` (default) | IPv4 required, IPv6 best-effort. Matches older versions. |
| `v6only` | IPv6 required, IPv4 never looked up. **Use this on DS-Lite.** |
| `v4only` | IPv4 required, IPv6 never looked up. |
| `auto` | Both attempted; succeeds if either resolves. |

```sh
netcup-autofirewall apply --ip-mode v6only --dns-hostname home.example.org
```

A mode never queries a family it does not want, so `v6only` costs no IPv4
timeout.

> **Caution with `auto`.** If a family that worked before transiently fails to
> resolve, `auto` proceeds with whatever is left and the rule for the missing
> family silently disappears — which can lock you out from that family. Prefer an
> explicit `v6only`/`v4only` when you know which families you have.

### IPv6 prefix width

By default the IPv6 rule allows exactly the detected address (`/128`). That is
the tightest setting, and it is right when the address is a stable single host.

It is often *not* what you want at home. Residential ISPs delegate a prefix, and
your devices each hold a different address within it — and privacy extensions
rotate those addresses regularly. A DynDNS AAAA record typically tracks the
router, so a `/128` rule allows only the router itself.

Set `--ipv6-prefix 64` to allow your whole `prefix::/64` instead:

```sh
netcup-autofirewall apply --ipv6-prefix 64
```

This mirrors how IPv4 already behaves: the router's single public IPv4 fronts
every device behind it, so a `/32` IPv4 rule already admits your whole home
network. Host bits are zeroed, so `2001:db8:1:2:3:4:5:6` becomes
`2001:db8:1:2::/64`.

The default stays `/128` so upgrading never widens your allow-list without you
asking. `--ipv4-prefix` exists too, for the rare delegated IPv4 block. Prefixes
shorter than `/8` are rejected — a typo like `6` instead of `64` would otherwise
open SSH to a large slice of the internet.

### Cloudflare mode

Pass `--cf` to additionally allow inbound **HTTPS (443)** from Cloudflare's
published edge ranges — so your origin only accepts Cloudflare-proxied traffic on
443 while SSH stays restricted to your IP. Port 80 is **not** opened.

```sh
netcup-autofirewall apply --cf --yes
```

This fetches the current ranges from `cloudflare.com/ips-v4` and `/ips-v6` at run
time and manages a separate policy named `cloudflare-https` (two ACCEPT rules on
443 — one for IPv4 CIDRs, one for IPv6), attached alongside `ssh-autofirewall`.
Because attaching any policy flips the interface's implicit ingress rule to
`DROP_ALL`, all other inbound ports remain blocked.

Enable it persistently with `"cloudflare": true` in the config (set once, then
plain `apply` keeps it on). To turn it off, run `apply --cf=false` — the
`cloudflare-https` policy is detached (SSH rules untouched).

### VPN mode (WireGuard / OpenVPN)

VPN protocols authenticate peers cryptographically and peers roam between
dynamic addresses, so exposing the VPN port to any source is the normal
configuration. Each VPN gets its own policy, attached alongside the others.

#### WireGuard

```sh
netcup-autofirewall apply --wg --yes                        # UDP 51820
netcup-autofirewall apply --wg --wireguard-port 51821 --yes
```

Manages a `wireguard` policy. WireGuard is UDP-only by protocol design.

#### OpenVPN

```sh
netcup-autofirewall apply --ovpn --yes                              # UDP 1194
netcup-autofirewall apply --ovpn --openvpn-protocol TCP --openvpn-port 443 --yes
```

Manages an `openvpn` policy. Unlike WireGuard, OpenVPN runs over UDP **or** TCP,
so `--openvpn-protocol` accepts either (default `UDP`).

Both can run at once, and combine freely with `--cf`:

```sh
netcup-autofirewall apply --cf --wg --ovpn --yes
```

Enable persistently with `"wireguard": true` / `"openvpn": true`; turn off with
`apply --wg=false` / `apply --ovpn=false` (detaches just that policy).

#### Egress rules, and the implicit-rule trap

**netcup's firewall is not stateful for UDP.** An inbound ACCEPT alone is not
always enough: if the interface's implicit *egress* rule is `DROP_ALL`, the VPN's
replies are dropped on the way out and the tunnel never establishes — even
though the ingress rule looks perfectly correct. The fix is an egress `ACCEPT`
matching the VPN port as the **source** port, since replies leave *from* it.

Adding that rule has a non-obvious consequence:

> **Attaching *any* egress rule flips the interface's implicit egress rule from
> `ACCEPT_ALL` to `DROP_ALL`.**

So adding a UDP egress rule for the VPN would, on its own, **drop all outbound
TCP** as a side effect — package updates, outbound HTTPS, tunnels. The VPN keeps
working, which makes it easy to miss.

Rather than depend on an implicit rule that changes underneath you, the tool
states the permissive behavior explicitly: whenever it emits any egress rule, it
also attaches an **`egress-allow-all`** policy permitting outbound TCP, UDP,
ICMP and ICMPv6. The implicit rule then no longer matters. ICMP is included
because a VPN needs path MTU discovery — without it, large packets hang inside
the tunnel while small ones succeed.

```sh
netcup-autofirewall apply --wg --vpn-egress always --yes
```

`--vpn-egress` takes three values:

| Value | Behavior |
|-------|----------|
| `auto` (default) | Emit VPN egress rules only where the interface's implicit egress rule is already restrictive — exactly where they are needed. |
| `always` | Always emit them (and the `egress-allow-all` policy with them). |
| `never` | Never emit them. |

`auto` reads each interface's current state before building the policies, so it
adapts as that state changes. The `egress-allow-all` policy is attached and
detached together with the egress rules, so turning them off reverts the
interface to `ACCEPT_ALL` rather than stranding it in `DROP_ALL`.

Two knobs for the allowance itself:

- `--egress-allow-all=false` (or `"egressAllowAll": false`) skips the policy. Use
  this only if you manage the interface's egress rules yourself — otherwise the
  interface loses all outbound traffic except the VPN's replies.
- `"egressAllowProtocols": ["TCP", "UDP"]` narrows the protocol set from the
  default four.

`status` shows a note whenever an interface is in `DROP_ALL`, since from then on
every outbound flow needs an explicit rule.

### Scheduled runs (built-in daemon)

Instead of wiring up host cron, the CLI can schedule itself. `run` applies once
immediately, then re-applies on a cron schedule, staying in the foreground until
interrupted:

```sh
netcup-autofirewall run                          # every 15 min (default)
netcup-autofirewall run --schedule "*/5 * * * *" # every 5 min
netcup-autofirewall run --cf --wg                # keep all policies current
netcup-autofirewall run --once                   # apply once and exit (no loop)
```

Scheduled applies never prompt (they run as if `--yes`). A failed cycle is logged
but does not stop the daemon — it retries on the next tick. The schedule persists
via `"schedule"` in the config. It handles `SIGINT`/`SIGTERM` for clean shutdown,
so it works well as a container entrypoint or under systemd:

```sh
docker run -d --restart unless-stopped -v netcup-cfg:/config \
  netcup-autofirewall run --cf --wg
```

### Other commands

```sh
netcup-autofirewall status   # read-only: detected IPs + current firewall state
netcup-autofirewall logout   # revoke the refresh token and clear credentials
```

## Configuration file

Location: `$XDG_CONFIG_HOME/netcup-autofirewall/config.json`
(default `~/.config/netcup-autofirewall/config.json`), written `0600`.

```json
{
  "refreshToken": "<stored by login>",
  "userId": 12345,
  "serverId": 67890,
  "mac": "aa:bb:cc:dd:ee:ff",
  "sshPort": "22",
  "policyName": "ssh-autofirewall",
  "ipv4PrefixLen": 32,
  "ipv6PrefixLen": 128,
  "ipSource": "echo",
  "echoUrl": "https://ip.example.com/",
  "echoUserAgent": "",
  "dnsHostname": "",
  "dnsServer": "",
  "ipMode": "dual",
  "cloudflare": false,
  "cloudflarePolicyName": "cloudflare-https",
  "wireguard": false,
  "wireguardPort": "51820",
  "wireguardPolicyName": "wireguard",
  "openvpn": false,
  "openvpnPort": "1194",
  "openvpnProtocol": "UDP",
  "openvpnPolicyName": "openvpn",
  "vpnEgress": "auto",
  "egressAllowAll": true,
  "egressAllowProtocols": ["TCP", "UDP", "ICMP", "ICMPv6"],
  "egressAllowPolicyName": "egress-allow-all",
  "schedule": "*/15 * * * *"
}
```

`userId` is resolved automatically from the API and cached.

### Managing several interfaces

Instead of a single `serverId`/`mac`, list several targets. Each may override the
`cloudflare`, `wireguard`, and `openvpn` toggles; omitted keys inherit the
top-level value. This lets, for example, only one host run the VPN, or the host
serving your echo endpoint always keep 443 open:

```json
{
  "cloudflare": false,
  "wireguard": true,
  "targets": [
    { "serverId": 67890, "mac": "aa:bb:cc:dd:ee:ff" },
    { "serverId": 67891, "mac": "11:22:33:44:55:66", "cloudflare": true, "wireguard": false }
  ]
}
```

### Flags

Most fields can be overridden per run:

| Area | Flags |
|------|-------|
| General | `--config`, `--server-id`, `--mac`, `--ssh-port`, `--policy-name`, `--schedule` |
| IP source | `--ip-source`, `--echo-url`, `--echo-user-agent`, `--dns-hostname`, `--dns-server` |
| Address handling | `--ip-mode`, `--ipv4-prefix`, `--ipv6-prefix` |
| Services | `--cf`, `--wg`, `--wireguard-port`, `--ovpn`, `--openvpn-port`, `--openvpn-protocol` |
| Egress | `--vpn-egress`, `--egress-allow-all` |

The service toggles are tri-state: leaving one off keeps the config value, while
`--wg=false` explicitly disables it for that run. Per-target overrides and the
policy-name fields are config-only.

## Keeping it current

Your public IP can change, so the allow-list needs periodic refreshing. The
simplest way is the built-in daemon (see [Scheduled runs](#scheduled-runs-built-in-daemon)):

```sh
netcup-autofirewall run --cf --wg     # applies now, then every 15 min
```

If you prefer host scheduling instead, invoke `apply --yes` from cron/launchd:

```
# crontab: refresh the SSH allow-list every 15 minutes
*/15 * * * * /path/to/netcup-autofirewall apply --yes >> /var/log/netcup-autofirewall.log 2>&1
```

## Caveats

- **Lockout risk.** This deliberately restricts SSH. Keep a serial/VNC console
  fallback available until you've confirmed it works. From the allowed IP, SSH
  keeps working; from any other IP, SSH on the configured port is denied.
- **Only the SSH port is governed by this policy.** If the interface's ingress
  implicit rule is `ACCEPT_ALL`, other ports remain open to all IPs — the tool
  prints a note when it detects this. Governing other ports is out of scope.
- **`--ip-mode auto` can widen a lockout.** If a family that previously resolved
  fails transiently, `auto` proceeds without it and that family's rule vanishes.
  Prefer an explicit mode when you know which families you have.
- **DNS caching can serve stale answers.** With `--dns-hostname`, a resolver
  caching longer than your apply interval means the firewall trails your actual
  IP. Use `--dns-server` to query the authoritative nameserver directly.
- **A wider IPv6 prefix is a wider allow-list.** `--ipv6-prefix 64` admits every
  host in your delegated prefix, which is the point at home but is looser than
  the `/128` default. Keep `/128` when the address is a stable single host.
- **Egress rules change the whole outbound policy.** Attaching any egress rule
  flips the interface's implicit egress rule to `DROP_ALL`, after which outbound
  traffic needs explicit rules. The `egress-allow-all` policy covers this
  automatically; disabling it with `--egress-allow-all=false` while egress rules
  are in play will cut the host off from everything except VPN replies.
- **Firewall writes are serialized per user.** The API rejects a write while a
  previous one is still settling. The tool retries with exponential backoff for
  up to 5 minutes; a run that still fails can be re-run safely, since every write
  is an idempotent upsert.
- The SCP `userId` is an internal SCP identifier, **not** your CCP customer
  number; it is resolved automatically via the userinfo endpoint.

## How it maps to the SCP API

| Step | Endpoint |
|------|----------|
| Device auth | `POST /realms/scp/protocol/openid-connect/auth/device` |
| Token / refresh | `POST /realms/scp/protocol/openid-connect/token` |
| Resolve user id | `GET /realms/scp/protocol/openid-connect/userinfo` |
| Find/create/update policy | `.../api/v1/users/{userId}/firewall-policies` |
| Read/attach on interface | `.../api/v1/servers/{serverId}/interfaces/{mac}/firewall` |
