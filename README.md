# netcup-autofirewall

A small Go CLI that restricts **SSH access on a NetCup server to your current
public IP** using NetCup's Server Control Panel (SCP) API. On each run it detects
your public IPv4/IPv6, writes them into a firewall policy named
`ssh-autofirewall`, and attaches that policy to the target interface —
**alongside** any policies already there, never replacing them.

The policy contains three ingress rules on the SSH port:

1. `ACCEPT` from your current public IPv4 (`/32`)
2. `ACCEPT` from your current public IPv6 (`/128`)
3. `DROP` from everyone else

Re-running `apply` after your IP changes updates the same policy in place, so it
never accumulates stale policies.

Public-IP detection is **self-hosted**: no third-party service ever sees your IP.
You run a tiny `echo-server` (included) on a machine you control — typically
behind Cloudflare on 443 — and the CLI asks it "what's my IP?".

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

### 2. Deploy the echo server

Public-IP detection uses your own `echo-server`, so no external service is
involved. Run it on a machine the CLI can reach — a good choice is another server
of yours behind Cloudflare on 443, which also breaks the chicken-and-egg problem
(the locked-down box can always reach a *different* box on 443).

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

### 3. Configure the target and endpoint

The CLI needs the **server id**, the **interface MAC** (both from the SCP web
UI), and the **echo endpoint URL**:

```sh
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

`apply` detects your public IP via the echo endpoint, shows exactly which IPs
will be allowed, asks for confirmation, then upserts and attaches the policy.

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

### WireGuard mode

Pass `--wg` to additionally allow inbound **WireGuard** on **UDP 51820** from any
source:

```sh
netcup-autofirewall apply --wg --yes
```

WireGuard authenticates peers cryptographically, so exposing the port to any IP
is the normal configuration (peers roam / use dynamic addresses). This manages a
separate `wireguard` policy (one INGRESS UDP ACCEPT rule), attached alongside the
others. The port is configurable via `"wireguardPort"` in the config.

Enable persistently with `"wireguard": true`; turn off with `apply --wg=false`
(detaches the `wireguard` policy, others untouched).

`--cf` and `--wg` combine freely — `apply --cf --wg --yes` maintains SSH,
Cloudflare HTTPS, and WireGuard together.

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
  "echoUrl": "https://ip.example.com/",
  "echoUserAgent": "",
  "cloudflare": false,
  "cloudflarePolicyName": "cloudflare-https",
  "wireguard": false,
  "wireguardPort": "51820",
  "wireguardPolicyName": "wireguard",
  "schedule": "*/15 * * * *"
}
```

Every field can be overridden per-run: `--config`, `--server-id`, `--mac`,
`--ssh-port`, `--policy-name`, `--echo-url`, `--echo-user-agent`, `--schedule`.
`userId` is resolved automatically from the API and cached.

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
