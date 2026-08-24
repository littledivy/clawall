# Configure the gateway

[Getting Started](/docs/getting-started/) gets you running with
the example config, untouched. This page covers the operational
tuning you reach for as soon as you take the gateway past
"kick-the-tyres" — different control plane, dashboard auth,
where to bind the dashboard, systemd, state-dir hardening, and
the rest.

## Transports: WireGuard, Tailscale, or both

Block presence inside the `gateway {}` block selects the transport.
The example config uses WireGuard:

```hcl
gateway {
  public_url = "https://gw.example.com"
  state_dir  = "/opt/clawpatrol"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
  }
}
```

If your fleet already lives on a tailnet, swap (or add) embedded tsnet:

```hcl
gateway {
  public_url = "https://gw.example.com"
  state_dir  = "/opt/clawpatrol"

  tailscale {
    authkey             = "{{secret:TS_AUTHKEY}}"
    funnel              = true
    tags                = ["tag:clawpatrol"]
    oauth_client_id     = "<tailscale oauth client id>"
    oauth_client_secret = "<tailscale oauth client secret>"
  }
}
```

Embedded tsnet joins the tailnet in-process — no UDP port to open,
no `iptables` rule, no host Tailscale daemon. `funnel = true` lets
non-tailnet devices reach the gateway over Tailscale Funnel.

Both blocks can coexist — peers from either transport land in the
same MITM handler. Drop either block to disable that transport.

#### Required tailnet ACL

The gateway routes client traffic by acting as their **Tailscale
exit node**. Clients call `EditPrefs(ExitNodeIP=<gateway>)` once
they join; routing only works if the tailnet ACL **auto-approves
the gateway as an exit node** for the client tag. Without this,
clients set the pref locally but every outbound dial silently
times out — the gateway never sees the traffic.

In your tailnet's ACL JSON, add (or extend) `autoApprovers`:

```jsonc
{
  "autoApprovers": {
    "exitNode": ["tag:clawpatrol"]   // matches tailscale.tags above
  },
  "tagOwners": {
    "tag:clawpatrol": ["autogroup:admin"]
  }
}
```

The tag must be the one you set in `tailscale.tags` on the
gateway config. If you skip this step, the daemon logs a
`tsnet probe: gateway unreachable via exit-node routing — check
autoApprovers.exitNode in your tailnet ACL` warning on first
boot, and every `clawpatrol run` hangs at "joining tailnet".

### WireGuard endpoint

The default WireGuard listener is `:51820` (set
`wireguard.listen_port` to override). Clients dial
`host(public_url):port`, so you only set `wireguard.endpoint` when
you need a non-default port advertised to clients or a different
host for WG than for the dashboard:

```hcl
wireguard {
  subnet_cidr = "10.55.0.0/24"
  listen_port = 41820                     # server binds this UDP port
  endpoint    = "wg.example.com:51820"    # advertised in client wg.conf
}
```

### Single-host (loopback) WireGuard

Running the gateway and `clawpatrol run` on the same machine — the
gateway under one user account, agents launched from another — is a
supported deployment, not a debug mode. Pin the advertised endpoint
to loopback so onboarded clients dial the gateway over the loopback
interface:

```hcl
gateway {
  state_dir = "/opt/clawpatrol"

  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint    = "127.0.0.1:51820"
  }
}
```

No `public_url`, no public UDP port. Useful for tightly-scoped
agent sandboxes that share a host with the gateway.

## Dashboard auth

**The dashboard is how operators connect endpoint credentials
and inspect live traffic, so it requires a password on every
request.**

The first time you open the dashboard you set a `root` password.
It lives bcrypt-hashed in `clawpatrol.db` and is checked on every
subsequent request. You can also manage the password from the CLI:

```bash
clawpatrol gateway --set-dashboard-password '<password>' gateway.hcl
clawpatrol gateway --reset-dashboard-password gateway.hcl
```

### Where to bind the dashboard

`gateway.dashboard_listen` is the dashboard's host-side HTTP bind.
The shapes that make sense for it — and the auth shortcuts available
on top of the root password — depend on which transport blocks you
declared, because each transport automatically exposes the
dashboard on its own overlay network as well.

#### With `wireguard {}` declared

The in-tunnel forwarder routes any connection to the dashboard port
on the gateway's WG IP to the dashboard, so joined devices reach
`http://<gateway-wg-ip>:8080` with nothing extra configured.
`dashboard_listen` only controls who can reach the dashboard from
**outside** the tunnel:

- **`127.0.0.1:8080`** (the example default) — only loopback.
  Operators who haven't joined as a device themselves reach the
  dashboard via SSH tunnel
  (`ssh -L 8080:127.0.0.1:8080 gateway-host`) or a local reverse
  proxy.
- **`0.0.0.0:8080`** — anyone with network reach to the host sees a
  login page. The root password is the only thing between the
  internet and the dashboard, so only do this when the gateway is
  fronted by an auth proxy (Cloudflare Access, oauth2-proxy) that
  does its own SSO first.

Without a `tailscale {}` block there's no tsnet whois identity to
match against, so the root password is the only auth.

#### With `tailscale {}` declared

The embedded tsnet node always serves the dashboard on the gateway's
tailnet IP at the dashboard port, so tailnet peers reach
`http://<gateway-tailnet-ip>:8080` with no extra configuration.
`dashboard_listen` controls the host-side bind:

- **`127.0.0.1:8080`** (recommended) — keeps the host socket
  loopback-only. Operators reach the dashboard over the tailnet
  using the tsnet IP; SSH tunnel is the out-of-band fallback when
  the tailnet is the thing that's broken.
- **`0.0.0.0:8080`** — also exposes the dashboard on every other
  network interface of the host (LAN, and the public IP if the host
  has one), on top of the always-on tailnet listener. Tailnet peers
  don't need this — they already reach the dashboard through the
  tsnet IP — so the only reason to bind `0.0.0.0` is to let
  something off the tailnet reach the dashboard. Do this only when
  the gateway sits behind an external auth proxy (Cloudflare Access,
  oauth2-proxy) doing its own SSO first; otherwise the root password
  is the only thing between those other interfaces and the
  dashboard.

Operators can be allowlisted by tailnet identity email so they skip
the root-password prompt:

```hcl
tailscale {
  authkey   = "{{secret:TS_AUTHKEY}}"
  operators = [
    "alice@example.com",
    "*@example.com",
  ]
}
```

Each entry is matched against the requesting peer's tsnet whois
login on every dashboard request. Tagged devices (your agents) have
a tag-name login, not a user email, so they never match a wildcard
entry — agent peers can never inherit operator powers through this
path.

`funnel = true` exposes a small allowlist of public-bootstrap routes
(`/api/onboard/{start,poll,claim}`, `/api/cred/*`) on `<node>.ts.net:443`
so off-tailnet devices can join and OAuth callbacks can land. **The
dashboard itself is not Funnel-reachable** — Funnel does not replace
the tailnet (or SSH) path for operator access.

### Dashboard branding

Set `dashboard_name` and `dashboard_logo_url` in `gateway {}` to
replace the bundled Claw Patrol name and logo in the dashboard header
and login page. `dashboard_icon_url` is optional; when omitted, the
dashboard reuses `dashboard_logo_url` for compact/mobile surfaces.

```hcl
gateway {
  dashboard_name     = "Acme Gateway"
  dashboard_logo_url = "https://assets.example.com/acme-logo.svg"
  dashboard_icon_url = "https://assets.example.com/acme-icon.svg"

  # ...
}
```

## Body size limits

The gateway buffers request and response bodies for two independent
purposes, each with its own size limit. Both live in an optional
`limits {}` block inside `gateway {}` and accept human-readable size
strings (`B`, `KiB`, `MiB`, `GiB` — all binary, so `1KiB` = 1024 bytes;
a bare number is bytes):

```hcl
gateway {
  limits {
    body_buffer  = "1MiB"  # buffer at most this much before the rules engine sees it
    body_storage = "4KiB"  # keep at most this much when persisting an action
  }
}
```

| Field | Default | What it bounds |
|-------|---------|----------------|
| `body_buffer` | `1MiB` (1048576 bytes) | The hot-path buffer the rules engine matches against (`http.body` / `http.body_json`). Every request pays this. Larger means rules can match more body at the cost of latency and memory; bodies past the cap are matched on the prefix and flagged truncated so rules whose outcome depends on the body fail closed. |
| `body_storage` | `4KiB` (4096 bytes) | The body sample persisted per action for the audit log shown on the action details page. Cold storage, per action. Larger means more useful debugging at the cost of disk and database size. |

Both fields are optional; omitting the block (or either field) keeps
today's defaults, so existing configs are unaffected. The two limits are
independent — a deployment may deliberately log more than it
rule-matches, or vice versa. If `body_buffer` is set smaller than
`body_storage` the gateway loads but emits a warning, since the rules
engine would then see less of the body than is persisted.

When a persisted body is truncated to the `body_storage` cap, the
action details page renders a **truncated** badge on that body section
so you know you are looking at a prefix, not the whole body.

## Run under systemd

For anything beyond a quick test, run the gateway as a dedicated
service user so its state directory isn't readable by any
non-root user on the box:

```bash
useradd --system --home /opt/clawpatrol --shell /usr/sbin/nologin clawpatrol
chown -R clawpatrol:clawpatrol /opt/clawpatrol
chmod 700 /opt/clawpatrol
```

Drop the following at
`/etc/systemd/system/clawpatrol-gateway.service`, adjusting the
three paths to wherever you put the binary and config:

```ini
[Unit]
Description=clawpatrol gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=clawpatrol
Group=clawpatrol
WorkingDirectory=/opt/clawpatrol
ExecStart=/usr/local/bin/clawpatrol gateway /opt/clawpatrol/gateway.hcl
Restart=on-failure
RestartSec=2
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

Then:

```bash
systemctl daemon-reload
systemctl enable --now clawpatrol-gateway
journalctl -u clawpatrol-gateway -f       # tail the gateway log
```

If you skip the dedicated-user step, the gateway logs a warning
at startup when `state_dir` or `clawpatrol.db` is readable beyond
owner.

## Security notes

A few footguns worth knowing about before you point an agent at a
production Claw Patrol gateway:

- **Don't run agents on the gateway host.** `clawpatrol run` is
  for client devices — the gateway's `state_dir` holds every
  credential the gateway mints plus the audit log. An agent running on
  the gateway host can read those directly, with or without
  `clawpatrol run` in front. The correct shape is: gateway on
  one box (small VPS, no human logins, no developer tools); your
  laptop / CI runner joins it over WireGuard. `clawpatrol run`
  prints a heads-up if it detects a gateway state db in a common
  location.

- **Lock down `state_dir`.** The systemd snippet above creates a
  dedicated `clawpatrol` service user with mode-700 ownership; if
  you skip that, anyone with shell access to the gateway host can
  read every credential. The gateway warns at startup when
  `state_dir` or `clawpatrol.db` is readable beyond owner.

- **`clawpatrol join --whole-machine` is for client devices
  only.** Running it on the gateway host itself routes the host's
  own traffic through its own WireGuard endpoint — a loop that
  breaks DNS, outbound traffic from the gateway daemon, and the
  dashboard's reachability. Per-process routing (the default
  `clawpatrol join` + `clawpatrol run` shape) is also what most
  people actually want on a multi-purpose laptop, so they don't
  accidentally route every browser tab through the gateway.

## Build from source

Released binaries are the supported path. To build from source
instead — for example to track an unreleased branch — set
`CLAWPATROL_FROM_SOURCE=1` on the installer (requires Go):

```bash
curl -fsSL https://clawpatrol.dev/install.sh | CLAWPATROL_FROM_SOURCE=1 sh
```

Set `CLAWPATROL_REF` to install a non-`main` ref.

## What's next

- [Config reference](/docs/config-reference/) — every HCL field, in detail
- [Rules](/docs/rules/) — gating writes behind a human or LLM
- [Architecture](/docs/architecture/) — how interception works
- [Security model](/docs/security-model/) — what Claw Patrol does and doesn't protect against
