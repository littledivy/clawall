# Localhost upstreams → source-device tunnel IP (design)

Status: **proposal** (cl-ukn8). Not yet implemented. Depends on the
run-time host-loopback forwarder from PR #589 (`clawpatrol run`), which
at time of writing lives on a side branch and is **not merged to main**.

## Problem

A user who wants to reach a service on their *own* host naively writes a
loopback upstream:

```hcl
endpoint "local_pg" "postgres" {
  host = "localhost:5432"   # or "127.0.0.1:5432"
}
```

This looks reasonable but silently dials the *gateway's* loopback, not
the author's (traced below). The Proposal makes this bare form a compile
error and offers `tunnel = tunnel.clawpatrol.self` as the explicit,
correct spelling.

`localhost` is a hostname, not an IP literal, so it is treated as a
resolvable host and claims a DNS-VIP at policy build
(`hasResolvableHostname`, `internal/config/compile.go:527`;
`RebuildFromPolicy`, `cmd/clawpatrol/dnsvip/dnsvip.go`). The agent
resolves `localhost` to that VIP, connects to it inside the WG/tsnet
netstack, and the gateway dispatches the connection
(`handleVIPConn` → `dispatchConnEndpoint`, `cmd/clawpatrol/main.go:1621`,
`:1703`).

The plugin then picks its upstream from the declared hosts and dials it:

- postgres: `ch.DialUpstream(ctx, "tcp", upstreamAddr)`,
  `internal/config/plugins/endpoints/postgres.go:271`
- ssh: `pickUpstream(ep.Hosts, ch.DstPort)` then
  `ch.DialUpstream(...)`, `internal/config/plugins/endpoints/ssh.go:151`

`DialUpstream` is the closure built in `dispatchConnEndpoint`
(`cmd/clawpatrol/main.go:1736`); it calls `g.dialThrough`
(`cmd/clawpatrol/tunnel.go:480`), which — absent a tunnel — falls back
to `g.dialer.DialContext`. That dialer runs on the **gateway's host
network**, so `localhost:5432` resolves to the *gateway's* own
loopback. The agent meant *its own* localhost (the postgres running on
the agent's host). Wrong target, silent.

This is the VIP/gateway-path counterpart to PR #589, which solved the
same "reach the agent host's loopback" problem for the
`clawpatrol run` wrapped-command path only.

## Proposal

Reaching the source device's own loopback is **opt-in and explicit**:
the endpoint declares the built-in `tunnel = tunnel.clawpatrol.self`
reference. A bare `host = "localhost:5432"` with **no** tunnel is a
compile error — the bare form silently dialed the *gateway's* loopback,
which is never what the author meant (see Open question 1). When an
endpoint bound to `tunnel.clawpatrol.self` is dispatched, the gateway
rewrites its dial target to **the source device's tunnel IP** and dials
it **back through the netstack** (not the host dialer). On the device
side, the existing PR #589 reverse-relay redirects that inbound
`tunnelIP:port` connection to the device's host loopback.

```hcl
endpoint "local_pg" "postgres" {
  host   = "localhost:5432"
  tunnel = tunnel.clawpatrol.self
}
```

```
agent app ──dial localhost:5432──▶ DNS-VIP ──▶ gateway VIP conn
gateway: endpoint tunnel is tunnel.clawpatrol.self
      └─ rewrite target → <sourceDeviceTunnelIP>:5432
      └─ dial back THROUGH the netstack (ts.Dial / wg netstack), not host net
device netns: inbound on tunnelIP:5432
      └─ PR #589 reverse-relay REDIRECT → host 127.0.0.1:5432 (real postgres)
```

The source device tunnel IP is already in hand at dispatch:
`pip := peerIP(c)` in `dispatchConnEndpoint`
(`cmd/clawpatrol/main.go:1710`), captured by the `DialUpstream` closure.
`tunnel.clawpatrol.self` resolves to that `pip` at dial time — it is
deliberately **not** a named device, so a device can only ever reach
its *own* loopback, never another device's (see Threat model). Sharing
one device's loopback service to other devices is out of scope; use
Tailscale for that.

## Open questions — resolved

### 1. How are localhost upstreams declared / validated in HCL?

**Decision: make the source-device loopback an explicit, built-in
tunnel reference — `tunnel = tunnel.clawpatrol.self`.** A loopback
`host` is meaningful in three distinct ways, and the HCL must
disambiguate them rather than guessing from the hostname:

| HCL                                            | Meaning                                              | Verdict |
| ---------------------------------------------- | ---------------------------------------------------- | ------- |
| `host = "localhost:5432"` (no tunnel)          | the *gateway's* own loopback — never the author's intent | **compile error** |
| `host = "localhost:5432"`, `tunnel = local_command.x` | loopback on the **far side** of a real tunnel (cloud_sql_proxy, kubectl-portforward-ssh, …) | **allowed, no rewrite** |
| `host = "localhost:5432"`, `tunnel = tunnel.clawpatrol.self` | the **source device's own** loopback (this feature) | **allowed, rewrite to `pip`** |

Reaching a loopback *through a real tunnel* is a common, legitimate
pattern (a service bound to `127.0.0.1` on the tunnel's far end, not
exposed to the internet). The earlier draft rejected "loopback +
explicit tunnel" outright; that was wrong — it would break exactly that
pattern. Such endpoints need **no special handling**: the tunnel
command already listens on its own loopback and the dispatcher dials it
as today (`feature_tunnel.hcl`). Only `tunnel.clawpatrol.self` triggers
the source-device rewrite.

`tunnel.clawpatrol.self` is a **built-in / reserved** tunnel reference,
not a user `tunnel "<type>" "<name>"` block. `self` is deliberately
device-agnostic: it binds to whichever device's VIP connection is live
at dispatch (`peerIP(c)`), so it can never name or reach a *different*
device's loopback. (Cross-device loopback sharing is explicitly a
non-goal — Tailscale already covers it.)

Add at compile time (`compileEndpoint`, `internal/config/compile.go`):

- Parse `tunnel.clawpatrol.self` as a reserved reference and set a
  `CompiledEndpoint.SelfTunnel bool` flag (no per-host string re-parse
  on the dispatch path).
- Validation:
  - A bare loopback `host` with no `tunnel` is a config error
    (`localhost`/`127.0.0.1`/`::1`, reuse `isLoopback`,
    `internal/config/config.go:1537`). Error text should point at
    `tunnel.clawpatrol.self`.
  - `tunnel.clawpatrol.self` requires the **reverse-relay capability**
    on the device side (PR #589). It is only meaningful for the direct
    VIP path, so it cannot be combined with another `tunnel = ...`
    block on the same endpoint.
  - A real-tunnel endpoint with a loopback `host` is accepted unchanged.
- A `tunnel.clawpatrol.self` endpoint still claims a VIP (it must, to be
  intercepted), as tunneled endpoints already force `RequiresVIP` on.

### 2. Per-device VIP→tunnel-IP mapping lifecycle + netns-side redirect

**Decision: no persistent per-device VIP allocation. Resolve to the
tunnel IP at dial time, per connection.** The VIP table stays
device-agnostic (one VIP per hostname, as today). The
device-specificity is applied late, in `DialUpstream`, using
`peerIP(c)` of the live connection. This avoids a per-device VIP
lifecycle entirely and matches the existing model where the same VIP
serves all devices and the profile filter + dispatch decide routing.

The netns-side redirect is **not new** — it is exactly the PR #589
reverse-relay (agent-netns worker installs an iptables nat REDIRECT,
host-netns supervisor bidi-copies to host loopback). The only new
requirement is that the relay must accept connections arriving on the
**tunnel IP** (from the gateway), not only `127.0.0.1` from the wrapped
command. See "Device-side dependency" below.

### 3. Approval flow + dashboard rendering

**Decision: no change to the approval chain; cosmetic dashboard change
only.** Approval keys off endpoint + rule + profile + agent IP
(`runApproveChain`, via the `Approve` closure in
`dispatchConnEndpoint`, `cmd/clawpatrol/main.go:1764`) — none of which
the rewrite touches. The dial-target rewrite happens *after* the
allow/approve decision, inside `DialUpstream`.

Dashboard: the event `Host` is the dialed hostname (`localhost`,
`eventHost`, `cmd/clawpatrol/main.go:1718`). Rendering raw `localhost`
is ambiguous across devices. Render it as `localhost (→ <device>)` or
keep `Host=localhost` and surface the resolved tunnel IP in the request
detail facets so operators can see which device's loopback was hit.

## Implementation sketch

### Gateway side (this repo, this feature)

The single choke point is the `DialUpstream` closure
(`cmd/clawpatrol/main.go:1736`). `pip` is already captured.

```go
DialUpstream: func(ctx context.Context, network, addr string) (net.Conn, error) {
    if addr == "" {
        return nil, fmt.Errorf("conn dispatch: plugin gave empty upstream addr")
    }
    // tunnel.clawpatrol.self: the agent meant ITS OWN localhost, not the
    // gateway's. Redirect to the source device's tunnel IP and dial
    // back through the netstack so the device-side reverse-relay
    // (PR #589) lands it on the device's host loopback. A real tunnel
    // (local_command.*, kubectl-portforward-ssh, …) falls through to
    // g.dialThrough unchanged — its loopback is the far end, not pip.
    if ep.SelfTunnel { // compile-time flag, not string re-parse
        _, port, err := net.SplitHostPort(addr)
        if err != nil {
            return nil, err
        }
        return g.dialBackToDevice(ctx, network, net.JoinHostPort(pip, port))
    }
    return g.dialThrough(ctx, ep, network, addr)
},
```

`dialBackToDevice` must dial **into the netstack**, not the host
network:

- **tsnet mode**: `tsnet.Server.Dial` routes through the tailnet to the
  peer (`run_tsnet_common.go:43` already uses `ts.Dial` as a transport;
  the gateway holds the server via `openListener`, `tailscale.go:83`).
- **WG mode**: dial via the embedded gVisor netstack
  (`tsnet.Server.Sys().Netstack` → `*netstack.Impl`, see
  `installTsnetUDPDNSCatchAll`, `tailscale.go:263`), targeting the
  peer's WG tunnel IP. `g.dialer` / `net.DialTimeout`
  (`wgRelay`, `main.go:3442`) are host-network and must **not** be used
  here.

Plumb the netstack dialer onto `Gateway` at startup (where the WG
server / tsnet server is created, `main.go:3027`, `:3077`) so
`dialBackToDevice` has a handle.

### Device-side dependency (PR #589 + extension)

PR #589's reverse-relay redirects `127.0.0.1:*` connect()s *from the
wrapped command* to the host loopback. For this feature the relay must
also catch connections arriving **from the gateway on the tunnel IP**.
Two options:

- **A (preferred): widen the REDIRECT match** so the nat rule captures
  `-d <tunnelIP> --dport <p>` (or the netns's TUN-facing address) in
  addition to `127.0.0.1`, routing both to the same host-loopback
  supervisor path. The SO_MARK/`-m mark RETURN` exemption that lets the
  worker's own dials bypass still applies unchanged.
- **B: a dedicated listener** on the tunnel IP per exposed loopback
  port that forwards to the supervisor. More moving parts; only if the
  iptables widening proves infeasible across the netns address layout.

This is its own bead — it cannot land until #589 is merged to main.

## Staging / dependency order

1. **Blocked on #589 merge to main.** Verify the reverse-relay is in
   `main`; this feature's device side extends it.
2. **cl-ukn8a — `tunnel.clawpatrol.self` parsing + validation.** Parse
   the reserved reference, set `CompiledEndpoint.SelfTunnel`; reject a
   bare loopback `host` with no tunnel; reject `tunnel.clawpatrol.self`
   combined with another tunnel. Leave real-tunnel loopback endpoints
   untouched. Pure config change, fully unit-testable
   (`internal/config/compile_test.go`), independent of #589.
3. **cl-ukn8b — gateway netstack dial-back.** Plumb the netstack dialer
   onto `Gateway`; add `dialBackToDevice`; rewrite the `DialUpstream`
   closure to fire on `ep.SelfTunnel`. Unit-test the rewrite decision;
   integration-test needs the device side.
4. **cl-ukn8c — device-side reverse-relay tunnel-IP capture** (option A
   above). Depends on #589 + cl-ukn8b.
5. **cl-ukn8d — dashboard rendering** of `localhost (→ device)`.

Step 2 is shippable and useful on its own (it makes a bare-loopback
mistake a load-time error pointing at `tunnel.clawpatrol.self`, instead
of a silent wrong-host dial). Steps 3–4 are the end-to-end feature and
gate on #589.

## Threat model notes

- The rewrite only ever targets `peerIP(c)` — the *source* device's own
  tunnel IP. A device can only ever reach its own loopback, never
  another device's, because `pip` is the connection's authenticated WG
  peer. No cross-device punch-through.
- Dialing must go through the netstack, so the target is constrained to
  the tailnet/WG address space; it cannot be steered at the gateway
  host's services or arbitrary IPs.
- The rewrite is opt-in via `tunnel.clawpatrol.self`, which is
  device-agnostic by construction (`self` = the live `peerIP(c)`), so it
  cannot name a third device. A bare loopback `host` is rejected at
  compile time, and a loopback reached over a *real* tunnel lands on
  that tunnel's far end — never on `pip` — so neither path can be
  steered at a third party.
- The device-side REDIRECT widening inherits #589's SO_MARK exemption
  and CAP_NET_ADMIN-less wrapped command — the agent app still cannot
  bypass the relay.
