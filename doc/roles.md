# Roles (RBAC)

Status: **V1 backend, additive.** No behavior change on upgrade. The
dashboard UI and the deeper follow-ups (removing the operators
allowlist, multi-user password login, onboarding-approve scoping, audit
log) are intentionally **not** in this change — see [Not in
V1](#not-in-v1).

## Why

Before this, authorization was binary. Any caller who cleared the
dashboard gate — the root password, or a tailnet login in the
`tailscale { operators = [...] }` allowlist — could do everything: edit
any profile, set any credential, approve any device. There was no way
to say "this operator may only manage the `avocet2` profile."

Roles add a layer on top of the existing identity gate: the gate still
decides *who you are*; roles decide *what you may do*.

## Model

Identity is decoupled from transport. A Tailscale whois login and a
dashboard password are two **identity providers** that bind to a user;
roles live in the database, not in the tailnet. The same role model
therefore works for a WireGuard-only node — which has no whois — the
moment that node gets a password (or, later, an OIDC) identity. This is
the property the standup flagged that pure Tailscale-groups ACLs can
never have.

Three tiers, weakest to strongest:

| Role     | Capability                                                  |
| -------- | ----------------------------------------------------------- |
| `viewer` | read the dashboard                                          |
| `editor` | viewer + assign devices to a profile + edit credentials     |
| `admin`  | editor + grant/revoke roles                                 |

Each grant is a **binding** of `(role, scope)`:

- `scope = "*"` — global; the role applies to every profile.
- `scope = "profile:<name>"` — the role applies to that one profile.

A global `editor` may edit every profile. A `profile:avocet2` editor
may assign devices to `avocet2` and nothing else, and may **not** edit
credentials (credentials are global — see
`migrations/sqlite/0011_credentials_global.sql`).

## Schema

`migrations/sqlite/0020_rbac.sql`:

```
rbac_users         (id, display_name, disabled, created_ns, updated_ns)
rbac_identities    (provider, external_id) -> user_id     provider ∈ {password, tailscale}
rbac_role_bindings (user_id, role, scope)
```

One user per identity in V1 (the user id encodes the identity); the
split into three tables keeps the door open for a future
many-identities-per-user merge and for new providers (`oidc`,
`device_token`) without a reshape.

## Enforcement

The middleware chain in `web.go` `handler()` is:

```
dashboardAuthGate( tailnetGate( authzGate( mux ) ) )
```

`dashboardAuthGate` and `tailnetGate` are unchanged — they still
establish the `principal` (password session or tailnet whois).
`authzGate` (new, `roles_api.go`) runs last:

1. resolves the principal to its `(role, scope)` bindings;
2. blocks `/api/rbac/{users,grant,revoke}` unless the caller is
   `admin/*`;
3. attaches the bindings to the request context for per-handler scope
   checks.

Per-handler scope checks:

| Handler                       | Check                          |
| ----------------------------- | ------------------------------ |
| `apiAgentProfile`             | `canEditProfile(targetProfile)`|
| `apiCredentialsSet` / `Clear` | `canEditGlobal` (creds global) |

## Backward compatibility

This change ships **additive**. The hinge is `effectiveBindings`: the
first time an already-gated identity is seen with no bindings, it is
lazily granted `admin/*`. Because the only identities that reach
`authzGate` are ones the existing gates already admit (root password,
or a login matching the `operators` allowlist), every caller keeps the
exact access they had before. Narrowing a principal is **opt-in**: an
admin revokes the `admin/*` binding and grants something tighter.

`seedRBAC` (called at boot from `main.go`) seeds the root password user
and every concrete operator login as `admin/*`, but never overwrites an
existing binding — so a narrower grant set by an admin survives
restarts. Wildcard operator entries (`*@domain`) are seeded lazily on
first request.

## API

All under `/api/rbac/`, reachable on the dashboard auth path; `authzGate`
enforces the role requirement.

- `GET  /api/rbac/me` — caller's own bindings + derived capabilities
  (the SPA uses this to show/hide controls). Any authorized caller.
- `GET  /api/rbac/users` — list users with identities + bindings.
  Admin only.
- `POST /api/rbac/grant` — `{provider, external_id, role, scope}`.
  Upsert a binding. Admin only. Scope is validated against declared
  profiles.
- `POST /api/rbac/revoke` — `{provider, external_id, role, scope}`.
  Delete a binding. Admin only. Refuses to revoke the caller's own
  `admin/*` (self-lockout guard).

Example — restrict an operator to one profile:

```sh
# grant scoped editor
curl -X POST .../api/rbac/grant -d \
  '{"provider":"tailscale","external_id":"alice@example.com","role":"editor","scope":"profile:avocet2"}'
# remove their inherited admin
curl -X POST .../api/rbac/revoke -d \
  '{"provider":"tailscale","external_id":"alice@example.com","role":"admin","scope":"*"}'
```

## Not in V1

Deferred deliberately; each is a follow-up:

- **Dashboard UI** for grant/revoke (the API is ready).
- **Removing the `operators` allowlist.** Today it stays the hard
  tailnet gate; roles only refine what an admitted operator may do.
  Making roles the *sole* authority is a breaking change to
  `gateway.hcl` and to how the first admin bootstraps — out of scope
  here.
- **Multi-user password login.** The schema supports it; the login
  form is still root-only.
- **Onboarding `/approve` scoping.** Still on the existing operator
  gate, not yet `canEditProfile`-scoped.
- **Audit log** of grants/revokes/edits.
