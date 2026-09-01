-- RBAC: transport-agnostic roles.
--
-- Until now authorization was binary: a caller who cleared the
-- dashboard gate (root password, or a tailnet login in the operators
-- allowlist) could do everything — edit any profile, set any
-- credential, approve any device. These tables add a roles layer on
-- top of that gate: identity is established by the existing gate
-- (password session or tailscale whois), then a (role, scope) lookup
-- decides what the identity may actually do.
--
-- Three tables, deliberately decoupled so identity is independent of
-- transport:
--
--   rbac_users         one row per principal (human or machine)
--   rbac_identities    external logins bound to a user — provider is
--                      'password' (dashboard username) or 'tailscale'
--                      (whois login); future: 'oidc', 'device_token'
--   rbac_role_bindings (role, scope) grants per user; scope is '*'
--                      (global) or 'profile:<name>'
--
-- A tailnet login becomes just one identity provider rather than the
-- authorization mechanism, so the same role model works for
-- WireGuard-only nodes (which have no whois) the moment they get a
-- password or OIDC identity.

CREATE TABLE rbac_users (
  id           TEXT PRIMARY KEY,
  display_name TEXT NOT NULL DEFAULT '',
  disabled     INTEGER NOT NULL DEFAULT 0,
  created_ns   INTEGER NOT NULL,
  updated_ns   INTEGER NOT NULL
);

CREATE TABLE rbac_identities (
  provider    TEXT NOT NULL,
  external_id TEXT NOT NULL,
  user_id     TEXT NOT NULL REFERENCES rbac_users(id) ON DELETE CASCADE,
  created_ns  INTEGER NOT NULL,
  PRIMARY KEY (provider, external_id)
);

CREATE INDEX rbac_identities_user_idx ON rbac_identities(user_id);

CREATE TABLE rbac_role_bindings (
  user_id    TEXT NOT NULL REFERENCES rbac_users(id) ON DELETE CASCADE,
  role       TEXT NOT NULL,
  scope      TEXT NOT NULL,
  created_ns INTEGER NOT NULL,
  PRIMARY KEY (user_id, role, scope)
);

CREATE INDEX rbac_role_bindings_user_idx ON rbac_role_bindings(user_id);
