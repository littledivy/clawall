package main

// Role-based access control. See migrations/sqlite/0020_rbac.sql for
// the data model and the rationale for decoupling identity from
// transport.
//
// The model is three tiers crossed with a scope:
//
//	viewer  read-only dashboard access
//	editor  viewer + profile assignment + credential / OAuth edits
//	admin   editor + user/role management
//
// A binding's scope is either scopeGlobal ("*") or a single profile
// ("profile:<name>"). A global editor may edit every profile; a
// profile-scoped editor may only touch the one named profile and may
// not edit global credentials.
//
// Backward compatibility: any identity the dashboard gate already lets
// through (root password, or a tailnet login matching the operators
// allowlist) is lazily granted admin/* the first time it is seen, so
// upgrading an existing deployment changes no behavior. Narrowing a
// principal is opt-in — an admin revokes the admin/* binding and
// grants something tighter.

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// RBAC roles, weakest to strongest.
const (
	roleViewer = "viewer"
	roleEditor = "editor"
	roleAdmin  = "admin"
)

// Binding scopes. scopeGlobal grants the role across every profile;
// otherwise a binding is pinned to one profile via scopeProfilePrefix.
const (
	scopeGlobal        = "*"
	scopeProfilePrefix = "profile:"
)

// Identity providers. A tailnet login and a dashboard username are two
// providers binding to (possibly different) users — the role model
// does not care which transport the request arrived on.
const (
	rbacProviderPassword  = "password"
	rbacProviderTailscale = "tailscale"
)

// profileScope builds the scope string for a single profile.
func profileScope(name string) string { return scopeProfilePrefix + name }

// roleRank orders the tiers so a stronger role satisfies a weaker
// requirement. Unknown strings rank 0 and satisfy nothing.
func roleRank(role string) int {
	switch role {
	case roleViewer:
		return 1
	case roleEditor:
		return 2
	case roleAdmin:
		return 3
	}
	return 0
}

// validRole reports whether role is one of the three known tiers.
func validRole(role string) bool { return roleRank(role) > 0 }

// roleBinding is a single (role, scope) grant.
type roleBinding struct {
	Role  string `json:"role"`
	Scope string `json:"scope"`
}

// providerForPrincipal maps a request principal to its RBAC identity
// coordinates. ok is false for principals that carry no stable
// identity (which never reach an authorized route).
func providerForPrincipal(p principal) (provider, externalID string, ok bool) {
	switch p.Kind {
	case principalDashboardPassword:
		return rbacProviderPassword, p.Owner, p.Owner != ""
	case principalTailnet:
		return rbacProviderTailscale, p.Owner, p.Owner != ""
	}
	return "", "", false
}

// rbacUserID is the stable internal id for an identity. One user per
// identity in V1 (id encodes the binding); the schema still supports
// many identities per user for a future merge.
func rbacUserID(provider, externalID string) string {
	return provider + ":" + externalID
}

// ensureUser inserts the user + identity rows for (provider,
// externalID) if absent and returns the user id. Idempotent.
func ensureUser(db *sql.DB, provider, externalID, displayName string) (string, error) {
	if db == nil {
		return "", fmt.Errorf("no db")
	}
	if provider == "" || externalID == "" {
		return "", fmt.Errorf("rbac: empty provider or external id")
	}
	id := rbacUserID(provider, externalID)
	now := time.Now().UnixNano()
	if displayName == "" {
		displayName = externalID
	}
	if _, err := db.Exec(
		`INSERT INTO rbac_users (id, display_name, disabled, created_ns, updated_ns)
		 VALUES (?, ?, 0, ?, ?)
		 ON CONFLICT(id) DO NOTHING`,
		id, displayName, now, now,
	); err != nil {
		return "", fmt.Errorf("rbac: ensure user: %w", err)
	}
	if _, err := db.Exec(
		`INSERT INTO rbac_identities (provider, external_id, user_id, created_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(provider, external_id) DO NOTHING`,
		provider, externalID, id, now,
	); err != nil {
		return "", fmt.Errorf("rbac: ensure identity: %w", err)
	}
	return id, nil
}

// bindingsForUser returns every (role, scope) grant for a user id.
func bindingsForUser(db *sql.DB, userID string) ([]roleBinding, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	rows, err := db.Query(
		`SELECT role, scope FROM rbac_role_bindings WHERE user_id = ? ORDER BY role, scope`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []roleBinding
	for rows.Next() {
		var b roleBinding
		if err := rows.Scan(&b.Role, &b.Scope); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// grantRole ensures the user exists and upserts a (role, scope)
// binding. Validates the role tier; scope shape is the caller's
// responsibility (the API layer validates against declared profiles).
func grantRole(db *sql.DB, provider, externalID, role, scope string) error {
	if !validRole(role) {
		return fmt.Errorf("rbac: unknown role %q", role)
	}
	if scope == "" {
		return fmt.Errorf("rbac: empty scope")
	}
	userID, err := ensureUser(db, provider, externalID, "")
	if err != nil {
		return err
	}
	_, err = db.Exec(
		`INSERT INTO rbac_role_bindings (user_id, role, scope, created_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(user_id, role, scope) DO NOTHING`,
		userID, role, scope, time.Now().UnixNano(),
	)
	return err
}

// revokeRole removes one (role, scope) binding for the identity.
// Idempotent — revoking an absent binding is a no-op.
func revokeRole(db *sql.DB, provider, externalID, role, scope string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	_, err := db.Exec(
		`DELETE FROM rbac_role_bindings WHERE user_id = ? AND role = ? AND scope = ?`,
		rbacUserID(provider, externalID), role, scope,
	)
	return err
}

// --- authorization predicates -------------------------------------

// hasGlobal reports whether any binding grants at least minRole at the
// global scope.
func hasGlobal(bindings []roleBinding, minRole string) bool {
	want := roleRank(minRole)
	for _, b := range bindings {
		if b.Scope == scopeGlobal && roleRank(b.Role) >= want {
			return true
		}
	}
	return false
}

// canView reports whether the principal may read the dashboard. Any
// binding at any scope is enough — a profile-scoped editor still needs
// to see the dashboard to do its job.
func canView(bindings []roleBinding) bool { return len(bindings) > 0 }

// canManageUsers reports whether the principal may grant/revoke roles.
// Admin at the global scope only.
func canManageUsers(bindings []roleBinding) bool { return hasGlobal(bindings, roleAdmin) }

// canEditGlobal reports whether the principal may perform an
// unscoped write (e.g. editing a credential, which is global). Global
// editor or admin.
func canEditGlobal(bindings []roleBinding) bool { return hasGlobal(bindings, roleEditor) }

// canEditProfile reports whether the principal may edit the named
// profile — a global editor/admin, or an editor/admin scoped to that
// profile.
func canEditProfile(bindings []roleBinding, profile string) bool {
	if hasGlobal(bindings, roleEditor) {
		return true
	}
	want := profileScope(profile)
	for _, b := range bindings {
		if b.Scope == want && roleRank(b.Role) >= roleRank(roleEditor) {
			return true
		}
	}
	return false
}

// --- request-scoped role context ----------------------------------

type rolesContextKey struct{}

func contextWithRoles(ctx context.Context, bindings []roleBinding) context.Context {
	return context.WithValue(ctx, rolesContextKey{}, bindings)
}

func rolesFromContext(ctx context.Context) ([]roleBinding, bool) {
	b, ok := ctx.Value(rolesContextKey{}).([]roleBinding)
	return b, ok
}

// --- seeding -------------------------------------------------------

// effectiveBindings resolves a principal to its bindings, lazily
// granting admin/* the first time an already-gated identity is seen.
// This is the backward-compatibility hinge: every caller the dashboard
// gate admits keeps full access until an admin narrows them.
func effectiveBindings(db *sql.DB, p principal) ([]roleBinding, error) {
	provider, externalID, ok := providerForPrincipal(p)
	if !ok {
		return nil, fmt.Errorf("rbac: principal has no identity")
	}
	userID, err := ensureUser(db, provider, externalID, p.Host)
	if err != nil {
		return nil, err
	}
	bindings, err := bindingsForUser(db, userID)
	if err != nil {
		return nil, err
	}
	if len(bindings) == 0 {
		if err := grantRole(db, provider, externalID, roleAdmin, scopeGlobal); err != nil {
			return nil, err
		}
		bindings = []roleBinding{{Role: roleAdmin, Scope: scopeGlobal}}
	}
	return bindings, nil
}

// seedRBAC bootstraps role rows at startup so the dashboard reflects
// them before anyone logs in. The root password user becomes admin/*,
// and every concrete operator login (non-wildcard entries) is seeded
// admin/* too. Wildcard operator entries ("*@domain") and any login
// not listed here are seeded lazily by effectiveBindings on first
// request. Existing bindings are never overwritten, so admin edits
// survive restarts.
func seedRBAC(db *sql.DB, operators []string) error {
	if db == nil {
		return fmt.Errorf("no db")
	}
	if err := seedAdminIfUnbound(db, rbacProviderPassword, dashboardRootUsername); err != nil {
		return fmt.Errorf("rbac: seed root: %w", err)
	}
	for _, entry := range operators {
		if strings.HasPrefix(entry, "*@") || !strings.Contains(entry, "@") {
			continue // wildcard / non-login — handled lazily
		}
		if err := seedAdminIfUnbound(db, rbacProviderTailscale, entry); err != nil {
			return fmt.Errorf("rbac: seed operator %q: %w", entry, err)
		}
	}
	return nil
}

// seedAdminIfUnbound grants admin/* to an identity only when it has no
// bindings yet, preserving any narrower grant an admin set later.
func seedAdminIfUnbound(db *sql.DB, provider, externalID string) error {
	userID, err := ensureUser(db, provider, externalID, "")
	if err != nil {
		return err
	}
	bindings, err := bindingsForUser(db, userID)
	if err != nil {
		return err
	}
	if len(bindings) > 0 {
		return nil
	}
	return grantRole(db, provider, externalID, roleAdmin, scopeGlobal)
}

// --- listing (for the management API) ------------------------------

// rbacUserView is the dashboard-facing shape of a user: its identities
// folded in and its bindings sorted for stable rendering.
type rbacUserView struct {
	ID          string        `json:"id"`
	DisplayName string        `json:"display_name"`
	Provider    string        `json:"provider"`
	ExternalID  string        `json:"external_id"`
	Bindings    []roleBinding `json:"bindings"`
}

// listRBACUsers returns every user with its identity + bindings, sorted
// by id for deterministic output.
func listRBACUsers(db *sql.DB) ([]rbacUserView, error) {
	if db == nil {
		return nil, fmt.Errorf("no db")
	}
	rows, err := db.Query(
		`SELECT u.id, u.display_name, i.provider, i.external_id
		   FROM rbac_users u
		   JOIN rbac_identities i ON i.user_id = u.id
		  ORDER BY u.id`,
	)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []rbacUserView
	for rows.Next() {
		var v rbacUserView
		if err := rows.Scan(&v.ID, &v.DisplayName, &v.Provider, &v.ExternalID); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for i := range out {
		b, err := bindingsForUser(db, out[i].ID)
		if err != nil {
			return nil, err
		}
		out[i].Bindings = b
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
