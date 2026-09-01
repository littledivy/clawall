package main

// Dashboard endpoints + middleware for RBAC. The middleware
// (authzGate) runs after the identity gates (dashboardAuthGate,
// tailnetGate) have injected a principal: it resolves the principal to
// its role bindings, enforces admin-only management routes, and stashes
// the bindings on the request context for per-handler scope checks.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// RBAC management route paths. /me is readable by any authorized
// caller (the SPA uses it to hide controls it can't use); the rest
// mutate or list grants and require admin/*.
const (
	rbacRouteMe     = "/api/rbac/me"
	rbacRouteUsers  = "/api/rbac/users"
	rbacRouteGrant  = "/api/rbac/grant"
	rbacRouteRevoke = "/api/rbac/revoke"
)

// isRBACAdminRoute reports whether path is an RBAC management route
// that requires admin/*. /api/rbac/me is excluded — it only reflects
// the caller's own grants.
func isRBACAdminRoute(path string) bool {
	return strings.HasPrefix(path, "/api/rbac/") && path != rbacRouteMe
}

// authzGate resolves the request principal to its role bindings,
// enforces admin-only management routes, and attaches the bindings to
// the context for downstream scope checks. Public and
// self-authenticating routes carry no dashboard principal and are
// passed straight through.
func (w *webMux) authzGate(next http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		req := w.authRequirementForPath(r.URL.Path)
		if req == authPublic || req == authSelfAuthenticating {
			next.ServeHTTP(rw, r)
			return
		}
		p, ok := principalFromContext(r.Context())
		if !ok {
			// No principal on a gated route should be impossible — the
			// upstream gates 401/403 first. Pass through defensively
			// rather than masking that bug with a confusing 403 here.
			next.ServeHTTP(rw, r)
			return
		}
		bindings, err := effectiveBindings(w.g.db, p)
		if err != nil {
			http.Error(rw, "authz lookup failed", http.StatusServiceUnavailable)
			return
		}
		if !canView(bindings) {
			http.Error(rw, "no role grants for this identity", http.StatusForbidden)
			return
		}
		if isRBACAdminRoute(r.URL.Path) && !canManageUsers(bindings) {
			http.Error(rw, "role management requires admin", http.StatusForbidden)
			return
		}
		next.ServeHTTP(rw, r.WithContext(contextWithRoles(r.Context(), bindings)))
	})
}

// apiRBACMe returns the caller's own bindings + derived capabilities so
// the dashboard can show/hide controls.
func (w *webMux) apiRBACMe(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	bindings, _ := rolesFromContext(r.Context())
	writeJSON(rw, map[string]any{
		"bindings":     bindings,
		"can_manage":   canManageUsers(bindings),
		"can_edit_all": canEditGlobal(bindings),
	})
}

// apiRBACUsers lists every user with identities + bindings. Admin-only
// (enforced by authzGate).
func (w *webMux) apiRBACUsers(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(rw, "GET", http.StatusMethodNotAllowed)
		return
	}
	users, err := listRBACUsers(w.g.db)
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, users)
}

// rbacGrantBody is the shared shape for grant/revoke. provider is
// "password" or "tailscale"; external_id is the username or whois
// login; scope is "*" or "profile:<name>".
type rbacGrantBody struct {
	Provider   string `json:"provider"`
	ExternalID string `json:"external_id"`
	Role       string `json:"role"`
	Scope      string `json:"scope"`
}

// validateScope accepts "*" or "profile:<name>" where the profile is
// declared in the loaded policy. A scope naming an unknown profile is
// rejected so a typo can't mint a binding that grants nothing (or, on
// a later profile rename, silently grants something).
func (w *webMux) validateScope(scope string) bool {
	if scope == scopeGlobal {
		return true
	}
	name, ok := strings.CutPrefix(scope, scopeProfilePrefix)
	if !ok || name == "" {
		return false
	}
	for _, n := range orderedProfileNames(w.g.cfg.Policy) {
		if n == name {
			return true
		}
	}
	return false
}

func validProvider(p string) bool {
	return p == rbacProviderPassword || p == rbacProviderTailscale
}

// apiRBACGrant upserts a (role, scope) binding for an identity.
func (w *webMux) apiRBACGrant(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body rbacGrantBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if !validProvider(body.Provider) || body.ExternalID == "" {
		http.Error(rw, "missing or invalid provider/external_id", http.StatusBadRequest)
		return
	}
	if !validRole(body.Role) {
		http.Error(rw, "role must be viewer, editor, or admin", http.StatusBadRequest)
		return
	}
	if !w.validateScope(body.Scope) {
		http.Error(rw, `scope must be "*" or "profile:<declared-profile>"`, http.StatusBadRequest)
		return
	}
	if err := grantRole(w.g.db, body.Provider, body.ExternalID, body.Role, body.Scope); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}

// apiRBACRevoke deletes one (role, scope) binding. Revoking the last
// admin/* binding is allowed — the lazy seed in effectiveBindings will
// not re-grant admin to an identity that still has any other binding,
// so an admin can fully demote an operator. Guard against locking
// everyone out by refusing to revoke the caller's own last admin
// binding.
func (w *webMux) apiRBACRevoke(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(rw, "POST", http.StatusMethodNotAllowed)
		return
	}
	var body rbacGrantBody
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(rw, err.Error(), http.StatusBadRequest)
		return
	}
	if !validProvider(body.Provider) || body.ExternalID == "" {
		http.Error(rw, "missing or invalid provider/external_id", http.StatusBadRequest)
		return
	}
	// Self-lockout guard: don't let an admin revoke their own admin/*
	// if it's their only admin grant.
	if body.Role == roleAdmin && body.Scope == scopeGlobal {
		if p, ok := principalFromContext(r.Context()); ok {
			prov, ext, ok := providerForPrincipal(p)
			if ok && prov == body.Provider && ext == body.ExternalID {
				http.Error(rw, "refusing to revoke your own admin/* binding", http.StatusBadRequest)
				return
			}
		}
	}
	if err := revokeRole(w.g.db, body.Provider, body.ExternalID, body.Role, body.Scope); err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(rw, map[string]any{"ok": true})
}
