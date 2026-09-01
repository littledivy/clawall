package main

import (
	"database/sql"
	"path/filepath"
	"testing"
)

func newRBACTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := OpenDB(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestRoleRankOrdering(t *testing.T) {
	if roleRank(roleAdmin) <= roleRank(roleEditor) || roleRank(roleEditor) <= roleRank(roleViewer) {
		t.Fatal("role ranks must be admin > editor > viewer")
	}
	if roleRank("nonsense") != 0 {
		t.Fatal("unknown role must rank 0")
	}
}

func TestGrantAndBindings(t *testing.T) {
	db := newRBACTestDB(t)
	if err := grantRole(db, rbacProviderTailscale, "alice@example.com", roleEditor, profileScope("avocet2")); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// Idempotent re-grant.
	if err := grantRole(db, rbacProviderTailscale, "alice@example.com", roleEditor, profileScope("avocet2")); err != nil {
		t.Fatalf("regrant: %v", err)
	}
	bs, err := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "alice@example.com"))
	if err != nil {
		t.Fatalf("bindings: %v", err)
	}
	if len(bs) != 1 || bs[0].Role != roleEditor || bs[0].Scope != profileScope("avocet2") {
		t.Fatalf("unexpected bindings: %+v", bs)
	}
}

func TestGrantRejectsUnknownRole(t *testing.T) {
	db := newRBACTestDB(t)
	if err := grantRole(db, rbacProviderPassword, "root", "superuser", scopeGlobal); err == nil {
		t.Fatal("expected error for unknown role")
	}
}

func TestAuthorizePredicates(t *testing.T) {
	globalAdmin := []roleBinding{{roleAdmin, scopeGlobal}}
	globalEditor := []roleBinding{{roleEditor, scopeGlobal}}
	scopedEditor := []roleBinding{{roleEditor, profileScope("avocet2")}}
	viewerOnly := []roleBinding{{roleViewer, scopeGlobal}}

	cases := []struct {
		name     string
		bindings []roleBinding
		view     bool
		manage   bool
		editAll  bool
		editAvo  bool
		editOrd  bool
	}{
		{"admin", globalAdmin, true, true, true, true, true},
		{"global editor", globalEditor, true, false, true, true, true},
		{"scoped editor", scopedEditor, true, false, false, true, false},
		{"viewer", viewerOnly, true, false, false, false, false},
		{"none", nil, false, false, false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if canView(c.bindings) != c.view {
				t.Errorf("canView = %v, want %v", canView(c.bindings), c.view)
			}
			if canManageUsers(c.bindings) != c.manage {
				t.Errorf("canManageUsers = %v, want %v", canManageUsers(c.bindings), c.manage)
			}
			if canEditGlobal(c.bindings) != c.editAll {
				t.Errorf("canEditGlobal = %v, want %v", canEditGlobal(c.bindings), c.editAll)
			}
			if canEditProfile(c.bindings, "avocet2") != c.editAvo {
				t.Errorf("canEditProfile(avocet2) = %v, want %v", canEditProfile(c.bindings, "avocet2"), c.editAvo)
			}
			if canEditProfile(c.bindings, "ord") != c.editOrd {
				t.Errorf("canEditProfile(ord) = %v, want %v", canEditProfile(c.bindings, "ord"), c.editOrd)
			}
		})
	}
}

func TestSeedRBACRootAndOperators(t *testing.T) {
	db := newRBACTestDB(t)
	ops := []string{"alice@example.com", "*@example.com", "tagged-devices"}
	if err := seedRBAC(db, ops); err != nil {
		t.Fatalf("seed: %v", err)
	}
	// root → admin/*
	rootBindings, _ := bindingsForUser(db, rbacUserID(rbacProviderPassword, dashboardRootUsername))
	if !canManageUsers(rootBindings) {
		t.Fatalf("root must be admin/*, got %+v", rootBindings)
	}
	// concrete operator → admin/*
	aliceBindings, _ := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "alice@example.com"))
	if !canManageUsers(aliceBindings) {
		t.Fatalf("alice must be admin/*, got %+v", aliceBindings)
	}
	// wildcard + non-login entries are NOT pre-seeded
	wildBindings, _ := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "*@example.com"))
	if len(wildBindings) != 0 {
		t.Fatalf("wildcard entry must not be seeded, got %+v", wildBindings)
	}
}

func TestSeedDoesNotOverrideNarrowedGrant(t *testing.T) {
	db := newRBACTestDB(t)
	// Admin narrows alice to a scoped editor.
	if err := grantRole(db, rbacProviderTailscale, "alice@example.com", roleEditor, profileScope("avocet2")); err != nil {
		t.Fatalf("grant: %v", err)
	}
	// A later restart re-seeds operators.
	if err := seedRBAC(db, []string{"alice@example.com"}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	bs, _ := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "alice@example.com"))
	if canManageUsers(bs) {
		t.Fatalf("seed must not re-promote a narrowed operator, got %+v", bs)
	}
	if !canEditProfile(bs, "avocet2") || canEditProfile(bs, "ord") {
		t.Fatalf("narrowed grant must survive restart, got %+v", bs)
	}
}

func TestEffectiveBindingsLazyAdminSeed(t *testing.T) {
	db := newRBACTestDB(t)
	// A wildcard-matched operator with no pre-seed gets admin/* lazily,
	// preserving pre-RBAC behavior.
	p := principal{Kind: principalTailnet, Owner: "bob@example.com", User: "bob@example.com"}
	bs, err := effectiveBindings(db, p)
	if err != nil {
		t.Fatalf("effectiveBindings: %v", err)
	}
	if !canManageUsers(bs) {
		t.Fatalf("first sight of gated identity must be admin/*, got %+v", bs)
	}
	// Persisted, so a second call returns the same without re-seeding.
	again, _ := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "bob@example.com"))
	if !canManageUsers(again) {
		t.Fatalf("lazy seed must persist, got %+v", again)
	}
}

func TestRevokeRole(t *testing.T) {
	db := newRBACTestDB(t)
	_ = grantRole(db, rbacProviderTailscale, "alice@example.com", roleAdmin, scopeGlobal)
	_ = grantRole(db, rbacProviderTailscale, "alice@example.com", roleEditor, profileScope("avocet2"))
	if err := revokeRole(db, rbacProviderTailscale, "alice@example.com", roleAdmin, scopeGlobal); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	bs, _ := bindingsForUser(db, rbacUserID(rbacProviderTailscale, "alice@example.com"))
	if canManageUsers(bs) {
		t.Fatalf("admin should be revoked, got %+v", bs)
	}
	if !canEditProfile(bs, "avocet2") {
		t.Fatalf("scoped editor should remain, got %+v", bs)
	}
}

func TestListRBACUsers(t *testing.T) {
	db := newRBACTestDB(t)
	_ = grantRole(db, rbacProviderPassword, "root", roleAdmin, scopeGlobal)
	_ = grantRole(db, rbacProviderTailscale, "alice@example.com", roleEditor, profileScope("avocet2"))
	users, err := listRBACUsers(db)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(users) != 2 {
		t.Fatalf("want 2 users, got %d: %+v", len(users), users)
	}
	// Sorted by id: "password:root" < "tailscale:alice@..."
	if users[0].Provider != rbacProviderPassword || users[1].Provider != rbacProviderTailscale {
		t.Fatalf("unexpected ordering: %+v", users)
	}
}
