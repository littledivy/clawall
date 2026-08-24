package config_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/denoland/clawpatrol/internal/config"
	_ "github.com/denoland/clawpatrol/internal/config/plugins/all"
)

// TestEmitRoundTrip loads each feature_*.hcl fixture, emits it back
// to HCL, parses the emitted bytes, and asserts the resulting Dump
// matches the original. Confirms Emit produces structurally
// equivalent output that the loader accepts — comments are NOT
// preserved (hclwrite + gohcl can't), but the typed shape is.
func TestEmitRoundTrip(t *testing.T) {
	entries, err := filepath.Glob("testdata/feature_*.hcl")
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	for _, path := range entries {
		name := strings.TrimSuffix(filepath.Base(path), ".hcl")
		t.Run(name, func(t *testing.T) {
			gw, diags := config.Load(path)
			if diags.HasErrors() {
				t.Fatalf("initial load: %v", diags)
			}
			emitted, err := config.Emit(gw)
			if err != nil {
				t.Fatalf("emit: %v", err)
			}

			gw2, diags := config.LoadBytes(emitted, "emitted.hcl")
			if diags.HasErrors() {
				t.Fatalf("re-load emitted bytes:\n--- emitted ---\n%s\n--- diags ---\n%v",
					emitted, diags)
			}

			want, err := gw.Dump()
			if err != nil {
				t.Fatalf("dump original: %v", err)
			}
			got, err := gw2.Dump()
			if err != nil {
				t.Fatalf("dump round-trip: %v", err)
			}
			if diff := cmp.Diff(string(want), string(got)); diff != "" {
				t.Errorf("round-trip mismatch (-original +emitted):\n%s\n--- emitted hcl ---\n%s",
					diff, emitted)
			}
		})
	}
}

// TestEmitFullSpec round-trips the verbatim v14 fixture. Catches
// emit gaps in the larger surface (multi-credential dispatch,
// approve chains with policy + cache_ttl, k8s endpoint description /
// server / ca_cert, etc.).
func TestEmitFullSpec(t *testing.T) {
	gw, diags := config.Load("testdata/full.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	emitted, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	gw2, diags := config.LoadBytes(emitted, "emitted.hcl")
	if diags.HasErrors() {
		t.Fatalf("re-load emitted bytes:\n--- emitted ---\n%s\n--- diags ---\n%v",
			emitted, diags)
	}
	want, _ := gw.Dump()
	got, _ := gw2.Dump()
	if diff := cmp.Diff(string(want), string(got)); diff != "" {
		t.Errorf("full-spec round-trip mismatch:\n%s", diff)
	}
}

func TestEmitDashboardConfigWrites(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`gateway {
  dashboard_config_writes = true
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
`), "writes.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	emitted, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !strings.Contains(string(emitted), "dashboard_config_writes = true") {
		t.Fatalf("emitted config missing dashboard_config_writes:\n%s", emitted)
	}
}

func TestEmitDashboardBranding(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`gateway {
  dashboard_name = "Acme Gateway"
  dashboard_logo_url = "https://assets.example.test/acme-logo.svg"
  dashboard_icon_url = "https://assets.example.test/acme-icon.svg"
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint = "127.0.0.1:51820"
  }
}
`), "branding.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	if got := gw.DashboardName(); got != "Acme Gateway" {
		t.Fatalf("DashboardName = %q", got)
	}
	if got := gw.DashboardLogoURL(); got != "https://assets.example.test/acme-logo.svg" {
		t.Fatalf("DashboardLogoURL = %q", got)
	}
	if got := gw.DashboardIconURL(); got != "https://assets.example.test/acme-icon.svg" {
		t.Fatalf("DashboardIconURL = %q", got)
	}

	emitted, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	for _, want := range []string{
		`dashboard_name`,
		`"Acme Gateway"`,
		`dashboard_logo_url`,
		`"https://assets.example.test/acme-logo.svg"`,
		`dashboard_icon_url`,
		`"https://assets.example.test/acme-icon.svg"`,
	} {
		if !strings.Contains(string(emitted), want) {
			t.Fatalf("emitted config missing %s:\n%s", want, emitted)
		}
	}
}

func TestEmitBasicAuthCredential(t *testing.T) {
	gw, diags := config.LoadBytes([]byte(`gateway {
  wireguard {
    subnet_cidr = "10.55.0.0/24"
    endpoint    = "127.0.0.1:51820"
  }
}

endpoint "https" "api" {
  hosts = ["api.example.com"]
}

credential "basic_auth" "api" {
  endpoint = https.api
  username = "agent"
}

profile "default" { credentials = [basic_auth.api] }
`), "basic-auth.hcl")
	if diags.HasErrors() {
		t.Fatalf("load: %v", diags)
	}
	emitted, err := config.Emit(gw)
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	if !strings.Contains(string(emitted), `credential "basic_auth" "api"`) {
		t.Fatalf("emitted config missing basic_auth credential:\n%s", emitted)
	}
	if !strings.Contains(string(emitted), `username = "agent"`) {
		t.Fatalf("emitted config missing basic_auth username:\n%s", emitted)
	}
	if _, diags := config.LoadBytes(emitted, "emitted.hcl"); diags.HasErrors() {
		t.Fatalf("re-load emitted bytes:\n--- emitted ---\n%s\n--- diags ---\n%v", emitted, diags)
	}
}
