// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package provider

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/backend/local"
)

// TestBuildConfig_DNSOnly_NoGlobal_NoPanic exercises the regression from
// issue #13: declaring a dns {} block without a sibling global {} block
// panicked because the NoResolv assignment dereferenced an unallocated
// config.Global.
//
// no_resolv is schema-defined as Optional+Computed with Default(false), so
// the framework always delivers a known non-null value to buildConfig even
// when the user writes only `dns { bind_dynamic = true }`. NoResolv is set
// to a known false here to model that exact wire shape.
func TestBuildConfig_DNSOnly_NoGlobal_NoPanic(t *testing.T) {
	r := &ConfigResource{}
	data := &ConfigResourceModel{
		Filename: types.StringValue("test.conf"),
		DNS: &DNSModel{
			BindDynamic: types.BoolValue(true),
			NoResolv:    types.BoolValue(false),
		},
	}

	cfg := r.buildConfig(data)
	if cfg == nil {
		t.Fatal("buildConfig returned nil")
	}
	if cfg.DNS == nil {
		t.Fatal("buildConfig produced nil DNS config")
	}
	if !cfg.DNS.BindDynamic {
		t.Fatal("bind_dynamic was not propagated")
	}
}

// TestBuildConfig_DNSOnly_NoResolvPropagates ensures that when no_resolv is
// set inside dns {} without a global {} block, the value still reaches the
// generated config (via lazy-initialized Global).
func TestBuildConfig_DNSOnly_NoResolvPropagates(t *testing.T) {
	r := &ConfigResource{}
	data := &ConfigResourceModel{
		Filename: types.StringValue("test.conf"),
		DNS: &DNSModel{
			NoResolv: types.BoolValue(true),
		},
	}

	cfg := r.buildConfig(data)
	if cfg == nil {
		t.Fatal("buildConfig returned nil")
	}
	if cfg.Global == nil {
		t.Fatal("expected Global to be lazy-initialized for NoResolv")
	}
	if !cfg.Global.NoResolv {
		t.Fatal("no_resolv was not propagated to Global.NoResolv")
	}
}

// newTestConfigResource builds a ConfigResource wired to a real LocalBackend
// rooted at the given temp dir. Used by import-helper tests.
func newTestConfigResource(t *testing.T) *ConfigResource {
	t.Helper()
	backend, err := local.New(local.Config{Platform: "linux"})
	if err != nil {
		t.Fatalf("local.New: %v", err)
	}
	return &ConfigResource{backend: backend, mode: "local"}
}

// TestLoadStateForImport_ReadsFile asserts that the import helper populates
// every state field from an absolute path to an existing config file. This is
// the happy path for issue #17 — the original ImportState produced empty state.
func TestLoadStateForImport_ReadsFile(t *testing.T) {
	r := newTestConfigResource(t)

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "imported.conf")
	expected := []byte("# imported by terraform\nbind-dynamic\ndomain-needed\n")
	if err := os.WriteFile(filePath, expected, 0644); err != nil {
		t.Fatal(err)
	}

	id, filename, content, contentHash, err := r.loadStateForImport(context.Background(), filePath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if filename != "imported.conf" {
		t.Errorf("filename: got %q, want %q", filename, "imported.conf")
	}
	if !bytes.Equal(content, expected) {
		t.Errorf("content mismatch:\n got %q\nwant %q", content, expected)
	}
	if id == "" {
		t.Error("id should be non-empty (sha256 of path)")
	}
	if contentHash == "" {
		t.Error("contentHash should be non-empty (sha256 of content)")
	}
	if id == contentHash {
		t.Error("id and contentHash should be distinct (different inputs)")
	}
}

// TestLoadStateForImport_RejectsRelativePath ensures the helper refuses
// relative paths so users hit a clear error instead of confusing behavior
// later when output_path resolves differently than expected.
func TestLoadStateForImport_RejectsRelativePath(t *testing.T) {
	r := newTestConfigResource(t)

	_, _, _, _, err := r.loadStateForImport(context.Background(), "relative/path.conf")
	if err == nil {
		t.Fatal("expected error for relative path, got nil")
	}
}

// TestLoadStateForImport_MissingFile ensures the helper surfaces a clear error
// when the import target doesn't exist, rather than silently producing empty
// state (which was the original v0.0.1 behavior).
func TestLoadStateForImport_MissingFile(t *testing.T) {
	r := newTestConfigResource(t)

	_, _, _, _, err := r.loadStateForImport(context.Background(), "/nonexistent/path/missing.conf")
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}
