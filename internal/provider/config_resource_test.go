// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/types"
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
