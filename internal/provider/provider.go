// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/backend"
	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/backend/local"
)

// Ensure DnsmasqProvider satisfies various provider interfaces.
var _ provider.Provider = &DnsmasqProvider{}

// DnsmasqProvider defines the provider implementation.
type DnsmasqProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// DnsmasqProviderModel describes the provider data model.
type DnsmasqProviderModel struct {
	Mode       types.String `tfsdk:"mode"`
	Platform   types.String `tfsdk:"platform"`
	ConfigPath types.String `tfsdk:"config_path"`
	ConfigDir  types.String `tfsdk:"config_dir"`

	SSH               *SSHConfigModel         `tfsdk:"ssh"`
	ServiceManagement *ServiceManagementModel `tfsdk:"service_management"`
}

// SSHConfigModel describes SSH connection configuration.
type SSHConfigModel struct {
	Host                  types.String `tfsdk:"host"`
	Port                  types.Int64  `tfsdk:"port"`
	User                  types.String `tfsdk:"user"`
	Password              types.String `tfsdk:"password"`
	PrivateKey            types.String `tfsdk:"private_key"`
	PrivateKeyPath        types.String `tfsdk:"private_key_path"`
	Passphrase            types.String `tfsdk:"passphrase"`
	KnownHostsFile        types.String `tfsdk:"known_hosts_file"`
	StrictHostKeyChecking types.Bool   `tfsdk:"strict_host_key_checking"`
	Timeout               types.Int64  `tfsdk:"timeout"`
}

// ServiceManagementModel describes service management configuration.
type ServiceManagementModel struct {
	Enabled              types.Bool   `tfsdk:"enabled"`
	Type                 types.String `tfsdk:"type"`
	ServiceName          types.String `tfsdk:"service_name"`
	ReloadCommand        types.String `tfsdk:"reload_command"`
	ValidateBeforeReload types.Bool   `tfsdk:"validate_before_reload"`
	RestartOnFail        types.Bool   `tfsdk:"restart_on_fail"`
}

// ProviderData holds the configured backend for use by resources.
type ProviderData struct {
	Backend backend.Backend
	Mode    string
}

func (p *DnsmasqProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "dnsmasq"
	resp.Version = p.version
}

func (p *DnsmasqProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing dnsmasq configuration files across multiple platforms and deployment scenarios.",
		Attributes: map[string]schema.Attribute{
			"mode": schema.StringAttribute{
				Optional:    true,
				Description: "Deployment mode: 'local' (default), 'ssh', or 'content_only'. Local mode writes to the local filesystem, SSH mode connects to remote servers, and content_only mode only generates configuration content without writing files.",
			},
			"platform": schema.StringAttribute{
				Optional:    true,
				Description: "Target platform: 'auto' (default), 'linux', 'macos', or 'windows'. When set to 'auto', the platform is detected automatically.",
			},
			"config_path": schema.StringAttribute{
				Optional:    true,
				Description: "Path to the main dnsmasq.conf file. Auto-detected based on platform if not specified.",
			},
			"config_dir": schema.StringAttribute{
				Optional:    true,
				Description: "Path to dnsmasq.d directory for additional config files. Auto-detected based on platform if not specified.",
			},
		},
		Blocks: map[string]schema.Block{
			"ssh": schema.SingleNestedBlock{
				Description: "SSH connection configuration for remote deployment. Only used when mode is 'ssh'.",
				Attributes: map[string]schema.Attribute{
					"host": schema.StringAttribute{
						Optional:    true,
						Description: "SSH host to connect to.",
					},
					"port": schema.Int64Attribute{
						Optional:    true,
						Description: "SSH port (default: 22).",
					},
					"user": schema.StringAttribute{
						Optional:    true,
						Description: "SSH username.",
					},
					"password": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "SSH password. Prefer using private_key for authentication.",
					},
					"private_key": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "PEM-encoded private key content.",
					},
					"private_key_path": schema.StringAttribute{
						Optional:    true,
						Description: "Path to private key file.",
					},
					"passphrase": schema.StringAttribute{
						Optional:    true,
						Sensitive:   true,
						Description: "Passphrase for encrypted private key.",
					},
					"known_hosts_file": schema.StringAttribute{
						Optional:    true,
						Description: "Path to known_hosts file for host key verification.",
					},
					"strict_host_key_checking": schema.BoolAttribute{
						Optional:    true,
						Description: "Enable strict host key checking (default: true).",
					},
					"timeout": schema.Int64Attribute{
						Optional:    true,
						Description: "Connection timeout in seconds (default: 30).",
					},
				},
			},
			"service_management": schema.SingleNestedBlock{
				Description: "Service management configuration for automatic reload/restart after configuration changes.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Description: "Enable automatic service management (default: false).",
					},
					"type": schema.StringAttribute{
						Optional:    true,
						Description: "Service manager type: 'systemd', 'launchd', 'init', 'brew_services', or 'none'. Auto-detected if not specified.",
					},
					"service_name": schema.StringAttribute{
						Optional:    true,
						Description: "Service name (default: dnsmasq).",
					},
					"reload_command": schema.StringAttribute{
						Optional:    true,
						Description: "Custom reload command. Overrides the default service manager reload.",
					},
					"validate_before_reload": schema.BoolAttribute{
						Optional:    true,
						Description: "Run 'dnsmasq --test' to validate configuration before reload (default: true).",
					},
					"restart_on_fail": schema.BoolAttribute{
						Optional:    true,
						Description: "Restart service if reload fails (default: false).",
					},
				},
			},
		},
	}
}

func (p *DnsmasqProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data DnsmasqProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Determine mode
	mode := "local"
	if !data.Mode.IsNull() && !data.Mode.IsUnknown() {
		mode = data.Mode.ValueString()
	}

	// Build provider data based on mode
	providerData := &ProviderData{
		Mode: mode,
	}

	switch mode {
	case "local":
		cfg := local.Config{}

		if !data.Platform.IsNull() {
			cfg.Platform = data.Platform.ValueString()
		}
		if !data.ConfigPath.IsNull() {
			cfg.ConfigPath = data.ConfigPath.ValueString()
		}
		if !data.ConfigDir.IsNull() {
			cfg.ConfigDir = data.ConfigDir.ValueString()
		}

		if data.ServiceManagement != nil {
			if !data.ServiceManagement.Type.IsNull() {
				cfg.ServiceManager = data.ServiceManagement.Type.ValueString()
			}
			if !data.ServiceManagement.ServiceName.IsNull() {
				cfg.ServiceName = data.ServiceManagement.ServiceName.ValueString()
			}
			if !data.ServiceManagement.ReloadCommand.IsNull() {
				cfg.ReloadCommand = data.ServiceManagement.ReloadCommand.ValueString()
			}
			if !data.ServiceManagement.ValidateBeforeReload.IsNull() {
				cfg.ValidateFirst = data.ServiceManagement.ValidateBeforeReload.ValueBool()
			}
			if !data.ServiceManagement.RestartOnFail.IsNull() {
				cfg.RestartOnFail = data.ServiceManagement.RestartOnFail.ValueBool()
			}
		}

		backend, err := local.New(cfg)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create Local Backend",
				"An unexpected error occurred when creating the local backend: "+err.Error(),
			)
			return
		}
		providerData.Backend = backend

	case "ssh":
		// SSH backend will be implemented in Phase 4
		resp.Diagnostics.AddError(
			"SSH Mode Not Yet Implemented",
			"SSH mode is planned for a future release. Please use 'local' or 'content_only' mode.",
		)
		return

	case "content_only":
		// Content-only backend just generates content without writing files
		// For now, use local backend with no service management
		cfg := local.Config{}
		if !data.Platform.IsNull() {
			cfg.Platform = data.Platform.ValueString()
		}
		backend, err := local.New(cfg)
		if err != nil {
			resp.Diagnostics.AddError(
				"Unable to Create Content Backend",
				"An unexpected error occurred when creating the content backend: "+err.Error(),
			)
			return
		}
		providerData.Backend = backend

	default:
		resp.Diagnostics.AddError(
			"Invalid Mode",
			"Mode must be 'local', 'ssh', or 'content_only'. Got: "+mode,
		)
		return
	}

	resp.DataSourceData = providerData
	resp.ResourceData = providerData
}

func (p *DnsmasqProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewConfigResource,
	}
}

func (p *DnsmasqProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		// Data sources will be added in Phase 3
	}
}

// New creates a new provider factory function.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &DnsmasqProvider{
			version: version,
		}
	}
}
