// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package provider

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/backend/local"
	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/dnsmasq"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &ConfigResource{}
var _ resource.ResourceWithImportState = &ConfigResource{}

// NewConfigResource creates a new config resource.
func NewConfigResource() resource.Resource {
	return &ConfigResource{}
}

// ConfigResource defines the resource implementation.
type ConfigResource struct {
	backend *local.LocalBackend
	mode    string
}

// ConfigResourceModel describes the resource data model.
type ConfigResourceModel struct {
	ID              types.String `tfsdk:"id"`
	Filename        types.String `tfsdk:"filename"`
	OutputPath      types.String `tfsdk:"output_path"`
	RenderedContent types.String `tfsdk:"rendered_content"`
	ContentHash     types.String `tfsdk:"content_hash"`

	// Global settings
	Global *GlobalModel `tfsdk:"global"`

	// DNS settings
	DNS *DNSModel `tfsdk:"dns"`

	// DNSSEC settings
	DNSSEC *DNSSECModel `tfsdk:"dnssec"`

	// DHCP settings
	DHCP *DHCPModel `tfsdk:"dhcp"`

	// TFTP settings
	TFTP *TFTPModel `tfsdk:"tftp"`

	// PXE settings
	PXE *PXEModel `tfsdk:"pxe"`

	// Router Advertisement settings
	RA *RAModel `tfsdk:"router_advertisement"`

	// DNS Records
	HostRecords    []HostRecordModel    `tfsdk:"host_record"`
	AddressRecords []AddressRecordModel `tfsdk:"address_record"`
	CNAMERecords   []CNAMERecordModel   `tfsdk:"cname_record"`
	MXRecords      []MXRecordModel      `tfsdk:"mx_record"`
	SRVRecords     []SRVRecordModel     `tfsdk:"srv_record"`
	TXTRecords     []TXTRecordModel     `tfsdk:"txt_record"`

	// DHCP Hosts
	DHCPHosts []DHCPHostModel `tfsdk:"dhcp_host"`

	// Custom options
	CustomOptions types.List `tfsdk:"custom_options"`
}

// GlobalModel represents global dnsmasq settings.
type GlobalModel struct {
	User            types.String `tfsdk:"user"`
	Group           types.String `tfsdk:"group"`
	LogQueries      types.Bool   `tfsdk:"log_queries"`
	LogFacility     types.String `tfsdk:"log_facility"`
	LogDHCP         types.Bool   `tfsdk:"log_dhcp"`
	LogAsync        types.Int64  `tfsdk:"log_async"`
	Domain          types.String `tfsdk:"domain"`
	ExpandHosts     types.Bool   `tfsdk:"expand_hosts"`
	LocaliseQueries types.Bool   `tfsdk:"localise_queries"`
}

// DNSModel represents DNS settings.
type DNSModel struct {
	Port              types.Int64      `tfsdk:"port"`
	ListenAddress     types.List       `tfsdk:"listen_address"`
	Interface         types.List       `tfsdk:"interface"`
	BindDynamic       types.Bool       `tfsdk:"bind_dynamic"`
	CacheSize         types.Int64      `tfsdk:"cache_size"`
	NoResolv          types.Bool       `tfsdk:"no_resolv"`
	DomainNeeded      types.Bool       `tfsdk:"domain_needed"`
	BogusPriv         types.Bool       `tfsdk:"bogus_priv"`
	DNSLoopDetect     types.Bool       `tfsdk:"dns_loop_detect"`
	StopDNSRebind     types.Bool       `tfsdk:"stop_dns_rebind"`
	RebindLocalhostOK types.Bool       `tfsdk:"rebind_localhost_ok"`
	Servers           []DNSServerModel `tfsdk:"server"`
}

// DNSServerModel represents an upstream DNS server.
type DNSServerModel struct {
	Address types.String `tfsdk:"address"`
	Domain  types.String `tfsdk:"domain"`
}

// DNSSECModel represents DNSSEC settings.
type DNSSECModel struct {
	Enabled       types.Bool `tfsdk:"enabled"`
	CheckUnsigned types.Bool `tfsdk:"check_unsigned"`
	TrustAnchor   types.List `tfsdk:"trust_anchor"`
}

// DHCPModel represents DHCP settings.
type DHCPModel struct {
	Enabled       types.Bool        `tfsdk:"enabled"`
	Authoritative types.Bool        `tfsdk:"authoritative"`
	Leasefile     types.String      `tfsdk:"leasefile"`
	Ranges        []DHCPRangeModel  `tfsdk:"range"`
	Options       []DHCPOptionModel `tfsdk:"option"`
}

// DHCPRangeModel represents a DHCP range.
type DHCPRangeModel struct {
	Start     types.String `tfsdk:"start"`
	End       types.String `tfsdk:"end"`
	Netmask   types.String `tfsdk:"netmask"`
	LeaseTime types.String `tfsdk:"lease_time"`
	Tag       types.String `tfsdk:"tag"`
}

// DHCPOptionModel represents a DHCP option.
type DHCPOptionModel struct {
	Number types.Int64  `tfsdk:"number"`
	Name   types.String `tfsdk:"name"`
	Value  types.String `tfsdk:"value"`
	Tag    types.String `tfsdk:"tag"`
}

// DHCPHostModel represents a static DHCP host.
type DHCPHostModel struct {
	MAC       types.String `tfsdk:"mac"`
	Name      types.String `tfsdk:"name"`
	IP        types.String `tfsdk:"ip"`
	LeaseTime types.String `tfsdk:"lease_time"`
}

// TFTPModel represents TFTP settings.
type TFTPModel struct {
	Enabled types.Bool   `tfsdk:"enabled"`
	Root    types.String `tfsdk:"root"`
	Secure  types.Bool   `tfsdk:"secure"`
}

// PXEModel represents PXE settings.
type PXEModel struct {
	Prompt   *PXEPromptModel   `tfsdk:"prompt"`
	Services []PXEServiceModel `tfsdk:"service"`
}

// PXEPromptModel represents the PXE prompt.
type PXEPromptModel struct {
	Text    types.String `tfsdk:"text"`
	Timeout types.Int64  `tfsdk:"timeout"`
}

// PXEServiceModel represents a PXE service.
type PXEServiceModel struct {
	CSA      types.String `tfsdk:"csa"`
	MenuText types.String `tfsdk:"menu_text"`
	Basename types.String `tfsdk:"basename"`
	Server   types.String `tfsdk:"server"`
}

// RAModel represents Router Advertisement settings.
type RAModel struct {
	Enabled types.Bool     `tfsdk:"enabled"`
	Params  []RAParamModel `tfsdk:"param"`
}

// RAParamModel represents RA parameters.
type RAParamModel struct {
	Interface types.String `tfsdk:"interface"`
	MTU       types.Int64  `tfsdk:"mtu"`
}

// HostRecordModel represents a host record.
type HostRecordModel struct {
	Name types.String `tfsdk:"name"`
	IPv4 types.String `tfsdk:"ipv4"`
	IPv6 types.String `tfsdk:"ipv6"`
	TTL  types.Int64  `tfsdk:"ttl"`
}

// AddressRecordModel represents an address record.
type AddressRecordModel struct {
	Domain types.String `tfsdk:"domain"`
	IP     types.String `tfsdk:"ip"`
}

// CNAMERecordModel represents a CNAME record.
type CNAMERecordModel struct {
	Alias  types.String `tfsdk:"alias"`
	Target types.String `tfsdk:"target"`
}

// MXRecordModel represents an MX record.
type MXRecordModel struct {
	Domain     types.String `tfsdk:"domain"`
	Target     types.String `tfsdk:"target"`
	Preference types.Int64  `tfsdk:"preference"`
}

// SRVRecordModel represents an SRV record.
type SRVRecordModel struct {
	Service  types.String `tfsdk:"service"`
	Target   types.String `tfsdk:"target"`
	Port     types.Int64  `tfsdk:"port"`
	Priority types.Int64  `tfsdk:"priority"`
	Weight   types.Int64  `tfsdk:"weight"`
}

// TXTRecordModel represents a TXT record.
type TXTRecordModel struct {
	Name  types.String `tfsdk:"name"`
	Value types.String `tfsdk:"value"`
}

func (r *ConfigResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_config"
}

func (r *ConfigResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manages a dnsmasq configuration file.",

		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier for this configuration.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"filename": schema.StringAttribute{
				Required:    true,
				Description: "Name of the configuration file to create (e.g., 'terraform-managed.conf').",
			},
			"output_path": schema.StringAttribute{
				Computed:    true,
				Description: "Full path where the configuration file was written.",
			},
			"rendered_content": schema.StringAttribute{
				Computed:    true,
				Description: "The generated dnsmasq configuration content.",
			},
			"content_hash": schema.StringAttribute{
				Computed:    true,
				Description: "SHA256 hash of the configuration content for drift detection.",
			},
			"custom_options": schema.ListAttribute{
				Optional:    true,
				ElementType: types.StringType,
				Description: "Additional custom configuration lines to append.",
			},
		},

		Blocks: map[string]schema.Block{
			"global": schema.SingleNestedBlock{
				Description: "Global dnsmasq settings.",
				Attributes: map[string]schema.Attribute{
					"user": schema.StringAttribute{
						Optional:    true,
						Description: "User to run dnsmasq as.",
					},
					"group": schema.StringAttribute{
						Optional:    true,
						Description: "Group to run dnsmasq as.",
					},
					"log_queries": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable DNS query logging.",
					},
					"log_facility": schema.StringAttribute{
						Optional:    true,
						Description: "Log facility or file path.",
					},
					"log_dhcp": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable DHCP logging.",
					},
					"log_async": schema.Int64Attribute{
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(0),
						Description: "Async logging queue size.",
					},
					"domain": schema.StringAttribute{
						Optional:    true,
						Description: "Domain for DHCP clients.",
					},
					"expand_hosts": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Add domain to simple hostnames.",
					},
					"localise_queries": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Return subnet-specific addresses.",
					},
				},
			},

			"dns": schema.SingleNestedBlock{
				Description: "DNS server settings.",
				Attributes: map[string]schema.Attribute{
					"port": schema.Int64Attribute{
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(53),
						Description: "DNS port (default: 53).",
					},
					"listen_address": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "IP addresses to listen on.",
					},
					"interface": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "Interfaces to listen on.",
					},
					"bind_dynamic": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable dynamic binding.",
					},
					"cache_size": schema.Int64Attribute{
						Optional:    true,
						Computed:    true,
						Default:     int64default.StaticInt64(150),
						Description: "DNS cache size.",
					},
					"no_resolv": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Don't read /etc/resolv.conf.",
					},
					"domain_needed": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Don't forward unqualified names.",
					},
					"bogus_priv": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Block private reverse lookups.",
					},
					"dns_loop_detect": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Detect DNS forwarding loops.",
					},
					"stop_dns_rebind": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Reject private range addresses in DNS responses.",
					},
					"rebind_localhost_ok": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Allow localhost in rebind check.",
					},
				},
				Blocks: map[string]schema.Block{
					"server": schema.ListNestedBlock{
						Description: "Upstream DNS servers.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"address": schema.StringAttribute{
									Required:    true,
									Description: "Server IP address.",
								},
								"domain": schema.StringAttribute{
									Optional:    true,
									Description: "Domain to use this server for.",
								},
							},
						},
					},
				},
			},

			"dnssec": schema.SingleNestedBlock{
				Description: "DNSSEC validation settings.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable DNSSEC validation.",
					},
					"check_unsigned": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Check unsigned replies.",
					},
					"trust_anchor": schema.ListAttribute{
						Optional:    true,
						ElementType: types.StringType,
						Description: "DNSSEC trust anchors.",
					},
				},
			},

			"dhcp": schema.SingleNestedBlock{
				Description: "DHCP server settings.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable DHCP server.",
					},
					"authoritative": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Act as authoritative DHCP server.",
					},
					"leasefile": schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Default:     stringdefault.StaticString("/var/lib/misc/dnsmasq.leases"),
						Description: "DHCP lease file path.",
					},
				},
				Blocks: map[string]schema.Block{
					"range": schema.ListNestedBlock{
						Description: "DHCP address ranges.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"start": schema.StringAttribute{
									Required:    true,
									Description: "Start of IP range.",
								},
								"end": schema.StringAttribute{
									Required:    true,
									Description: "End of IP range.",
								},
								"netmask": schema.StringAttribute{
									Optional:    true,
									Description: "Network mask.",
								},
								"lease_time": schema.StringAttribute{
									Optional:    true,
									Computed:    true,
									Default:     stringdefault.StaticString("24h"),
									Description: "Lease time (e.g., '24h', '1d').",
								},
								"tag": schema.StringAttribute{
									Optional:    true,
									Description: "Tag for this range.",
								},
							},
						},
					},
					"option": schema.ListNestedBlock{
						Description: "DHCP options.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"number": schema.Int64Attribute{
									Optional:    true,
									Description: "Option number.",
								},
								"name": schema.StringAttribute{
									Optional:    true,
									Description: "Option name.",
								},
								"value": schema.StringAttribute{
									Required:    true,
									Description: "Option value.",
								},
								"tag": schema.StringAttribute{
									Optional:    true,
									Description: "Apply to specific tag.",
								},
							},
						},
					},
				},
			},

			"tftp": schema.SingleNestedBlock{
				Description: "TFTP server settings.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable TFTP server.",
					},
					"root": schema.StringAttribute{
						Optional:    true,
						Description: "TFTP root directory.",
					},
					"secure": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Only serve files owned by dnsmasq user.",
					},
				},
			},

			"pxe": schema.SingleNestedBlock{
				Description: "PXE boot settings.",
				Blocks: map[string]schema.Block{
					"prompt": schema.SingleNestedBlock{
						Description: "PXE boot prompt.",
						Attributes: map[string]schema.Attribute{
							"text": schema.StringAttribute{
								Optional:    true,
								Description: "Prompt text.",
							},
							"timeout": schema.Int64Attribute{
								Optional:    true,
								Computed:    true,
								Default:     int64default.StaticInt64(10),
								Description: "Timeout in seconds.",
							},
						},
					},
					"service": schema.ListNestedBlock{
						Description: "PXE boot services.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"csa": schema.StringAttribute{
									Optional:    true,
									Description: "Client system architecture.",
								},
								"menu_text": schema.StringAttribute{
									Optional:    true,
									Description: "Menu text.",
								},
								"basename": schema.StringAttribute{
									Optional:    true,
									Description: "Boot file basename.",
								},
								"server": schema.StringAttribute{
									Optional:    true,
									Description: "Boot server address.",
								},
							},
						},
					},
				},
			},

			"router_advertisement": schema.SingleNestedBlock{
				Description: "IPv6 Router Advertisement settings.",
				Attributes: map[string]schema.Attribute{
					"enabled": schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Default:     booldefault.StaticBool(false),
						Description: "Enable router advertisement.",
					},
				},
				Blocks: map[string]schema.Block{
					"param": schema.ListNestedBlock{
						Description: "RA parameters per interface.",
						NestedObject: schema.NestedBlockObject{
							Attributes: map[string]schema.Attribute{
								"interface": schema.StringAttribute{
									Required:    true,
									Description: "Interface name.",
								},
								"mtu": schema.Int64Attribute{
									Optional:    true,
									Description: "MTU to advertise.",
								},
							},
						},
					},
				},
			},

			"host_record": schema.ListNestedBlock{
				Description: "DNS host records (A/AAAA).",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Hostname.",
						},
						"ipv4": schema.StringAttribute{
							Optional:    true,
							Description: "IPv4 address.",
						},
						"ipv6": schema.StringAttribute{
							Optional:    true,
							Description: "IPv6 address.",
						},
						"ttl": schema.Int64Attribute{
							Optional:    true,
							Description: "TTL in seconds.",
						},
					},
				},
			},

			"address_record": schema.ListNestedBlock{
				Description: "Address records for domain-to-IP mapping.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"domain": schema.StringAttribute{
							Required:    true,
							Description: "Domain name (supports wildcards).",
						},
						"ip": schema.StringAttribute{
							Required:    true,
							Description: "IP address (use 0.0.0.0 to block).",
						},
					},
				},
			},

			"cname_record": schema.ListNestedBlock{
				Description: "CNAME alias records.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"alias": schema.StringAttribute{
							Required:    true,
							Description: "Alias name.",
						},
						"target": schema.StringAttribute{
							Required:    true,
							Description: "Target hostname.",
						},
					},
				},
			},

			"mx_record": schema.ListNestedBlock{
				Description: "MX mail exchange records.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"domain": schema.StringAttribute{
							Required:    true,
							Description: "Domain name.",
						},
						"target": schema.StringAttribute{
							Required:    true,
							Description: "Mail server hostname.",
						},
						"preference": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Default:     int64default.StaticInt64(10),
							Description: "MX preference (lower = higher priority).",
						},
					},
				},
			},

			"srv_record": schema.ListNestedBlock{
				Description: "SRV service records.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"service": schema.StringAttribute{
							Required:    true,
							Description: "Service name (e.g., '_ldap._tcp.example.com').",
						},
						"target": schema.StringAttribute{
							Required:    true,
							Description: "Target hostname.",
						},
						"port": schema.Int64Attribute{
							Required:    true,
							Description: "Port number.",
						},
						"priority": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Default:     int64default.StaticInt64(0),
							Description: "Priority.",
						},
						"weight": schema.Int64Attribute{
							Optional:    true,
							Computed:    true,
							Default:     int64default.StaticInt64(0),
							Description: "Weight.",
						},
					},
				},
			},

			"txt_record": schema.ListNestedBlock{
				Description: "TXT text records.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"name": schema.StringAttribute{
							Required:    true,
							Description: "Record name.",
						},
						"value": schema.StringAttribute{
							Required:    true,
							Description: "Record value.",
						},
					},
				},
			},

			"dhcp_host": schema.ListNestedBlock{
				Description: "Static DHCP host assignments.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"mac": schema.StringAttribute{
							Required:    true,
							Description: "MAC address.",
						},
						"name": schema.StringAttribute{
							Optional:    true,
							Description: "Hostname.",
						},
						"ip": schema.StringAttribute{
							Required:    true,
							Description: "IP address.",
						},
						"lease_time": schema.StringAttribute{
							Optional:    true,
							Description: "Lease time (e.g., 'infinite', '24h').",
						},
					},
				},
			},
		},
	}
}

func (r *ConfigResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}

	providerData, ok := req.ProviderData.(*ProviderData)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *ProviderData, got: %T", req.ProviderData),
		)
		return
	}

	r.backend = providerData.Backend.(*local.LocalBackend)
	r.mode = providerData.Mode
}

func (r *ConfigResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data ConfigResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build dnsmasq config from model
	config := r.buildConfig(&data)

	// Validate configuration
	validator := dnsmasq.NewValidator(config)
	if errors := validator.Validate(); len(errors) > 0 {
		for _, err := range errors {
			resp.Diagnostics.AddError("Configuration Validation Error", err.Error())
		}
		return
	}

	// Generate configuration content
	generator := dnsmasq.NewGenerator(config, dnsmasq.GeneratorOptions{IncludeComments: true})
	content, err := generator.Generate()
	if err != nil {
		resp.Diagnostics.AddError("Configuration Generation Error", err.Error())
		return
	}

	// Determine output path
	paths := r.backend.GetPaths()
	outputPath := filepath.Join(paths.ConfigDir, data.Filename.ValueString())

	// Write configuration file (unless content_only mode)
	if r.mode != "content_only" {
		if err := r.backend.WriteConfig(ctx, outputPath, content, 0644); err != nil {
			resp.Diagnostics.AddError("Failed to Write Configuration", err.Error())
			return
		}
	}

	// Set computed attributes
	data.ID = types.StringValue(fmt.Sprintf("%x", sha256.Sum256([]byte(outputPath))))
	data.OutputPath = types.StringValue(outputPath)
	data.RenderedContent = types.StringValue(string(content))
	data.ContentHash = types.StringValue(fmt.Sprintf("%x", sha256.Sum256(content)))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConfigResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data ConfigResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Check if file exists (for local mode)
	if r.mode == "local" && !data.OutputPath.IsNull() {
		exists, err := r.backend.FileExists(ctx, data.OutputPath.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to Check Configuration File", err.Error())
			return
		}
		if !exists {
			resp.State.RemoveResource(ctx)
			return
		}

		// Read current content and check for drift
		content, err := r.backend.ReadConfig(ctx, data.OutputPath.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Failed to Read Configuration File", err.Error())
			return
		}

		currentHash := fmt.Sprintf("%x", sha256.Sum256(content))
		if currentHash != data.ContentHash.ValueString() {
			// Content has drifted
			data.RenderedContent = types.StringValue(string(content))
			data.ContentHash = types.StringValue(currentHash)
		}
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConfigResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data ConfigResourceModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Build and validate config
	config := r.buildConfig(&data)
	validator := dnsmasq.NewValidator(config)
	if errors := validator.Validate(); len(errors) > 0 {
		for _, err := range errors {
			resp.Diagnostics.AddError("Configuration Validation Error", err.Error())
		}
		return
	}

	// Generate content
	generator := dnsmasq.NewGenerator(config, dnsmasq.GeneratorOptions{IncludeComments: true})
	content, err := generator.Generate()
	if err != nil {
		resp.Diagnostics.AddError("Configuration Generation Error", err.Error())
		return
	}

	// Determine output path
	paths := r.backend.GetPaths()
	outputPath := filepath.Join(paths.ConfigDir, data.Filename.ValueString())

	// Write configuration
	if r.mode != "content_only" {
		if err := r.backend.WriteConfig(ctx, outputPath, content, 0644); err != nil {
			resp.Diagnostics.AddError("Failed to Write Configuration", err.Error())
			return
		}
	}

	// Update computed attributes
	data.OutputPath = types.StringValue(outputPath)
	data.RenderedContent = types.StringValue(string(content))
	data.ContentHash = types.StringValue(fmt.Sprintf("%x", sha256.Sum256(content)))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *ConfigResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data ConfigResourceModel

	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Delete configuration file
	if r.mode != "content_only" && !data.OutputPath.IsNull() {
		if err := r.backend.DeleteConfig(ctx, data.OutputPath.ValueString()); err != nil {
			if !os.IsNotExist(err) {
				resp.Diagnostics.AddError("Failed to Delete Configuration", err.Error())
				return
			}
		}
	}
}

func (r *ConfigResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// buildConfig converts the Terraform model to a dnsmasq.Config struct.
func (r *ConfigResource) buildConfig(data *ConfigResourceModel) *dnsmasq.Config {
	config := &dnsmasq.Config{
		Name:       data.Filename.ValueString(),
		OutputPath: data.OutputPath.ValueString(),
	}

	// Global settings
	if data.Global != nil {
		config.Global = &dnsmasq.GlobalConfig{
			User:            data.Global.User.ValueString(),
			Group:           data.Global.Group.ValueString(),
			LogQueries:      data.Global.LogQueries.ValueBool(),
			LogFacility:     data.Global.LogFacility.ValueString(),
			LogDHCP:         data.Global.LogDHCP.ValueBool(),
			LogAsync:        int(data.Global.LogAsync.ValueInt64()),
			Domain:          data.Global.Domain.ValueString(),
			ExpandHosts:     data.Global.ExpandHosts.ValueBool(),
			LocaliseQueries: data.Global.LocaliseQueries.ValueBool(),
		}
	}

	// DNS settings
	if data.DNS != nil {
		config.DNS = &dnsmasq.DNSConfig{
			Port:              int(data.DNS.Port.ValueInt64()),
			BindDynamic:       data.DNS.BindDynamic.ValueBool(),
			CacheSize:         int(data.DNS.CacheSize.ValueInt64()),
			DomainNeeded:      data.DNS.DomainNeeded.ValueBool(),
			BogusPriv:         data.DNS.BogusPriv.ValueBool(),
			DNSLoopDetect:     data.DNS.DNSLoopDetect.ValueBool(),
			StopDNSRebind:     data.DNS.StopDNSRebind.ValueBool(),
			RebindLocalhostOK: data.DNS.RebindLocalhostOK.ValueBool(),
		}

		// Listen addresses
		if !data.DNS.ListenAddress.IsNull() {
			var addresses []string
			data.DNS.ListenAddress.ElementsAs(ctx, &addresses, false)
			config.DNS.ListenAddress = addresses
		}

		// Interfaces
		if !data.DNS.Interface.IsNull() {
			var interfaces []string
			data.DNS.Interface.ElementsAs(ctx, &interfaces, false)
			config.DNS.Interface = interfaces
		}

		// No resolv
		if !data.DNS.NoResolv.IsNull() {
			config.Global.NoResolv = data.DNS.NoResolv.ValueBool()
		}

		// DNS servers
		for _, srv := range data.DNS.Servers {
			config.DNS.Servers = append(config.DNS.Servers, dnsmasq.DNSServer{
				Address: srv.Address.ValueString(),
				Domain:  srv.Domain.ValueString(),
			})
		}
	}

	// DNSSEC settings
	if data.DNSSEC != nil && data.DNSSEC.Enabled.ValueBool() {
		config.DNSSEC = &dnsmasq.DNSSECConfig{
			Enabled:       true,
			CheckUnsigned: data.DNSSEC.CheckUnsigned.ValueBool(),
		}
		if !data.DNSSEC.TrustAnchor.IsNull() {
			var anchors []string
			data.DNSSEC.TrustAnchor.ElementsAs(ctx, &anchors, false)
			config.DNSSEC.TrustAnchor = anchors
		}
	}

	// DHCP settings
	if data.DHCP != nil && data.DHCP.Enabled.ValueBool() {
		config.DHCP = &dnsmasq.DHCPConfig{
			Enabled:       true,
			Authoritative: data.DHCP.Authoritative.ValueBool(),
			Leasefile:     data.DHCP.Leasefile.ValueString(),
		}

		// DHCP ranges
		for _, r := range data.DHCP.Ranges {
			config.DHCP.Ranges = append(config.DHCP.Ranges, dnsmasq.DHCPRange{
				Tag:       r.Tag.ValueString(),
				Start:     r.Start.ValueString(),
				End:       r.End.ValueString(),
				Netmask:   r.Netmask.ValueString(),
				LeaseTime: r.LeaseTime.ValueString(),
			})
		}

		// DHCP options
		for _, opt := range data.DHCP.Options {
			config.DHCP.Options = append(config.DHCP.Options, dnsmasq.DHCPOption{
				Number: int(opt.Number.ValueInt64()),
				Name:   opt.Name.ValueString(),
				Value:  opt.Value.ValueString(),
				Tag:    opt.Tag.ValueString(),
			})
		}
	}

	// TFTP settings
	if data.TFTP != nil && data.TFTP.Enabled.ValueBool() {
		config.TFTP = &dnsmasq.TFTPConfig{
			Enabled: true,
			Root:    data.TFTP.Root.ValueString(),
			Secure:  data.TFTP.Secure.ValueBool(),
		}
	}

	// PXE settings
	if data.PXE != nil {
		config.PXE = &dnsmasq.PXEConfig{}
		if data.PXE.Prompt != nil {
			config.PXE.Prompt = &dnsmasq.PXEPrompt{
				Text:    data.PXE.Prompt.Text.ValueString(),
				Timeout: int(data.PXE.Prompt.Timeout.ValueInt64()),
			}
		}
		for _, svc := range data.PXE.Services {
			config.PXE.Services = append(config.PXE.Services, dnsmasq.PXEService{
				CSA:      svc.CSA.ValueString(),
				MenuText: svc.MenuText.ValueString(),
				Basename: svc.Basename.ValueString(),
				Server:   svc.Server.ValueString(),
			})
		}
	}

	// Router Advertisement
	if data.RA != nil && data.RA.Enabled.ValueBool() {
		config.RA = &dnsmasq.RouterAdvertisementConfig{
			Enabled: true,
		}
		for _, p := range data.RA.Params {
			config.RA.Params = append(config.RA.Params, dnsmasq.RAParam{
				Interface: p.Interface.ValueString(),
				MTU:       int(p.MTU.ValueInt64()),
			})
		}
	}

	// Host records
	for _, hr := range data.HostRecords {
		config.HostRecords = append(config.HostRecords, dnsmasq.HostRecord{
			Name: hr.Name.ValueString(),
			IPv4: hr.IPv4.ValueString(),
			IPv6: hr.IPv6.ValueString(),
			TTL:  int(hr.TTL.ValueInt64()),
		})
	}

	// Address records
	for _, ar := range data.AddressRecords {
		config.AddressRecords = append(config.AddressRecords, dnsmasq.AddressRecord{
			Domain: ar.Domain.ValueString(),
			IP:     ar.IP.ValueString(),
		})
	}

	// CNAME records
	for _, cr := range data.CNAMERecords {
		config.CNAMERecords = append(config.CNAMERecords, dnsmasq.CNAMERecord{
			Alias:  cr.Alias.ValueString(),
			Target: cr.Target.ValueString(),
		})
	}

	// MX records
	for _, mx := range data.MXRecords {
		config.MXRecords = append(config.MXRecords, dnsmasq.MXRecord{
			Domain:     mx.Domain.ValueString(),
			Target:     mx.Target.ValueString(),
			Preference: int(mx.Preference.ValueInt64()),
		})
	}

	// SRV records
	for _, srv := range data.SRVRecords {
		config.SRVRecords = append(config.SRVRecords, dnsmasq.SRVRecord{
			Service:  srv.Service.ValueString(),
			Target:   srv.Target.ValueString(),
			Port:     int(srv.Port.ValueInt64()),
			Priority: int(srv.Priority.ValueInt64()),
			Weight:   int(srv.Weight.ValueInt64()),
		})
	}

	// TXT records
	for _, txt := range data.TXTRecords {
		config.TXTRecords = append(config.TXTRecords, dnsmasq.TXTRecord{
			Name:  txt.Name.ValueString(),
			Value: txt.Value.ValueString(),
		})
	}

	// DHCP hosts
	for _, h := range data.DHCPHosts {
		config.DHCPHosts = append(config.DHCPHosts, dnsmasq.DHCPHost{
			MAC:       h.MAC.ValueString(),
			Name:      h.Name.ValueString(),
			IP:        h.IP.ValueString(),
			LeaseTime: h.LeaseTime.ValueString(),
		})
	}

	// Custom options
	if !data.CustomOptions.IsNull() {
		var options []string
		data.CustomOptions.ElementsAs(ctx, &options, false)
		config.CustomOptions = options
	}

	return config
}

// ctx is a helper for the context used in buildConfig.
var ctx = context.Background()
