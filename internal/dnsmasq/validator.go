// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package dnsmasq

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

// ValidationError represents a configuration validation error.
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Validator validates dnsmasq configuration.
type Validator struct {
	config *Config
	errors []ValidationError
}

// NewValidator creates a new validator.
func NewValidator(config *Config) *Validator {
	return &Validator{
		config: config,
		errors: []ValidationError{},
	}
}

// Validate runs all validation checks.
func (v *Validator) Validate() []ValidationError {
	v.errors = []ValidationError{}

	v.validateGlobal()
	v.validateDNS()
	v.validateDNSSEC()
	v.validateDHCP()
	v.validateDHCPHosts()
	v.validateTFTP()
	v.validatePXE()
	v.validateRA()
	v.validateRecords()

	return v.errors
}

// HasErrors returns true if validation found errors.
func (v *Validator) HasErrors() bool {
	return len(v.errors) > 0
}

func (v *Validator) addError(field, message string) {
	v.errors = append(v.errors, ValidationError{Field: field, Message: message})
}

func (v *Validator) validateGlobal() {
	if v.config.Global == nil {
		return
	}

	cfg := v.config.Global

	if cfg.LogAsync < 0 {
		v.addError("global.log_async", "must be non-negative")
	}
	if cfg.LogAsync > 100 {
		v.addError("global.log_async", "maximum value is 100")
	}
}

func (v *Validator) validateDNS() {
	if v.config.DNS == nil {
		return
	}

	cfg := v.config.DNS

	// Port validation
	if cfg.Port < 0 || cfg.Port > 65535 {
		v.addError("dns.port", "must be between 0 and 65535")
	}

	// Listen addresses
	for i, addr := range cfg.ListenAddress {
		if !isValidIP(addr) {
			v.addError(fmt.Sprintf("dns.listen_address[%d]", i),
				fmt.Sprintf("invalid IP address: %s", addr))
		}
	}

	// Upstream servers
	for i, srv := range cfg.Servers {
		if srv.Address == "" {
			v.addError(fmt.Sprintf("dns.server[%d].address", i), "address is required")
		} else {
			// Address can be IP, IP#port, or IP@source
			addr := srv.Address
			addr = strings.Split(addr, "#")[0]
			addr = strings.Split(addr, "@")[0]
			if !isValidIP(addr) {
				v.addError(fmt.Sprintf("dns.server[%d].address", i),
					fmt.Sprintf("invalid IP address: %s", addr))
			}
		}
	}

	// Reverse servers
	for i, rsrv := range cfg.RevServers {
		if rsrv.Subnet == "" {
			v.addError(fmt.Sprintf("dns.rev_server[%d].subnet", i), "subnet is required")
		} else if !isValidCIDR(rsrv.Subnet) {
			v.addError(fmt.Sprintf("dns.rev_server[%d].subnet", i),
				fmt.Sprintf("invalid CIDR: %s", rsrv.Subnet))
		}
		if rsrv.Nameserver == "" {
			v.addError(fmt.Sprintf("dns.rev_server[%d].nameserver", i), "nameserver is required")
		} else if !isValidIP(rsrv.Nameserver) {
			v.addError(fmt.Sprintf("dns.rev_server[%d].nameserver", i),
				fmt.Sprintf("invalid IP address: %s", rsrv.Nameserver))
		}
	}

	// Cache settings
	if cfg.CacheSize < 0 {
		v.addError("dns.cache_size", "must be non-negative")
	}
	if cfg.LocalTTL < 0 {
		v.addError("dns.local_ttl", "must be non-negative")
	}
	if cfg.NegTTL < 0 {
		v.addError("dns.neg_ttl", "must be non-negative")
	}
	if cfg.MaxTTL < 0 {
		v.addError("dns.max_ttl", "must be non-negative")
	}
	if cfg.MinCacheTTL < 0 {
		v.addError("dns.min_cache_ttl", "must be non-negative")
	}
	if cfg.MaxCacheTTL < 0 {
		v.addError("dns.max_cache_ttl", "must be non-negative")
	}
	if cfg.MinCacheTTL > 0 && cfg.MaxCacheTTL > 0 && cfg.MinCacheTTL > cfg.MaxCacheTTL {
		v.addError("dns.min_cache_ttl", "cannot be greater than max_cache_ttl")
	}
}

func (v *Validator) validateDNSSEC() {
	if v.config.DNSSEC == nil || !v.config.DNSSEC.Enabled {
		return
	}

	// DNSSEC validation requires upstream servers or no-resolv
	if v.config.DNS != nil && len(v.config.DNS.Servers) == 0 {
		if v.config.Global == nil || !v.config.Global.NoResolv {
			// This is just a warning, not an error
		}
	}
}

func (v *Validator) validateDHCP() {
	if v.config.DHCP == nil || !v.config.DHCP.Enabled {
		return
	}

	cfg := v.config.DHCP

	if cfg.LeaseMax < 0 {
		v.addError("dhcp.lease_max", "must be non-negative")
	}

	// DHCPv4 ranges
	for i, r := range cfg.Ranges {
		if r.Start == "" {
			v.addError(fmt.Sprintf("dhcp.range[%d].start", i), "start address is required")
		} else if !isValidIPv4(r.Start) {
			v.addError(fmt.Sprintf("dhcp.range[%d].start", i),
				fmt.Sprintf("invalid IPv4 address: %s", r.Start))
		}
		if r.End == "" {
			v.addError(fmt.Sprintf("dhcp.range[%d].end", i), "end address is required")
		} else if !isValidIPv4(r.End) {
			v.addError(fmt.Sprintf("dhcp.range[%d].end", i),
				fmt.Sprintf("invalid IPv4 address: %s", r.End))
		}
		if r.Netmask != "" && !isValidIPv4(r.Netmask) {
			v.addError(fmt.Sprintf("dhcp.range[%d].netmask", i),
				fmt.Sprintf("invalid netmask: %s", r.Netmask))
		}
		if r.LeaseTime != "" && !isValidLeaseTime(r.LeaseTime) {
			v.addError(fmt.Sprintf("dhcp.range[%d].lease_time", i),
				fmt.Sprintf("invalid lease time: %s", r.LeaseTime))
		}
	}

	// DHCPv6 ranges
	for i, r := range cfg.RangesV6 {
		if r.Start != "" && !isValidIPv6(r.Start) {
			v.addError(fmt.Sprintf("dhcp.range_v6[%d].start", i),
				fmt.Sprintf("invalid IPv6 address: %s", r.Start))
		}
		if r.End != "" && !isValidIPv6(r.End) {
			v.addError(fmt.Sprintf("dhcp.range_v6[%d].end", i),
				fmt.Sprintf("invalid IPv6 address: %s", r.End))
		}
		if r.PrefixLength < 0 || r.PrefixLength > 128 {
			v.addError(fmt.Sprintf("dhcp.range_v6[%d].prefix_length", i),
				"prefix length must be between 0 and 128")
		}
		validModes := map[string]bool{
			"ra-only": true, "slaac": true, "ra-stateless": true, "ra-names": true, "": true,
		}
		if !validModes[r.Mode] {
			v.addError(fmt.Sprintf("dhcp.range_v6[%d].mode", i),
				fmt.Sprintf("invalid mode: %s (must be ra-only, slaac, ra-stateless, or ra-names)", r.Mode))
		}
	}

	// DHCP options
	for i, opt := range cfg.Options {
		if opt.Number <= 0 && opt.Name == "" {
			v.addError(fmt.Sprintf("dhcp.option[%d]", i),
				"either number or name must be specified")
		}
		if opt.Number > 0 && (opt.Number < 1 || opt.Number > 255) {
			v.addError(fmt.Sprintf("dhcp.option[%d].number", i),
				"option number must be between 1 and 255")
		}
	}
}

func (v *Validator) validateDHCPHosts() {
	for i, h := range v.config.DHCPHosts {
		if h.MAC == "" && h.ClientID == "" {
			v.addError(fmt.Sprintf("dhcp_host[%d]", i),
				"either mac or client_id must be specified")
		}
		if h.MAC != "" && !isValidMAC(h.MAC) {
			v.addError(fmt.Sprintf("dhcp_host[%d].mac", i),
				fmt.Sprintf("invalid MAC address: %s", h.MAC))
		}
		if h.IP != "" && !isValidIP(h.IP) {
			v.addError(fmt.Sprintf("dhcp_host[%d].ip", i),
				fmt.Sprintf("invalid IP address: %s", h.IP))
		}
		if h.LeaseTime != "" && !isValidLeaseTime(h.LeaseTime) {
			v.addError(fmt.Sprintf("dhcp_host[%d].lease_time", i),
				fmt.Sprintf("invalid lease time: %s", h.LeaseTime))
		}
	}
}

func (v *Validator) validateTFTP() {
	if v.config.TFTP == nil || !v.config.TFTP.Enabled {
		return
	}

	cfg := v.config.TFTP

	if cfg.MaxConnections < 0 {
		v.addError("tftp.max_connections", "must be non-negative")
	}
	if cfg.MTU < 0 {
		v.addError("tftp.mtu", "must be non-negative")
	}
	if cfg.PortRange != "" {
		parts := strings.Split(cfg.PortRange, "-")
		if len(parts) != 2 {
			v.addError("tftp.port_range", "must be in format 'start-end'")
		} else {
			start, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 != nil || err2 != nil {
				v.addError("tftp.port_range", "invalid port numbers")
			} else if start < 1 || start > 65535 || end < 1 || end > 65535 {
				v.addError("tftp.port_range", "ports must be between 1 and 65535")
			} else if start > end {
				v.addError("tftp.port_range", "start port must be less than or equal to end port")
			}
		}
	}
	validUniqueRoot := map[string]bool{"": true, "ip": true, "mac": true}
	if !validUniqueRoot[cfg.UniqueRoot] {
		v.addError("tftp.unique_root", "must be 'ip' or 'mac'")
	}
}

func (v *Validator) validatePXE() {
	if v.config.PXE == nil {
		return
	}

	cfg := v.config.PXE

	if cfg.Prompt != nil {
		if cfg.Prompt.Timeout < 0 {
			v.addError("pxe.prompt.timeout", "must be non-negative")
		}
	}

	for i, svc := range cfg.Services {
		if svc.CSA == "" {
			v.addError(fmt.Sprintf("pxe.service[%d].csa", i),
				"client system architecture is required")
		}
		if svc.Basename == "" {
			v.addError(fmt.Sprintf("pxe.service[%d].basename", i),
				"basename is required")
		}
		if svc.Server != "" && !isValidIP(svc.Server) {
			v.addError(fmt.Sprintf("pxe.service[%d].server", i),
				fmt.Sprintf("invalid IP address: %s", svc.Server))
		}
	}
}

func (v *Validator) validateRA() {
	if v.config.RA == nil || !v.config.RA.Enabled {
		return
	}

	cfg := v.config.RA

	for i, p := range cfg.Params {
		if p.Interface == "" {
			v.addError(fmt.Sprintf("ra.param[%d].interface", i), "interface is required")
		}
		if p.MTU < 0 {
			v.addError(fmt.Sprintf("ra.param[%d].mtu", i), "must be non-negative")
		}
		if p.Lifetime < 0 {
			v.addError(fmt.Sprintf("ra.param[%d].lifetime", i), "must be non-negative")
		}
		if p.HighPriority && p.LowPriority {
			v.addError(fmt.Sprintf("ra.param[%d]", i),
				"cannot set both high_priority and low_priority")
		}
	}

	for i, rdnss := range cfg.RDNSS {
		if rdnss.Address == "" {
			v.addError(fmt.Sprintf("ra.rdnss[%d].address", i), "address is required")
		} else if !isValidIPv6(rdnss.Address) {
			v.addError(fmt.Sprintf("ra.rdnss[%d].address", i),
				fmt.Sprintf("invalid IPv6 address: %s", rdnss.Address))
		}
		if rdnss.Lifetime < 0 {
			v.addError(fmt.Sprintf("ra.rdnss[%d].lifetime", i), "must be non-negative")
		}
	}
}

func (v *Validator) validateRecords() {
	// Host records
	for i, hr := range v.config.HostRecords {
		if hr.Name == "" {
			v.addError(fmt.Sprintf("host_record[%d].name", i), "name is required")
		}
		if hr.IPv4 == "" && hr.IPv6 == "" {
			v.addError(fmt.Sprintf("host_record[%d]", i),
				"at least one of ipv4 or ipv6 must be specified")
		}
		if hr.IPv4 != "" && !isValidIPv4(hr.IPv4) {
			v.addError(fmt.Sprintf("host_record[%d].ipv4", i),
				fmt.Sprintf("invalid IPv4 address: %s", hr.IPv4))
		}
		if hr.IPv6 != "" && !isValidIPv6(hr.IPv6) {
			v.addError(fmt.Sprintf("host_record[%d].ipv6", i),
				fmt.Sprintf("invalid IPv6 address: %s", hr.IPv6))
		}
		if hr.TTL < 0 {
			v.addError(fmt.Sprintf("host_record[%d].ttl", i), "must be non-negative")
		}
	}

	// Address records
	for i, ar := range v.config.AddressRecords {
		if ar.Domain == "" {
			v.addError(fmt.Sprintf("address_record[%d].domain", i), "domain is required")
		}
		if ar.IP == "" {
			v.addError(fmt.Sprintf("address_record[%d].ip", i), "ip is required")
		} else if !isValidIP(ar.IP) {
			v.addError(fmt.Sprintf("address_record[%d].ip", i),
				fmt.Sprintf("invalid IP address: %s", ar.IP))
		}
	}

	// CNAME records
	for i, cr := range v.config.CNAMERecords {
		if cr.Alias == "" {
			v.addError(fmt.Sprintf("cname_record[%d].alias", i), "alias is required")
		}
		if cr.Target == "" {
			v.addError(fmt.Sprintf("cname_record[%d].target", i), "target is required")
		}
	}

	// MX records
	for i, mx := range v.config.MXRecords {
		if mx.Domain == "" {
			v.addError(fmt.Sprintf("mx_record[%d].domain", i), "domain is required")
		}
		if mx.Target == "" {
			v.addError(fmt.Sprintf("mx_record[%d].target", i), "target is required")
		}
		if mx.Preference < 0 || mx.Preference > 65535 {
			v.addError(fmt.Sprintf("mx_record[%d].preference", i),
				"must be between 0 and 65535")
		}
	}

	// SRV records
	for i, srv := range v.config.SRVRecords {
		if srv.Service == "" {
			v.addError(fmt.Sprintf("srv_record[%d].service", i), "service is required")
		}
		if srv.Target == "" {
			v.addError(fmt.Sprintf("srv_record[%d].target", i), "target is required")
		}
		if srv.Port < 0 || srv.Port > 65535 {
			v.addError(fmt.Sprintf("srv_record[%d].port", i),
				"must be between 0 and 65535")
		}
		if srv.Priority < 0 || srv.Priority > 65535 {
			v.addError(fmt.Sprintf("srv_record[%d].priority", i),
				"must be between 0 and 65535")
		}
		if srv.Weight < 0 || srv.Weight > 65535 {
			v.addError(fmt.Sprintf("srv_record[%d].weight", i),
				"must be between 0 and 65535")
		}
	}

	// TXT records
	for i, txt := range v.config.TXTRecords {
		if txt.Name == "" {
			v.addError(fmt.Sprintf("txt_record[%d].name", i), "name is required")
		}
		if txt.Value == "" {
			v.addError(fmt.Sprintf("txt_record[%d].value", i), "value is required")
		}
	}

	// PTR records
	for i, ptr := range v.config.PTRRecords {
		if ptr.PTRName == "" {
			v.addError(fmt.Sprintf("ptr_record[%d].ptr_name", i), "ptr_name is required")
		}
		if ptr.Target == "" {
			v.addError(fmt.Sprintf("ptr_record[%d].target", i), "target is required")
		}
	}

	// CAA records
	for i, caa := range v.config.CAARecords {
		if caa.Name == "" {
			v.addError(fmt.Sprintf("caa_record[%d].name", i), "name is required")
		}
		if caa.Tag == "" {
			v.addError(fmt.Sprintf("caa_record[%d].tag", i), "tag is required")
		}
		validTags := map[string]bool{"issue": true, "issuewild": true, "iodef": true}
		if !validTags[caa.Tag] {
			v.addError(fmt.Sprintf("caa_record[%d].tag", i),
				"must be 'issue', 'issuewild', or 'iodef'")
		}
		if caa.Flags < 0 || caa.Flags > 255 {
			v.addError(fmt.Sprintf("caa_record[%d].flags", i),
				"must be between 0 and 255")
		}
	}
}

// Validation helper functions

func isValidIP(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isValidIPv4(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() != nil
}

func isValidIPv6(ip string) bool {
	parsed := net.ParseIP(ip)
	return parsed != nil && parsed.To4() == nil
}

func isValidCIDR(cidr string) bool {
	_, _, err := net.ParseCIDR(cidr)
	return err == nil
}

func isValidMAC(mac string) bool {
	// Support various MAC address formats
	patterns := []string{
		`^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$`,  // 00:11:22:33:44:55
		`^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$`,  // 00-11-22-33-44-55
		`^([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4}$`, // 0011.2233.4455
		`^[0-9A-Fa-f]{12}$`,                     // 001122334455
	}
	for _, pattern := range patterns {
		if matched, _ := regexp.MatchString(pattern, mac); matched {
			return true
		}
	}
	return false
}

func isValidLeaseTime(lt string) bool {
	// Valid formats: "infinite", seconds, or number with suffix (m, h, d, w)
	if lt == "infinite" {
		return true
	}
	// Try parsing as number (seconds)
	if _, err := strconv.Atoi(lt); err == nil {
		return true
	}
	// Try parsing with suffix
	if matched, _ := regexp.MatchString(`^\d+[smhdw]$`, lt); matched {
		return true
	}
	return false
}

func isValidDomain(domain string) bool {
	// Basic domain validation
	if domain == "" {
		return false
	}
	// Allow wildcards
	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}
	// Simple pattern match for domain names
	pattern := `^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$`
	matched, _ := regexp.MatchString(pattern, domain)
	return matched
}
