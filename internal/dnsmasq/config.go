// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package dnsmasq

// Config represents the complete dnsmasq configuration.
type Config struct {
	// Name is an identifier for this configuration
	Name string

	// OutputPath is the path where the config file will be written
	OutputPath string

	// Global settings
	Global *GlobalConfig

	// DNS settings
	DNS *DNSConfig

	// DNSSEC settings
	DNSSEC *DNSSECConfig

	// DHCP settings
	DHCP *DHCPConfig

	// TFTP settings
	TFTP *TFTPConfig

	// PXE settings
	PXE *PXEConfig

	// Router Advertisement settings
	RA *RouterAdvertisementConfig

	// DNS Records
	HostRecords    []HostRecord
	AddressRecords []AddressRecord
	CNAMERecords   []CNAMERecord
	MXRecords      []MXRecord
	SRVRecords     []SRVRecord
	TXTRecords     []TXTRecord
	PTRRecords     []PTRRecord
	NAPTRRecords   []NAPTRRecord
	CAARecords     []CAARecord

	// DHCP Hosts
	DHCPHosts []DHCPHost

	// Custom options (raw lines to append)
	CustomOptions []string
}

// GlobalConfig represents global dnsmasq settings.
type GlobalConfig struct {
	// User to run as after startup
	User string

	// Group to run as after startup
	Group string

	// Enable query logging
	LogQueries bool

	// Log facility (syslog facility or file path)
	LogFacility string

	// Enable DHCP logging
	LogDHCP bool

	// Async logging queue size
	LogAsync int

	// Configuration directory to include
	ConfDir string

	// Additional configuration files to include
	ConfFile []string

	// Don't read /etc/hosts
	NoHosts bool

	// Additional hosts files
	AddnHosts []string

	// Expand simple names by adding domain
	ExpandHosts bool

	// Domain for DHCP clients
	Domain string

	// Local domain (don't forward to upstream)
	Local string

	// Filter Windows-specific DNS queries
	FilterWin2K bool

	// Return subnet-specific addresses
	LocaliseQueries bool

	// PID file location
	PidFile string

	// Don't read /etc/resolv.conf
	NoResolv bool

	// Alternative resolv.conf file
	ResolvFile string

	// Don't poll resolv.conf for changes
	NoPoll bool
}

// DNSConfig represents DNS-specific configuration.
type DNSConfig struct {
	// Port to listen on (default 53)
	Port int

	// Addresses to listen on
	ListenAddress []string

	// Interfaces to listen on
	Interface []string

	// Interfaces to exclude
	ExceptInterface []string

	// Bind only to specified interfaces
	BindInterfaces bool

	// Dynamic binding mode
	BindDynamic bool

	// Upstream DNS servers
	Servers []DNSServer

	// Reverse DNS servers
	RevServers []RevServer

	// Query behavior
	StrictOrder       bool
	AllServers        bool
	DomainNeeded      bool
	BogusPriv         bool
	DNSLoopDetect     bool
	StopDNSRebind     bool
	RebindLocalhostOK bool
	RebindDomainOK    []string

	// Dynamic server list file
	ServersFile string

	// Cache settings
	CacheSize   int
	NoNegcache  bool
	LocalTTL    int
	NegTTL      int
	MaxTTL      int
	MaxCacheTTL int
	MinCacheTTL int
	AuthTTL     int

	// EDNS settings
	EDNSPacketMax int

	// Query forwarding limits
	DNSForwardMax int
}

// DNSServer represents an upstream DNS server.
type DNSServer struct {
	// Server address (IP or IP#port)
	Address string

	// Domain to use this server for (optional)
	Domain string

	// Source address to use (optional)
	Source string
}

// RevServer represents a reverse DNS server configuration.
type RevServer struct {
	// Subnet in CIDR notation
	Subnet string

	// Nameserver address
	Nameserver string
}

// DNSSECConfig represents DNSSEC configuration.
type DNSSECConfig struct {
	// Enable DNSSEC validation
	Enabled bool

	// Check that unsigned DNS replies are legitimate
	CheckUnsigned bool

	// Don't check DNSSEC signature timestamps
	NoTimecheck bool

	// Trust anchors for DNSSEC validation
	TrustAnchor []string

	// Timestamp file for DNSSEC
	Timestamp string
}

// DHCPConfig represents DHCP configuration.
type DHCPConfig struct {
	// Enable DHCP
	Enabled bool

	// Act as authoritative DHCP server
	Authoritative bool

	// Lease file path
	Leasefile string

	// Maximum number of leases
	LeaseMax int

	// DHCPv4 ranges
	Ranges []DHCPRange

	// DHCPv6 ranges
	RangesV6 []DHCPRangeV6

	// DHCP options
	Options []DHCPOption

	// Vendor class matching
	VendorClasses []VendorClass

	// User class matching
	UserClasses []UserClass

	// Boot options for PXE/BOOTP
	BootOptions []BootOption

	// Ignore client-supplied hostnames
	IgnoreNames bool

	// Generate hostnames from MAC addresses
	GenerateNames bool

	// Script to run on lease changes
	Script string

	// User to run script as
	ScriptUser string

	// Enable rapid commit (RFC 4039)
	RapidCommit bool

	// Sequential IP allocation
	SequentialIP bool

	// Read /etc/ethers for static assignments
	ReadEthers bool
}

// DHCPRange represents a DHCPv4 address range.
type DHCPRange struct {
	// Tag for this range
	Tag string

	// Start of range
	Start string

	// End of range
	End string

	// Netmask
	Netmask string

	// Lease time
	LeaseTime string

	// Interface for this range
	Interface string
}

// DHCPRangeV6 represents a DHCPv6 address range.
type DHCPRangeV6 struct {
	// Tag for this range
	Tag string

	// Start of range
	Start string

	// End of range
	End string

	// Prefix length
	PrefixLength int

	// Lease time
	LeaseTime string

	// Mode: ra-only, slaac, ra-stateless, ra-names
	Mode string

	// Constructor interface
	Constructor string
}

// DHCPOption represents a DHCP option.
type DHCPOption struct {
	// Option number
	Number int

	// Option name (alternative to number)
	Name string

	// Option value
	Value string

	// Tag to apply option to
	Tag string

	// Force option even if client doesn't request it
	Force bool
}

// VendorClass represents a DHCP vendor class match.
type VendorClass struct {
	// Tag to set when matched
	Tag string

	// Vendor class string to match
	Match string
}

// UserClass represents a DHCP user class match.
type UserClass struct {
	// Tag to set when matched
	Tag string

	// User class string to match
	Match string
}

// BootOption represents PXE/BOOTP boot configuration.
type BootOption struct {
	// Boot filename
	Filename string

	// Boot server address
	Server string

	// Tag to apply this option to
	Tag string
}

// DHCPHost represents a static DHCP host assignment.
type DHCPHost struct {
	// MAC address
	MAC string

	// Client ID (alternative to MAC)
	ClientID string

	// Hostname
	Name string

	// IP address
	IP string

	// Lease time
	LeaseTime string

	// Tags to apply
	Tags []string

	// Ignore this client
	Ignore bool
}

// TFTPConfig represents TFTP server configuration.
type TFTPConfig struct {
	// Enable TFTP server
	Enabled bool

	// Root directory
	Root string

	// Only serve files owned by user running dnsmasq
	Secure bool

	// Continue if TFTP setup fails
	NoFail bool

	// Per-client root directory mode: "ip" or "mac"
	UniqueRoot string

	// Convert filenames to lowercase
	Lowercase bool

	// Maximum concurrent transfers
	MaxConnections int

	// MTU override
	MTU int

	// Disable blocksize negotiation
	NoBlocksize bool

	// Port range for transfers
	PortRange string

	// Use only port 69
	SinglePort bool
}

// PXEConfig represents PXE boot configuration.
type PXEConfig struct {
	// Boot menu prompt
	Prompt *PXEPrompt

	// Boot services
	Services []PXEService
}

// PXEPrompt represents the PXE boot prompt.
type PXEPrompt struct {
	// Prompt text
	Text string

	// Timeout in seconds
	Timeout int
}

// PXEService represents a PXE boot service.
type PXEService struct {
	// Client system architecture (e.g., "x86PC", "x86-64_EFI")
	CSA string

	// Menu text
	MenuText string

	// Boot file basename
	Basename string

	// Boot server address (optional)
	Server string
}

// RouterAdvertisementConfig represents IPv6 router advertisement configuration.
type RouterAdvertisementConfig struct {
	// Enable router advertisement
	Enabled bool

	// RA parameters per interface
	Params []RAParam

	// RDNSS options
	RDNSS []RDNSS
}

// RAParam represents router advertisement parameters for an interface.
type RAParam struct {
	// Interface name
	Interface string

	// MTU to advertise
	MTU int

	// High priority flag
	HighPriority bool

	// Low priority flag
	LowPriority bool

	// RA interval (min,max or single value)
	Interval string

	// Router lifetime
	Lifetime int
}

// RDNSS represents an RDNSS (Recursive DNS Server) option.
type RDNSS struct {
	// DNS server address
	Address string

	// Lifetime in seconds
	Lifetime int
}

// HostRecord represents a host-record entry (A/AAAA/PTR).
type HostRecord struct {
	// Hostname
	Name string

	// IPv4 address
	IPv4 string

	// IPv6 address
	IPv6 string

	// TTL
	TTL int
}

// AddressRecord represents an address entry for domain-to-IP mapping.
type AddressRecord struct {
	// Domain (can include wildcards)
	Domain string

	// IP address (can be 0.0.0.0 to block)
	IP string
}

// CNAMERecord represents a CNAME alias.
type CNAMERecord struct {
	// Alias name
	Alias string

	// Target hostname
	Target string
}

// MXRecord represents a mail exchange record.
type MXRecord struct {
	// Domain
	Domain string

	// Mail server target
	Target string

	// Preference (lower = higher priority)
	Preference int
}

// SRVRecord represents a service record.
type SRVRecord struct {
	// Service name (e.g., "_ldap._tcp.example.com")
	Service string

	// Target hostname
	Target string

	// Port
	Port int

	// Priority
	Priority int

	// Weight
	Weight int
}

// TXTRecord represents a text record.
type TXTRecord struct {
	// Name
	Name string

	// Value
	Value string
}

// PTRRecord represents a pointer record.
type PTRRecord struct {
	// PTR name (e.g., "10.1.168.192.in-addr.arpa")
	PTRName string

	// Target hostname
	Target string
}

// NAPTRRecord represents a NAPTR record.
type NAPTRRecord struct {
	// Name
	Name string

	// Order
	Order int

	// Preference
	Preference int

	// Flags
	Flags string

	// Service
	Service string

	// Regexp
	Regexp string

	// Replacement
	Replacement string
}

// CAARecord represents a CAA record.
type CAARecord struct {
	// Name
	Name string

	// Flags
	Flags int

	// Tag (e.g., "issue", "issuewild", "iodef")
	Tag string

	// Value
	Value string
}
