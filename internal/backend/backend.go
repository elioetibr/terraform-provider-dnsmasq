// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package backend

import (
	"context"
	"io"
	"os"
	"time"
)

// Backend defines the interface for configuration storage backends.
type Backend interface {
	ConfigWriter
	ConfigReader
	CommandExecutor
	ServiceManager
	io.Closer
}

// ConfigWriter handles writing configuration files.
type ConfigWriter interface {
	// WriteConfig writes configuration content to the specified path.
	WriteConfig(ctx context.Context, path string, content []byte, mode os.FileMode) error

	// DeleteConfig removes a configuration file.
	DeleteConfig(ctx context.Context, path string) error
}

// ConfigReader handles reading configuration files.
type ConfigReader interface {
	// ReadConfig reads configuration content from the specified path.
	ReadConfig(ctx context.Context, path string) ([]byte, error)

	// FileExists checks if a configuration file exists.
	FileExists(ctx context.Context, path string) (bool, error)

	// ListDir lists files in a directory.
	ListDir(ctx context.Context, path string) ([]FileInfo, error)
}

// CommandExecutor executes commands on the target system.
type CommandExecutor interface {
	// Execute runs a command and returns output.
	Execute(ctx context.Context, cmd string, args ...string) (stdout, stderr []byte, err error)
}

// ServiceManager manages the dnsmasq service.
type ServiceManager interface {
	// Reload triggers a configuration reload.
	Reload(ctx context.Context) error

	// Restart restarts the service.
	Restart(ctx context.Context) error

	// Status returns the service status.
	Status(ctx context.Context) (ServiceStatus, error)

	// IsRunning checks if the service is running.
	IsRunning(ctx context.Context) (bool, error)

	// ValidateConfig validates the configuration using dnsmasq --test.
	ValidateConfig(ctx context.Context) error
}

// FileInfo represents file metadata.
type FileInfo struct {
	Name    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

// Platform represents the target operating system.
type Platform string

const (
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformWindows Platform = "windows"
	PlatformUnknown Platform = "unknown"
)

// ServiceManagerType represents the type of service manager.
type ServiceManagerType string

const (
	ServiceManagerSystemd      ServiceManagerType = "systemd"
	ServiceManagerLaunchd      ServiceManagerType = "launchd"
	ServiceManagerBrewServices ServiceManagerType = "brew_services"
	ServiceManagerInit         ServiceManagerType = "init"
	ServiceManagerNone         ServiceManagerType = "none"
)

// PlatformPaths contains platform-specific default paths.
type PlatformPaths struct {
	// MainConfig is the path to the main dnsmasq.conf file.
	MainConfig string

	// ConfigDir is the path to the configuration directory (dnsmasq.d).
	ConfigDir string

	// IncludePattern is the glob pattern for included config files.
	IncludePattern string

	// PidFile is the path to the PID file.
	PidFile string

	// DnsmasqBinary is the path to the dnsmasq binary.
	DnsmasqBinary string
}

// ServiceStatus represents the current service state.
type ServiceStatus struct {
	Running   bool
	Enabled   bool
	PID       int
	StartTime time.Time
	Error     string
}

// Config holds backend configuration.
type Config struct {
	// Mode is the backend type: "local", "ssh", or "content_only"
	Mode string

	// Platform is the target platform
	Platform Platform

	// Local backend configuration
	Local *LocalConfig

	// SSH backend configuration
	SSH *SSHConfig

	// Service management configuration
	Service *ServiceConfig
}

// LocalConfig holds local backend configuration.
type LocalConfig struct {
	// ConfigPath is the path to the main configuration file.
	ConfigPath string

	// ConfigDir is the path to the configuration directory.
	ConfigDir string
}

// SSHConfig holds SSH backend configuration.
type SSHConfig struct {
	// Host is the SSH server hostname or IP.
	Host string

	// Port is the SSH port (default 22).
	Port int

	// User is the SSH username.
	User string

	// Password is the SSH password (prefer PrivateKey).
	Password string

	// PrivateKey is the PEM-encoded private key content.
	PrivateKey string

	// PrivateKeyPath is the path to the private key file.
	PrivateKeyPath string

	// Passphrase is the passphrase for encrypted private keys.
	Passphrase string

	// KnownHostsFile is the path to the known_hosts file.
	KnownHostsFile string

	// StrictHostKeyChecking enables strict host key verification.
	StrictHostKeyChecking bool

	// Timeout is the connection timeout in seconds.
	Timeout int

	// ConfigPath is the remote path to the configuration file.
	ConfigPath string

	// ConfigDir is the remote path to the configuration directory.
	ConfigDir string

	// Bastion is the bastion/jump host configuration.
	Bastion *SSHConfig
}

// ServiceConfig holds service management configuration.
type ServiceConfig struct {
	// Enabled enables automatic service management.
	Enabled bool

	// Type is the service manager type.
	Type ServiceManagerType

	// ServiceName is the service name (default: dnsmasq).
	ServiceName string

	// ReloadCommand is a custom reload command.
	ReloadCommand string

	// ValidateBeforeReload runs dnsmasq --test before reload.
	ValidateBeforeReload bool

	// RestartOnFail restarts if reload fails.
	RestartOnFail bool

	// DnsmasqBinary is the path to the dnsmasq binary.
	DnsmasqBinary string
}

// GetDefaultPaths returns platform-specific default paths.
func GetDefaultPaths(platform Platform) PlatformPaths {
	switch platform {
	case PlatformLinux:
		return PlatformPaths{
			MainConfig:     "/etc/dnsmasq.conf",
			ConfigDir:      "/etc/dnsmasq.d",
			IncludePattern: "/etc/dnsmasq.d/*.conf",
			PidFile:        "/var/run/dnsmasq.pid",
			DnsmasqBinary:  "/usr/sbin/dnsmasq",
		}
	case PlatformMacOS:
		// Check for Apple Silicon vs Intel paths
		// This is a simplified check; actual detection should be done at runtime
		return PlatformPaths{
			MainConfig:     "/opt/homebrew/etc/dnsmasq.conf",
			ConfigDir:      "/opt/homebrew/etc/dnsmasq.d",
			IncludePattern: "/opt/homebrew/etc/dnsmasq.d/*.conf",
			PidFile:        "/opt/homebrew/var/run/dnsmasq.pid",
			DnsmasqBinary:  "/opt/homebrew/sbin/dnsmasq",
		}
	case PlatformWindows:
		return PlatformPaths{
			MainConfig:    "C:\\dnsmasq\\dnsmasq.conf",
			ConfigDir:     "C:\\dnsmasq\\dnsmasq.d",
			DnsmasqBinary: "C:\\dnsmasq\\dnsmasq.exe",
		}
	default:
		return PlatformPaths{}
	}
}

// GetDefaultServiceManager returns the default service manager for a platform.
func GetDefaultServiceManager(platform Platform) ServiceManagerType {
	switch platform {
	case PlatformLinux:
		return ServiceManagerSystemd
	case PlatformMacOS:
		return ServiceManagerBrewServices
	default:
		return ServiceManagerNone
	}
}
