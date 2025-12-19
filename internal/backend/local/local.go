// Copyright (c) Elio Severo Junior
// SPDX-License-Identifier: MIT

package local

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/elioseverojunior/terraform-provider-dnsmasq/internal/backend"
)

// LocalBackend implements the Backend interface for local filesystem operations.
type LocalBackend struct {
	platform       backend.Platform
	paths          backend.PlatformPaths
	serviceManager backend.ServiceManagerType
	serviceName    string
	customReload   string
	validateFirst  bool
	restartOnFail  bool
	dnsmasqBinary  string
}

// Config holds configuration for the local backend.
type Config struct {
	Platform       string
	ConfigPath     string
	ConfigDir      string
	ServiceManager string
	ServiceName    string
	ReloadCommand  string
	ValidateFirst  bool
	RestartOnFail  bool
	DnsmasqBinary  string
}

// New creates a new local backend.
func New(cfg Config) (*LocalBackend, error) {
	lb := &LocalBackend{
		serviceName:   cfg.ServiceName,
		customReload:  cfg.ReloadCommand,
		validateFirst: cfg.ValidateFirst,
		restartOnFail: cfg.RestartOnFail,
		dnsmasqBinary: cfg.DnsmasqBinary,
	}

	// Detect platform
	if cfg.Platform == "" || cfg.Platform == "auto" {
		lb.platform = detectLocalPlatform()
	} else {
		lb.platform = backend.Platform(cfg.Platform)
	}

	// Set default paths based on platform
	lb.paths = backend.GetDefaultPaths(lb.platform)

	// Override with user-provided paths
	if cfg.ConfigPath != "" {
		lb.paths.MainConfig = cfg.ConfigPath
	}
	if cfg.ConfigDir != "" {
		lb.paths.ConfigDir = cfg.ConfigDir
	}

	// Detect or use provided service manager
	if cfg.ServiceManager != "" && cfg.ServiceManager != "auto" {
		lb.serviceManager = backend.ServiceManagerType(cfg.ServiceManager)
	} else {
		lb.serviceManager = detectServiceManager(lb.platform)
	}

	// Set defaults
	if lb.serviceName == "" {
		lb.serviceName = "dnsmasq"
	}
	if lb.dnsmasqBinary == "" {
		lb.dnsmasqBinary = lb.paths.DnsmasqBinary
		if lb.dnsmasqBinary == "" {
			lb.dnsmasqBinary = "dnsmasq"
		}
	}

	return lb, nil
}

// WriteConfig writes configuration content to the specified path.
func (lb *LocalBackend) WriteConfig(ctx context.Context, path string, content []byte, mode os.FileMode) error {
	// Ensure parent directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	// Write to temp file first for atomic operation
	tmpFile, err := os.CreateTemp(dir, ".dnsmasq-*.conf.tmp")
	if err != nil {
		return fmt.Errorf("failed to create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath) // Cleanup on failure

	if _, err := tmpFile.Write(content); err != nil {
		tmpFile.Close()
		return fmt.Errorf("failed to write content: %w", err)
	}
	if err := tmpFile.Close(); err != nil {
		return fmt.Errorf("failed to close temp file: %w", err)
	}

	if err := os.Chmod(tmpPath, mode); err != nil {
		return fmt.Errorf("failed to set permissions: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("failed to move config into place: %w", err)
	}

	return nil
}

// ReadConfig reads configuration content from the specified path.
func (lb *LocalBackend) ReadConfig(ctx context.Context, path string) ([]byte, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}
	return content, nil
}

// DeleteConfig removes a configuration file.
func (lb *LocalBackend) DeleteConfig(ctx context.Context, path string) error {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to delete config file: %w", err)
	}
	return nil
}

// FileExists checks if a configuration file exists.
func (lb *LocalBackend) FileExists(ctx context.Context, path string) (bool, error) {
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("failed to check file: %w", err)
	}
	return true, nil
}

// ListDir lists files in a directory.
func (lb *LocalBackend) ListDir(ctx context.Context, path string) ([]backend.FileInfo, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, fmt.Errorf("failed to list directory: %w", err)
	}

	var files []backend.FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		files = append(files, backend.FileInfo{
			Name:    entry.Name(),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   entry.IsDir(),
		})
	}

	return files, nil
}

// Execute runs a command and returns output.
func (lb *LocalBackend) Execute(ctx context.Context, cmd string, args ...string) ([]byte, []byte, error) {
	c := exec.CommandContext(ctx, cmd, args...)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

// Reload triggers a configuration reload.
func (lb *LocalBackend) Reload(ctx context.Context) error {
	// Validate first if enabled
	if lb.validateFirst {
		if err := lb.ValidateConfig(ctx); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	// Use custom reload command if provided
	if lb.customReload != "" {
		_, stderr, err := lb.Execute(ctx, "sh", "-c", lb.customReload)
		if err != nil {
			if lb.restartOnFail {
				return lb.Restart(ctx)
			}
			return fmt.Errorf("reload failed: %s", stderr)
		}
		return nil
	}

	var err error
	switch lb.serviceManager {
	case backend.ServiceManagerSystemd:
		_, _, err = lb.Execute(ctx, "systemctl", "reload", lb.serviceName)
	case backend.ServiceManagerLaunchd:
		_, _, err = lb.Execute(ctx, "launchctl", "kickstart", "-k",
			fmt.Sprintf("system/%s", lb.serviceName))
	case backend.ServiceManagerBrewServices:
		// Brew services don't support reload, need restart
		_, _, err = lb.Execute(ctx, "brew", "services", "restart", lb.serviceName)
	case backend.ServiceManagerInit:
		_, _, err = lb.Execute(ctx, "/etc/init.d/"+lb.serviceName, "reload")
	default:
		err = lb.sendHUP(ctx)
	}

	if err != nil && lb.restartOnFail {
		return lb.Restart(ctx)
	}
	return err
}

// Restart restarts the service.
func (lb *LocalBackend) Restart(ctx context.Context) error {
	if lb.validateFirst {
		if err := lb.ValidateConfig(ctx); err != nil {
			return fmt.Errorf("configuration validation failed: %w", err)
		}
	}

	switch lb.serviceManager {
	case backend.ServiceManagerSystemd:
		_, _, err := lb.Execute(ctx, "systemctl", "restart", lb.serviceName)
		return err
	case backend.ServiceManagerLaunchd:
		// Stop then start
		lb.Execute(ctx, "launchctl", "bootout", fmt.Sprintf("system/%s", lb.serviceName))
		_, _, err := lb.Execute(ctx, "launchctl", "bootstrap", "system",
			fmt.Sprintf("/Library/LaunchDaemons/%s.plist", lb.serviceName))
		return err
	case backend.ServiceManagerBrewServices:
		_, _, err := lb.Execute(ctx, "brew", "services", "restart", lb.serviceName)
		return err
	case backend.ServiceManagerInit:
		_, _, err := lb.Execute(ctx, "/etc/init.d/"+lb.serviceName, "restart")
		return err
	default:
		return lb.sendHUP(ctx)
	}
}

// Status returns the service status.
func (lb *LocalBackend) Status(ctx context.Context) (backend.ServiceStatus, error) {
	status := backend.ServiceStatus{}

	switch lb.serviceManager {
	case backend.ServiceManagerSystemd:
		stdout, _, err := lb.Execute(ctx, "systemctl", "show", lb.serviceName,
			"--property=ActiveState,MainPID")
		if err != nil {
			return status, err
		}

		for _, line := range strings.Split(string(stdout), "\n") {
			if strings.HasPrefix(line, "ActiveState=") {
				state := strings.TrimPrefix(line, "ActiveState=")
				status.Running = state == "active"
			}
			if strings.HasPrefix(line, "MainPID=") {
				pid, _ := strconv.Atoi(strings.TrimPrefix(line, "MainPID="))
				status.PID = pid
			}
		}

	case backend.ServiceManagerBrewServices:
		stdout, _, err := lb.Execute(ctx, "brew", "services", "info", lb.serviceName)
		if err != nil {
			return status, err
		}
		status.Running = strings.Contains(string(stdout), "started")

	default:
		// Check PID file
		if lb.paths.PidFile != "" {
			content, err := os.ReadFile(lb.paths.PidFile)
			if err == nil {
				pid, _ := strconv.Atoi(strings.TrimSpace(string(content)))
				status.PID = pid
				if pid > 0 {
					// Check if process is running
					process, err := os.FindProcess(pid)
					if err == nil && process != nil {
						status.Running = true
					}
				}
			}
		}
	}

	return status, nil
}

// IsRunning checks if the service is running.
func (lb *LocalBackend) IsRunning(ctx context.Context) (bool, error) {
	status, err := lb.Status(ctx)
	if err != nil {
		return false, err
	}
	return status.Running, nil
}

// ValidateConfig validates the configuration using dnsmasq --test.
func (lb *LocalBackend) ValidateConfig(ctx context.Context) error {
	stdout, stderr, err := lb.Execute(ctx, lb.dnsmasqBinary, "--test")
	if err != nil {
		return fmt.Errorf("configuration validation failed: %s %s", stdout, stderr)
	}
	return nil
}

// Close releases any resources.
func (lb *LocalBackend) Close() error {
	return nil
}

// GetPaths returns the configured paths.
func (lb *LocalBackend) GetPaths() backend.PlatformPaths {
	return lb.paths
}

// GetPlatform returns the detected platform.
func (lb *LocalBackend) GetPlatform() backend.Platform {
	return lb.platform
}

// sendHUP sends SIGHUP to the dnsmasq process.
func (lb *LocalBackend) sendHUP(ctx context.Context) error {
	// Get PID from pid file
	if lb.paths.PidFile == "" {
		return fmt.Errorf("no PID file configured")
	}

	content, err := os.ReadFile(lb.paths.PidFile)
	if err != nil {
		return fmt.Errorf("could not read PID file: %w", err)
	}

	pid, err := strconv.Atoi(strings.TrimSpace(string(content)))
	if err != nil {
		return fmt.Errorf("invalid PID: %w", err)
	}

	_, stderr, err := lb.Execute(ctx, "kill", "-HUP", strconv.Itoa(pid))
	if err != nil {
		return fmt.Errorf("failed to send SIGHUP: %s", stderr)
	}
	return nil
}

// detectLocalPlatform detects the current operating system.
func detectLocalPlatform() backend.Platform {
	switch runtime.GOOS {
	case "linux":
		return backend.PlatformLinux
	case "darwin":
		return backend.PlatformMacOS
	case "windows":
		return backend.PlatformWindows
	default:
		return backend.PlatformUnknown
	}
}

// detectServiceManager detects the available service manager.
func detectServiceManager(platform backend.Platform) backend.ServiceManagerType {
	switch platform {
	case backend.PlatformLinux:
		// Check for systemd
		if _, err := exec.LookPath("systemctl"); err == nil {
			// Verify systemd is actually running
			if _, err := os.Stat("/run/systemd/system"); err == nil {
				return backend.ServiceManagerSystemd
			}
		}
		// Fallback to init
		if _, err := os.Stat("/etc/init.d"); err == nil {
			return backend.ServiceManagerInit
		}
		return backend.ServiceManagerNone

	case backend.PlatformMacOS:
		// Check for Homebrew services
		if _, err := exec.LookPath("brew"); err == nil {
			return backend.ServiceManagerBrewServices
		}
		return backend.ServiceManagerLaunchd

	default:
		return backend.ServiceManagerNone
	}
}
