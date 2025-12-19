# Configure the dnsmasq provider
provider "dnsmasq" {
  # Deployment mode: 'local', 'ssh', or 'content_only'
  mode = "local"

  # Platform auto-detection (linux, macos, windows)
  platform = "auto"

  # Optional: service management
  service_management {
    enabled               = true
    validate_before_reload = true
  }
}
