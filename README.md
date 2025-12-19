# Terraform Provider for dnsmasq

[![Go](https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat&logo=go)](https://go.dev/)
[![Terraform](https://img.shields.io/badge/Terraform-1.0+-7B42BC?style=flat&logo=terraform)](https://www.terraform.io/)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

A comprehensive Terraform provider for managing dnsmasq configuration files across Windows, Linux, and macOS. This provider enables infrastructure-as-code management of DNS, DHCP, TFTP, PXE boot, and Router Advertisement configurations.

## Table of Contents

- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Provider Configuration](#provider-configuration)
- [Resources](#resources)
- [Platform Support](#platform-support)
- [Documentation](#documentation)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

## Features

### DNS Configuration

- **Upstream Servers**: Configure upstream DNS servers with optional domain-specific routing
- **Caching**: Configurable cache size and behavior
- **DNSSEC**: Full DNSSEC validation support
- **Record Types**: A, AAAA, CNAME, MX, SRV, TXT records
- **Domain Management**: Local domains, expand-hosts, bogus-priv
- **Security**: DNS rebind protection, loop detection

### DHCP Configuration

- **IPv4/IPv6 Ranges**: Multiple DHCP ranges with lease time configuration
- **Static Hosts**: MAC-based static IP assignments
- **Options**: Full DHCP option support (router, DNS, domain, NTP, etc.)
- **Authoritative Mode**: Act as the authoritative DHCP server
- **Lease Management**: Configurable lease files and times

### Network Boot

- **TFTP Server**: Built-in TFTP configuration for network boot
- **PXE Boot**: Full PXE boot menu and service configuration
- **Secure Mode**: Restrict TFTP to files owned by dnsmasq user

### Additional Features

- **Router Advertisement**: IPv6 router advertisement configuration
- **Cross-Platform**: Works on Linux, macOS (Intel and ARM), and Windows
- **Deployment Modes**: Local filesystem, SSH remote, or content-only for Kubernetes
- **Service Management**: Automatic service reload after configuration changes
- **Validation**: Configuration validation before deployment

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.22 (for building from source)
- [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) (on target system)

## Installation

### From Source

```bash
git clone https://github.com/elioseverojunior/terraform-provider-dnsmasq.git
cd terraform-provider-dnsmasq
make install
```

### Manual Installation

```bash
go build -o terraform-provider-dnsmasq
mkdir -p ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/dnsmasq/0.1.0/$(go env GOOS)_$(go env GOARCH)
cp terraform-provider-dnsmasq ~/.terraform.d/plugins/registry.terraform.io/elioseverojunior/dnsmasq/0.1.0/$(go env GOOS)_$(go env GOARCH)/
```

### Terraform Configuration

Add the provider to your Terraform configuration:

```hcl
terraform {
  required_providers {
    dnsmasq = {
      source  = "elioseverojunior/dnsmasq"
      version = "~> 0.1.0"
    }
  }
}
```

## Quick Start

### Basic DNS Configuration

```hcl
provider "dnsmasq" {
  mode     = "local"
  platform = "auto"
}

resource "dnsmasq_config" "main" {
  filename = "terraform-managed.conf"

  global {
    domain       = "local.lan"
    expand_hosts = true
  }

  dns {
    port           = 53
    listen_address = ["127.0.0.1"]
    cache_size     = 1000

    server {
      address = "8.8.8.8"
    }

    server {
      address = "8.8.4.4"
    }
  }

  host_record {
    name = "server1"
    ipv4 = "192.168.1.10"
  }
}

output "config_path" {
  value = dnsmasq_config.main.output_path
}

output "config_content" {
  value     = dnsmasq_config.main.rendered_content
  sensitive = true
}
```

## Provider Configuration

### Local Mode (Default)

Write configuration files to the local filesystem:

```hcl
provider "dnsmasq" {
  mode     = "local"
  platform = "auto"  # auto, linux, macos, windows

  # Optional: Custom paths
  config_path = "/etc/dnsmasq.conf"
  config_dir  = "/etc/dnsmasq.d"

  service_management {
    enabled                = true
    validate_before_reload = true
    restart_on_fail        = false
  }
}
```

### SSH Mode (Remote Deployment)

Deploy configuration to remote servers via SSH:

```hcl
provider "dnsmasq" {
  mode = "ssh"

  ssh {
    host             = "dns-server.example.com"
    port             = 22
    user             = "admin"
    private_key_path = "~/.ssh/id_rsa"
    # Or use password authentication
    # password = var.ssh_password
  }

  service_management {
    enabled      = true
    type         = "systemd"
    service_name = "dnsmasq"
  }
}
```

### Content-Only Mode (Kubernetes/Containers)

Generate configuration content without writing files:

```hcl
provider "dnsmasq" {
  mode = "content_only"
}

resource "dnsmasq_config" "k8s" {
  filename = "dnsmasq.conf"

  dns {
    port           = 53
    listen_address = ["0.0.0.0"]
    cache_size     = 10000
  }
}

# Use rendered_content in a Kubernetes ConfigMap
resource "kubernetes_config_map" "dnsmasq" {
  metadata {
    name = "dnsmasq-config"
  }

  data = {
    "dnsmasq.conf" = dnsmasq_config.k8s.rendered_content
  }
}
```

## Resources

### dnsmasq_config

The primary resource for managing dnsmasq configuration. See the [full documentation](docs/resources/config.md) for all available options.

#### Example: Complete Configuration

```hcl
resource "dnsmasq_config" "main" {
  filename = "terraform-managed.conf"

  # Global settings
  global {
    user         = "dnsmasq"
    log_queries  = true
    domain       = "local.lan"
    expand_hosts = true
  }

  # DNS settings
  dns {
    port           = 53
    listen_address = ["127.0.0.1", "192.168.1.1"]
    cache_size     = 10000
    domain_needed  = true
    bogus_priv     = true

    server {
      address = "8.8.8.8"
    }

    server {
      address = "192.168.1.254"
      domain  = "corp.local"
    }
  }

  # DNSSEC
  dnssec {
    enabled        = true
    check_unsigned = true
  }

  # DNS Records
  host_record {
    name = "server1"
    ipv4 = "192.168.1.10"
  }

  host_record {
    name = "server2"
    ipv4 = "192.168.1.11"
    ipv6 = "fd00::11"
  }

  address_record {
    domain = "ads.example.com"
    ip     = "0.0.0.0"  # Block this domain
  }

  cname_record {
    alias  = "www"
    target = "server1.local.lan"
  }

  mx_record {
    domain     = "local.lan"
    target     = "mail.local.lan"
    preference = 10
  }

  # DHCP configuration
  dhcp {
    enabled       = true
    authoritative = true
    leasefile     = "/var/lib/misc/dnsmasq.leases"

    range {
      start      = "192.168.1.100"
      end        = "192.168.1.200"
      netmask    = "255.255.255.0"
      lease_time = "24h"
    }

    option {
      number = 3  # Router
      value  = "192.168.1.1"
    }

    option {
      number = 6  # DNS Server
      value  = "192.168.1.1"
    }
  }

  # Static DHCP hosts
  dhcp_host {
    mac  = "00:11:22:33:44:55"
    name = "workstation1"
    ip   = "192.168.1.50"
  }

  # TFTP for PXE boot
  tftp {
    enabled = true
    root    = "/var/lib/tftpboot"
    secure  = true
  }

  # PXE boot menu
  pxe {
    prompt {
      text    = "Press F8 for boot menu"
      timeout = 10
    }

    service {
      csa       = "x86PC"
      menu_text = "Install Linux"
      basename  = "pxelinux"
    }
  }

  # IPv6 Router Advertisement
  router_advertisement {
    enabled = true

    param {
      interface = "eth0"
      mtu       = 1500
    }
  }
}
```

#### Outputs

| Name | Description |
|------|-------------|
| `id` | Unique identifier for the configuration |
| `output_path` | Full path where the configuration file was written |
| `rendered_content` | The generated dnsmasq configuration content |
| `content_hash` | SHA256 hash for drift detection |

## Platform Support

The provider automatically detects the platform and uses appropriate default paths:

| Platform | Config Path | Config Directory | Service Manager |
|----------|-------------|------------------|-----------------|
| Linux | `/etc/dnsmasq.conf` | `/etc/dnsmasq.d` | systemd / init |
| macOS (ARM) | `/opt/homebrew/etc/dnsmasq.conf` | `/opt/homebrew/etc/dnsmasq.d` | brew_services |
| macOS (Intel) | `/usr/local/etc/dnsmasq.conf` | `/usr/local/etc/dnsmasq.d` | brew_services |
| Windows | `C:\dnsmasq\dnsmasq.conf` | `C:\dnsmasq\dnsmasq.d` | none |

## Documentation

Full documentation is available in the [docs](./docs) directory:

- [Provider Configuration](./docs/index.md)
- [dnsmasq_config Resource](./docs/resources/config.md)

### Generated Configuration Format

The provider generates standard dnsmasq configuration format:

```conf
# Terraform-managed dnsmasq configuration
# DO NOT EDIT MANUALLY

user=dnsmasq
log-queries
domain=local.lan
expand-hosts

port=53
listen-address=127.0.0.1
listen-address=192.168.1.1
cache-size=10000
domain-needed
bogus-priv
server=8.8.8.8
server=/corp.local/192.168.1.254

dnssec
dnssec-check-unsigned

host-record=server1,192.168.1.10
address=/ads.example.com/0.0.0.0
cname=www,server1.local.lan
mx-host=local.lan,mail.local.lan,10

dhcp-authoritative
dhcp-leasefile=/var/lib/misc/dnsmasq.leases
dhcp-range=192.168.1.100,192.168.1.200,255.255.255.0,24h
dhcp-option=3,192.168.1.1
dhcp-host=00:11:22:33:44:55,workstation1,192.168.1.50

enable-tftp
tftp-root=/var/lib/tftpboot
tftp-secure
```

## Development

### Build Commands

```bash
make build      # Build the provider binary
make install    # Build and install to ~/.terraform.d/plugins
make test       # Run unit tests
make testacc    # Run acceptance tests (TF_ACC=1)
make docs       # Generate documentation with tfplugindocs
make fmt        # Format code
make vet        # Vet code
make lint       # Run golangci-lint
make tidy       # Run go mod tidy
make clean      # Remove built binary
make all        # fmt, vet, build, test, docs
```

### Project Structure

```
terraform-provider-dnsmasq/
├── main.go                          # Provider entry point
├── go.mod / go.sum                  # Go modules
├── Makefile                         # Build automation
│
├── internal/
│   ├── dnsmasq/
│   │   ├── config.go                # Configuration types
│   │   ├── generator.go             # Config file generator
│   │   └── validator.go             # Configuration validation
│   │
│   ├── backend/
│   │   ├── backend.go               # Backend interface definitions
│   │   └── local/
│   │       └── local.go             # Local filesystem backend
│   │
│   └── provider/
│       ├── provider.go              # Provider implementation
│       └── config_resource.go       # dnsmasq_config resource
│
├── examples/
│   ├── provider/                    # Provider configuration examples
│   └── resources/dnsmasq_config/    # Resource examples
│
├── docs/                            # Generated documentation
│   ├── index.md                     # Provider documentation
│   └── resources/
│       └── config.md                # Resource documentation
│
└── tools/
    └── tools.go                     # Build tools (tfplugindocs)
```

### Running Tests

```bash
# Unit tests
make test

# Acceptance tests (requires local dnsmasq)
TF_ACC=1 make testacc
```

## Roadmap

- [x] **Phase 1**: Foundation (config types, generator, local backend)
- [x] **Phase 2**: Primary resource (dnsmasq_config with full schema)
- [x] **Phase 5**: Documentation generation (partial - tfplugindocs)
- [ ] **Phase 3**: Data sources and granular resources
- [ ] **Phase 4**: SSH backend and Kubernetes support
- [ ] **Phase 5**: Acceptance tests and polish

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Related Projects

- [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) - Lightweight DNS/DHCP server
- [Terraform](https://www.terraform.io/) - Infrastructure as Code
- [terraform-plugin-framework](https://github.com/hashicorp/terraform-plugin-framework) - Terraform Provider SDK
