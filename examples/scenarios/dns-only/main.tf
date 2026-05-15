# Scenario: DNS-only dnsmasq deployment
#
# A lightweight resolver: caches upstream lookups, blocks an ad list,
# serves a few local A/AAAA records, and refuses to forward unqualified
# names. No DHCP, no TFTP, no PXE — just DNS.
#
# Typical use: drop-in resolver on a developer workstation or a small
# home network gateway.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    dnsmasq = {
      source  = "elioetibr/dnsmasq"
      version = ">= 0.0.3"
    }
  }
}

provider "dnsmasq" {
  mode = "local"
}

resource "dnsmasq_config" "resolver" {
  filename = "10-resolver.conf"

  global {
    log_queries = false
    domain      = "lan"
  }

  dns {
    listen_address = ["127.0.0.1", "::1"]
    cache_size     = 4096
    domain_needed  = true
    bogus_priv     = true
    no_resolv      = true # don't read /etc/resolv.conf; use only the upstreams below

    server {
      address = "1.1.1.1"
    }

    server {
      address = "1.0.0.1"
    }

    # Selectively forward an internal zone to a corporate resolver.
    server {
      address = "192.168.10.53"
      domain  = "corp.lan"
    }
  }

  # Local A/AAAA records.
  host_record {
    name = "router.lan"
    ipv4 = "192.168.1.1"
  }

  host_record {
    name = "nas.lan"
    ipv4 = "192.168.1.20"
    ipv6 = "fd00::20"
    ttl  = 300
  }

  # Ad blocking via sinkhole.
  address_record {
    domain = "doubleclick.net"
    ip     = "0.0.0.0"
  }

  address_record {
    domain = "googletagmanager.com"
    ip     = "0.0.0.0"
  }
}

output "rendered" {
  value     = dnsmasq_config.resolver.rendered_content
  sensitive = true
}
