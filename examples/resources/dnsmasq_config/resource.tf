# Example: Full dnsmasq configuration
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
      address = "8.8.4.4"
    }

    server {
      address = "192.168.1.254"
      domain  = "corp.local"
    }
  }

  # Host records (A/AAAA)
  host_record {
    name = "server1"
    ipv4 = "192.168.1.10"
  }

  host_record {
    name = "server2"
    ipv4 = "192.168.1.11"
    ipv6 = "fd00::11"
  }

  # Address records for domain blocking
  address_record {
    domain = "ads.example.com"
    ip     = "0.0.0.0"
  }

  # CNAME aliases
  cname_record {
    alias  = "www"
    target = "server1.local.lan"
  }

  # MX records
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
      number = 3
      value  = "192.168.1.1"
    }

    option {
      number = 6
      value  = "192.168.1.1"
    }
  }

  # Static DHCP hosts
  dhcp_host {
    mac  = "00:11:22:33:44:55"
    name = "workstation1"
    ip   = "192.168.1.50"
  }
}

# Output the generated configuration
output "config_path" {
  value = dnsmasq_config.main.output_path
}

output "config_content" {
  value     = dnsmasq_config.main.rendered_content
  sensitive = true
}
