# Scenario: PXE boot server
#
# dnsmasq serves as the DHCP + TFTP + PXE boot infrastructure for a small
# lab subnet. Clients power on, receive an IP and the boot loader
# filename, then fetch the boot image over TFTP.
#
# Typical use: bare-metal provisioning lab, classroom imaging, OS installer.

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

resource "dnsmasq_config" "pxe" {
  filename = "20-pxe-boot.conf"

  global {
    log_dhcp = true
    domain   = "lab.local"
  }

  dns {
    domain_needed = true
    bogus_priv    = true

    server {
      address = "1.1.1.1"
    }
  }

  # DHCP for the lab subnet.
  dhcp {
    enabled       = true
    authoritative = true
    leasefile     = "/var/lib/misc/dnsmasq.leases"

    range {
      start      = "10.20.30.100"
      end        = "10.20.30.200"
      netmask    = "255.255.255.0"
      lease_time = "1h"
    }

    # Router and DNS server.
    option {
      number = 3
      value  = "10.20.30.1"
    }

    option {
      number = 6
      value  = "10.20.30.1"
    }
  }

  # TFTP server for the boot images.
  tftp {
    enabled = true
    root    = "/srv/tftp"
    secure  = true
  }

  # PXE menu shown to booting clients.
  pxe {
    prompt {
      text    = "Press F8 for boot menu"
      timeout = 5
    }

    # Legacy BIOS clients.
    service {
      csa       = "x86PC"
      menu_text = "Network install (BIOS)"
      basename  = "pxelinux"
    }

    # UEFI x86_64 clients.
    service {
      csa       = "X86-64_EFI"
      menu_text = "Network install (UEFI)"
      basename  = "shimx64.efi"
    }
  }

  # Reserve a known-good IP for a specific lab workstation.
  dhcp_host {
    mac        = "00:11:22:33:44:55"
    name       = "lab-workstation-01"
    ip         = "10.20.30.10"
    lease_time = "infinite"
  }
}
