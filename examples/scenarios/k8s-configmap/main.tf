# Scenario: Generate dnsmasq config for a Kubernetes ConfigMap
#
# `content_only` mode skips writing anything to the local filesystem and
# exposes the rendered config via `rendered_content`. That string is fed
# into a Kubernetes ConfigMap, which is then mounted into a dnsmasq
# DaemonSet (deployment not shown here — that's downstream of this
# config).
#
# Typical use: cluster-local DNS resolver running as a privileged
# DaemonSet on each node.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    dnsmasq = {
      source  = "elioetibr/dnsmasq"
      version = ">= 0.0.3"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = ">= 2.20.0"
    }
  }
}

provider "dnsmasq" {
  # content_only mode: generate the config string in-memory; do not touch
  # any local filesystem path. This is the integration point for K8s,
  # Nomad, or any other system that consumes config as data.
  mode = "content_only"
}

provider "kubernetes" {
  # Reads ~/.kube/config by default; override in your environment.
}

resource "dnsmasq_config" "node_dns" {
  filename = "node-dns.conf"

  global {
    log_queries = false
    domain      = "cluster.local"
  }

  dns {
    listen_address = ["0.0.0.0"]
    cache_size     = 10000
    domain_needed  = true
    bogus_priv     = true
    no_resolv      = true

    server {
      address = "10.96.0.10" # in-cluster CoreDNS service IP
      domain  = "cluster.local"
    }

    server {
      address = "1.1.1.1" # public fallback
    }
  }

  # Block known telemetry endpoints at the resolver layer.
  address_record {
    domain = "telemetry.example.invalid"
    ip     = "0.0.0.0"
  }
}

resource "kubernetes_config_map" "dnsmasq" {
  metadata {
    name      = "dnsmasq-config"
    namespace = "kube-system"
    labels = {
      "app.kubernetes.io/name"      = "dnsmasq"
      "app.kubernetes.io/component" = "node-dns"
    }
  }

  data = {
    "dnsmasq.conf" = dnsmasq_config.node_dns.rendered_content
  }
}

output "config_hash" {
  description = "SHA256 of the rendered config — useful as a pod annotation to trigger rollouts on config change."
  value       = dnsmasq_config.node_dns.content_hash
}
