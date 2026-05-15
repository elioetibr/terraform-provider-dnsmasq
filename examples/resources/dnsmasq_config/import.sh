# Import an existing dnsmasq configuration file by its absolute path.
# The provider derives id, filename, rendered_content, and content_hash from
# the file at the given path. Import is supported only when the provider
# `mode` is `local` (the default); `content_only` mode has no on-disk file.

# Linux (system package):
terraform import dnsmasq_config.main /etc/dnsmasq.d/terraform-managed.conf

# macOS — Apple Silicon (Homebrew):
terraform import dnsmasq_config.main /opt/homebrew/etc/dnsmasq.d/terraform-managed.conf

# macOS — Intel (Homebrew):
terraform import dnsmasq_config.main /usr/local/etc/dnsmasq.d/terraform-managed.conf

# Windows:
terraform import dnsmasq_config.main C:\dnsmasq\dnsmasq.d\terraform-managed.conf
