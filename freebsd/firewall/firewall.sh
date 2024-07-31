#!/bin/sh

# Define the external interface and the internal target
EXT_IF="hn1" # Replace with your actual external interface name
TARGET="192.168.33.136"

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Append the configuration to /etc/pf.conf
cat <<EOL >> /etc/pf.conf

# Define the external interface and the internal target
ext_if = "$EXT_IF" # Replace with your actual external interface name
target = "$TARGET"

# Normalize and scrub incoming packets
scrub in all

# Define NAT rules for forwarding SSH traffic to the target
nat on \$ext_if from \$target to any -> (\$ext_if)

# Redirection rule to forward SSH traffic
rdr pass on \$ext_if proto tcp from any to (\$ext_if) port 22 -> \$target port 22

# Default deny rule for inbound traffic (optional for security)
block in all
pass out all

# Allow SSH traffic to be forwarded
pass in on \$ext_if proto tcp from any to \$target port 22
EOL

echo "Configuration successfully appended to /etc/pf.conf"

# Reload the PF rules
pfctl -f /etc/pf.conf
pfctl -e

echo "PF rules reloaded and enabled"
