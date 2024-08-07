#!/bin/sh

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Set appropriate permissions
chmod 644 ~/devopsScripts/firewall/pf.conf
# Replace the existing /etc/pf.conf with the new file
mv ~/devopsScripts/firewall/pf.conf /etc/pf.conf

echo "/etc/pf.conf updated"


# Set appropriate permissions
chmod 644 ~/devopsScripts/firewall/sshd_config
# Replace the existing /etc/ssh/sshd_config with the new file
mv ~/devopsScripts/firewall/sshd_config /etc/ssh/sshd_config
# Restart the SSH service to apply the changes
service sshd restart

echo "SSHD configuration updated and service restarted."

# Reload the PF rules
pfctl -f /etc/pf.conf
pfctl -e

echo "PF rules reloaded and enabled"
echo ""
echo ""
