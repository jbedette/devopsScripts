#!/bin/sh

echo "start firewall.sh"

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi

# Set appropriate permissions
cp  ~/devopsScripts/freebsd/firewall/pf.conf  ~/devopsScripts/freebsd/firewall/pf_x.conf
chmod 744 ~/devopsScripts/freebsd/firewall/pf_x.conf
# Replace the existing /etc/pf.conf with the new file
mv ~/devopsScripts/freebsd/firewall/pf_x.conf /etc/pf.conf

echo "/etc/pf.conf updated"


# Set appropriate permissions
cp  ~/devopsScripts/freebsd/firewall/sshd_config  ~/devopsScripts/freebsd/firewall/sshd_config_x
chmod 744 ~/devopsScripts/freebsd/firewall/sshd_config_x
# Replace the existing /etc/ssh/sshd_config with the new file
mv ~/devopsScripts/freebsd/firewall/sshd_config_x /etc/ssh/sshd_config
# Restart the SSH service to apply the changes
service sshd restart

echo "SSHD configuration updated and service restarted."

# Reload the PF rules
pfctl -f /etc/pf.conf
pfctl -e

echo "PF rules reloaded and enabled"
echo ""
echo ""
