pf_enable="YES"
pf_rules="/etc/pf.conf"

# Define the external interface and the internal target
ext_if = "em0" # Replace with your actual external interface name
target = "192.168.33.136"

# Normalize and scrub incoming packets
scrub in all

# Define NAT rules for forwarding SSH traffic to the target
nat on $ext_if from $target to any -> ($ext_if)

# Redirection rule to forward SSH traffic
rdr pass on $ext_if proto tcp from any to ($ext_if) port 22 -> $target port 22

# Default deny rule for inbound traffic (optional for security)
block in all
pass out all

# Allow SSH traffic to be forwarded
pass in on $ext_if proto tcp from any to $target port 22

sudo pfctl -f /etc/pf.conf
sudo pfctl -e
