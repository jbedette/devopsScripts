
#!/bin/sh

# Define the external interface and the internal target
EXT_IF="hn1"
TARGET="192.168.33.136"
NEW_SSH_PORT=2222

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

# Allow management SSH traffic on new port
pass in on \$ext_if proto tcp from any to (\$ext_if) port 2222
EOL

echo "Configuration successfully appended to /etc/pf.conf"

# New SSHD config content
SSHD_CONFIG_CONTENT='
#	$OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# Note that some of FreeBSDs defaults differ from OpenBSDs, and
# FreeBSD has a few additional options.

Port 2222
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::

#HostKey /etc/ssh/ssh_host_rsa_key
#HostKey /etc/ssh/ssh_host_ecdsa_key
#HostKey /etc/ssh/ssh_host_ed25519_key

# Ciphers and keying
#RekeyLimit default none

# Logging
#SyslogFacility AUTH
#LogLevel INFO

# Authentication:

#LoginGraceTime 2m
#PermitRootLogin no
#StrictModes yes
#MaxAuthTries 6
#MaxSessions 10

#PubkeyAuthentication yes

# The default is to check both .ssh/authorized_keys and .ssh/authorized_keys2
# but this is overridden so installations will only check .ssh/authorized_keys
AuthorizedKeysFile	.ssh/authorized_keys

#AuthorizedPrincipalsFile none

#AuthorizedKeysCommand none
#AuthorizedKeysCommandUser nobody

# For this to work you will also need host keys in /etc/ssh/ssh_known_hosts
#HostbasedAuthentication no
# Change to yes if you dont trust ~/.ssh/known_hosts for
# HostbasedAuthentication
#IgnoreUserKnownHosts no
# Dont read the users ~/.rhosts and ~/.shosts files
#IgnoreRhosts yes

# Change to yes to enable built-in password authentication.
# Note that passwords may also be accepted via KbdInteractiveAuthentication.
#PasswordAuthentication no
#PermitEmptyPasswords no

# Change to no to disable PAM authentication
#KbdInteractiveAuthentication yes

# Kerberos options
#KerberosAuthentication no
#KerberosOrLocalPasswd yes
#KerberosTicketCleanup yes
#KerberosGetAFSToken no

# GSSAPI options
#GSSAPIAuthentication no
#GSSAPICleanupCredentials yes

# Set this to no to disable PAM authentication, account processing,
# and session processing. If this is enabled, PAM authentication will
# be allowed through the KbdInteractiveAuthentication and
# PasswordAuthentication.  Depending on your PAM configuration,
# PAM authentication via KbdInteractiveAuthentication may bypass
# the setting of "PermitRootLogin prohibit-password".
# If you just want the PAM account and session checks to run without
# PAM authentication, then enable this but set PasswordAuthentication
# and KbdInteractiveAuthentication to no.
#UsePAM yes

#AllowAgentForwarding yes
#AllowTcpForwarding yes
#GatewayPorts no
#X11Forwarding yes
#X11DisplayOffset 10
#X11UseLocalhost yes
#PermitTTY yes
#PrintMotd yes
#PrintLastLog yes
#TCPKeepAlive yes
#PermitUserEnvironment no
#Compression delayed
#ClientAliveInterval 0
#ClientAliveCountMax 3
#UseDNS yes
#PidFile /var/run/sshd.pid
#MaxStartups 10:30:100
#PermitTunnel no
#ChrootDirectory none
#UseBlacklist no
#VersionAddendum FreeBSD-20230316

# no default banner path
#Banner none

# override default of no subsystems
Subsystem	sftp	/usr/libexec/sftp-server

# Example of overriding settings on a per-user basis
#Match User anoncvs
#	X11Forwarding no
#	AllowTcpForwarding no
#	PermitTTY no
#	ForceCommand cvs server
'

# Create a temporary file with the new sshd_config content
echo "$SSHD_CONFIG_CONTENT" > /tmp/sshd_config_new

# Set appropriate permissions
chmod 644 /tmp/sshd_config_new

# Replace the existing /etc/ssh/sshd_config with the new file
mv /tmp/sshd_config_new /etc/ssh/sshd_config

# Restart the SSH service to apply the changes
service sshd restart

echo "SSHD configuration updated and service restarted."

# Reload the PF rules
pfctl -f /etc/pf.conf
pfctl -e

echo "PF rules reloaded and enabled"

# Function to check if SSH service is running on the new port
check_ssh_service() {
    echo "Checking if SSH service is running on port $NEW_SSH_PORT..."
    if netstat -an | grep LISTEN | grep -q ":$NEW_SSH_PORT"; then
        echo "SSH service is running on port $NEW_SSH_PORT."
    else
        echo "SSH service is NOT running on port $NEW_SSH_PORT."
        OTHER_PORT=$(netstat -an | grep LISTEN | grep sshd | awk '{print $4}' | sed 's/.*://')
        if [ -n "$OTHER_PORT" ]; then
            echo "SSH service is running on port $OTHER_PORT instead."
        else
            echo "SSH service is not running."
        fi
        return 1
    fi
}

# Function to check if PF rules are applied
check_pf_rules() {
    echo "Checking PF rules..."
    if pfctl -sr | grep -q "$TARGET"; then
        echo "PF rules are correctly applied."
    else
        echo "PF rules are NOT correctly applied."
        return 1
    fi
}

# Function to test SSH connectivity to the new port
test_ssh_connectivity() {
    echo "Testing SSH connectivity to localhost on port $NEW_SSH_PORT..."
    if ssh -p $NEW_SSH_PORT -o ConnectTimeout=5 localhost exit 2>/dev/null; then
        echo "Successfully connected to SSH on port $NEW_SSH_PORT."
    else
        echo "Failed to connect to SSH on port $NEW_SSH_PORT."
        return 1
    fi
}

# Function to test SSH forwarding
test_ssh_forwarding() {
    echo "Testing SSH forwarding to target machine $TARGET..."
    if ssh -J localhost:$NEW_SSH_PORT -o ConnectTimeout=5 jbedette@$TARGET exit 2>/dev/null; then
        echo "Successfully forwarded SSH to $TARGET."
    else
        echo "Failed to forward SSH to $TARGET."
        return 1
    fi
}

# Run the tests
check_ssh_service && check_pf_rules && test_ssh_connectivity && test_ssh_forwarding

if [ $? -eq 0 ]; then
    echo "All tests passed successfully."
else
    echo "Some tests failed. Please check the details above."
fi
