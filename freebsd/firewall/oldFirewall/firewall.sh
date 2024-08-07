#!/bin/sh

# Define the external interface and the internal target
EXT_IF="hn0"
INT_IF="hn1"
TARGET="192.168.33.163"
NEW_SSH_PORT=22222

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root"
    exit 1
fi


PF_CONFIG_CONTENT='
ext_if="hn0"
int_if="hn1"

icmp_types="{ echoreq, unreach }"
services="{ ssh, domain, http, ntp, https }"
server="192.168.33.163"
ssh_rdr="22222"

table <rfc6890> { 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 \
                  172.16.0.0/12 192.0.0.0/24 192.0.0.0/29 192.0.2.0/24 192.88.99.0/24 \
                  192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 \
                  240.0.0.0/4 255.255.255.255/32 }
table <bruteforce> persist

#options
set skip on lo0

#normalization
scrub in all fragment reassemble max-mss 1441

#NAT rules
nat on $ext_if from $int_if:network to any -> ($ext_if)

#Redirection rules
# Forward SSH traffic from bastion host port 22 to Ubuntu system port 22
rdr on $ext_if proto tcp from any to ($ext_if) port 22 -> $server port 22

#blocking rules
antispoof quick for $ext_if
block in quick on egress from <rfc6890>
block return out quick on egress to <rfc6890>
block log all


#pass rules
pass in quick on $int_if inet proto udp from any port = bootpc to 255.255.255.255 port = bootps keep state label "allow access to DHCP server"
pass in quick on $int_if inet proto udp from any port = bootpc to $int_if:network port = bootps keep state label "allow access to DHCP server"
pass out quick on $int_if inet proto udp from $int_if:0 port = bootps to any port = bootpc keep state label "allow access to DHCP server"

pass in quick on $ext_if inet proto udp from any port = bootps to $ext_if:0 port = bootpc keep state label "allow access to DHCP client"
pass out quick on $ext_if inet proto udp from $ext_if:0 port = bootpc to any port = bootps keep state label "allow access to DHCP client"


pass in on $ext_if proto tcp to port { ssh } keep state (max-src-conn 15, max-src-conn-rate 3/1, overload <bruteforce> flush global)
pass out on $ext_if proto { tcp, udp } to port $services
pass out on $ext_if inet proto icmp icmp-type $icmp_types
pass in on $int_if from $int_if:network to any
pass out on $int_if from $int_if:network to any


# SSH server on firewall management port
pass in on $ext_if proto tcp to port $ssh_rdr keep state (max-src-conn 15, max-src-conn-rate 3/1, overload <bruteforce> flush global)
'


# Create a temporary file with the new pf.conf content
echo "$PF_CONFIG_CONTENT" > /tmp/pf_new.conf

# Set appropriate permissions
chmod 644 /tmp/pf_new.conf

# Replace the existing /etc/pf.conf with the new file
mv /tmp/pf_new.conf /etc/pf.conf

echo "/etc/pf.conf updated"

# New SSHD config content
SSHD_CONFIG_CONTENT='
# $OpenBSD: sshd_config,v 1.104 2021/07/02 05:11:21 dtucker Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

# Note that some of FreeBSDs defaults differ from OpenBSDs, and
# FreeBSD has a few additional options.

Port 22222
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
echo ""
echo ""
