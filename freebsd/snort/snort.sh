#!/bin/sh

# pkg install -y tcpreplay

# # Install Snort
# echo "Installing Snort3..."
# pkg install -y snort3
# pkg install -y nmap

# Check if the installation was successful
# if [ $? -eq 0 ]; then
#     echo "Snort installed successfully."
# else
#     echo "Failed to install Snort. Exiting."
#     exit 1
# fi

# Enable Snort to start on boot
echo "Enabling Snort to start on boot..."
sysrc snort_enable="YES"

chmod +x ~/devopsScripts/freebsd/snort/snort
cp ~/devopsScripts/freebsd/snort/snort /usr/local/etc/rc.d/.

# Check if enabling Snort was successful
if [ $? -eq 0 ]; then
    echo "Snort is set to start on boot."
else
    echo "Failed to set Snort to start on boot. Exiting."
    exit 1
fi

# Create rules
SMBGHOST_RULES='/usr/local/etc/snort/rules/smbghost.rules'
SMBGHOST_ALERT='alert tcp any any -> any 445 
(
    msg:"1, SMBGhost attempt detected";
    flow:to_server,established;
    content:"|FC53 4AAF|", depth 4, offset 4;
    byte_test:1,!&,0x01,0;
    byte_test:1,&,0x08,4;
    metadata:service smb;
    reference:cve,2020-0796;
    sid:1000001;
    rev:1;
)
'
SMBGHOST_ALERT2='alert tcp any any -> any 445 
(
    msg:"2, ANY 445 SMB SMBGhost CVE-2020-0796 exploit attempt";
    classtype:attempted-admin;
    metadata:service smb;
    reference:cve,2020-0796;
    sid:1000003;
    rev:1;
)'
SMBGHOST_ALERT3='alert tcp any any -> any 445 (msg:"SMBv3 CVE-2020-0796 basic content detection"; content:"|FF 53 4D 42|"; metadata:service netbios-ssn; reference:cve,2020-0796; classtype:attempted-admin; sid:1000010; rev:1;)'
SMBGHOST_ALERT4='alert tcp any any -> any 445 (msg:"SMBv3 CVE-2020-0796 exploit attempt"; flow:to_server,established; content:"|FF 53 4D 42|", depth 4 , offset 4; content:"|FE|SMB|", depth 4, offset 0; metadata:service netbios-ssn; reference:cve,2020-0796; classtype:attempted-admin; sid:1000011; rev:1;)'
SMBGHOST_ALERT5='alert tcp any any -> any 445 (msg:"SMBGhost CVE-2020-0796 detected"; content:"|FE 53 4D 42 40 00 00 00 00 08 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00|"; reference:cve,2020-0796; classtype:attempted-admin; sid:1000012; rev:1;)'
SMBGHOST_ALERT6='alert tcp any any -> any 445 (msg:"SMBGhost attempt detected"; content:"|FC 53 4A AF|", offset 4, depth 4; metadata:service smb; reference:cve,2020-0796; sid:2000001; rev:1;)'
SMBGHOST_ALERT7='alert tcp any any -> any 445 (msg:"SMBGhost attempt detected"; content:"|FC 53 4D 42|", offset 4, depth 4; metadata:service smb; reference:cve,2020-0796; sid:2000002; rev:1;)'


SMBGHOST_DROP='drop tcp any any -> any 445 
(
    msg:"SMBGhost attempt detected - dropping"; 
    flow:to_server,established; 
    content:"|FC53 4AAF|";
    byte_test:1,!&,0x01,0;
    byte_test:1,&,0x08,4;
    metadata:service smb; 
    reference:cve,2020-0796;
    sid:1000002;
    rev:1;
)'

SSH_LOG='log tcp any any -> $HOME_NET 22222 (msg:"LOG SSH connection attempt"; sid:1000003; rev:1;)'
SSH_PASS='pass tcp any 22222 -> any 22 (msg:"PASS SSH connection attempt"; sid:1000004; rev:1;)'
SSH_PASS_ALL='pass tcp any any -> any any (msg:"PASS SSH connection attempt"; sid:1000004; rev:1;)'
SSH_ALERT='alert tcp any any -> $HOME_NET 22 (msg:"ALERT SSH connection attempt"; sid:1000005; rev:1;)'
SSH_ALERT_22222='alert tcp any any -> $HOME_NET 22222 (msg:"ALERT SSH connection attempt"; sid:1000006; rev:1;)'
ANY_ALERT='alert tcp any any -> any any (msg:"any tcp thing happened";sid:1000006;rev:1)'

mkdir /usr/local/etc/snort/rules
cp ~/devopsScripts/freebsd/snort/smbghost.rules $SMBGHOST_RULES


# update snort.lua with new file pointing to my rules
cp ~/devopsScripts/freebsd/snort/snort.lua /usr/local/etc/snort/snort.lua

# make snort log location
mkdir -p /var/log/snort
chmod -R 755 /var/log/snort

# add snort to groups for service
chown root:wheel /usr/local/bin/snort
chown root:wheel /usr/local/etc/snort/snort.lua
chown root:wheel /var/log/snort

# turn off sums for testing
ifconfig hn0 -txcsum -rxcsum
ifconfig hn1 -txcsum -rxcsum

echo '#!/bin/sh 
snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/rules/smbghost.rules -r ~/devopsScripts/SMBGHOST/SMBGhost.pcap' -l /var/log/snort > snort_check.sh
chmod +x snort_check.sh

echo '#!/bin/sh 
snort -c /usr/local/etc/snort/snort.lua -r ~/devopsScripts/SMBGHOST/SMBGhost.pcap -i hn0 -l /var/log/snort -u root -g wheel' > run_snort.sh
chmod +x run_snort.sh

echo '#!/bin/sh 
tcpreplay -i hn0 ~/devopsScripts/SMBGHOST/SMBGhost.pcap' > replay_smb.sh
chmod +x replay_smb.sh

echo "snort start"
service snort start
echo "snort status"
service snort status


#set env variables for ease of testing
SNRT="setenv SNRT '/usr/local/etc/snort/'"
SNRTL="setenv SNRTL '/usr/local/etc/snort/snort.lua'"
SLOGS="setenv alerts 'cat /var/log/snort/alert*'"
SNRTS="setenv SNRTS 'service snort status'"
echo $SNRT >> ~/.cshrc
echo $SNRTL >> ~/.cshrc
echo $SLOGS >> ~/.cshrc
echo $SNRTS >> ~/.cshrc
