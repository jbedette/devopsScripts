#!/bin/sh


# Install Snort & tcpreplay
# echo "Installing Snort3 & tcpreplay..."
# pkg install -y snort3
# pkg install -y tcpreplay

# Enable Snort to start on boot
echo "Enabling Snort to start on boot..."
sysrc snort_enable="YES"

# Move snort service to rc.d
chmod +x ~/devopsScripts/freebsd/snort/snort
cp ~/devopsScripts/freebsd/snort/snort /usr/local/etc/rc.d/.

# Create rules
SMBGHOST_RULES='/usr/local/etc/snort/rules/smbghost.rules'
mkdir /usr/local/etc/snort/rules
cp ~/devopsScripts/freebsd/snort/smbghost.rules $SMBGHOST_RULES


# update snort.lua with new file pointing to my rules
cp ~/devopsScripts/freebsd/snort/snort.lua /usr/local/etc/snort/snort.lua

# make snort log location
mkdir -p /var/log/snort

# echo '#!/bin/sh 
# snort -c /usr/local/etc/snort/snort.lua -R /usr/local/etc/snort/rules/smbghost.rules -r ~/devopsScripts/SMBGHOST/SMBGhost.pcap' -l /var/log/snort > snort_check.sh
# chmod +x snort_check.sh

# echo '#!/bin/sh 
# snort -c /usr/local/etc/snort/snort.lua -r ~/devopsScripts/SMBGHOST/SMBGhost.pcap -i hn0 -l /var/log/snort -u root -g wheel' > run_snort.sh
# chmod +x run_snort.sh

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
