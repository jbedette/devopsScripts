#!/bin/sh

# Install Snort
echo "Installing Snort3..."
pkg install -y snort3

# Check if the installation was successful
if [ $? -eq 0 ]; then
    echo "Snort installed successfully."
else
    echo "Failed to install Snort. Exiting."
    exit 1
fi

# Enable Snort to start on boot
echo "Enabling Snort to start on boot..."
sysrc snort_enable="YES"

# move snort service to correct place
chmod +x ~/devopsScripts/freebsd/snort/snort3
cp ~/devopsScripts/freebsd/snort/snort3 /usr/local/etc/rc.d/.

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
    msg:"SMBGhost attempt detected";
    flow:to_server,established;
    content:"|FC53 4AAF|";
    byte_test:1,!&,0x01,0;
    byte_test:1,&,0x08,4;
    metadata:service smb;
    reference:cve,2020-0796;
    sid:1000001;
    rev:1;
)
'
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
mkdir /usr/local/etc/snort/rules
echo $SMBGHOST_ALERT > $SMBGHOST_RULES
echo $SMBGHOST_DROP >> $SMBGHOST_RULES
echo ""
echo "SMB GHOST rule at $SMBGHOST_RULES"
cat $SMBGHOST_RULES
echo ""

# update snort.lua with new file pointing to my rules
cp ~/devopsScripts/freebsd/snort/snort.lua /usr/local/etc/snort/snort.lua

mkdir -p /var/log/snort
chown -R snort:snort /var/log/snort
chmod -R 755 /var/log/snort



# # Snort rule config tests
# snort -c /usr/local/etc/snort/snort.lua -T
# echo ""
# snort -c /usr/local/etc/snort/snort.lua -T | grep smbghost
# echo ""

echo '#!/bin/sh 
snort -c /usr/local/etc/snort/snort.lua -T' > snort_check.sh
chmod +x snort_check.sh
cp snort_check.sh /usr/local/etc/snort/

service snort3 start

