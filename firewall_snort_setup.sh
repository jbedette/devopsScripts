#!/bin/sh

#pkg install -y tcpreplay
cp ~/devopsScripts/freebsd/firewall/firewall.sh ./freebsd/firewall/firewall_x.sh
cp ~devopsScripts/freebsd/snort/snort.sh ./freebsd/snort/snort_x.sh
chmod +x ~/devopsScripts/freebsd/firewall/firewall_x.sh
chmod +x ~/devopsScripts/freebsd/snort/snort_x.sh
~/devopsScripts/freebsd/firewall/firewall_x.sh
# ~/devopsScripts/freebsd/snort/snort_x.sh