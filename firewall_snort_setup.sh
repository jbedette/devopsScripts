#!/bin/sh

#pkg install -y tcpreplay
chmod +x ./freebsd/firewall/firewall.sh
chmod +x ./freebsd/snort/snort.sh
chmod +x ./freebsd/firewall/firewall.sh ./freebsd/firewall/firewall_x.sh
chmod +x ./freebsd/snort/snort.sh ./freebsd/snort/snort_x.sh
./freebsd/firewall/firewall_x.sh
# ./freebsd/snort/snort_x.sh