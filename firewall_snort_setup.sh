#!/bin/sh

#pkg install -y tcpreplay
cp ./freebsd/firewall/firewall.sh ./freebsd/firewall/firewall_x.sh
cp ./freebsd/snort/snort.sh ./freebsd/snort/snort_x.sh
chmod +x ./freebsd/firewall/firewall_x.sh
chmod +x ./freebsd/snort/snort_x.sh
./freebsd/firewall/firewall_x.sh
# ./freebsd/snort/snort_x.sh