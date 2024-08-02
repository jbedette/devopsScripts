#!/bin/sh

#pkg install -y tcpreplay
chmod +x ./freebsd/firewall/firewall.sh
chmod +x ./freebsd/snort/snort.sh
./freebsd/firewall/firewall.sh
./freebsd/snort/snort.sh