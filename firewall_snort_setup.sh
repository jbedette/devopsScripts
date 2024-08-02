#!/bin/sh

pkg install tcpreplay
chmod +x ./freebsd/firewall/firewall.sh
chmod +x ./freebsd/snort/snort.sh
./freebsd/firewall/firewall.sh
./freebsd/snort/snort.sh