#!/bin/sh

cd ~/devopsScripts
git pull
chmod +x ./freebsd/firewall/firewall.sh
chmod +x ./freebsd/snort/snort.sh
./freebsd/firewall/firewall.sh
./freebsd/snort/snort.sh