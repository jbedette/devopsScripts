#!/bin/bash
cd ~
sudo ssh-keygen -t ed25519
scp ~/.ssh/id_ed25519.pub jbedette@ada.cs.pdx.edu:~/ubuntu_id_ed.pub
sudo rmmod floppy
echo "blacklist floppy" | sudo tee /etc/modprobe.d/blacklist-floppy.conf
sudo dpkg-reconfigure initramfs-tools
sudo apt upgrade
sudo apt -y update
sudo apt install podman docker.io zsh containerd
sudo lvextend --extents +100%FREE /dev/ubuntu-vg/ubuntu-lv --resizefs
ip a s | grep inet > ~/ubuntu_ip.txt
scp ~/ubuntu_ip.txt jbedette@ada.cs.pdx.edu:.