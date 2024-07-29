Better interface for freeBSD VM

You may have noticed that the default console window for the freeBSD VM is...subpar. It's not the worst, but it is within hailing distance. So, let's fix that.

To do this, we need a few pieces:

    A terminal emulator that supports serial connections -- putty, MobaXTerm, etc.
    The name of the VM we want to add the pipe to -- we'll use freebsd
    The name of the pipe we want to add -- we'll use \\.\pipe\freebsd
    An administrative PowerShell prompt

    First, we need to create the pipe using Set-VMComPort. To do this, run the following command in an administrative PowerShell prompt:

```
    ❯ Set-VMComPort -VMName freebsd -Number 1 \\.\pipe\freebsd
```

This example assigns the first COM power (aka serial port) to the pipe \\.\pipe\freebsd. You can change the name of the pipe to whatever you want, but you'll need to remember it for the next step.

Create the named pipe instance (using this constructor) via the following command in an administrative PowerShell prompt:

```
❯ New-Object System.IO.Pipes.NamedPipeServerStream("\\.\pipe\freebsd", "InOut", 100, "Byte", "None", 1024, 1024)
```
    That's the pipe name we used in the first step, bidirectional, at most 100 instances, byte transmission mode, no options, and default in/out buffer sizes.

    Run putty (or whatever terminal emulator you are using) as Administrator.

    Create a new serial connection, and set the serial line to \\.\pipe\freebsd (or whatever you named your pipe). Set the speed to 115200. Click "Open".

    putty serial connection

    I would recommend setting the font to something palatable, and set the window size to a known value. I use 140x40, but you can use whatever you want.

    Now, run the VM, at the boot menu type 5 until you get to "Dual (Serial Primary)". This will direct the console output to the serial port. Hit enter to continue booting.

    Now you can interact with the VM via putty! This means copy/paste support, better keyboard mapping, even scrolling support!

Some additional thoughts. I would suggest letting the VM know about the size of the terminal window. This can be directly accomplished at the command line with something like stty rows 40 cols 140 if you used my recommended size above.
Hyper-V Enhanced Session Mode for Ubuntu VM

Hyper-V has two modes for interacting with VMs. The default for a Linux guest is the standard console mode, which is what you get when you run a VM. The second is Enhanced Session Mode, which allows you to use RDP to connect to the VM. This is useful if you want to use a GUI on the VM, or if you want to copy/paste between the VM and your host system, or share resources in some other fashion. So how do we enable this on our Ubuntu VM?

First, and this should be obvious, you should install a desktop environment on you VM. Which you choose is entirely up to you, but I use the package kubuntu-desktop. Other options include cinnamon-desktop-environment, ubuntu-desktop, lubuntu-desktop, ubuntu-mate-desktop, xubuntu-desktop, and others. There are more DEs than you can shake a stick at!

In point of fact, I would suggest installing the following packages:

$ sudo apt install kubuntu-desktop podman docker.io zsh tmux ruby-dev fonts-inconsolata autojump bat emacs build-essential cowsay figlet filters fortunes dos2unix containerd python3-pip cargo cmake

Do you need all of these? Not necessarily. We will be making use of the different container runtimes, so you'll need those, at least (podman, docker.io, and containerd). The rest are just tools that are useful to have and that I like. Edit as you see fit.

Once you have a DE in place and running, run the below script to enable Enhanced Session Mode from the VM side. You'll need to reboot the VM after running it.

```
#!/bin/bash

#
# This script is for Ubuntu 22.04 Jammy Jellyfish to download and install XRDP+XORGXRDP via
# source.
#
# This script originally from Github user Hinara (https://github.com/Hinara/linux-vm-tools/blob/ubuntu20-04/ubuntu/22.04/install.sh) with modifications to work for us

# To download from the ubuntu VM:
# curl -LO https://raw.githubusercontent.com/dkmcgrath/sysadmin/main/enhanced_session.sh

# tweaked to remove some stuff that wasn't necessary.
###############################################################################
# Update our machine to the latest code if we need to.
#

if [ "$(id -u)" -ne 0 ]; then
    echo 'This script must be run with root privileges' >&2
    exit 1
fi

apt update && apt upgrade -y

if [ -f /var/run/reboot-required ]; then
    echo "A reboot is required in order to proceed with the install." >&2
    echo "Please reboot and re-run this script to finish the install." >&2
    exit 1
fi

###############################################################################
# XRDP
#

# Install hv_kvp utils for XRDP
# Install the xrdp service so we have the auto start behavior
if apt install -y xrdp linux-tools-virtual linux-cloud-tools-virtual >/dev/null 2>&1; then
    echo "Successfully installed xrdp."
else
    echo "Failed to install xrdp." >&2
    exit 1
fi

systemctl stop xrdp
systemctl stop xrdp-sesman

# Configure the installed XRDP ini files.
# use vsock transport.
sed -i_orig -e 's/port=3389/port=vsock:\/\/-1:3389/g' /etc/xrdp/xrdp.ini
# use rdp security.
sed -i_orig -e 's/security_layer=negotiate/security_layer=rdp/g' /etc/xrdp/xrdp.ini
# remove encryption validation.
sed -i_orig -e 's/crypt_level=high/crypt_level=none/g' /etc/xrdp/xrdp.ini
# disable bitmap compression since its local its much faster
sed -i_orig -e 's/bitmap_compression=true/bitmap_compression=false/g' /etc/xrdp/xrdp.ini

# rename the redirected drives to 'shared-drives'
sed -i -e 's/FuseMountName=thinclient_drives/FuseMountName=shared-drives/g' /etc/xrdp/sesman.ini

# Changed the allowed_users
sed -i_orig -e 's/allowed_users=console/allowed_users=anybody/g' /etc/X11/Xwrapper.config

# Blacklist the vmw module
if [ ! -e /etc/modprobe.d/blacklist-vmw_vsock_vmci_transport.conf ]; then
  echo "blacklist vmw_vsock_vmci_transport" > /etc/modprobe.d/blacklist-vmw_vsock_vmci_transport.conf
fi

#Ensure hv_sock gets loaded
if [ ! -e /etc/modules-load.d/hv_sock.conf ]; then
  echo "hv_sock" > /etc/modules-load.d/hv_sock.conf
fi

# Configure the policy xrdp session
cat > /etc/polkit-1/localauthority/50-local.d/45-allow-colord.pkla <<EOF
[Allow Colord all Users]
Identity=unix-user:*
Action=org.freedesktop.color-manager.create-device;org.freedesktop.color-manager.create-profile;org.freedesktop.color-manager.delete-device;org.freedesktop.color-manager.delete-profile;org.freedesktop.color-manager.modify-device;org.freedesktop.color-manager.modify-profile
ResultAny=no
ResultInactive=no
ResultActive=yes
EOF

# reconfigure the service
systemctl daemon-reload
systemctl start xrdp

#
# End XRDP
###############################################################################

echo "Install is complete."
echo "Reboot your machine to begin using XRDP."
```
After the VM is back up and running, you'll need to enable Enhanced Session Mode on the host side. To do this, open PowerShell as an Administrator and run the following command:
```
Set-VM -VMName <your_vm_name> -EnhancedSessionTransportType HvSocket
```
Now, when you connect to your VM from the Hyper-V manager, you'll be able to use Enhanced Session Mode!