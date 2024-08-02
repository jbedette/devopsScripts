#!/bin/sh

# Install Snort
echo "Installing Snort..."
pkg install -y snort

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

# Check if enabling Snort was successful
if [ $? -eq 0 ]; then
    echo "Snort is set to start on boot."
else
    echo "Failed to set Snort to start on boot. Exiting."
    exit 1
fi

echo "Script completed."
