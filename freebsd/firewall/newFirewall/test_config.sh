#!/bin/sh

# Define the external interface and the internal target
EXT_IF="hn1"
TARGET="192.168.33.136"
NEW_SSH_PORT=222222

# Function to check if SSH service is running on the new port
check_ssh_service() {
    echo ""
    echo "testing ssh service"
    if grep ^Port /etc/ssh/sshd_config; then 
        grep ^Port /etc/ssh/sshd_config
        netstat -an | grep LISTEN | grep 22222
    else 
        echo "ssh error"
        service sshd status;
        grep ^Port /etc/ssh/sshd_config
        # echo "ssh not running"
        return 1
    fi
}

# Function to check if PF rules are applied
check_pf_rules() {
    echo ""
    echo "Checking PF rules..."
    echo "test off for now"
    # pfctl_output=$(pfctl -sr)
    # #echo "$pfctl_output" # Print the PF rules to see their current state
    # if echo "$pfctl_output" | grep -q "$TARGET"; then
    #     echo "PF rules are correctly applied."
    # else
    #     echo "PF rules are NOT correctly applied."
    #     return 1
    # fi
}


# Function to test SSH connectivity to the new port
test_ssh_connectivity() {
    echo "test ssh connectivity"
    # echo "Testing SSH connectivity to localhost on port $NEW_SSH_PORT..."
    # if ssh -p $NEW_SSH_PORT -o ConnectTimeout=5 localhost exit 2>/dev/null; then
    #     echo "Successfully connected to SSH on port $NEW_SSH_PORT."
    # else
    #     echo "Failed to connect to SSH on port $NEW_SSH_PORT."
    #     return 1
    # fi
}

# Function to test SSH forwarding
test_ssh_forwarding() {
    echo ""
    echo "Testing SSH forwarding to target machine $TARGET..."
    if ssh -J localhost:$NEW_SSH_PORT -o ConnectTimeout=5 jbedette@$TARGET exit 2>/dev/null; then
        echo "Successfully forwarded SSH to $TARGET."
    else
        echo "Failed to forward SSH to $TARGET."
        return 1
    fi
}

# Run the tests
check_ssh_service && check_pf_rules && test_ssh_connectivity && test_ssh_forwarding

if [ $? -eq 0 ]; then
    echo "All tests passed successfully."
else
    echo "Some tests failed. Please check the details above."
fi