from scapy.all import get_if_list, conf

# List available network interfaces
interfaces = get_if_list()
print("Available network interfaces:")
for iface in interfaces:
    print(iface)

# List detailed information about network interfaces
for iface in conf.ifaces.values():
    name = getattr(iface, 'name', 'N/A')
    description = getattr(iface, 'description', 'N/A')
    mac = getattr(iface, 'mac', 'N/A')
    ip = getattr(iface, 'ip', 'N/A')
    network = getattr(iface, 'network', 'N/A')
    broadcast = getattr(iface, 'broadcast', 'N/A')
    
    print(f"\nInterface: {name}")
    print(f"    Description: {description}")
    print(f"    MAC address: {mac}")
    print(f"    IP address: {ip}")
    print(f"    Network: {network}")
    print(f"    Broadcast: {broadcast}")