from scapy.all import rdpcap, sendp, send, IP

# # Define the file path and target IP address
# pcap_file = "SMBghost.pcap"
# target_ip = "172.23.70.16"

# # Read packets from the PCAP file
# packets = rdpcap(pcap_file)

# # Send each packet to the target IP address
# for packet in packets:
#     packet[IP].dst = target_ip
#     sendp(packet, iface="vEthernet (Default Switch)")

# print(f"Packets from {pcap_file} sent to {target_ip}")


# Load the pcap file
pcap_file = 'SMBGhost.pcap'
packets = rdpcap(pcap_file)

# Define the IP and port of the FreeBSD VM
freebsd_ip = '172.23.70.16'
redirected_port = 22222

# Modify the packets to set the destination IP and port to the FreeBSD VM
for packet in packets:
    if packet.haslayer('IP'):
        packet['IP'].dst = freebsd_ip
    if packet.haslayer('TCP'):
        packet['TCP'].dport = redirected_port

# Send the modified packets
send(packets)
