from scapy.all import *
import re
import subprocess
import time

# List of IP addresses to ignore (e.g., local network devices)
ignore_ips = ['192.168.1.1', '192.168.1.2']

# List of known malicious IP addresses or domains
malicious_ips = ['1.2.3.4', 'malicious-domain.com']

# Regular expressions to match known malware signatures
malware_signatures = ['[a-zA-Z0-9+/]{4,}[=]{0,2}(?:[a-zA-Z0-9+/]{4})*(?:[a-zA-Z0-9+/]{2}==|[a-zA-Z0-9+/]{3}=)?', 'ShellExecuteExA']

def analyze_packet(packet):
    # Ignore packets from specified IP addresses
    if packet.haslayer(IP) and packet[IP].src in ignore_ips:
        return
    # Analyze the packet headers and payloads to identify any signs of malicious activity
    if packet.haslayer(IP):
        # Check for unusual packet sizes or fragmentation
        if packet[IP].len > 1500 or packet[IP].flags == 1:
            print("Suspicious packet size or fragmentation detected:")
        else:
            print("Nothing Here")
        print(packet.summary())
        # Check for unusual TTL values
        if packet[IP].ttl == 1:
            print("TTL expired packet detected:")
            print(packet.summary())
        # Check for known malicious IP addresses or domains
        if packet[IP].dst in malicious_ips:
            print("Malicious IP address or domain detected:")
            print(packet.summary())
    if packet.haslayer(TCP):
        # Check for unusual TCP flags or sequence numbers
        if packet[TCP].flags == 0x29 or packet[TCP].seq == 0:
            print("Suspicious TCP flag or sequence number detected:")
            print(packet.summary())
        # Check for payloads that match known malware signatures
        if packet[TCP].payload:
            payload = str(packet[TCP].payload)
            for signature in malware_signatures:
                if re.search(signature, payload, re.IGNORECASE):
                    print("Malware signature detected:")
                    print(packet.summary())

# Start Wireshark capture on all interfaces for a specified duration (e.g., 5 minutes)
capture_duration = 30  # 5 minutes
wireshark_command = ['tshark', '-i', 'any', '-a', 'duration:' + str(capture_duration), '-w', 'captured_traffic.pcapng']
subprocess.Popen(wireshark_command)
time.sleep(capture_duration)  # Wait for the capture to complete

# Analyze the captured traffic using the analyze_packet function
capture_file = 'captured_traffic.pcapng'
capture = rdpcap(capture_file)

for packet in capture:
    analyze_packet(packet)
