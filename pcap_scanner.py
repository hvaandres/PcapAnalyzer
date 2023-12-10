# This file will analyze your pcap file and generate a report

import scapy.all as scapy

def analyze_packet(packet, report_file):
    # Extract IP addresses and protocol
    if packet.haslayer(scapy.IP):
        src_ip = packet[scapy.IP].src
        dst_ip = packet[scapy.IP].dst
        protocol = "TCP" if packet.haslayer(scapy.TCP) else "UDP" if packet.haslayer(scapy.UDP) else "Other"

        # Check if it's an HTTP request
        if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
            payload = packet[scapy.Raw].load.decode(errors='ignore')
            if "GET" in payload:
                protocol = "HTTP GET"
            elif "POST" in payload:
                protocol = "HTTP POST"

        # Write to report file
        with open(report_file, "a") as file:
            file.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}\n")

def main(pcap_file, report_file):
    # Read the pcap file
    packets = scapy.rdpcap(pcap_file)

    # Analyze each packet and write to report file
    for packet in packets:
        analyze_packet(packet, report_file)

if __name__ == "__main__":
    # Replace 'your_pcap_file.pcap' with the actual pcap file you want to analyze
    pcap_file_path = '[your_pcap_file.pcap]'
    # Define the report file
    report_file_path = 'report.txt'
    
    # Analyze the pcap file and generate the report
    main(pcap_file_path, report_file_path)
    
    print(f"Analysis completed. Report saved to {report_file_path}")
