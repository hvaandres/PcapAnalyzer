# This code will analyze your pcap file and generate a report.
# You have a section to select the pcap file you want to analyze and another section to select the report file name you want to generate.
# The analyze_packet function will extract the source IP address, destination IP address, and protocol of each packet.
# If the packet has an HTTP payload, it will extract the HTTP method (GET or POST) and use that as the protocol instead.
# You will also have a potential to select the packet you want to analyze.

import scapy.all as scapy
import re
import time

def extract_http_headers(payload):
    headers = {}
    header_lines = re.findall(r'(.*?): (.*?)\r\n', payload)
    for header in header_lines:
        headers[header[0].lower()] = header[1]
    return headers

def is_sql_injection(payload):
    # Add more SQL injection patterns as needed
    sql_injection_patterns = ["' or 'a'='a", "1=1"]
    return any(pattern in payload for pattern in sql_injection_patterns)

def analyze_http_packet(packet, report_file):
    # Check if it's an HTTP request
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.IP):
        protocol = packet.getlayer(scapy.IP).getfieldval("proto")
        payload = packet[scapy.Raw].load.decode(errors='ignore')

        # Check for HTTP GET or POST request
        if "GET" in payload or "POST" in payload:
            url_match = re.search(r'(GET|POST) (.*?) HTTP', payload)
            user_match = re.search(r'(?i)(?:user|username)=(\w+)', payload)
            password_match = re.search(r'(?i)password=([^&\s]+)', payload)
            status_match = re.search(r'HTTP/1.\d (\d{3})', payload)

            # Extract HTTP headers
            headers = extract_http_headers(payload)

            # Write to report file
            with open(report_file, "a") as file:
                try:
                    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(float(packet.time)))
                except TypeError:
                    timestamp = "Unknown Timestamp"
                
                file.write(f"{timestamp} - Source IP: {packet[scapy.IP].src}, Destination IP: {packet[scapy.IP].dst} - ")
                if url_match:
                    file.write(f"Protocol: {protocol}, Type: {url_match.group(1)}, URL: {url_match.group(2)} ")
                if user_match:
                    file.write(f"User: {user_match.group(1)} ")
                if password_match:
                    file.write(f"Password: {password_match.group(1)} ")
                if status_match:
                    file.write(f"Status: {status_match.group(1)} ")

                # Extract additional details from headers
                if 'host' in headers:
                    file.write(f"Host: {headers['host']} ")
                if 'user-agent' in headers:
                    file.write(f"User-Agent: {headers['user-agent']} ")
                if 'accept' in headers:
                    file.write(f"Accept: {headers['accept']} ")
                if 'referer' in headers:
                    file.write(f"Referer: {headers['referer']} ")
                if 'cookie' in headers:
                    file.write(f"Cookies: {headers['cookie']} ")
                if 'content-type' in headers and 'multipart/form-data' in headers['content-type']:
                    file.write("MIME Multipart Media Encapsulation Detected ")

                # Check for potential SQL injection
                if is_sql_injection(payload):
                    file.write("Potential SQL Injection Attack Detected ")

                file.write("\n")

def main(pcap_file, report_file):
    # Read the pcap file
    packets = scapy.rdpcap(pcap_file)

    # Analyze each packet for HTTP GET and POST requests in lines 1 to 20
    for packet in packets[:20]:
        analyze_http_packet(packet, report_file)

if __name__ == "__main__":
    # Replace 'your_pcap_file.pcap' with the actual pcap file you want to analyze
    pcap_file_path = '[your_pcap_file.pcap]'
    
    # Define the report file
    report_file_path = '[file_name].txt]'
    
    # Analyze the pcap file for HTTP GET and POST requests in lines 1 to 20
    main(pcap_file_path, report_file_path)
    
    print(f"Analysis completed. Report saved to {report_file_path}")
