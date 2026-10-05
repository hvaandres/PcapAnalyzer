# This code will analyze your pcap file and generate a report.
# You have a section to select the pcap file you want to analyze and another section to select the report file name you want to generate.
# The analyze_packet function will extract the source IP address, destination IP address, and protocol of each packet.
# Only packets carrying an HTTP request to an endpoint (GET, PUT, POST or DELETE) are kept; these are the only
# records the AI step ever sees.
# You will also have a potential to select the packet you want to analyze.

import argparse
import re
import sys
import time
from pathlib import Path
from urllib.parse import unquote_plus

import scapy.all as scapy

from pcap_utils import (
    DEFAULT_INPUT_DIR,
    DEFAULT_OUTPUT_DIR,
    ENDPOINT_REQUEST,
    SQL_PATTERNS as SHARED_SQL_PATTERNS,
    find_pcap_files,
    next_report_path,
    resolve_path,
)

REPORT_BASE_NAME = "pcap_http_analyzed"


class PcapAnalyzer:
    """Analyze HTTP traffic from a PCAP file and generate a report."""

    SQL_PATTERNS = SHARED_SQL_PATTERNS

    def __init__(self, pcap_file, report_file):
        self.pcap_file = Path(pcap_file)
        self.report_file = Path(report_file)

    def load_packets(self):
        """Load packets from the PCAP file."""
        return scapy.rdpcap(str(self.pcap_file))

    def extract_payload(self, packet):
        """Extract and decode the packet payload."""
        return packet[scapy.Raw].load.decode(errors="ignore")

    def extract_headers(self, payload):
        """Extract HTTP headers from the payload."""
        pattern = r"(.*?)\s*:\s*(.*?)\r\n"

        return {
            name.lower(): value.strip()
            for name, value in re.findall(pattern, payload)
        }

    def extract_http_data(self, payload):
        """Extract HTTP request and response information."""
        return {
            "request": ENDPOINT_REQUEST.match(payload),
            "user": re.search(
                r"(?i)(?:user|username)=([^&\s]+)",
                payload
            ),
            "password": re.search(
                r"(?i)password=([^&\s]+)",
                payload
            ),
            "status": re.search(
                r"HTTP/1\.\d\s+(\d{3})",
                payload
            ),
        }

    def detect_sql_injection(self, payload):
        """Check the payload for basic SQL injection indicators."""
        # Decode first: a form post carries "%27+or+%27a%27%3D%27a", which only
        # matches a pattern once it is turned back into "' or 'a'='a".
        payload = unquote_plus(payload).lower()

        return [
            pattern
            for pattern in self.SQL_PATTERNS
            if pattern in payload
        ]

    def get_timestamp(self, packet):
        """Convert the packet timestamp into a readable format."""
        return time.strftime(
            "%Y-%m-%d %H:%M:%S",
            time.localtime(float(packet.time))
        )

    def analyze_packet(self, packet):
        """Analyze a single packet."""
        required_layers = (
            packet.haslayer(scapy.Raw),
            packet.haslayer(scapy.IP),
        )

        if not all(required_layers):
            return None

        payload = self.extract_payload(packet)

        # Keep only requests to an endpoint (GET/PUT/POST/DELETE).
        if not ENDPOINT_REQUEST.match(payload):
            return None

        return {
            "timestamp": self.get_timestamp(packet),
            "source": packet[scapy.IP].src,
            "destination": packet[scapy.IP].dst,
            "protocol": packet[scapy.IP].proto,
            "http": self.extract_http_data(payload),
            "headers": self.extract_headers(payload),
            "sql_findings": self.detect_sql_injection(payload),
        }

    def format_result(self, result):
        """Convert packet findings into a report entry."""
        http = result["http"]
        headers = result["headers"]

        details = [
            result["timestamp"],
            f"Source IP: {result['source']}",
            f"Destination IP: {result['destination']}",
            f"Protocol: {result['protocol']}",
        ]

        request = http["request"]

        if request:
            details.extend([
                f"Method: {request.group(1)}",
                f"URL: {request.group(2)}",
            ])

        if http["user"]:
            details.append(
                f"User: {http['user'].group(1)}"
            )

        if http["password"]:
            details.append(
                "Password: [REDACTED]"
            )

        if http["status"]:
            details.append(
                f"Status: {http['status'].group(1)}"
            )

        header_fields = {
            "host": "Host",
            "user-agent": "User-Agent",
            "accept": "Accept",
            "referer": "Referer",
        }

        details.extend(
            f"{label}: {headers[header]}"
            for header, label in header_fields.items()
            if header in headers
        )

        if "cookie" in headers:
            details.append("Cookies: [REDACTED]")

        content_type = headers.get("content-type", "")

        if "multipart/form-data" in content_type:
            details.append("Multipart Form Data Detected")

        if result["sql_findings"]:
            details.append("Potential SQL Injection Detected")

        return " | ".join(details)

    def write_report(self, results):
        """Write analysis results to the report file."""
        with self.report_file.open("w", encoding="utf-8") as report:
            report.write(f"# Source capture: {self.pcap_file.name}\n")

            for result in results:
                report.write(
                    self.format_result(result) + "\n"
                )

    def analyze(self, packet_limit=None):
        """Run the complete PCAP analysis."""
        packets = self.load_packets()

        selected_packets = (
            packets[:packet_limit]
            if packet_limit
            else packets
        )

        results = list(
            filter(
                None,
                map(self.analyze_packet, selected_packets)
            )
        )

        self.write_report(results)

        return results


def main():
    """Application entry point."""
    parser = argparse.ArgumentParser(
        description="Generate an HTTP traffic report for every pcap in a folder."
    )
    parser.add_argument(
        "--input-folder",
        type=Path,
        default=DEFAULT_INPUT_DIR,
        help=f"Folder to scan for .pcap/.pcapng files (default: {DEFAULT_INPUT_DIR.name}/).",
    )
    parser.add_argument(
        "--output-folder",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help=f"Folder for the reports (default: {DEFAULT_OUTPUT_DIR.name}/).",
    )
    parser.add_argument(
        "--packet-limit",
        type=int,
        default=0,
        help="Packets to inspect per file; 0 means all (default). This scanner makes no "
        "paid API calls, so there is no cost reason to truncate.",
    )
    args = parser.parse_args()

    input_folder = resolve_path(args.input_folder)
    output_folder = resolve_path(args.output_folder)
    pcap_files = find_pcap_files(input_folder)

    if not pcap_files:
        print(f"No .pcap or .pcapng files found in {input_folder}")
        return 1

    for pcap_file in pcap_files:
        report_file = next_report_path(output_folder, REPORT_BASE_NAME)

        analyzer = PcapAnalyzer(pcap_file, report_file)
        analyzer.analyze(packet_limit=args.packet_limit or None)

        print(f"{pcap_file.name} -> {report_file}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
