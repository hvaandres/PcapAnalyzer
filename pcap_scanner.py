# Analyze every pcap file in a folder and write a basic IP/protocol report for each.
#
# With no arguments it reads ./pcap_file and writes to ./Examples_Outputs as
# pcap_analyzed.txt, pcap_analyzed002.txt, pcap_analyzed003.txt, ...

import argparse
import sys
from pathlib import Path

import scapy.all as scapy

from pcap_utils import (
    DEFAULT_INPUT_DIR,
    DEFAULT_OUTPUT_DIR,
    ENDPOINT_REQUEST,
    find_pcap_files,
    next_report_path,
    resolve_path,
)

REPORT_BASE_NAME = "pcap_analyzed"


def describe_packet(packet):
    """Return a one-line description of an IP packet, or None if not IP."""
    if not packet.haslayer(scapy.IP):
        return None

    src_ip = packet[scapy.IP].src
    dst_ip = packet[scapy.IP].dst

    if packet.haslayer(scapy.TCP):
        protocol = "TCP"
    elif packet.haslayer(scapy.UDP):
        protocol = "UDP"
    else:
        protocol = "Other"

    # Upgrade the label when the TCP payload looks like an HTTP request.
    if packet.haslayer(scapy.Raw) and packet.haslayer(scapy.TCP):
        payload = packet[scapy.Raw].load.decode(errors="ignore")
        request = ENDPOINT_REQUEST.match(payload)
        if request:
            protocol = f"HTTP {request.group(1)}"

    return f"Source IP: {src_ip}, Destination IP: {dst_ip}, Protocol: {protocol}"


def analyze(pcap_file, report_file):
    """Write a report line for every IP packet in the capture."""
    packets = scapy.rdpcap(str(pcap_file))

    with Path(report_file).open("w", encoding="utf-8") as report:
        report.write(f"# Source capture: {Path(pcap_file).name}\n")

        for packet in packets:
            line = describe_packet(packet)
            if line:
                report.write(line + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Generate a basic IP/protocol report for every pcap in a folder."
    )
    parser.add_argument(
        "pcap_file",
        nargs="?",
        type=Path,
        default=None,
        help="Optional single .pcap to analyze instead of the whole input folder.",
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
    args = parser.parse_args()

    if args.pcap_file:
        pcap_files = [args.pcap_file]
    else:
        input_folder = resolve_path(args.input_folder)
        pcap_files = find_pcap_files(input_folder)

        if not pcap_files:
            print(f"No .pcap or .pcapng files found in {input_folder}")
            return 1

    output_folder = resolve_path(args.output_folder)
    failures = 0

    for pcap_file in pcap_files:
        if not pcap_file.is_file():
            print(f"PCAP file not found: {pcap_file}")
            failures += 1
            continue

        report_file = next_report_path(output_folder, REPORT_BASE_NAME)
        analyze(pcap_file, report_file)
        print(f"{pcap_file.name} -> {report_file}")

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
