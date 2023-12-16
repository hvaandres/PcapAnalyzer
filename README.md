# PcapAnalyzer
Welcome to PcapAnalyzer, a comprehensive toolkit for working with pcap files, which are commonly used to store network traffic captures. This repository provides a suite of tools designed to analyze, inspect, and extract insights from packet capture files. Whether you are a network security professional, a system administrator, or a developer working on network-related projects, PcapAnalyzer equips you with the essential utilities to streamline your pcap file analysis workflow.

Also, I added OpenAI's GPT-3 model to generate a report for the pcap file. The report is generated in the form of a text file. The report contains the following information:

- Source IP
- Destination IP
- Host: [URL, IP]
- Type of vulnerability: [if any]
- Description of the problem: [if any]
- Possible Solutions: [if any]
- User-Agent: [Browser, OS, Device]
- Request Type: [Get, Post, Put, Delete]
- Is Successful: [yes, no]




## Key Features:
- Packet Inspection: Dive deep into network packets to examine headers, payloads, and other relevant information.

- Traffic Analysis: Gain insights into network traffic patterns, protocols, and potential anomalies.

- Filtering Capabilities: Efficiently filter and sort packets based on various criteria, enhancing targeted analysis.

- Extraction Tools: Extract specific data, files, or metadata from pcap files for further examination.

- Integration Support: Seamlessly integrate PcapAnalyzer into your existing network security or monitoring workflows.

- User-Friendly Interface: Enjoy a user-friendly interface that simplifies the complexities of pcap file analysis.

## Getting Started:
To get started, clone the repository and explore the documentation for detailed instructions on installing, configuring, and utilizing the tools provided by PcapAnalyzer.

Get an account on OpenAI's GPT-3 API and add the API key to the code. You can get an account here: https://beta.openai.com/. You can also use the free version of the API.


## Installation:
- Install Scapy: `pip install scapy`
- Install OpenAI's API: `pip install openai`
- Add the API key to the code.

## Things to change in the code:
- Change the path to the pcap file in the code.
- Change the path to the output file in the code.
- Change the path to the output directory in the code.
- If your file is big and you want to extract the data from it, you can also change the number of packets to be read in the code if you want to analyze a specific number of packets. For example, if you want to analyze the first 20 packets, you can change the code to:

```
for packet in packets[:20]:
        analyze_http_packet(packet, report_file)
```

## Tools Included:
- PacketInspector: A tool for in-depth inspection of individual network packets.

- FilterUtility: Efficiently filter and sort pcap files based on specific criteria.

- ExtractionWizard: Extract files, data, or metadata from pcap captures.

## Contributing:
Contributions to PcapAnalyzer are welcome! Feel free to submit bug reports, feature requests, or even pull requests to enhance the functionality of this pcap analysis toolkit.

