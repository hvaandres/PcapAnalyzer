# Packet Capture Analysis Report

- **Capture:** `IT6300FE.pcap`
- **Generated:** 2026-10-03 18:59
- **Built from:** `pcap_analyzed.txt`
- **AI narrative:** not included (disabled with --no-ai)

## Executive summary

IT6300FE.pcap contains 371 IP packets between 4 hosts. No high or medium severity findings were detected.

*Summary generated from rule-based findings.*

## At a glance

- IP packets: **371** across **4** hosts
- HTTP requests: **0** in **0** activity window(s)
- First / last HTTP request: - / -
- Findings: **0 high**, **0 medium**, 0 low, 0 info

## Key findings

No rule-based findings were triggered by the available data.

## What happened

No timestamped HTTP activity was available.

## Hosts

| IP address | Role | Packets sent | Packets received | Notes |
| --- | --- | --- | --- | --- |
| 161.28.112.58 | other | 95 | 108 | - |
| 161.28.112.67 | other | 108 | 95 | - |
| 161.28.112.43 | other | 72 | 96 | - |
| 161.28.112.66 | other | 96 | 72 | - |

## Traffic breakdown

| Protocol | Packets | Share |
| --- | --- | --- |
| TCP | 340 | 92% |
| HTTP GET | 19 | 5% |
| HTTP POST | 12 | 3% |

Busiest conversations (both directions combined):

| Host A | Host B | Packets |
| --- | --- | --- |
| 161.28.112.58 | 161.28.112.67 | 203 |
| 161.28.112.43 | 161.28.112.66 | 168 |

## HTTP activity

No HTTP requests were available.

## Recommended actions

No actions triggered by the findings.

## Data notes and limits

- No pcap_http_analyzed report was found for this capture, so HTTP findings are missing.
- Findings are heuristics over text reports, not a full packet inspection: SQL injection detection is substring matching and can miss obfuscated payloads or flag harmless text.
- Encrypted traffic (HTTPS) cannot be inspected; it appears only as TCP in the packet counts.
- Passwords and cookie values are redacted by the scanner, and timestamps are in the local time of the machine that analyzed the capture.
