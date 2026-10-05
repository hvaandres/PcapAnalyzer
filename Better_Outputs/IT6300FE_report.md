# Network Security Assessment Report

| Item | Detail |
| --- | --- |
| Subject | Packet capture `IT6300FE.pcap` |
| Report date | 2026-10-04 18:57 |
| Activity period | 2016-04-14 11:28:39 to 2016-11-29 13:22:46 (HTTP activity) |
| Overall risk | **High** |
| Findings | 2 high, 1 medium, 0 low, 0 informational |
| Source data | `pcap_analyzed002.txt`, `pcap_http_analyzed.txt` |
| AI-assisted narrative | Not included (disabled with --no-ai) |

## 1. Executive Summary

IT6300FE.pcap contains 371 IP packets between 4 hosts and 31 HTTP requests in 2 burst(s) of activity, from 2016-04-14 11:28:39 to 2016-11-29 13:22:46. 2 high, 1 medium-severity finding(s): Attack tool detected: Hydra (161.28.112.67 -> 161.28.112.58); SQL injection indicators (161.28.112.66 -> 161.28.112.43); Web traffic is unencrypted (plain HTTP).

**Overall risk: High.** Rated on the most severe findings: 2 high and 1 medium-severity finding(s).

Key issues:

- **[HIGH]** Attack tool detected: Hydra (161.28.112.67 -> 161.28.112.58)
- **[HIGH]** SQL injection indicators (161.28.112.66 -> 161.28.112.43)
- **[MEDIUM]** Web traffic is unencrypted (plain HTTP)

Sections 3 and 4 list every finding with its evidence and fix. Section 7 is the prioritized action list.

## 2. Scope and Methodology

**Scope**

- Capture analyzed: `IT6300FE.pcap`
- 371 IP packets between 4 hosts, and 31 HTTP endpoint requests (GET, PUT, POST, DELETE).
- Encrypted traffic (HTTPS) is outside the scope: it cannot be read from a capture.

**Method**

- Every packet is analyzed locally, offline and without AI.
- Findings come from fixed rules: known attack-tool signatures in the User-Agent, SQL injection patterns, repeated POSTs to one endpoint, and unencrypted web traffic.
- The AI step, when enabled, only sees the endpoint requests and the rule-based findings. It writes the narrative; it does not create findings.

**Severity ratings**

| Severity | Meaning |
| --- | --- |
| High | Active attack or serious weakness. Act immediately. |
| Medium | Meaningful weakness or suspicious behavior. Fix soon. |
| Low | Minor weakness or hardening gap. Fix as part of routine work. |
| Informational | For awareness only. No action required. |

## 3. Summary of Findings

| ID | Severity | Finding | Affected |
| --- | --- | --- | --- |
| F-01 | High | Attack tool detected: Hydra (161.28.112.67 -> 161.28.112.58) | 161.28.112.67, 161.28.112.58 |
| F-02 | High | SQL injection indicators (161.28.112.66 -> 161.28.112.43) | 161.28.112.66, 161.28.112.43, /cgi-bin/badstore.cgi, /sqlInjection.php |
| F-03 | Medium | Web traffic is unencrypted (plain HTTP) | 161.28.112.43, 161.28.112.58 |

## 4. Detailed Findings

### F-01: Attack tool detected: Hydra (161.28.112.67 -> 161.28.112.58)

- **Severity:** High
- **Affected:** 161.28.112.67, 161.28.112.58

**Description**

161.28.112.67 sent 14 requests to 161.28.112.58 (8 POST, 6 GET) at 2016-11-29 13:22:46 with the User-Agent 'Mozilla/5.0 (Hydra)'. Hydra is an online password-guessing (brute-force) tool; legitimate browsers do not send this.

**Evidence**

```text
14 x /cgi-bin/badstore.cgi?action=login
```

**Impact**

If any guessed credential was valid, the attacker gained unauthorized access to an account or application on 161.28.112.58. Even failed attempts can lock out real users and load the server.

**Recommendation**

Block or rate-limit 161.28.112.67. Review authentication and access logs on 161.28.112.58 for the same period to see whether any attempt succeeded, and enforce account lockout and multi-factor authentication.

### F-02: SQL injection indicators (161.28.112.66 -> 161.28.112.43)

- **Severity:** High
- **Affected:** 161.28.112.66, 161.28.112.43, /cgi-bin/badstore.cgi, /sqlInjection.php

**Description**

3 request(s) from 161.28.112.66 to 161.28.112.43 between 2016-04-14 11:28:51 and 2016-04-14 11:29:30 (39s) contained patterns typical of SQL injection, targeting: /cgi-bin/badstore.cgi, /sqlInjection.php. The analyzed data cannot show whether the injection worked; that needs the server's response and database logs.

**Evidence**

```text
2016-04-14 11:28:51  POST /sqlInjection.php  (user value: "uvu' or 'a'='a")
2016-04-14 11:29:23  POST /cgi-bin/badstore.cgi?action=login  (flagged by scanner; payload is in the request body)
2016-04-14 11:29:30  POST /cgi-bin/badstore.cgi?action=login  (flagged by scanner; payload is in the request body)
```

**Impact**

A successful injection can bypass logins and expose, change or delete database contents, including user accounts and personal data.

**Recommendation**

Check the endpoint(s) /cgi-bin/badstore.cgi, /sqlInjection.php on 161.28.112.43: use parameterized queries, validate input, and inspect database and web logs for unexpected logins or data access around that time.

### F-03: Web traffic is unencrypted (plain HTTP)

- **Severity:** Medium
- **Affected:** 161.28.112.43, 161.28.112.58

**Description**

31 HTTP request(s) were sent unencrypted; 13 carried session cookies; 10 submitted a login form. Anyone on the network path can read or alter this traffic, including credentials and session cookies.

**Impact**

Credentials, session cookies and form data can be intercepted and reused to impersonate users, and traffic can be modified in transit.

**Recommendation**

Serve the application over HTTPS only, redirect HTTP to HTTPS, and mark session cookies Secure and HttpOnly.

## 5. Timeline of Events

| Start | End | Source -> Destination | Requests | Host header(s) | Notes |
| --- | --- | --- | --- | --- | --- |
| 2016-04-14 11:28:39 | 2016-04-14 11:30:08 | 161.28.112.66 -> 161.28.112.43 | 17 | www.badstore.net, www.sql.net | 3 SQL injection indicator(s) |
| 2016-11-29 13:22:46 | 2016-11-29 13:22:46 | 161.28.112.67 -> 161.28.112.58 | 14 | 161.28.112.58 | attack tool: Hydra |

## 6. Hosts Involved

| IP address | Role | Packets sent | Packets received | Notes |
| --- | --- | --- | --- | --- |
| 161.28.112.58 | web server | 95 | 108 | targeted by 161.28.112.67 |
| 161.28.112.67 | web client | 108 | 95 | uses Hydra |
| 161.28.112.43 | web server | 72 | 96 | targeted by 161.28.112.66 |
| 161.28.112.66 | web client | 96 | 72 | 3 SQL injection indicator(s) |

## 7. Recommendations

1. **[High]** (F-01) Block or rate-limit 161.28.112.67. Review authentication and access logs on 161.28.112.58 for the same period to see whether any attempt succeeded, and enforce account lockout and multi-factor authentication.
2. **[High]** (F-02) Check the endpoint(s) /cgi-bin/badstore.cgi, /sqlInjection.php on 161.28.112.43: use parameterized queries, validate input, and inspect database and web logs for unexpected logins or data access around that time.
3. **[Medium]** (F-03) Serve the application over HTTPS only, redirect HTTP to HTTPS, and mark session cookies Secure and HttpOnly.

## 8. Limitations

- No server responses were recorded for 31 request(s), because the HTTP scanner keeps only GET, PUT, POST and DELETE requests. Success or failure of requests is mostly unknown.
- Findings are heuristics over text reports, not a full packet inspection: SQL injection detection is substring matching and can miss obfuscated payloads or flag harmless text.
- Encrypted traffic (HTTPS) cannot be inspected; it appears only as TCP in the packet counts.
- Passwords and cookie values are redacted by the scanner, and timestamps are in the local time of the machine that analyzed the capture.

## Appendix A: Traffic Statistics

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

## Appendix B: HTTP Activity

| Method | Requests |
| --- | --- |
| GET | 19 |
| POST | 12 |

Requested sites (Host header):

| Host | Requests |
| --- | --- |
| www.badstore.net | 15 |
| 161.28.112.58 | 14 |
| www.sql.net | 2 |

Most requested URLs:

| URL | Requests |
| --- | --- |
| /cgi-bin/badstore.cgi?action=login | 16 |
| /cgi-bin/bsheader.cgi | 4 |
| / | 2 |
| /sqlInjection.php | 1 |
| /images/BadStore.jpg | 1 |
| /images/cart.jpg | 1 |
| /images/store1.jpg | 1 |
| /images/index.gif | 1 |
| /favicon.ico | 1 |
| /cgi-bin/badstore.cgi?action=loginregister | 1 |

User-Agents:

| User-Agent | Requests |
| --- | --- |
| Mozilla/5.0 (X11; Linux x86_64; rv:43.0) Gecko/20100101 Firefox/43.0 Iceweasel/43.0.4 | 17 |
| Mozilla/5.0 (Hydra) | 14 |

No response codes were recorded.
