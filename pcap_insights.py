"""Turn the analyzed pcap reports into facts a person can act on.

Input is the text written by ``pcap_scanner.py`` (``pcap_analyzed*.txt``) and
``breakdown_packets_scanner.py`` (``pcap_http_analyzed*.txt``). Everything here
is deterministic and offline: the findings are rule-based and each one carries
the evidence that triggered it. The AI layer in ``pcap_formatted.py`` only
adds narrative on top of these facts.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from urllib.parse import unquote_plus

from pcap_utils import ENDPOINT_METHODS, SQL_PATTERNS

TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# Requests from one source to one destination separated by more than this many
# seconds are treated as separate bursts of activity.
SESSION_GAP_SECONDS = 300

# Repeated POSTs to one URL from one source at or above this count are reported
# as possible credential guessing.
REPEATED_POST_THRESHOLD = 5

MAX_EVIDENCE_LINES = 6

# User-Agent fragments of well-known offensive tools -> what they are.
ATTACK_TOOLS = {
    "hydra": "an online password-guessing (brute-force) tool",
    "sqlmap": "an automated SQL-injection tool",
    "nikto": "a web-server vulnerability scanner",
    "nmap": "a network and service scanner",
    "masscan": "a high-speed port scanner",
    "nessus": "a vulnerability scanner",
    "openvas": "a vulnerability scanner",
    "acunetix": "a web vulnerability scanner",
    "wpscan": "a WordPress vulnerability scanner",
    "dirbuster": "a hidden-path brute-forcing tool",
    "gobuster": "a hidden-path brute-forcing tool",
    "havij": "an automated SQL-injection tool",
    "w3af": "a web application attack framework",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}

BASIC_FILE = re.compile(r"^pcap_analyzed(\d{3})?\.txt$")
HTTP_FILE = re.compile(r"^pcap_http_analyzed(\d{3})?\.txt$")
HEADER_LINE = re.compile(r"^#\s*Source capture:\s*(.+?)\s*$")
BASIC_LINE = re.compile(r"^Source IP: (\S+), Destination IP: (\S+), Protocol: (.+?)\s*$")


# --------------------------------------------------------------------------- #
# Data model
# --------------------------------------------------------------------------- #


@dataclass
class PacketRecord:
    src: str
    dst: str
    protocol: str


@dataclass
class HttpEvent:
    """One line of the HTTP report: a request or a response."""

    time: datetime | None
    src: str = ""
    dst: str = ""
    method: str = ""
    url: str = ""
    host: str = ""
    user_agent: str = ""
    status: str = ""
    user: str = ""
    referer: str = ""
    has_cookies: bool = False
    multipart: bool = False
    scanner_sqli_flag: bool = False

    @property
    def is_request(self) -> bool:
        return bool(self.method)

    @property
    def decoded_url(self) -> str:
        return unquote_plus(self.url)

    @property
    def decoded_user(self) -> str:
        return unquote_plus(self.user)

    @property
    def attack_tool(self) -> str | None:
        agent = self.user_agent.lower()
        for tool in ATTACK_TOOLS:
            if tool in agent:
                return tool
        return None

    @property
    def sqli_matches(self) -> list[str]:
        """Patterns found in the decoded URL and user value of this request."""
        text = f"{self.decoded_url} {self.decoded_user}".lower()
        return [pattern for pattern in SQL_PATTERNS if pattern in text]

    @property
    def sqli_suspected(self) -> bool:
        return self.scanner_sqli_flag or bool(self.sqli_matches)


@dataclass
class CaptureData:
    name: str
    basic_file: Path | None = None
    http_file: Path | None = None
    packets: list[PacketRecord] = field(default_factory=list)
    events: list[HttpEvent] = field(default_factory=list)

    @property
    def requests(self) -> list[HttpEvent]:
        """Requests to an endpoint (GET/PUT/POST/DELETE): the only data the AI may see."""
        return [event for event in self.events if event.method in ENDPOINT_METHODS]


@dataclass
class Finding:
    severity: str
    title: str
    detail: str
    evidence: list[str]
    recommendation: str
    affected: list[str] = field(default_factory=list)
    impact: str = ""


@dataclass
class HostInfo:
    ip: str
    roles: list[str]
    sent: int
    received: int
    notes: list[str]


@dataclass
class ActivityWindow:
    src: str
    dst: str
    start: datetime
    end: datetime
    requests: int
    hosts: list[str]
    sqli: int
    tools: list[str]


@dataclass
class Analysis:
    packet_count: int
    request_count: int
    protocols: Counter
    conversations: list[tuple[str, str, int]]
    hosts: list[HostInfo]
    methods: Counter
    virtual_hosts: Counter
    top_urls: list[tuple[str, int]]
    user_agents: Counter
    statuses: Counter
    windows: list[ActivityWindow]
    findings: list[Finding]
    first_seen: datetime | None
    last_seen: datetime | None
    limits: list[str]

    @property
    def known_ips(self) -> set[str]:
        return {host.ip for host in self.hosts}


# --------------------------------------------------------------------------- #
# Discovery and parsing
# --------------------------------------------------------------------------- #


def _read_lines(path: Path) -> list[str]:
    return Path(path).read_text(encoding="utf-8", errors="replace").splitlines()


def read_capture_name(path: Path) -> str | None:
    """Return the capture named in the report's ``# Source capture:`` header."""
    for line in _read_lines(path)[:3]:
        match = HEADER_LINE.match(line)
        if match:
            return match.group(1)
    return None


def discover_reports(folder: Path) -> dict[str, dict[str, Path]]:
    """Group analyzed reports by capture, keeping the newest of each kind.

    Newer runs have higher numbers (``pcap_analyzed.txt`` is run 1,
    ``pcap_analyzed002.txt`` is run 2, ...), so the highest number wins.
    """
    best: dict[str, dict[str, tuple[int, Path]]] = {}

    for path in sorted(Path(folder).glob("*.txt")):
        for kind, pattern in (("basic", BASIC_FILE), ("http", HTTP_FILE)):
            match = pattern.match(path.name)
            if not match:
                continue

            number = int(match.group(1)) if match.group(1) else 1
            name = read_capture_name(path) or f"unknown ({path.name})"
            slot = best.setdefault(name, {})

            if kind not in slot or number > slot[kind][0]:
                slot[kind] = (number, path)

    return {
        name: {kind: path for kind, (_, path) in kinds.items()}
        for name, kinds in best.items()
    }


def parse_basic_report(path: Path) -> list[PacketRecord]:
    packets = []
    for line in _read_lines(path):
        match = BASIC_LINE.match(line)
        if match:
            packets.append(PacketRecord(*match.groups()))
    return packets


def parse_http_line(line: str) -> HttpEvent | None:
    """Parse ``<time> | Key: value | Key: value | Flag`` into an event."""
    parts = [part.strip() for part in line.split(" | ")]

    try:
        event = HttpEvent(time=datetime.strptime(parts[0], TIME_FORMAT))
    except ValueError:
        return None

    for part in parts[1:]:
        key, separator, value = part.partition(": ")

        if separator:
            if key == "Source IP":
                event.src = value
            elif key == "Destination IP":
                event.dst = value
            elif key == "Method":
                event.method = value
            elif key == "URL":
                event.url = value
            elif key == "Host":
                event.host = value
            elif key == "User-Agent":
                event.user_agent = value
            elif key == "Status":
                event.status = value
            elif key == "User":
                event.user = value
            elif key == "Referer":
                event.referer = value
            elif key == "Cookies":
                event.has_cookies = True
        elif part == "Multipart Form Data Detected":
            event.multipart = True
        elif part == "Potential SQL Injection Detected":
            event.scanner_sqli_flag = True

    return event if event.src and event.dst else None


def parse_http_report(path: Path) -> list[HttpEvent]:
    events = []
    for line in _read_lines(path):
        if line.startswith("#") or not line.strip():
            continue
        event = parse_http_line(line)
        if event:
            events.append(event)
    return events


def load_capture(name: str, basic_file: Path | None, http_file: Path | None) -> CaptureData:
    return CaptureData(
        name=name,
        basic_file=basic_file,
        http_file=http_file,
        packets=parse_basic_report(basic_file) if basic_file else [],
        events=parse_http_report(http_file) if http_file else [],
    )


# --------------------------------------------------------------------------- #
# Analysis
# --------------------------------------------------------------------------- #


def _stamp(value: datetime | None) -> str:
    return value.strftime(TIME_FORMAT) if value else "unknown time"


def _build_windows(requests: list[HttpEvent]) -> list[ActivityWindow]:
    by_pair: dict[tuple[str, str], list[HttpEvent]] = defaultdict(list)
    for event in requests:
        if event.time:
            by_pair[(event.src, event.dst)].append(event)

    def close(src: str, dst: str, group: list[HttpEvent]) -> ActivityWindow:
        return ActivityWindow(
            src=src,
            dst=dst,
            start=group[0].time,
            end=group[-1].time,
            requests=len(group),
            hosts=sorted({event.host for event in group if event.host}),
            sqli=sum(1 for event in group if event.sqli_suspected),
            tools=sorted({event.attack_tool for event in group if event.attack_tool}),
        )

    windows = []
    for (src, dst), events in by_pair.items():
        events.sort(key=lambda event: event.time)
        group = [events[0]]

        for event in events[1:]:
            gap = (event.time - group[-1].time).total_seconds()
            if gap > SESSION_GAP_SECONDS:
                windows.append(close(src, dst, group))
                group = [event]
            else:
                group.append(event)

        windows.append(close(src, dst, group))

    return sorted(windows, key=lambda window: (window.start, window.src))


def _evidence_line(event: HttpEvent) -> str:
    line = f"{_stamp(event.time)}  {event.method} {event.decoded_url}"
    if event.user:
        line += f"  (user value: {event.decoded_user!r})"
    if event.scanner_sqli_flag and not event.sqli_matches:
        line += "  (flagged by scanner; payload is in the request body)"
    return line


def _cap_evidence(lines: list[str]) -> list[str]:
    if len(lines) <= MAX_EVIDENCE_LINES:
        return lines
    hidden = len(lines) - MAX_EVIDENCE_LINES
    return lines[:MAX_EVIDENCE_LINES] + [f"... and {hidden} more"]


def _span(events: list[HttpEvent]) -> str:
    times = [event.time for event in events if event.time]
    if not times:
        return "at an unknown time"
    start, end = min(times), max(times)
    seconds = int((end - start).total_seconds())
    if seconds == 0:
        return f"at {_stamp(start)}"
    return f"between {_stamp(start)} and {_stamp(end)} ({seconds}s)"


def _detect_findings(requests: list[HttpEvent]) -> list[Finding]:
    findings: list[Finding] = []

    # 1. Attack tools announcing themselves in the User-Agent.
    tool_pairs: set[tuple[str, str]] = set()
    by_tool: dict[tuple[str, str, str], list[HttpEvent]] = defaultdict(list)
    for event in requests:
        tool = event.attack_tool
        if tool:
            by_tool[(tool, event.src, event.dst)].append(event)

    for (tool, src, dst), events in by_tool.items():
        tool_pairs.add((src, dst))
        methods = Counter(event.method for event in events)
        mix = ", ".join(f"{count} {method}" for method, count in methods.most_common())
        urls = Counter(event.decoded_url for event in events)

        findings.append(
            Finding(
                severity="HIGH",
                title=f"Attack tool detected: {tool.title()} ({src} -> {dst})",
                detail=(
                    f"{src} sent {len(events)} requests to {dst} ({mix}) "
                    f"{_span(events)} with the User-Agent {events[0].user_agent!r}. "
                    f"{tool.title()} is {ATTACK_TOOLS[tool]}; legitimate browsers do not send this."
                ),
                evidence=[f"{count} x {url}" for url, count in urls.most_common(MAX_EVIDENCE_LINES)],
                recommendation=(
                    f"Block or rate-limit {src}. Review authentication and access logs on {dst} "
                    f"for the same period to see whether any attempt succeeded, and enforce "
                    f"account lockout and multi-factor authentication."
                ),
                affected=[src, dst],
                impact=(
                    f"If any guessed credential was valid, the attacker gained unauthorized access "
                    f"to an account or application on {dst}. Even failed attempts can lock out "
                    f"real users and load the server."
                ),
            )
        )

    # 2. SQL injection indicators.
    sqli_pairs: dict[tuple[str, str], list[HttpEvent]] = defaultdict(list)
    for event in requests:
        if event.sqli_suspected:
            sqli_pairs[(event.src, event.dst)].append(event)

    for (src, dst), events in sqli_pairs.items():
        urls = sorted({event.decoded_url.split("?")[0] for event in events})
        findings.append(
            Finding(
                severity="HIGH",
                title=f"SQL injection indicators ({src} -> {dst})",
                detail=(
                    f"{len(events)} request(s) from {src} to {dst} {_span(events)} contained "
                    f"patterns typical of SQL injection, targeting: {', '.join(urls)}. "
                    f"The analyzed data cannot show whether the injection worked; that "
                    f"needs the server's response and database logs."
                ),
                evidence=_cap_evidence([_evidence_line(event) for event in events]),
                recommendation=(
                    f"Check the endpoint(s) {', '.join(urls)} on {dst}: use "
                    f"parameterized queries, validate input, and inspect database and web "
                    f"logs for unexpected logins or data access around that time."
                ),
                affected=[src, dst, *urls],
                impact=(
                    "A successful injection can bypass logins and expose, change or delete "
                    "database contents, including user accounts and personal data."
                ),
            )
        )

    # 3. Many POSTs to one URL, unless a known tool already explains them.
    repeated: dict[tuple[str, str, str], list[HttpEvent]] = defaultdict(list)
    for event in requests:
        if event.method == "POST":
            repeated[(event.src, event.dst, event.decoded_url)].append(event)

    for (src, dst, url), events in repeated.items():
        if len(events) < REPEATED_POST_THRESHOLD or (src, dst) in tool_pairs:
            continue
        findings.append(
            Finding(
                severity="MEDIUM",
                title=f"Repeated POSTs to one endpoint ({src} -> {dst})",
                detail=(
                    f"{src} sent {len(events)} POST requests to {url} on {dst} "
                    f"{_span(events)}. Rapid repetition against a form is a common sign of "
                    f"credential guessing or automated abuse."
                ),
                evidence=[],
                recommendation=(
                    f"Add rate limiting and account lockout to {url}, and review the "
                    f"authentication log on {dst} for failed logins from {src}."
                ),
                affected=[src, dst, url],
                impact=(
                    "Successful password guessing gives access to user accounts. Heavy "
                    "repetition can also slow or disrupt the service."
                ),
            )
        )

    # 4. Everything seen here was readable on the wire.
    cookies = [event for event in requests if event.has_cookies]
    logins = [event for event in requests if event.method == "POST" and "login" in event.decoded_url.lower()]
    if requests:
        parts = [f"{len(requests)} HTTP request(s) were sent unencrypted"]
        if cookies:
            parts.append(f"{len(cookies)} carried session cookies")
        if logins:
            parts.append(f"{len(logins)} submitted a login form")

        findings.append(
            Finding(
                severity="MEDIUM" if (cookies or logins) else "LOW",
                title="Web traffic is unencrypted (plain HTTP)",
                detail=(
                    "; ".join(parts) + ". Anyone on the network path can read or alter this "
                    "traffic, including credentials and session cookies."
                ),
                evidence=[],
                recommendation=(
                    "Serve the application over HTTPS only, redirect HTTP to HTTPS, and mark "
                    "session cookies Secure and HttpOnly."
                ),
                affected=sorted({event.dst for event in requests}),
                impact=(
                    "Credentials, session cookies and form data can be intercepted and reused "
                    "to impersonate users, and traffic can be modified in transit."
                ),
            )
        )

    return sorted(findings, key=lambda finding: SEVERITY_ORDER[finding.severity])


def _build_hosts(data: CaptureData, requests: list[HttpEvent]) -> list[HostInfo]:
    sent = Counter(packet.src for packet in data.packets)
    received = Counter(packet.dst for packet in data.packets)
    clients = Counter(event.src for event in requests)
    servers = Counter(event.dst for event in requests)

    hosts = []
    for ip in set(sent) | set(received) | set(clients) | set(servers):
        roles = []
        if ip in clients:
            roles.append("web client")
        if ip in servers:
            roles.append("web server")

        notes = []
        tools = sorted({event.attack_tool for event in requests if event.src == ip and event.attack_tool})
        if tools:
            notes.append("uses " + ", ".join(tool.title() for tool in tools))
        injections = sum(1 for event in requests if event.src == ip and event.sqli_suspected)
        if injections:
            notes.append(f"{injections} SQL injection indicator(s)")
        attackers = sorted(
            {e.src for e in requests if e.dst == ip and (e.attack_tool or e.sqli_suspected)}
        )
        if attackers:
            notes.append("targeted by " + ", ".join(attackers))

        hosts.append(HostInfo(ip, roles or ["other"], sent[ip], received[ip], notes))

    # Flagged hosts first, then busiest.
    return sorted(hosts, key=lambda h: (not h.notes, -(h.sent + h.received), h.ip))


def _build_limits(data: CaptureData, analysis_requests: list[HttpEvent], statuses: Counter) -> list[str]:
    limits = []

    if not data.basic_file:
        limits.append("No pcap_analyzed report was found for this capture, so packet-level statistics are missing.")
    if not data.http_file:
        limits.append("No pcap_http_analyzed report was found for this capture, so HTTP findings are missing.")

    if analysis_requests and sum(statuses.values()) < len(analysis_requests):
        recorded = sum(statuses.values())
        seen = "No server responses were" if not recorded else f"Only {recorded} server response(s) were"
        limits.append(
            f"{seen} recorded for {len(analysis_requests)} request(s), because the HTTP scanner "
            f"keeps only GET, PUT, POST and DELETE requests. Success or failure of requests is "
            f"mostly unknown."
        )

    limits.extend(
        [
            "Findings are heuristics over text reports, not a full packet inspection: SQL injection "
            "detection is substring matching and can miss obfuscated payloads or flag harmless text.",
            "Encrypted traffic (HTTPS) cannot be inspected; it appears only as TCP in the packet counts.",
            "Passwords and cookie values are redacted by the scanner, and timestamps are in the local "
            "time of the machine that analyzed the capture.",
        ]
    )
    return limits


def analyze(data: CaptureData) -> Analysis:
    requests = data.requests
    protocols = Counter(packet.protocol for packet in data.packets)

    pairs: Counter = Counter(tuple(sorted((packet.src, packet.dst))) for packet in data.packets)
    conversations = [(a, b, count) for (a, b), count in pairs.most_common(8)]

    statuses = Counter(event.status for event in data.events if event.status)
    times = [event.time for event in data.events if event.time]

    return Analysis(
        packet_count=len(data.packets),
        request_count=len(requests),
        protocols=protocols,
        conversations=conversations,
        hosts=_build_hosts(data, requests),
        methods=Counter(event.method for event in requests),
        virtual_hosts=Counter(event.host for event in requests if event.host),
        top_urls=Counter(event.decoded_url for event in requests).most_common(10),
        user_agents=Counter(event.user_agent for event in requests if event.user_agent),
        statuses=statuses,
        windows=_build_windows(requests),
        findings=_detect_findings(requests),
        first_seen=min(times) if times else None,
        last_seen=max(times) if times else None,
        limits=_build_limits(data, requests, statuses),
    )


def local_summary(name: str, analysis: Analysis) -> str:
    """A plain-language summary built from the findings, with no AI involved."""
    parts = [
        f"{name} contains {analysis.packet_count} IP packets between {len(analysis.hosts)} hosts"
        if analysis.packet_count
        else f"{name} was analyzed from its HTTP report"
    ]

    if analysis.request_count:
        parts[0] += (
            f" and {analysis.request_count} HTTP requests in {len(analysis.windows)} "
            f"burst(s) of activity, from {_stamp(analysis.first_seen)} to {_stamp(analysis.last_seen)}."
        )
    else:
        parts[0] += "."

    counts = Counter(finding.severity for finding in analysis.findings)
    important = [f for f in analysis.findings if f.severity in ("HIGH", "MEDIUM")]

    if important:
        summary = ", ".join(f"{counts[s]} {s.lower()}" for s in ("HIGH", "MEDIUM") if counts[s])
        parts.append(f"{summary}-severity finding(s): " + "; ".join(f.title for f in important) + ".")
    else:
        parts.append("No high or medium severity findings were detected.")

    return " ".join(parts)
