"""Turn the analyzed pcap reports into a report people can actually act on.

Pipeline:
  pcap_scanner.py            -> Examples_Outputs/pcap_analyzed*.txt       (packet list)
  breakdown_packets_scanner  -> Examples_Outputs/pcap_http_analyzed*.txt  (HTTP detail)
  pcap_formatted.py (this)   -> Better_Outputs/<capture>_report.md

``pcap_insights`` computes the facts and rule-based findings locally. Gemini is
then called ONCE per capture with a compact digest of those facts to write the
executive summary, a plain-language timeline and prioritized recommendations.
The report is still complete without the AI: if there is no API key, the API
rejects the request, or ``--no-ai`` is given, the local sections are written
and the report says why the AI sections are missing.

Cost controls: the AI only sees endpoint traffic (GET, PUT, POST, DELETE
requests); the rest of the capture is analyzed locally for free, and a capture
with no endpoint requests makes no AI call at all. On top of that: cheapest
Flash-Lite model by default, thinking disabled, output capped, and a single
request per capture instead of one per packet.

Created by Andres Haro, 2026.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import random
import re
import sys
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from google import genai
from google.genai import errors as genai_errors
from google.genai import types

from pcap_insights import (
    Analysis,
    CaptureData,
    discover_reports,
    load_capture,
    analyze,
    local_summary,
    SEVERITY_ORDER,
)
from pcap_utils import DEFAULT_OUTPUT_DIR, resolve_path

LOGGER = logging.getLogger("pcap_formatted")

# Flash-Lite is Google's cheapest generally-available tier. Override with the
# GEMINI_MODEL environment variable if your project has access to something
# cheaper (for example the legacy "gemini-2.5-flash-lite").
DEFAULT_MODEL = "gemini-3.1-flash-lite"

# Approximate USD per 1M tokens, used only for the cost estimate printed at the
# end of a run. Keep in sync with https://ai.google.dev/gemini-api/docs/pricing
PRICING_USD_PER_MTOK: dict[str, tuple[float, float]] = {
    "gemini-3.1-flash-lite": (0.25, 1.50),
    "gemini-3.5-flash-lite": (0.30, 2.50),
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.30, 2.50),
}

DEFAULT_ANALYZED_DIR = DEFAULT_OUTPUT_DIR  # where the scanners write
DEFAULT_REPORT_DIR = "Better_Outputs"

RETRYABLE_STATUS = {429, 500, 502, 503, 504}
FATAL_STATUS = {400, 401, 403, 404}

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

SYSTEM_INSTRUCTION = (
    "You are a senior network security analyst writing for a reader who is not a "
    "packet-analysis expert. You receive structured facts extracted from a packet "
    "capture. Rules: use ONLY the facts provided; never invent IP addresses, URLs, "
    "hostnames, tools, dates or outcomes. The data usually cannot prove whether an "
    "attack succeeded; say so rather than guessing. Be specific: cite the IPs, URLs, "
    "counts and times from the facts. Use plain, short sentences. Do not explain "
    "what protocols or headers are in general. Never call a host or activity "
    "'confirmed' malicious or an attack 'successful': the data only shows indicators "
    "and attempts. The report already lists each finding's 'recommendation'; do NOT "
    "repeat or rephrase those. 'recommendations' must contain only complementary "
    "actions that add something new (at most 3), or be empty."
)

RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "executive_summary": {
            "type": "string",
            "description": "3 to 5 sentences: what happened, who was involved, how serious it is.",
        },
        "what_happened": {
            "type": "array",
            "description": "Chronological bullets, one per activity window, in plain language.",
            "items": {"type": "string"},
        },
        "overall_risk": {"type": "string", "enum": ["Low", "Medium", "High", "Critical"]},
        "risk_rationale": {"type": "string", "description": "One or two sentences justifying the rating."},
        "recommendations": {
            "type": "array",
            "description": "Prioritized actions, most urgent first.",
            "items": {
                "type": "object",
                "properties": {
                    "priority": {"type": "string", "enum": ["High", "Medium", "Low"]},
                    "action": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["priority", "action", "reason"],
            },
        },
        "open_questions": {
            "type": "array",
            "description": "What an analyst should check next because the data cannot answer it.",
            "items": {"type": "string"},
        },
    },
    "required": [
        "executive_summary",
        "what_happened",
        "overall_risk",
        "risk_rationale",
        "recommendations",
        "open_questions",
    ],
}


class AIError(RuntimeError):
    """The AI step failed for this capture; the local report is still written."""


class FatalAPIError(AIError):
    """Retrying cannot fix this (bad key, API disabled, unknown model)."""


# --------------------------------------------------------------------------- #
# AI layer
# --------------------------------------------------------------------------- #


@dataclass
class Recommendation:
    priority: str
    action: str
    reason: str


@dataclass
class AIInsights:
    executive_summary: str
    what_happened: list[str] = field(default_factory=list)
    overall_risk: str = ""
    risk_rationale: str = ""
    recommendations: list[Recommendation] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)

    @classmethod
    def from_json(cls, payload: str) -> "AIInsights":
        data = json.loads(payload)

        def texts(key: str) -> list[str]:
            return [str(item).strip() for item in data.get(key, []) if str(item).strip()]

        recommendations = [
            Recommendation(
                priority=str(item.get("priority", "")).strip(),
                action=str(item.get("action", "")).strip(),
                reason=str(item.get("reason", "")).strip(),
            )
            for item in data.get("recommendations", [])
            if isinstance(item, dict) and str(item.get("action", "")).strip()
        ]

        return cls(
            executive_summary=str(data.get("executive_summary", "")).strip(),
            what_happened=texts("what_happened"),
            overall_risk=str(data.get("overall_risk", "")).strip(),
            risk_rationale=str(data.get("risk_rationale", "")).strip(),
            recommendations=recommendations,
            open_questions=texts("open_questions"),
        )

    def all_text(self) -> str:
        parts = [self.executive_summary, self.risk_rationale, *self.what_happened, *self.open_questions]
        parts.extend(f"{r.action} {r.reason}" for r in self.recommendations)
        return "\n".join(parts)

    def check_grounded(self, known_ips: set[str]) -> None:
        """Reject output that mentions an IP address the capture never contained."""
        invented = sorted(set(IPV4.findall(self.all_text())) - known_ips)
        if invented:
            raise AIError(
                "the model mentioned IP address(es) that are not in the capture "
                f"({', '.join(invented)}), so its narrative was discarded"
            )


@dataclass
class Usage:
    prompt_tokens: int = 0
    output_tokens: int = 0
    requests: int = 0

    def add(self, metadata: Any) -> None:
        self.requests += 1
        self.prompt_tokens += getattr(metadata, "prompt_token_count", 0) or 0
        self.output_tokens += getattr(metadata, "candidates_token_count", 0) or 0

    def estimated_cost_usd(self, model: str) -> float | None:
        price = PRICING_USD_PER_MTOK.get(model)
        if price is None:
            return None
        in_rate, out_rate = price
        return (self.prompt_tokens * in_rate + self.output_tokens * out_rate) / 1_000_000


def build_digest(data: CaptureData, analysis: Analysis) -> dict[str, Any]:
    """Compact summary of the endpoint (GET/PUT/POST/DELETE) traffic only.

    Packet-level data (protocol mix, non-HTTP hosts, conversations) is analyzed
    locally and deliberately left out: it costs tokens and the rules already
    cover it.
    """
    endpoints = Counter((event.method, event.decoded_url) for event in data.requests)

    return {
        "capture": data.name,
        "totals": {
            "endpoint_requests": analysis.request_count,
            "first_seen": analysis.first_seen.isoformat(sep=" ") if analysis.first_seen else None,
            "last_seen": analysis.last_seen.isoformat(sep=" ") if analysis.last_seen else None,
        },
        "hosts": [
            {"ip": host.ip, "roles": host.roles, "notes": host.notes}
            for host in analysis.hosts
            if host.roles != ["other"]
        ][:10],
        "endpoints": [
            {"method": method, "url": url, "count": count}
            for (method, url), count in endpoints.most_common(15)
        ],
        "activity_windows": [
            {
                "start": window.start.isoformat(sep=" "),
                "end": window.end.isoformat(sep=" "),
                "source": window.src,
                "destination": window.dst,
                "requests": window.requests,
                "virtual_hosts": window.hosts,
                "sql_injection_indicators": window.sqli,
                "attack_tools": window.tools,
            }
            for window in analysis.windows[:12]
        ],
        "http": {
            "methods": dict(analysis.methods),
            "user_agents": dict(analysis.user_agents.most_common(5)),
        },
        "rule_based_findings": [
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "evidence": finding.evidence[:4],
                "recommendation": finding.recommendation,
            }
            for finding in analysis.findings
        ],
    }


class InsightsClient:
    """One cost-capped Gemini request per capture."""

    def __init__(
        self,
        api_key: str,
        model: str = DEFAULT_MODEL,
        max_output_tokens: int = 1400,
        max_retries: int = 4,
    ) -> None:
        self._client = genai.Client(api_key=api_key)
        self.model = model
        self._max_retries = max_retries
        self.usage = Usage()
        self._config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            response_mime_type="application/json",
            response_json_schema=RESPONSE_SCHEMA,
            max_output_tokens=max_output_tokens,
            temperature=0.2,
            # Reasoning tokens bill at the output rate; the facts are already computed.
            thinking_config=types.ThinkingConfig(thinking_budget=0),
            automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
        )

    def summarize(self, digest: dict[str, Any], known_ips: set[str]) -> AIInsights:
        prompt = (
            "Analyze this packet capture. Facts (JSON):\n"
            + json.dumps(digest, separators=(",", ":"), ensure_ascii=False)
        )

        for attempt in range(self._max_retries):
            try:
                response = self._client.models.generate_content(
                    model=self.model, contents=prompt, config=self._config
                )
            except genai_errors.APIError as exc:
                if exc.code in FATAL_STATUS:
                    raise FatalAPIError(self._fatal_hint(exc)) from exc
                if exc.code in RETRYABLE_STATUS and attempt < self._max_retries - 1:
                    delay = min(2**attempt + random.uniform(0, 0.5), 30)
                    LOGGER.warning("Retrying in %.1fs after API error: %s", delay, exc)
                    time.sleep(delay)
                    continue
                raise AIError(f"Gemini request failed: {exc}") from exc
            except Exception as exc:  # noqa: BLE001 - never let the AI step kill the report
                raise AIError(f"unexpected error calling Gemini: {exc}") from exc

            self.usage.add(getattr(response, "usage_metadata", None))
            text = (response.text or "").strip()
            if not text:
                raise AIError("empty response from the model")

            try:
                insights = AIInsights.from_json(text)
            except (json.JSONDecodeError, TypeError, AttributeError) as exc:
                raise AIError(
                    "the model response was not valid JSON (it may have been cut off; "
                    "try a larger --max-output-tokens)"
                ) from exc

            insights.check_grounded(known_ips)
            return insights

        raise AIError("retries exhausted")

    def _fatal_hint(self, exc: genai_errors.APIError) -> str:
        message = " ".join((getattr(exc, "message", "") or str(exc)).split())
        if len(message) > 220:
            message = message[:217] + "..."

        if exc.code == 404:
            return f"model '{self.model}' is not available to this API key (use --model or $GEMINI_MODEL): {message}"
        if exc.code in (401, 403):
            return (
                "the API rejected this key. Check GEMINI_API_KEY and that the Generative "
                f"Language API is enabled for its Google Cloud project: {message}"
            )
        return f"{exc.code}: {message}"


# --------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------- #


def _cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    lines.extend("| " + " | ".join(_cell(cell) for cell in row) + " |" for row in rows)
    return "\n".join(lines)


def _share(count: int, total: int) -> str:
    return f"{count / total:.0%}" if total else "-"


def _when(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S") if value else "-"


RISK_LABEL = {"HIGH": "High", "MEDIUM": "Medium", "LOW": "Low", "INFO": "Informational"}

SEVERITY_MEANING = {
    "HIGH": "Active attack or serious weakness. Act immediately.",
    "MEDIUM": "Meaningful weakness or suspicious behavior. Fix soon.",
    "LOW": "Minor weakness or hardening gap. Fix as part of routine work.",
    "INFO": "For awareness only. No action required.",
}


def local_risk(analysis: Analysis) -> str:
    """Overall risk from the most severe finding (used when there is no AI rating)."""
    for severity in SEVERITY_ORDER:
        if any(finding.severity == severity for finding in analysis.findings):
            return RISK_LABEL[severity]
    return "Informational"


def local_rationale(analysis: Analysis, counts: dict[str, int]) -> str:
    if not analysis.findings:
        return "No findings were detected in the available data."
    serious = [f"{counts[s]} {s.lower()}" for s in ("HIGH", "MEDIUM") if counts[s]]
    if serious:
        return "Rated on the most severe findings: " + " and ".join(serious) + "-severity finding(s)."
    return "Only low-severity or informational findings were detected."


def render_report(
    data: CaptureData,
    analysis: Analysis,
    insights: AIInsights | None,
    ai_note: str,
    model: str,
) -> str:
    """Write a standard security assessment report in Markdown."""
    out: list[str] = []
    add = out.append

    counts = {s: sum(1 for f in analysis.findings if f.severity == s) for s in SEVERITY_ORDER}
    ids = {id(f): f"F-{n:02d}" for n, f in enumerate(analysis.findings, 1)}
    risk = insights.overall_risk if insights and insights.overall_risk else local_risk(analysis)
    rationale = (
        insights.risk_rationale if insights and insights.risk_rationale else local_rationale(analysis, counts)
    )
    sources = ", ".join(f"`{p.name}`" for p in (data.basic_file, data.http_file) if p) or "none"
    short_note = ai_note.split(". ")[0].rstrip(".")
    period = (
        f"{_when(analysis.first_seen)} to {_when(analysis.last_seen)} (HTTP activity)"
        if analysis.first_seen
        else "Not available"
    )

    # ---- Title block ------------------------------------------------------ #
    add("# Network Security Assessment Report")
    add("")
    add(
        md_table(
            ["Item", "Detail"],
            [
                ["Subject", f"Packet capture `{data.name}`"],
                ["Report date", datetime.now().strftime("%Y-%m-%d %H:%M")],
                ["Activity period", period],
                ["Overall risk", f"**{risk}**"],
                ["Findings", f"{counts['HIGH']} high, {counts['MEDIUM']} medium, {counts['LOW']} low, {counts['INFO']} informational"],
                ["Source data", sources],
                ["AI-assisted narrative", f"`{model}`" if insights else f"Not included ({short_note})"],
            ],
        )
    )
    add("")

    # ---- 1. Executive summary -------------------------------------------- #
    add("## 1. Executive Summary")
    add("")
    if insights and insights.executive_summary:
        add(insights.executive_summary)
    else:
        add(local_summary(data.name, analysis))
    add("")
    add(f"**Overall risk: {risk}.** {rationale}".strip())
    add("")
    important = [f for f in analysis.findings if f.severity in ("HIGH", "MEDIUM")]
    if important:
        add("Key issues:")
        add("")
        out.extend(f"- **[{f.severity}]** {f.title}" for f in important)
        add("")
    add(
        "Sections 3 and 4 list every finding with its evidence and fix. "
        "Section 7 is the prioritized action list."
    )
    add("")

    # ---- 2. Scope and methodology ---------------------------------------- #
    add("## 2. Scope and Methodology")
    add("")
    add("**Scope**")
    add("")
    add(f"- Capture analyzed: `{data.name}`")
    add(
        f"- {analysis.packet_count} IP packets between {len(analysis.hosts)} hosts, and "
        f"{analysis.request_count} HTTP endpoint requests (GET, PUT, POST, DELETE)."
    )
    add("- Encrypted traffic (HTTPS) is outside the scope: it cannot be read from a capture.")
    add("")
    add("**Method**")
    add("")
    add("- Every packet is analyzed locally, offline and without AI.")
    add(
        "- Findings come from fixed rules: known attack-tool signatures in the User-Agent, "
        "SQL injection patterns, repeated POSTs to one endpoint, and unencrypted web traffic."
    )
    add(
        "- The AI step, when enabled, only sees the endpoint requests and the rule-based findings. "
        "It writes the narrative; it does not create findings."
    )
    add("")
    add("**Severity ratings**")
    add("")
    add(md_table(["Severity", "Meaning"], [[RISK_LABEL[s], SEVERITY_MEANING[s]] for s in SEVERITY_ORDER]))
    add("")

    # ---- 3. Summary of findings ------------------------------------------ #
    add("## 3. Summary of Findings")
    add("")
    if analysis.findings:
        rows = [
            [ids[id(f)], RISK_LABEL[f.severity], f.title, ", ".join(f.affected) or "-"]
            for f in analysis.findings
        ]
        add(md_table(["ID", "Severity", "Finding", "Affected"], rows))
    else:
        add("No findings were triggered by the available data.")
    add("")

    # ---- 4. Detailed findings -------------------------------------------- #
    add("## 4. Detailed Findings")
    add("")
    if analysis.findings:
        for finding in analysis.findings:
            add(f"### {ids[id(finding)]}: {finding.title}")
            add("")
            add(f"- **Severity:** {RISK_LABEL[finding.severity]}")
            if finding.affected:
                add(f"- **Affected:** {', '.join(finding.affected)}")
            add("")
            add("**Description**")
            add("")
            add(finding.detail)
            add("")
            if finding.evidence:
                add("**Evidence**")
                add("")
                add("```text")
                out.extend(finding.evidence)
                add("```")
                add("")
            if finding.impact:
                add("**Impact**")
                add("")
                add(finding.impact)
                add("")
            add("**Recommendation**")
            add("")
            add(finding.recommendation)
            add("")
    else:
        add("None.")
        add("")

    # ---- 5. Timeline ------------------------------------------------------ #
    add("## 5. Timeline of Events")
    add("")
    if insights and insights.what_happened:
        out.extend(f"- {line}" for line in insights.what_happened)
        add("")
        add("*Narrative written by the AI; the table below is the underlying data.*")
        add("")
    if analysis.windows:
        rows = []
        for window in analysis.windows:
            notes = []
            if window.tools:
                notes.append("attack tool: " + ", ".join(t.title() for t in window.tools))
            if window.sqli:
                notes.append(f"{window.sqli} SQL injection indicator(s)")
            rows.append(
                [
                    _when(window.start),
                    _when(window.end),
                    f"{window.src} -> {window.dst}",
                    window.requests,
                    ", ".join(window.hosts) or "-",
                    "; ".join(notes) or "-",
                ]
            )
        add(md_table(["Start", "End", "Source -> Destination", "Requests", "Host header(s)", "Notes"], rows))
    else:
        add("No timestamped HTTP activity was available.")
    add("")

    # ---- 6. Affected assets ---------------------------------------------- #
    add("## 6. Hosts Involved")
    add("")
    if analysis.hosts:
        rows = [
            [
                host.ip,
                ", ".join(host.roles),
                host.sent or "-",
                host.received or "-",
                "; ".join(host.notes) or "-",
            ]
            for host in analysis.hosts
        ]
        add(md_table(["IP address", "Role", "Packets sent", "Packets received", "Notes"], rows))
    else:
        add("No hosts found.")
    add("")

    # ---- 7. Recommendations ---------------------------------------------- #
    add("## 7. Recommendations")
    add("")
    seen: set[str] = set()
    step = 1
    for finding in analysis.findings:
        if finding.recommendation in seen:
            continue
        seen.add(finding.recommendation)
        add(f"{step}. **[{RISK_LABEL[finding.severity]}]** ({ids[id(finding)]}) {finding.recommendation}")
        step += 1
    if not seen:
        add("No actions triggered by the findings.")
    add("")

    if insights and insights.recommendations:
        add("Additional AI suggestions, most urgent first:")
        add("")
        for rec in insights.recommendations:
            reason = f" {rec.reason}" if rec.reason else ""
            add(f"- **[{rec.priority or 'N/A'}]** {rec.action}{reason}")
        add("")

    if insights and insights.open_questions:
        add("**Further investigation.** The data cannot answer these; check them next:")
        add("")
        out.extend(f"- {question}" for question in insights.open_questions)
        add("")

    # ---- 8. Limitations --------------------------------------------------- #
    add("## 8. Limitations")
    add("")
    out.extend(f"- {note}" for note in analysis.limits)
    add("")

    # ---- Appendices ------------------------------------------------------- #
    add("## Appendix A: Traffic Statistics")
    add("")
    if analysis.protocols:
        rows = [
            [protocol, count, _share(count, analysis.packet_count)]
            for protocol, count in analysis.protocols.most_common()
        ]
        add(md_table(["Protocol", "Packets", "Share"], rows))
        add("")
        add("Busiest conversations (both directions combined):")
        add("")
        add(md_table(["Host A", "Host B", "Packets"], [[a, b, n] for a, b, n in analysis.conversations]))
    else:
        add("No packet-level data was available.")
    add("")

    add("## Appendix B: HTTP Activity")
    add("")
    if analysis.request_count:
        add(md_table(["Method", "Requests"], [[m, n] for m, n in analysis.methods.most_common()]))
        add("")
        add("Requested sites (Host header):")
        add("")
        add(md_table(["Host", "Requests"], [[h, n] for h, n in analysis.virtual_hosts.most_common()]))
        add("")
        add("Most requested URLs:")
        add("")
        add(md_table(["URL", "Requests"], [[url, n] for url, n in analysis.top_urls]))
        add("")
        add("User-Agents:")
        add("")
        add(md_table(["User-Agent", "Requests"], [[ua, n] for ua, n in analysis.user_agents.most_common()]))
        add("")
        if analysis.statuses:
            add(
                "Response codes recorded: "
                + ", ".join(f"{code} x{n}" for code, n in sorted(analysis.statuses.items()))
            )
        else:
            add("No response codes were recorded.")
    else:
        add("No HTTP endpoint requests were available.")
    add("")

    return "\n".join(out)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def safe_filename(name: str) -> str:
    return re.sub(r"[^\w.-]+", "_", Path(name).stem).strip("_") or "capture"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Turn the analyzed pcap reports into an actionable Markdown report."
    )
    parser.add_argument(
        "--input-folder",
        type=Path,
        default=None,
        help="Folder holding pcap_analyzed*.txt and pcap_http_analyzed*.txt "
        "(default: $analyzed_folder_path or Examples_Outputs/).",
    )
    parser.add_argument(
        "--output-folder",
        type=Path,
        default=None,
        help=f"Folder for the finished reports (default: $output_folder_path or {DEFAULT_REPORT_DIR}/).",
    )
    parser.add_argument(
        "--model",
        default=None,
        help=f"Gemini model ID (default: $GEMINI_MODEL or {DEFAULT_MODEL}).",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip Gemini entirely and write the local, rule-based report (free).",
    )
    parser.add_argument(
        "--max-output-tokens",
        type=int,
        default=1400,
        help="Cap on billed output tokens per capture.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )
    if not args.verbose:
        for noisy in ("httpx", "google_genai", "google_genai.models"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    load_dotenv()

    input_folder = resolve_path(
        args.input_folder or os.getenv("analyzed_folder_path") or DEFAULT_ANALYZED_DIR
    )
    output_folder = resolve_path(
        args.output_folder or os.getenv("output_folder_path") or DEFAULT_REPORT_DIR
    )

    if not input_folder.is_dir():
        LOGGER.error("Input folder does not exist: %s", input_folder)
        return 1

    captures = discover_reports(input_folder)
    if not captures:
        LOGGER.error(
            "No pcap_analyzed*.txt or pcap_http_analyzed*.txt found in %s. "
            "Run pcap_scanner.py and breakdown_packets_scanner.py first.",
            input_folder,
        )
        return 1

    model = args.model or os.getenv("GEMINI_MODEL", DEFAULT_MODEL)
    client: InsightsClient | None = None
    ai_note = ""

    if args.no_ai:
        ai_note = "disabled with --no-ai"
    elif not os.getenv("GEMINI_API_KEY"):
        ai_note = "GEMINI_API_KEY is not set"
        LOGGER.warning("%s; writing the rule-based report only.", ai_note)
    else:
        client = InsightsClient(
            api_key=os.environ["GEMINI_API_KEY"],
            model=model,
            max_output_tokens=args.max_output_tokens,
        )

    output_folder.mkdir(parents=True, exist_ok=True)
    written = 0

    for name, files in sorted(captures.items()):
        data = load_capture(name, files.get("basic"), files.get("http"))
        analysis = analyze(data)
        insights: AIInsights | None = None
        capture_note = ai_note

        if client and not analysis.request_count:
            # Nothing hit an endpoint, so there is nothing worth paying to summarize.
            capture_note = "no GET/PUT/POST/DELETE endpoint requests found, so the AI step was skipped"
            LOGGER.info("%s: %s.", name, capture_note)
        elif client:
            try:
                insights = client.summarize(build_digest(data, analysis), analysis.known_ips)
            except FatalAPIError as exc:
                ai_note = capture_note = str(exc)
                LOGGER.warning("AI step disabled for this run: %s", ai_note)
                client = None  # every remaining capture would fail the same way
            except AIError as exc:
                capture_note = str(exc)
                LOGGER.warning("No AI narrative for %s: %s", name, capture_note)

        report_path = output_folder / f"{safe_filename(name)}_report.md"
        report_path.write_text(
            render_report(data, analysis, insights, capture_note, model), encoding="utf-8"
        )
        written += 1
        LOGGER.info(
            "%s -> %s (%d packets, %d requests, %d findings)",
            name,
            report_path,
            analysis.packet_count,
            analysis.request_count,
            len(analysis.findings),
        )

    if args.no_ai or not os.getenv("GEMINI_API_KEY"):
        return 0

    if client is not None:
        usage = client.usage
        cost = usage.estimated_cost_usd(model)
        LOGGER.info(
            "AI usage: %d call(s), %d in / %d out tokens%s",
            usage.requests,
            usage.prompt_tokens,
            usage.output_tokens,
            f", about ${cost:.5f}" if cost is not None else "",
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
