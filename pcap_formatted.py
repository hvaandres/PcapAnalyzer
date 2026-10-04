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

Cost controls: cheapest Flash-Lite model by default, thinking disabled, output
capped, and a single request per capture instead of one per packet.

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
    "what protocols or headers are in general."
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
    """Compact, factual summary of one capture: everything the model may use."""
    return {
        "capture": data.name,
        "totals": {
            "ip_packets": analysis.packet_count,
            "http_requests": analysis.request_count,
            "hosts": len(analysis.hosts),
            "first_seen": analysis.first_seen.isoformat(sep=" ") if analysis.first_seen else None,
            "last_seen": analysis.last_seen.isoformat(sep=" ") if analysis.last_seen else None,
        },
        "protocols": dict(analysis.protocols.most_common(8)),
        "hosts": [
            {
                "ip": host.ip,
                "roles": host.roles,
                "packets_sent": host.sent,
                "packets_received": host.received,
                "notes": host.notes,
            }
            for host in analysis.hosts[:10]
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
            "top_urls": [{"url": url, "count": count} for url, count in analysis.top_urls[:10]],
            "user_agents": dict(analysis.user_agents.most_common(5)),
            "status_codes_recorded": dict(analysis.statuses),
        },
        "rule_based_findings": [
            {
                "severity": finding.severity,
                "title": finding.title,
                "detail": finding.detail,
                "evidence": finding.evidence[:4],
            }
            for finding in analysis.findings
        ],
        "data_limits": analysis.limits,
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


def render_report(
    data: CaptureData,
    analysis: Analysis,
    insights: AIInsights | None,
    ai_note: str,
    model: str,
) -> str:
    out: list[str] = []
    add = out.append

    sources = ", ".join(f"`{p.name}`" for p in (data.basic_file, data.http_file) if p) or "none"
    counts = {s: sum(1 for f in analysis.findings if f.severity == s) for s in SEVERITY_ORDER}

    add("# Packet Capture Analysis Report")
    add("")
    add(f"- **Capture:** `{data.name}`")
    add(f"- **Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    add(f"- **Built from:** {sources}")
    short_note = ai_note.split(". ")[0].rstrip(".")
    add(f"- **AI narrative:** {f'`{model}`' if insights else f'not included ({short_note})'}")
    add("")

    # ---- Summary ---------------------------------------------------------- #
    add("## Executive summary")
    add("")
    if insights and insights.executive_summary:
        add(insights.executive_summary)
        if insights.overall_risk:
            add("")
            add(f"**Overall risk: {insights.overall_risk}.** {insights.risk_rationale}".strip())
        add("")
        add("*Summary written by the AI from the facts below.*")
    else:
        add(local_summary(data.name, analysis))
        add("")
        add("*Summary generated from rule-based findings.*")
    add("")

    add("## At a glance")
    add("")
    add(f"- IP packets: **{analysis.packet_count}** across **{len(analysis.hosts)}** hosts")
    add(f"- HTTP requests: **{analysis.request_count}** in **{len(analysis.windows)}** activity window(s)")
    add(f"- First / last HTTP request: {_when(analysis.first_seen)} / {_when(analysis.last_seen)}")
    add(
        f"- Findings: **{counts['HIGH']} high**, **{counts['MEDIUM']} medium**, "
        f"{counts['LOW']} low, {counts['INFO']} info"
    )
    add("")

    # ---- Findings --------------------------------------------------------- #
    add("## Key findings")
    add("")
    if analysis.findings:
        for finding in analysis.findings:
            add(f"### [{finding.severity}] {finding.title}")
            add("")
            add(finding.detail)
            if finding.evidence:
                add("")
                add("Evidence:")
                add("")
                out.extend(f"- `{line}`" for line in finding.evidence)
            add("")
            add(f"**Recommended:** {finding.recommendation}")
            add("")
    else:
        add("No rule-based findings were triggered by the available data.")
        add("")

    # ---- Timeline --------------------------------------------------------- #
    add("## What happened")
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

    # ---- Hosts ------------------------------------------------------------ #
    add("## Hosts")
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

    # ---- Traffic ---------------------------------------------------------- #
    add("## Traffic breakdown")
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

    # ---- HTTP ------------------------------------------------------------- #
    add("## HTTP activity")
    add("")
    if analysis.request_count:
        add(
            md_table(
                ["Method", "Requests"],
                [[method, count] for method, count in analysis.methods.most_common()],
            )
        )
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
        add("No HTTP requests were available.")
    add("")

    # ---- Actions ---------------------------------------------------------- #
    add("## Recommended actions")
    add("")
    seen: set[str] = set()
    step = 1
    for finding in analysis.findings:
        if finding.recommendation in seen:
            continue
        seen.add(finding.recommendation)
        add(f"{step}. **[{finding.severity}]** {finding.recommendation}")
        step += 1
    if not seen:
        add("No actions triggered by the findings.")
    add("")

    if insights and insights.recommendations:
        add("Additional AI suggestions, most urgent first:")
        add("")
        for rec in insights.recommendations:
            reason = f" {rec.reason}" if rec.reason else ""
            add(f"- **[{rec.priority.upper() or 'N/A'}]** {rec.action}{reason}")
        add("")

    if insights and insights.open_questions:
        add("## Open questions")
        add("")
        add("The data cannot answer these; check them next:")
        add("")
        out.extend(f"- {question}" for question in insights.open_questions)
        add("")

    # ---- Limits ----------------------------------------------------------- #
    add("## Data notes and limits")
    add("")
    out.extend(f"- {note}" for note in analysis.limits)
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

        if client:
            try:
                insights = client.summarize(build_digest(data, analysis), analysis.known_ips)
            except FatalAPIError as exc:
                ai_note = str(exc)
                LOGGER.warning("AI step disabled for this run: %s", ai_note)
                client = None  # every remaining capture would fail the same way
            except AIError as exc:
                ai_note = str(exc)
                LOGGER.warning("No AI narrative for %s: %s", name, ai_note)

        report_path = output_folder / f"{safe_filename(name)}_report.md"
        report_path.write_text(
            render_report(data, analysis, insights, ai_note, model), encoding="utf-8"
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
