"""Helpers shared by the PcapAnalyzer scripts."""

import re
from pathlib import Path

# Resolved from this file, not the shell's working directory, so the scripts
# behave the same no matter where they are launched from.
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_INPUT_DIR = BASE_DIR / "pcap_file"
DEFAULT_OUTPUT_DIR = BASE_DIR / "Examples_Outputs"

PCAP_PATTERNS = ("*.pcap", "*.pcapng")

# Only HTTP requests that hit an endpoint with one of these methods are kept in
# the HTTP report and sent to the AI. Everything else in the capture is still
# analyzed locally (free), but never billed.
ENDPOINT_METHODS = ("GET", "PUT", "POST", "DELETE")
ENDPOINT_REQUEST = re.compile(r"(GET|PUT|POST|DELETE)\s+(\S+)\s+HTTP/")

# Lower-case substrings that suggest SQL injection. They are matched against the
# URL-decoded request, because form posts encode quotes and spaces
# ("%27+or+%27" is "' or '"). These are heuristics: expect some false positives
# and some misses.
SQL_PATTERNS = (
    "' or ",
    '" or ',
    "1=1",
    "union select",
    "drop table",
    "sleep(",
    "benchmark(",
    "xp_cmdshell",
)


def resolve_path(value):
    """Turn a user/env supplied path into a Path anchored at the repo root.

    Absolute paths are returned unchanged; relative ones are resolved against
    the repo root instead of the current working directory.
    """
    return BASE_DIR / Path(value).expanduser()


def find_pcap_files(folder):
    """Return every .pcap/.pcapng file directly inside ``folder``, sorted."""
    folder = Path(folder)
    files = []

    for pattern in PCAP_PATTERNS:
        files.extend(folder.glob(pattern))

    return sorted(files)


def next_report_path(output_dir, base="pcap_analyzed", suffix=".txt"):
    """Return a report path that does not exist yet.

    The first report is ``<base>.txt``; later ones are ``<base>002.txt``,
    ``<base>003.txt`` and so on, so earlier reports are never overwritten.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    candidate = output_dir / f"{base}{suffix}"
    number = 2

    while candidate.exists():
        candidate = output_dir / f"{base}{number:03d}{suffix}"
        number += 1

    return candidate
