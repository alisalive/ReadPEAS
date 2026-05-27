"""Analyze SUID binary findings from LinPEAS output."""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

# ── GTFOBins database ──────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "gtfobins.json"
_db: Optional[Dict] = None


def _load_db() -> Dict:
    """Load and cache the GTFOBins JSON database from disk."""
    global _db
    if _db is None:
        with open(_DB_PATH, encoding="utf-8") as fh:
            _db = json.load(fh)
    return _db


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_suid_section(section_text: str) -> List[str]:
    """Extract SUID binary full paths from LinPEAS SUID section text."""
    paths: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Binary path is the last token starting with '/' (handles ls -l format)
        for token in reversed(stripped.split()):
            if token.startswith("/"):
                if not token.startswith("/snap/") and token not in seen:
                    seen.add(token)
                    paths.append(token)
                break
    return paths


def normalize_binary(path: str) -> List[str]:
    """Return candidate GTFOBins lookup names for a path, from specific to generic.

    Examples:
        /usr/bin/python3.9  -> ["python3.9", "python3", "python"]
        /usr/bin/vim.basic  -> ["vim.basic", "vim"]
        /usr/bin/find       -> ["find"]
    """
    name = os.path.basename(path)
    candidates: List[str] = []
    seen: set = set()

    current = name
    while current:
        if current not in seen:
            seen.add(current)
            candidates.append(current)

        # Strip trailing .suffix (e.g. ".9", ".basic")
        no_suffix = re.sub(r"\.[^.]+$", "", current)
        if no_suffix and no_suffix != current:
            current = no_suffix
            continue

        # Strip trailing digits (e.g. "python3" -> "python")
        no_digits = re.sub(r"\d+$", "", current)
        if no_digits and no_digits != current:
            current = no_digits
            continue

        break

    return candidates


def lookup_suid(binary: str) -> List[str]:
    """Return GTFOBins suid commands for a binary, or empty list if not found."""
    db = _load_db()
    return list(db.get(binary, {}).get("suid", []))


_NON_STANDARD_PREFIXES = ("/nfs_share/", "/opt/", "/home/", "/tmp/", "/var/", "/srv/")


def analyze(section_text: str) -> List[Dict]:
    """Analyze a SUID section and return a list of structured findings.

    Each finding has keys: binary, full_path, severity, type, commands.
    When a normalized candidate matched, matched_as is also included.
    Severity is CRITICAL when GTFOBins commands exist OR the path is
    non-standard; non-standard binaries always get fallback commands prepended.
    Otherwise INFO.
    """
    findings: List[Dict] = []

    for full_path in parse_suid_section(section_text):
        candidates = normalize_binary(full_path)
        matched_as: Optional[str] = None
        commands: List[str] = []

        for candidate in candidates:
            cmds = lookup_suid(candidate)
            if cmds:
                matched_as = candidate
                commands = cmds
                break

        non_standard = any(full_path.startswith(p) for p in _NON_STANDARD_PREFIXES)

        fallback = [f"{full_path} -p", full_path]
        if non_standard:
            # Any SUID binary in a non-standard path is always CRITICAL.
            # Prepend direct-path fallback so TRY FIRST is the simple command.
            commands = fallback + commands
            severity = "CRITICAL"
        else:
            severity = "CRITICAL" if commands else "INFO"

        finding: Dict = {
            "binary": os.path.basename(full_path),
            "full_path": full_path,
            "severity": severity,
            "type": "suid",
            "commands": commands,
        }
        if matched_as is not None:
            finding["matched_as"] = matched_as
        if non_standard:
            finding["non_standard"] = True

        findings.append(finding)

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
-rwsr-xr-x 1 root root 174872 Dec  3  2023 /usr/bin/sudo
-rwsr-xr-x 1 root root  51024 Sep 13  2023 /usr/bin/newgrp
-rwsr-xr-x 1 root root 166056 Jan 19  2024 /usr/bin/find
-rwsr-xr-x 1 root root  44784 Jan 20  2024 /usr/bin/python3.9
-rwsr-xr-x 1 root root  35192 Mar 23  2022 /usr/bin/vim.basic
-rwsr-xr-x 1 root root  22912 Mar 23  2022 /usr/bin/notabin
"""

    print("=== parse_suid_section ===")
    paths = parse_suid_section(SAMPLE)
    print("Paths found:", paths)

    print("\n=== normalize_binary ===")
    for p in ["/usr/bin/python3.9", "/usr/bin/vim.basic", "/usr/bin/find"]:
        print(f"  {p!r} -> {normalize_binary(p)}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        matched = finding.get("matched_as", finding["binary"])
        print(
            f"[{finding['severity']}] {finding['full_path']}"
            f"  (matched_as={matched!r}, {len(cmds)} command(s))"
        )
        for cmd in cmds[:2]:
            print(f"    $ {cmd}")
        if len(cmds) > 2:
            print(f"    ... and {len(cmds) - 2} more")
