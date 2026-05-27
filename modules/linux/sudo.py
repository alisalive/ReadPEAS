"""Analyze sudo -l findings from LinPEAS output."""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional, Tuple

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


# ── Regex patterns ─────────────────────────────────────────────────────────────
# Matches sudo rule lines produced by `sudo -l`:
#   (root) NOPASSWD: /usr/bin/vim
#   (ALL : ALL) NOPASSWD: ALL
#   (root) /usr/bin/find
_SUDO_RULE_RE = re.compile(
    r"\([^)]+\)\s+(?:(?:NOPASSWD|PASSWD)\s*:\s*)?(.+)",
    re.IGNORECASE,
)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _parse_sudo_rules(section_text: str) -> List[Tuple[str, str]]:
    """Return (binary_name, full_path) pairs from sudo -l section text."""
    rules: List[Tuple[str, str]] = []
    seen: set = set()

    for line in section_text.splitlines():
        m = _SUDO_RULE_RE.search(line)
        if not m:
            continue
        # First token is the command; the rest are arguments.
        cmd = m.group(1).strip().split()[0]
        if cmd.upper() == "ALL":
            if "ALL" not in seen:
                seen.add("ALL")
                rules.append(("ALL", "ALL"))
            continue
        name = os.path.basename(cmd)
        if name and name not in seen:
            seen.add(name)
            rules.append((name, cmd))

    return rules


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_sudo_section(section_text: str) -> List[str]:
    """Extract binary names from sudo -l output lines."""
    return [name for name, _ in _parse_sudo_rules(section_text)]


def lookup_sudo(binary: str) -> List[str]:
    """Return GTFOBins sudo commands for a binary, or empty list if not found."""
    db = _load_db()
    return list(db.get(binary, {}).get("sudo", []))


def analyze(section_text: str) -> List[Dict]:
    """Analyze a sudo -l section and return a list of structured findings.

    Each finding has keys: binary, full_path, severity, type, commands.
    Severity is CRITICAL when GTFOBins commands exist (or binary is ALL),
    otherwise INFO.
    """
    findings: List[Dict] = []

    for binary, full_path in _parse_sudo_rules(section_text):
        if binary == "ALL":
            findings.append({
                "binary": "ALL",
                "full_path": "ALL",
                "severity": "CRITICAL",
                "type": "sudo",
                "commands": ["sudo /bin/bash", "sudo su"],
            })
            continue

        commands = lookup_sudo(binary)
        findings.append({
            "binary": binary,
            "full_path": full_path,
            "severity": "CRITICAL" if commands else "INFO",
            "type": "sudo",
            "commands": commands,
        })

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
Matching Defaults entries for ctf on target:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

User ctf may run the following commands on target:
    (root) NOPASSWD: /usr/bin/vim
    (ALL : ALL) NOPASSWD: ALL
    (root) NOPASSWD: /usr/bin/python3 /opt/script.py
    (root) /usr/bin/find
    (root) NOPASSWD: /usr/bin/notabin
"""

    print("=== parse_sudo_section ===")
    names = parse_sudo_section(SAMPLE)
    print("Binaries found:", names)

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(
            f"[{finding['severity']}] {finding['full_path']}"
            f"  ({len(cmds)} command(s))"
        )
        for cmd in cmds[:2]:  # show first two commands only
            print(f"    $ {cmd}")
        if len(cmds) > 2:
            print(f"    ... and {len(cmds) - 2} more")
