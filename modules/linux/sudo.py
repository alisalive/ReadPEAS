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
#   (ALL : ALL) /usr/bin/vim
# Group 1: "NOPASSWD: " prefix (or None); Group 2: command string
_SUDO_RULE_RE = re.compile(
    r"\([^)]+\)\s+(NOPASSWD\s*:\s*)?(.+)",
    re.IGNORECASE,
)


# ── Internal helpers ───────────────────────────────────────────────────────────

def _parse_sudo_rules(section_text: str) -> List[Tuple[str, str, bool]]:
    """Return (binary_name, full_path, nopasswd) tuples from sudo -l section text."""
    rules: List[Tuple[str, str, bool]] = []
    seen: set = set()

    for line in section_text.splitlines():
        m = _SUDO_RULE_RE.search(line)
        if not m:
            continue
        nopasswd: bool = bool(m.group(1)) or "NOPASSWD" in line.upper()
        # Strip any residual flag tokens from group(2) (e.g. SETENV: before NOPASSWD:)
        raw = m.group(2).strip()
        cmd_part = re.sub(r"^(?:[A-Za-z_]+\s*:\s*)+", "", raw).strip()
        cmd = cmd_part.split()[0] if cmd_part else ""
        if cmd.upper() == "ALL":
            if "ALL" not in seen:
                seen.add("ALL")
                rules.append(("ALL", "ALL", nopasswd))
            continue
        name = os.path.basename(cmd)
        if name and name not in seen:
            seen.add(name)
            rules.append((name, cmd, nopasswd))

    return rules


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_sudo_section(section_text: str) -> List[str]:
    """Extract binary names from sudo -l output lines."""
    return [name for name, _, _ in _parse_sudo_rules(section_text)]


def lookup_sudo(binary: str) -> List[str]:
    """Return GTFOBins sudo commands for a binary, or empty list if not found."""
    db = _load_db()
    return list(db.get(binary, {}).get("sudo", []))


def _prefix_sudo(commands: List[str], binary: str, full_path: str) -> List[str]:
    """Prepend 'sudo <full_path>' to each command, replacing the leading binary name."""
    prefixed: List[str] = []
    for cmd in commands:
        parts = cmd.split(None, 1)
        if parts and parts[0] == binary:
            rest = parts[1] if len(parts) > 1 else ""
            prefixed.append(f"sudo {full_path} {rest}".rstrip())
        else:
            prefixed.append(f"sudo {cmd}")
    return prefixed


def analyze(section_text: str) -> List[Dict]:
    """Analyze a sudo -l section and return a list of structured findings.

    Each finding has keys: binary, full_path, severity, type, nopasswd, commands.
    Severity: NOPASSWD + commands -> CRITICAL; NOPASSWD only -> HIGH;
              password required + commands -> HIGH; otherwise -> INFO.
    """
    findings: List[Dict] = []

    for binary, full_path, nopasswd in _parse_sudo_rules(section_text):
        if binary == "ALL":
            findings.append({
                "binary": "ALL",
                "full_path": "ALL",
                "severity": "CRITICAL",
                "type": "sudo",
                "nopasswd": nopasswd,
                "commands": ["sudo /bin/bash", "sudo su"],
            })
            continue

        commands = _prefix_sudo(lookup_sudo(binary), binary, full_path)
        if nopasswd:
            severity = "CRITICAL" if commands else "HIGH"
        else:
            severity = "HIGH" if commands else "INFO"

        findings.append({
            "binary": binary,
            "full_path": full_path,
            "severity": severity,
            "type": "sudo",
            "nopasswd": nopasswd,
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
