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
#   (will) NOPASSWD: /usr/bin/python3 /opt/script.py *
# Group 1: sudo user spec; Group 2: "NOPASSWD: " prefix (or None); Group 3: command string
_SUDO_RULE_RE = re.compile(
    r"\(([^)]+)\)\s+(NOPASSWD\s*:\s*)?(.+)",
    re.IGNORECASE,
)


# ── Internal helpers ───────────────────────────────────────────────────────────

def normalize_binary(name: str) -> List[str]:
    """Return candidate GTFOBins lookup names for a binary name, from specific to generic.

    Examples: python3 -> ["python3", "python"]; vim.basic -> ["vim.basic", "vim"]
    """
    candidates: List[str] = []
    seen: set = set()
    current = name
    while current:
        if current not in seen:
            seen.add(current)
            candidates.append(current)
        no_suffix = re.sub(r"\.[^.]+$", "", current)
        if no_suffix and no_suffix != current:
            current = no_suffix
            continue
        no_digits = re.sub(r"\d+$", "", current)
        if no_digits and no_digits != current:
            current = no_digits
            continue
        break
    return candidates


def _parse_sudo_rules(section_text: str) -> List[Tuple[str, str, bool, str]]:
    """Return (binary_name, full_path, nopasswd, sudo_user) tuples from sudo -l section text."""
    rules: List[Tuple[str, str, bool, str]] = []
    seen: set = set()

    for line in section_text.splitlines():
        m = _SUDO_RULE_RE.search(line)
        if not m:
            continue
        sudo_user: str = m.group(1).strip()
        nopasswd: bool = bool(m.group(2)) or "NOPASSWD" in line.upper()
        # Strip any residual flag tokens from group(3) (e.g. SETENV: before NOPASSWD:)
        raw = m.group(3).strip()
        cmd_part = re.sub(r"^(?:[A-Za-z_]+\s*:\s*)+", "", raw).strip()
        cmd = cmd_part.split()[0] if cmd_part else ""
        if cmd.upper() == "ALL":
            if "ALL" not in seen:
                seen.add("ALL")
                rules.append(("ALL", "ALL", nopasswd, sudo_user))
            continue
        name = os.path.basename(cmd)
        if name and name not in seen:
            seen.add(name)
            rules.append((name, cmd, nopasswd, sudo_user))

    return rules


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_sudo_section(section_text: str) -> List[str]:
    """Extract binary names from sudo -l output lines."""
    return [name for name, _, _, _ in _parse_sudo_rules(section_text)]


def lookup_sudo(binary: str) -> List[str]:
    """Return GTFOBins sudo commands for a binary, or empty list if not found."""
    db = _load_db()
    return list(db.get(binary, {}).get("sudo", []))


def _prefix_sudo(commands: List[str], binary: str, full_path: str, sudo_user: str = "") -> List[str]:
    """Prepend 'sudo [-u user] <full_path>' to each command, replacing the leading binary name."""
    # Build user flag: omit for root/ALL, include for specific users like "will"
    raw_user = sudo_user.split(":")[0].strip()
    user_flag = f"-u {raw_user} " if raw_user.upper() not in ("ROOT", "ALL", "") else ""

    prefixed: List[str] = []
    for cmd in commands:
        parts = cmd.split(None, 1)
        if parts and parts[0] == binary:
            rest = parts[1] if len(parts) > 1 else ""
            prefixed.append(f"sudo {user_flag}{full_path} {rest}".rstrip())
        else:
            prefixed.append(f"sudo {user_flag}{cmd}")
    return prefixed


def analyze(section_text: str) -> List[Dict]:
    """Analyze a sudo -l section and return a list of structured findings.

    Each finding has keys: binary, full_path, severity, type, nopasswd, commands.
    Severity: NOPASSWD -> always CRITICAL; password required + commands -> HIGH; otherwise INFO.
    """
    findings: List[Dict] = []

    for binary, full_path, nopasswd, sudo_user in _parse_sudo_rules(section_text):
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

        # Try binary name and fallbacks (e.g. python3 -> python) for GTFOBins lookup
        commands: List[str] = []
        matched_as: Optional[str] = None
        for candidate in normalize_binary(binary):
            cmds = lookup_sudo(candidate)
            if cmds:
                matched_as = candidate
                commands = _prefix_sudo(cmds, candidate, full_path, sudo_user)
                break

        # NOPASSWD is always CRITICAL — attacker can run the binary without a password
        if nopasswd:
            severity = "CRITICAL"
        else:
            severity = "HIGH" if commands else "INFO"

        finding: Dict = {
            "binary": binary,
            "full_path": full_path,
            "severity": severity,
            "type": "sudo",
            "nopasswd": nopasswd,
            "commands": commands,
        }
        if matched_as is not None and matched_as != binary:
            finding["matched_as"] = matched_as

        findings.append(finding)

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
