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

def _is_sgid_only(stripped_line: str) -> bool:
    """Return True if the line shows SGID permissions but not SUID.

    SUID: owner-execute position (index 3) is 's' or 'S'.
    SGID: group-execute position (index 6) is 's' or 'S'.
    Skip entries that are SGID-only; they do not grant root access.
    """
    m = _PERM_STR_RE.match(stripped_line)
    if not m:
        return False
    perm = m.group(1)
    has_suid = perm[3] in ("s", "S")
    has_sgid = perm[6] in ("s", "S")
    return has_sgid and not has_suid


def parse_suid_section(section_text: str) -> List[str]:
    """Extract SUID binary full paths from LinPEAS SUID section text."""
    paths: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        # Skip SGID-only entries (group-execute setgid, not owner setuid).
        if _is_sgid_only(stripped):
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


def _replace_binary(commands: List[str], matched_as: str, full_path: str) -> List[str]:
    """Replace the leading GTFOBins generic name with the actual full path in each command."""
    result = []
    for cmd in commands:
        parts = cmd.split(None, 1)
        if parts and parts[0] == matched_as:
            rest = (" " + parts[1]) if len(parts) > 1 else ""
            result.append(full_path + rest)
        else:
            result.append(cmd)
    return result


# Matches the permission string at the start of an ls -l line (10 chars).
_PERM_STR_RE = re.compile(r"^([-dl][rwxsStT-]{9})\s")

_NON_STANDARD_PREFIXES = ("/nfs_share/", "/opt/", "/home/", "/tmp/", "/var/", "/srv/")
_STANDARD_PREFIXES = ("/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/")

# Binaries that are well-known system SUID utilities — not interesting for privesc research.
_KNOWN_SAFE = {
    "su", "sudo", "passwd", "mount", "umount", "ping", "chsh",
    "gpasswd", "newgrp", "newuidmap", "newgidmap", "pkexec",
    "crontab", "at", "wall", "write", "ssh-agent", "staprun",
    "traceroute6", "Xorg", "arping", "clockdiff",
}

_UNKNOWN_SUID_NOTE = (
    "Unknown SUID binary — investigate manually, "
    "may call system commands without full path (PATH hijack risk)"
)


def analyze(section_text: str) -> List[Dict]:
    """Analyze a SUID section and return a list of structured findings.

    Each finding has keys: binary, full_path, severity, type, commands.
    When a normalized candidate matched, matched_as is also included.
    Severity rules:
      CRITICAL — GTFOBins commands found, OR binary in a non-standard path.
      HIGH     — binary in a standard path, not in GTFOBins, not in _KNOWN_SAFE.
      INFO     — all others (well-known safe binaries with no GTFOBins entry).
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
                commands = _replace_binary(cmds, candidate, full_path)
                break

        binary_name  = os.path.basename(full_path)
        non_standard = any(full_path.startswith(p) for p in _NON_STANDARD_PREFIXES)
        in_standard  = any(full_path.startswith(p) for p in _STANDARD_PREFIXES)
        is_known_safe = binary_name in _KNOWN_SAFE

        note: Optional[str] = None
        fallback = [f"{full_path} -p", full_path]

        if non_standard:
            # Any SUID binary in a non-standard path is always CRITICAL.
            commands = fallback + commands
            severity = "CRITICAL"
        elif commands:
            severity = "CRITICAL"
        elif in_standard and not is_known_safe:
            # Unknown binary in a standard path — flag for manual investigation.
            severity = "HIGH"
            note = _UNKNOWN_SUID_NOTE
            commands = [
                f"# {_UNKNOWN_SUID_NOTE}",
                f"strings {full_path}  # look for relative command calls without full path",
                f"ltrace {full_path} 2>/dev/null | head -20  # trace library/system calls",
            ]
        else:
            severity = "INFO"

        finding: Dict = {
            "binary": binary_name,
            "full_path": full_path,
            "severity": severity,
            "type": "suid",
            "commands": commands,
        }
        if matched_as is not None:
            finding["matched_as"] = matched_as
        if non_standard:
            finding["non_standard"] = True
        if note is not None:
            finding["note"] = note

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
