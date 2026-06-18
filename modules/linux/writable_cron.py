"""Cross-reference cron jobs with confirmed writable paths to find exploitable cron scripts."""

import re
from typing import Dict, List, Set

from modules.linux.cron import parse_cron_section, generate_commands

# Matches any absolute path token (stops at whitespace or shell metacharacters)
_ABS_PATH_RE = re.compile(r"(/[^\s;|&><'\"\\]+)")

# Matches a cron schedule line: 5 time fields or @keyword (e.g. @reboot)
# Used to exclude cron job lines from writable-path extraction.
_CRON_LINE_RE = re.compile(r"^(?:[\d*/,\-]+\s+){4}[\d*/,\-]|^\s*@\w+")


def parse_writable_paths(section_text: str) -> Set[str]:
    """Extract confirmed-writable absolute paths from LinPEAS writable-files section text.

    Skips cron schedule lines so that command paths inside cron entries are not
    mistakenly treated as confirmed-writable paths.
    """
    paths: Set[str] = set()
    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        # Skip cron schedule lines (they appear in combined text alongside writable lines)
        if _CRON_LINE_RE.match(line):
            continue
        for m in _ABS_PATH_RE.finditer(line):
            path = m.group(1).rstrip(".,;:)")
            if path:
                paths.add(path)
    return paths


def analyze(section_text: str) -> List[Dict]:
    """Return CRITICAL/HIGH findings for cron scripts confirmed writable by LinPEAS.

    Requires combined cron + writable-files section text (supplied by extractor).
    Only flags scripts where LinPEAS explicitly listed the path as writable —
    stricter than cron.py which guesses writability from non-standard path prefixes.
    """
    jobs = parse_cron_section(section_text)
    writable = parse_writable_paths(section_text)

    findings: List[Dict] = []
    seen: Set[str] = set()

    for job in jobs:
        script = job["command"].split()[0]
        if not script.startswith("/"):
            continue
        if script not in writable:
            continue
        if script in seen:
            continue
        seen.add(script)

        # Root-run + confirmed writable = CRITICAL (direct root code execution)
        severity = "CRITICAL" if job["user"] == "root" else "HIGH"
        findings.append({
            "script": script,
            "schedule": job["schedule"],
            "run_as": job["user"],
            "severity": severity,
            "type": "writable_cron",
            "commands": generate_commands(script),
        })

    return findings


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SAMPLE = """
* * * * * root /etc/scripts/clean_up.sh
*/5 * * * * www-data /var/scripts/cleanup.py
* * * * * root /usr/bin/logrotate

/etc/scripts/clean_up.sh
/var/scripts/cleanup.py
/home/user/notes.txt
"""

    print("=== parse_writable_paths ===")
    paths = parse_writable_paths(SAMPLE)
    for p in sorted(paths):
        print(f"  {p}")

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    if not findings:
        print("  No findings.")
    for f in findings:
        print(f"[{f['severity']}] {f['script']} (run_as={f['run_as']}, type={f['type']})")
        for cmd in f["commands"]:
            print(f"  $ {cmd}")
