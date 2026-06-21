"""Cross-reference cron jobs with confirmed writable paths to find exploitable cron scripts."""

import re
from typing import Dict, List, Set, Tuple

from modules.linux.cron import parse_cron_section, generate_commands

# Matches any absolute path token (stops at whitespace or shell metacharacters)
_ABS_PATH_RE = re.compile(r"(/[^\s;|&><'\"\\]+)")

# Matches a cron schedule line: 5 time fields or @keyword (e.g. @reboot)
# Used to exclude cron job lines from writable-path extraction.
_CRON_LINE_RE = re.compile(r"^(?:[\d*/,\-]+\s+){4}[\d*/,\-]|^\s*@\w+")

# Matches an ls -l permission string at the start of a line
_PERM_LINE_RE = re.compile(r"^([-dlbcsp](?:[r-][w-][xsStT-]){3})")

# "Contents of /path/file:" lines show file contents — not writable-file indicators
_CONTENTS_HEADER_RE = re.compile(r"^Contents of /", re.IGNORECASE)


def _is_perm_writable(perm: str) -> bool:
    """Return True if the ls -l permission string has group-write or other-write."""
    # group-write is index 5, other-write is index 8
    return len(perm) >= 10 and (perm[5] == "w" or perm[8] == "w")


def _is_executable(perm: str) -> bool:
    """Return True if the ls -l permission string has any execute bit set."""
    # owner-exec index 3, group-exec index 6, other-exec index 9
    return len(perm) >= 10 and (perm[3] in "xs" or perm[6] in "xs" or perm[9] in "xt")


def parse_writable_paths(section_text: str) -> Tuple[Set[str], Set[str]]:
    """Extract writable absolute paths from LinPEAS section text.

    Returns (confirmed, cron_path):
      confirmed:      bare paths (explicitly listed as writable by LinPEAS) plus
                      writable non-executable ls -l paths.
      cron_path:      writable AND executable paths from ls -l lines
                      (from 'Writable scripts in cron path' sections).
                      Only files confirmed writable by permission bits are included.

    Skips cron schedule lines to avoid treating cron command paths as writable.
    Skips ls -l lines where the permission string shows the file is NOT writable.
    """
    confirmed: Set[str] = set()
    cron_path: Set[str] = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _CRON_LINE_RE.match(line):
            continue
        if _CONTENTS_HEADER_RE.match(line):
            continue
        # Skip shebang lines and script content lines (from "Contents of" blocks)
        if line.startswith("#!") or line.startswith("cd ") or line.startswith("SHELL=") or line.startswith("PATH="):
            continue

        perm_m = _PERM_LINE_RE.match(line)
        if perm_m:
            perm = perm_m.group(1)
            if not _is_perm_writable(perm):
                continue  # Not group/other-writable — skip
            for m in _ABS_PATH_RE.finditer(line):
                path = m.group(1).rstrip(".,;:)")
                if path:
                    if _is_executable(perm):
                        cron_path.add(path)
                    else:
                        confirmed.add(path)
        else:
            # Bare path line from an explicit writable-files section
            for m in _ABS_PATH_RE.finditer(line):
                path = m.group(1).rstrip(".,;:)")
                if path:
                    confirmed.add(path)

    return confirmed, cron_path


def analyze(section_text: str) -> List[Dict]:
    """Return CRITICAL/HIGH findings for cron scripts confirmed writable by LinPEAS.

    Requires combined cron + writable-files section text (supplied by extractor).
    Two categories of findings:
      1. Scripts directly called by cron AND confirmed writable → CRITICAL (root) / HIGH.
      2. Writable executable scripts in cron PATH not directly in cron → HIGH (indirect).
    """
    jobs = parse_cron_section(section_text)
    confirmed, cron_path = parse_writable_paths(section_text)
    all_writable = confirmed | cron_path

    findings: List[Dict] = []
    seen: Set[str] = set()
    cron_scripts: Set[str] = set()

    for job in jobs:
        script = job["command"].split()[0]
        if not script.startswith("/"):
            continue
        cron_scripts.add(script)
        if script not in all_writable:
            continue
        if script in seen:
            continue
        seen.add(script)

        severity = "CRITICAL" if job["user"] == "root" else "HIGH"
        findings.append({
            "script": script,
            "schedule": job["schedule"],
            "run_as": job["user"],
            "severity": severity,
            "type": "writable_cron",
            "commands": generate_commands(script),
        })

    # Report writable executable scripts in cron PATH not directly called by cron
    for script in sorted(cron_path - cron_scripts - seen):
        seen.add(script)
        findings.append({
            "script": script,
            "schedule": "(cron PATH)",
            "run_as": "indirect",
            "severity": "HIGH",
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

-rwxrwxr-x 1 root staff 512 Jan 1 /etc/scripts/clean_up.sh
-rwxr-xr-x 1 root root  256 Jan 1 /usr/local/bin/not_writable.sh
-rwxrwxr-x 1 root staff 128 Jan 1 /usr/local/sbin/side_script.sh

/var/scripts/cleanup.py
/home/user/notes.txt
"""

    print("=== parse_writable_paths ===")
    conf, cp = parse_writable_paths(SAMPLE)
    print(f"  confirmed:  {sorted(conf)}")
    print(f"  cron_path:  {sorted(cp)}")

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    if not findings:
        print("  No findings.")
    for f in findings:
        print(f"[{f['severity']}] {f['script']} (run_as={f['run_as']}, type={f['type']})")
        for cmd in f["commands"]:
            print(f"  $ {cmd}")
