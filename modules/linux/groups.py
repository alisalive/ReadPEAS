"""Detect dangerous group memberships from LinPEAS output."""

import re
from typing import List, Dict

# Matches the standard 'id' output: groups=1000(user),116(lxd),998(docker)
_ID_GROUPS_RE = re.compile(r"groups=([^\s]+)", re.IGNORECASE)

# Matches a named group inside the groups= field: 116(lxd)
_GROUP_NAME_RE = re.compile(r"\d+\(([^)]+)\)")

# Matches "Current user groups: docker lxd disk" style
_CURRENT_GROUPS_RE = re.compile(r"current\s+user\s+groups\s*:\s*(.+)", re.IGNORECASE)

# Severity order for sorting
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

DANGEROUS_GROUPS: Dict[str, Dict] = {
    # docker → handled by modules/linux/docker_group.py (detailed exploit)
    # lxd    → handled by modules/linux/lxd_group.py   (detailed exploit)
    "disk": {
        "severity": "CRITICAL",
        "description": "Disk group allows reading raw disk - full filesystem access",
        "commands": [
            "df -h  # find the main disk device (e.g. /dev/sda1)",
            "debugfs /dev/sda1",
            "cat /etc/shadow  # inside debugfs prompt",
            "cat /root/.ssh/id_rsa  # inside debugfs prompt",
        ],
    },
    "shadow": {
        "severity": "CRITICAL",
        "description": "Shadow group can read /etc/shadow - crack root hash",
        "commands": [
            "cat /etc/shadow",
            "john /etc/shadow --wordlist=/usr/share/wordlists/rockyou.txt",
            "# Or: hashcat -m 1800 hash.txt /usr/share/wordlists/rockyou.txt",
        ],
    },
    "adm": {
        "severity": "HIGH",
        "description": "adm group can read system logs - may contain passwords",
        "commands": [
            "grep -r 'password\\|passwd\\|secret' /var/log/ 2>/dev/null",
            "cat /var/log/auth.log | grep -i 'password'",
        ],
    },
    "video": {
        "severity": "MEDIUM",
        "description": "Video group can capture screen content",
        "commands": [
            "cat /dev/fb0 > /tmp/screen.raw (framebuffer screenshot)",
        ],
    },
}


def parse_groups_section(section_text: str) -> List[str]:
    """Extract current user's group names from LinPEAS output."""
    groups: List[str] = []
    seen: set = set()

    def _add(name: str) -> None:
        name = name.strip()
        if name and name not in seen:
            seen.add(name)
            groups.append(name)

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # "uid=1000(user) gid=1000(user) groups=1000(user),116(lxd),998(docker)"
        m = _ID_GROUPS_RE.search(line)
        if m:
            for name in _GROUP_NAME_RE.findall(m.group(1)):
                _add(name)
            continue

        # "Current user groups: docker lxd disk"
        m = _CURRENT_GROUPS_RE.search(line)
        if m:
            for name in m.group(1).split():
                _add(name)

    return groups


def analyze(section_text: str) -> List[Dict]:
    """Parse LinPEAS output and return findings for dangerous group memberships."""
    user_groups = parse_groups_section(section_text)

    findings: List[Dict] = []
    for group in user_groups:
        info = DANGEROUS_GROUPS.get(group)
        if info is None:
            continue
        findings.append({
            "group": group,
            "severity": info["severity"],
            "type": "group",
            "description": info["description"],
            "commands": info["commands"],
        })

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99))
    return findings


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SAMPLE = """
# Current user context:
uid=1000(user) gid=1000(user) groups=1000(user),116(lxd),998(docker),4(adm),6(disk)
"""

    print("=== parse_groups_section ===")
    grps = parse_groups_section(SAMPLE)
    for g in grps:
        print(g)

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    for f in findings:
        print(f"[{f['severity']}] {f['group']} ({f['type']}): {f['description']}")
        for cmd in f["commands"]:
            print(f"  {cmd}")
        print()
