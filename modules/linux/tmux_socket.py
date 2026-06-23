"""Detect accessible root tmux sockets from LinPEAS process output."""

import re
from typing import Dict, List

# Matches root tmux process lines with -S /socket/path.
# The captured group must start with '/' to avoid matching -s session-name (lowercase).
_TMUX_ROOT_RE = re.compile(
    r"root\s+\d+.*?tmux\S*\s+.*?-S\s+(/\S+)",
    re.IGNORECASE,
)

# Keywords that suggest a path is writable/accessible
_WRITABLE_KEYWORDS = ("writable", "srwxrwx", "srw-rw-", "srwrw", "rw-rw-")


def parse_tmux_section(section_text: str) -> List[Dict]:
    """Extract root tmux socket paths and check if they appear writable."""
    sockets: Dict[str, bool] = {}

    for m in _TMUX_ROOT_RE.finditer(section_text):
        socket_path = m.group(1)
        if socket_path not in sockets:
            sockets[socket_path] = False

    # Cross-reference: check if socket path appears in a writable context
    for socket_path in list(sockets.keys()):
        pat = re.compile(re.escape(socket_path))
        for occ in pat.finditer(section_text):
            start = max(0, occ.start() - 30)
            ctx = section_text[start : occ.end() + 60].lower()
            if any(kw in ctx for kw in _WRITABLE_KEYWORDS):
                sockets[socket_path] = True
                break

    return [{"socket_path": k, "writable": v} for k, v in sockets.items()]


def generate_commands(socket_path: str) -> List[str]:
    """Generate tmux socket attach commands."""
    return [
        f"ls -la {socket_path}  # verify permissions",
        f"tmux -S {socket_path} attach -t 0",
        "# You land directly in root's running shell",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for accessible root tmux sockets.

    Returns CRITICAL if socket is confirmed writable, HIGH otherwise.
    """
    findings: List[Dict] = []
    for entry in parse_tmux_section(section_text):
        socket_path = entry["socket_path"]
        severity = "CRITICAL" if entry["writable"] else "HIGH"
        findings.append({
            "socket_path": socket_path,
            "severity": severity,
            "type": "tmux_socket",
            "description": "root tmux session with accessible socket",
            "commands": generate_commands(socket_path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
root       956  0.0  tmux new-session -s main -d -S /.devs/dev_sess
Writable: /.devs/dev_sess
"""
    print("=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['socket_path']}  ({f['description']})")
        for cmd in f["commands"]:
            print(f"  $ {cmd}")
