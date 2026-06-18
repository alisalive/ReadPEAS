"""Extract and prioritize privilege escalation findings from LinPEAS/WinPEAS output."""

from typing import Dict, List

from core.parser import parse
from modules.linux.sudo import analyze as analyze_sudo
from modules.linux.suid import analyze as analyze_suid
from modules.linux.capabilities import analyze as analyze_capabilities
from modules.linux.cron import analyze as analyze_cron
from modules.linux.writable_passwd import analyze as analyze_writable
from modules.linux.path_hijack import analyze as analyze_path
from modules.linux.groups import analyze as analyze_groups
from modules.linux.writable_cron import analyze as analyze_writable_cron

# Maps each analyzer to the LinPEAS section name keywords it handles.
SECTION_MAP = [
    (analyze_sudo,          ["sudo", "sudoers"]),
    (analyze_suid,          ["suid", "sgid"]),
    (analyze_capabilities,  ["capabilities", "getcap"]),
    (analyze_cron,          ["cron", "cronjob", "crontab"]),
    (analyze_writable,      ["writable", "interesting files", "file permissions"]),
    (analyze_writable_cron, ["cron", "cronjob", "crontab", "writable", "interesting files"]),
    (analyze_path,          ["path", "environment"]),
    (analyze_groups,        ["groups", "current user", "uid="]),
]

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def extract(raw_text: str) -> Dict:
    """Parse raw LinPEAS/WinPEAS output and return sorted privilege escalation findings."""
    parsed = parse(raw_text)
    os_name: str = parsed["os"]
    sections: Dict[str, str] = parsed["sections"]

    if os_name != "linux":
        return {
            "os": os_name,
            "total": 0,
            "findings": [],
            "error": "Only Linux supported currently",
        }

    findings: List[Dict] = []

    for analyzer, keywords in SECTION_MAP:
        # Collect all sections whose name contains any keyword, then analyze combined.
        matched_chunks = [
            content for section_name, content in sections.items()
            if any(kw in section_name.lower() for kw in keywords)
        ]
        if matched_chunks:
            findings.extend(analyzer("\n".join(matched_chunks)))

    findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.get("severity", "INFO"), 4))

    return {
        "os": os_name,
        "total": len(findings),
        "findings": findings,
    }


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Synthetic LinPEAS snippet covering all three module types.
    SAMPLE = """\
╔══════════╣ Sudo version
sudo version 1.9.5

╔══════════╣ Checking sudo permissions
Matching Defaults entries for ctf:
    env_reset, mail_badpass

User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /usr/bin/notabin

╔══════════╣ SUID - Check easy privesc, exploits and write perms
-rwsr-xr-x 1 root root 166056 Jan 19 2024 /usr/bin/find
-rwsr-xr-x 1 root root  22912 Mar 23 2022 /usr/bin/notabin2

╔══════════╣ Capabilities
/usr/bin/python3.9 = cap_setuid+ep
/usr/bin/ping = cap_net_raw+ep
/usr/bin/openssl = cap_net_bind_service+ep
"""

    result = extract(SAMPLE)
    print(f"OS      : {result['os']}")
    print(f"Total   : {result['total']}")
    print()
    for f in result["findings"]:
        cmds = f.get("commands", [])
        matched = f.get("matched_as", f.get("binary", ""))
        caps_info = f"  caps={f['caps']}" if "caps" in f else ""
        print(
            f"[{f['severity']}] [{f['type']}] {f['full_path']}{caps_info}"
            f"  (matched_as={matched!r}, {len(cmds)} cmd(s))"
        )
        for cmd in cmds[:2]:
            print(f"    $ {cmd}")
        if len(cmds) > 2:
            print(f"    ... and {len(cmds) - 2} more")
