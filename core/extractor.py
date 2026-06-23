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
from modules.linux.pythonpath import analyze as analyze_pythonpath
from modules.linux.ld_preload import analyze as analyze_ld_preload
from modules.linux.nfs import analyze as analyze_nfs
from modules.linux.systemd_service import analyze as analyze_systemd
from modules.linux.logrotate import analyze as analyze_logrotate
from modules.linux.mysql_udf import analyze as analyze_mysql_udf
from modules.linux.docker_sock import analyze as analyze_docker_sock
from modules.linux.credentials import analyze as analyze_credentials
from modules.linux.wildcard_injection import analyze as analyze_wildcard
from modules.linux.motd_writable import analyze as analyze_motd_writable
from modules.linux.lxd_group import analyze as analyze_lxd_group
from modules.linux.docker_group import analyze as analyze_docker_group
from modules.linux.tmux_socket import analyze as analyze_tmux_socket
from modules.linux.service_binary import analyze as analyze_service_binary
from modules.linux.ssh_keys import analyze as analyze_ssh_keys
from modules.linux.screen_exploit import analyze as analyze_screen_exploit
from modules.linux.writable_cron_d import analyze as analyze_writable_cron_d
from modules.linux.writable_exec_script import analyze as analyze_writable_exec

# Maps each analyzer to the LinPEAS section name keywords it handles.
# Keywords are matched case-insensitively as substrings of the section name.
# Multiple modules may receive the same section; each filters internally.
# Keywords cover both manually-crafted test samples AND real LinPEAS output
# (which may use wider chapter names or slightly different sub-section labels).
SECTION_MAP = [
    (analyze_sudo,            ["sudo", "sudoers"]),
    (analyze_suid,            ["suid"]),
    (analyze_capabilities,    ["capabilities", "getcap"]),
    (analyze_cron,            ["cron", "cronjob", "crontab"]),
    (analyze_writable,        ["writable", "interesting files", "file permissions", "passwd"]),
    (analyze_writable_cron,   ["cron", "cronjob", "crontab", "writable", "interesting files"]),
    (analyze_path,            ["path", "environment"]),
    (analyze_groups,          ["groups", "current user", "uid=", "group", "my user"]),
    (analyze_pythonpath,      ["sudo", "sudoers", "python"]),
    (analyze_ld_preload,      ["sudo", "sudoers", "ld.so", "preload"]),
    (analyze_nfs,             ["nfs", "exports", "no_root_squash", "mount"]),
    (analyze_systemd,         ["init", "systemd", "rc.d", "interesting files", "writable", "timer"]),
    (analyze_logrotate,       ["logrotten", "writable log", "logrotate"]),
    (analyze_mysql_udf,       ["processes", "mysql", "software", "interesting processes", "sql"]),
    (analyze_docker_sock,     ["unix sockets", "sockets", "interesting files", "writable", "docker", "container"]),
    (analyze_credentials,     ["password", "credential", "backup", "wordpress", "http conf", "analyzing", "history", "interesting file", "ssh"]),
    (analyze_wildcard,        ["cron", "cronjob", "crontab"]),
    (analyze_motd_writable,   ["group writable", "interesting writable", "update-motd", "writable", "group"]),
    (analyze_lxd_group,       ["groups", "current user", "interesting groups", "group", "my user"]),
    (analyze_docker_group,    ["groups", "current user", "interesting groups", "group", "my user"]),
    (analyze_tmux_socket,     ["processes", "running processes", "interesting processes", "interesting writable", "writable", "process"]),
    (analyze_service_binary,  ["analyzing .service", "service file", "systemd", "service"]),
    (analyze_ssh_keys,        ["private ssh", "ssh key", "analyzing ssh", "ssh", "key"]),
    (analyze_screen_exploit,  ["suid"]),
    (analyze_writable_cron_d, ["writable", "cron", "interesting files"]),
    (analyze_writable_exec,   ["group writable", "executable files", "added by user", "writable", "executable", "group"]),
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

    # Suppress sudo finding when a pythonpath CRITICAL/HIGH covers the same binary
    # (the SETENV rule restricts python to a specific script, so GTFOBins commands don't apply).
    pythonpath_binaries = {
        f["full_path"] for f in findings if f.get("type") == "pythonpath"
    }
    if pythonpath_binaries:
        findings = [
            f for f in findings
            if not (f.get("type") == "sudo" and f.get("full_path") in pythonpath_binaries)
        ]

    # Suppress cron finding if a writable_cron finding exists for the same script.
    writable_cron_scripts = {
        f["script"] for f in findings
        if f.get("type") == "writable_cron"
    }
    if writable_cron_scripts:
        findings = [
            f for f in findings
            if not (
                f.get("type") == "cron"
                and f.get("script", "").split()[0] in writable_cron_scripts
            )
        ]

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
