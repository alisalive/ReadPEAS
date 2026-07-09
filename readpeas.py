"""ReadPEAS — CLI entry point for parsing LinPEAS/WinPEAS output."""

import argparse
import json
import os
import sys
from typing import Dict, List, Optional

from core.extractor import extract
from output.terminal import print_results, print_default, print_tldr, print_top

_VERSION = "0.1.0"

_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _finding_md_title(f: Dict) -> str:
    """Return a Markdown heading title for a finding."""
    ftype = f.get("type", "")
    if ftype in ("sudo", "suid", "capabilities"):
        binary    = f.get("binary", "")
        full_path = f.get("full_path", "")
        title = f"{ftype} — {binary} ({full_path})"
        caps = f.get("caps")
        if caps:
            title += f" [{caps}]"
        return title
    elif ftype in ("cron", "writable_cron"):
        script   = f.get("script", "")
        schedule = f.get("schedule", "")
        run_as   = f.get("run_as", "")
        return f"{ftype} — {script} (every: {schedule}, run_as: {run_as})"
    elif ftype == "writable_file":
        return f"{ftype} — {f.get('file', '')}"
    elif ftype == "ld_preload":
        env_var  = f.get("env_var", "")
        sudo_cmd = f.get("sudo_command", "")
        return f"{ftype} — {env_var} (via: {sudo_cmd})"
    elif ftype == "nfs":
        return f"{ftype} — {f.get('export_path', '')} (no_root_squash)"
    elif ftype == "path_hijack":
        return f"{ftype} — {f.get('writable_dir', '')}"
    elif ftype == "group":
        return f"{ftype} — {f.get('group', '')}  {f.get('description', '')}"
    elif ftype == "credential":
        pw = f.get("password", "")
        return f"{ftype} — {pw!r}"
    elif ftype == "wildcard_injection":
        script = f.get("script", "")
        return f"{ftype} — {script} (tar wildcard in cron)"
    elif ftype == "systemd_service":
        return f"{ftype} — {f.get('service_path', '')}"
    elif ftype == "logrotate":
        return f"{ftype} — {f.get('log_path', '')} (logrotten)"
    elif ftype == "mysql_udf":
        return f"{ftype} — mysqld running as root (UDF injection)"
    elif ftype == "docker_sock":
        return f"{ftype} — /var/run/docker.sock (writable)"
    elif ftype == "motd_writable":
        return f"{ftype} — {f.get('motd_path', '')} (runs as root on SSH login)"
    elif ftype == "lxd_group":
        return f"{ftype} — {f.get('description', '')}"
    elif ftype == "docker_group":
        return f"{ftype} — {f.get('description', '')}"
    elif ftype == "tmux_socket":
        return f"{ftype} — {f.get('socket_path', '')} (root tmux socket)"
    elif ftype == "service_binary":
        return f"{ftype} — {f.get('binary_path', '')} (writable service binary)"
    elif ftype == "ssh_keys":
        enc = f.get("encrypted")
        enc_str = "unencrypted" if enc is False else ("encrypted" if enc else "unknown encryption")
        return f"{ftype} — {f.get('key_path', '')} ({enc_str})"
    elif ftype == "screen_exploit":
        return f"{ftype} — {f.get('binary_path', '')} (EDB-41154)"
    elif ftype == "writable_cron_d":
        return f"{ftype} — {f.get('cron_path', '')} (writable cron.d file)"
    elif ftype == "writable_exec_script":
        return f"{ftype} — {f.get('script_path', '')} (group-writable executable script)"
    elif ftype == "sudo_not_root_bypass":
        binary    = f.get("binary", "")
        full_path = f.get("full_path", "")
        return f"{ftype} — {binary} ({full_path}) [{f.get('cve', '')}]"
    elif ftype == "kernel_exploit":
        return f"{ftype} — {f.get('name', '')} ({f.get('cve', '')})"
    else:
        return f"{ftype} — {f.get('full_path', f.get('file', ''))}"


def _write_markdown(result: Dict, input_file: Optional[str]) -> None:
    """Write findings to a Markdown report file."""
    file_name = os.path.basename(input_file) if input_file else "stdin"
    md_name   = os.path.splitext(file_name)[0] + ".md"

    lines: List[str] = []
    lines.append("# ReadPEAS Report")
    lines.append(
        f"**File:** {file_name}  **OS:** {result.get('os', 'unknown')}"
        f"  **Total:** {result.get('total', 0)} findings"
    )
    lines.append("")

    by_severity: Dict[str, list] = {s: [] for s in _SEVERITY_ORDER}
    for f in result.get("findings", []):
        sev = f.get("severity", "INFO")
        if sev in by_severity:
            by_severity[sev].append(f)

    for sev in _SEVERITY_ORDER:
        grp = by_severity[sev]
        if not grp:
            continue
        lines.append(f"## {sev}")
        lines.append("")
        for f in grp:
            title = _finding_md_title(f)
            lines.append(f"### {title}")
            cmds = f.get("commands", [])
            if cmds:
                lines.append("**Commands:**")
                lines.append("```")
                for cmd in cmds:
                    lines.append(cmd)
                lines.append("```")
            else:
                lines.append("*No exploit commands found.*")
            lines.append("")

    with open(md_name, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print(f"Saved: {md_name}")


def _read_input(file_path):
    """Read raw text from file (utf-8, fallback to latin-1) or return None."""
    try:
        with open(file_path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(file_path, encoding="latin-1") as fh:
            return fh.read()


def main():
    parser = argparse.ArgumentParser(
        prog="readpeas",
        usage="readpeas <file> [--ip IP] [--port PORT] [--tldr | --top | --all]",
        description=(
            "Parse LinPEAS/WinPEAS output and show privesc commands.\n\n"
            "Output modes (terminal, in order of precedence):\n"
            "  (default)  show ONLY the single best paste-ready privesc command\n"
            "  --tldr     print ONLY that command (or steps), nothing else\n"
            "  --top      print up to 3 best paste-ready findings, compact\n"
            "  --all      show every finding, fully decorated (old default behavior)"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("file", nargs="?", metavar="FILE", help="path to LinPEAS/WinPEAS output file")
    parser.add_argument(
        "-f", "--file", dest="file_flag", metavar="FILE",
        help="alternate way to pass the file (deprecated, use the positional argument instead)",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FORMAT",
        choices=["terminal", "json", "markdown"],
        default="terminal",
        help="output format: terminal (default), json, or markdown",
    )
    parser.add_argument(
        "--only",
        metavar="SEVERITY",
        help="filter findings by severity: critical, high, info",
    )
    parser.add_argument("--ip", metavar="IP", help="attacker IP (replaces LHOST in all commands)")
    parser.add_argument(
        "--port",
        metavar="PORT",
        type=int,
        default=4444,
        help="attacker port (replaces LPORT in all commands, default 4444)",
    )
    parser.add_argument(
        "--all", action="store_true",
        help="show every finding with full decoration (old default terminal behavior)",
    )
    parser.add_argument(
        "--tldr", action="store_true",
        help="print ONLY the single best paste-ready command(s), nothing else",
    )
    parser.add_argument(
        "--top", action="store_true",
        help="print up to 3 best paste-ready findings, compact",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_VERSION}")

    args = parser.parse_args()

    # ── Input ──────────────────────────────────────────────────────────────────
    filepath = args.file or args.file_flag

    if filepath:
        if not os.path.isfile(filepath):
            sys.stderr.write(f"error: file not found: {filepath}\n")
            sys.exit(1)
        raw_text = _read_input(filepath)
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
    else:
        parser.print_usage(sys.stderr)
        sys.stderr.write("error: provide a file path, -f FILE, or pipe input via stdin\n")
        sys.exit(1)

    # ── Process ────────────────────────────────────────────────────────────────
    result = extract(raw_text)

    if result.get("error") and result.get("total", 0) == 0:
        sys.stderr.write(f"[!] {result['error']}\n")
        sys.exit(1)

    # ── Output ─────────────────────────────────────────────────────────────────
    if args.output == "json":
        print(json.dumps(result, indent=2))
    elif args.output == "markdown":
        _write_markdown(result, filepath)
    elif args.tldr:
        print_tldr(result, ip=args.ip, port=args.port)
    elif args.top:
        print_top(result, ip=args.ip, port=args.port)
    elif args.all:
        print_results(result, only_severity=args.only, ip=args.ip, port=args.port)
    else:
        print_default(result, ip=args.ip, port=args.port)


if __name__ == "__main__":
    main()
