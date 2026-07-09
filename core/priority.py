"""Compute the single best paste-ready privesc command per finding.

Each module's ``commands`` list mixes investigation hints, comments, and
alternative one-liners in different shapes. This module inspects the
``type`` of a finding and extracts a ``primary_command`` (a short list of
genuinely paste-ready commands) plus ``other_commands`` (everything else,
shown only in --all mode).

A finding with an empty ``primary_command`` is not eligible to be selected
as "the single best" finding for default/--tldr/--top rendering, but it is
still shown in --all mode using its original ``commands`` field.
"""

from typing import Dict, List, Optional, Tuple

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Severities eligible for selection (INFO is never shown as "the best finding").
_ELIGIBLE_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM")

# Explicit tie-break order: earlier entries win when severity is equal.
MODULE_PRIORITY: List[str] = [
    "sudo", "sudo_not_root_bypass", "suid", "capabilities", "kernel_exploit",
    "writable_exec_script", "writable_cron",
    "cron", "writable_cron_d", "motd_writable", "lxd_group", "docker_group",
    "docker_sock", "screen_exploit", "nfs", "systemd_service", "logrotate",
    "mysql_udf", "service_binary", "ld_preload", "pythonpath", "ssh_keys",
    "wildcard_injection", "tmux_socket", "credentials", "writable_file",
    "group", "path_hijack",
]

# Types whose primary command is simply the first entry in `commands`
# (alternative one-liners; only one needs to run).
_FIRST = {
    "sudo", "cron", "writable_cron", "ld_preload",
    "writable_cron_d", "motd_writable", "docker_group",
}

# Types where `commands` may start with a label/comment before the real one-liner.
_FIRST_NONCOMMENT = {"capabilities", "docker_sock"}

# Types where `commands` is a single complete sequential exploit with no comments.
_LEADING_STOP_AT_COMMENT = {"nfs", "mysql_udf"}

# Types where the real exploit is `commands[:k]` (up to first comment) PLUS
# a final command that appears right after that comment (e.g. a restart step).
_LEADING_PLUS_TRAILING = {"systemd_service", "logrotate", "service_binary"}

# Types where every comment line is just noise — keep everything else, in order.
_SEQUENCE_FILTER_COMMENTS = {
    "credentials", "wildcard_injection", "ssh_keys", "screen_exploit",
    "sudo_not_root_bypass", "kernel_exploit",
}

# Types where the real commands are the contiguous non-comment run right after
# the first comment line (label comment, then real steps, then trailing comment).
_RUN_AFTER_FIRST_COMMENT = {"lxd_group", "writable_exec_script"}

# Types with no genuinely one-shot paste-ready primary command.
_NONE_INELIGIBLE = {"path_hijack", "group"}

# Placeholder tokens that mean "you must fill this in manually" — any command
# containing one of these is dropped from the primary command list.
_PLACEHOLDER_TOKENS = (
    "PASTE_HASH_HERE", "<service-name>", "TARGET_BINARY",
    "<ID>", "<user>", "<target>",
)


def _is_comment(cmd: str) -> bool:
    """Return True if the command string is a comment/hint line, not a real command."""
    return cmd.strip().startswith("#")


def _first_noncomment(commands: List[str]) -> List[str]:
    """Return the first non-comment command as a singleton list, or [] if none."""
    for cmd in commands:
        if not _is_comment(cmd):
            return [cmd]
    return []


def _leading_until_comment(commands: List[str]) -> List[str]:
    """Return the leading run of non-comment commands, stopping at the first comment."""
    result: List[str] = []
    for cmd in commands:
        if _is_comment(cmd):
            break
        result.append(cmd)
    return result


def _sequence_filter_comments(commands: List[str]) -> List[str]:
    """Return all commands with comment lines removed, preserving order."""
    return [cmd for cmd in commands if not _is_comment(cmd)]


def _run_after_first_comment(commands: List[str]) -> List[str]:
    """Return the contiguous non-comment run immediately following the first comment."""
    idx: Optional[int] = None
    for i, cmd in enumerate(commands):
        if _is_comment(cmd):
            idx = i
            break
    if idx is None:
        return []
    result: List[str] = []
    for cmd in commands[idx + 1:]:
        if _is_comment(cmd):
            break
        result.append(cmd)
    return result


def _strip_placeholders(commands: List[str]) -> List[str]:
    """Remove commands that contain a manual-fill-in placeholder token."""
    return [c for c in commands if not any(tok in c for tok in _PLACEHOLDER_TOKENS)]


def get_primary_commands(finding: Dict) -> List[str]:
    """Return the genuinely paste-ready primary command(s) for a finding, or [] if none."""
    ftype = finding.get("type", "")
    commands = finding.get("commands", [])
    if not commands:
        return []

    if ftype in _FIRST:
        result = [commands[0]]
    elif ftype in _FIRST_NONCOMMENT:
        result = _first_noncomment(commands)
    elif ftype == "suid":
        result = [] if _is_comment(commands[0]) else [commands[0]]
    elif ftype in _LEADING_STOP_AT_COMMENT:
        result = _leading_until_comment(commands)
    elif ftype in _LEADING_PLUS_TRAILING:
        result = _leading_until_comment(commands) + _run_after_first_comment(commands)
    elif ftype in _SEQUENCE_FILTER_COMMENTS:
        result = _sequence_filter_comments(commands)
    elif ftype in _RUN_AFTER_FIRST_COMMENT:
        result = _run_after_first_comment(commands)
    elif ftype == "pythonpath":
        result = commands[1:] if len(commands) > 1 else []
    elif ftype == "tmux_socket":
        result = [commands[1]] if len(commands) > 1 else []
    elif ftype == "writable_file":
        file_path = finding.get("file", "")
        if file_path == "/etc/passwd":
            result = commands[:2] if len(commands) >= 2 else []
        elif file_path == "/etc/shadow":
            result = []  # requires manually pasting a generated hash between steps
        else:
            result = list(commands)  # sudoers, crontab: fully paste-ready as-is
    elif ftype in _NONE_INELIGIBLE:
        result = []
    else:
        result = []

    return _strip_placeholders(result)


def attach_primary_commands(findings: List[Dict]) -> List[Dict]:
    """Mutate each finding to add `primary_command` and `other_commands` keys."""
    for finding in findings:
        primary = get_primary_commands(finding)
        finding["primary_command"] = primary
        original = finding.get("commands", [])
        if primary:
            finding["other_commands"] = [c for c in original if c not in primary]
        else:
            finding["other_commands"] = list(original)
    return findings


def _module_rank(ftype: str) -> int:
    """Return the tie-break rank for a finding type (lower = higher priority)."""
    try:
        return MODULE_PRIORITY.index(ftype)
    except ValueError:
        return len(MODULE_PRIORITY)


def _sort_key(finding: Dict) -> Tuple[int, int]:
    severity = finding.get("severity", "INFO")
    return (_SEVERITY_ORDER.get(severity, 4), _module_rank(finding.get("type", "")))


def select_best(findings: List[Dict]) -> Tuple[Optional[Dict], bool]:
    """Return (best_finding, manual_only) for default/--tldr rendering.

    manual_only is True when no genuinely paste-ready finding exists but an
    investigation-only (CRITICAL/HIGH/MEDIUM with commands but no primary)
    finding does.
    """
    eligible = [
        f for f in findings
        if f.get("severity") in _ELIGIBLE_SEVERITIES and f.get("primary_command")
    ]
    if eligible:
        eligible.sort(key=_sort_key)
        return eligible[0], False

    manual = [
        f for f in findings
        if f.get("severity") in _ELIGIBLE_SEVERITIES and f.get("commands")
    ]
    if manual:
        manual.sort(key=_sort_key)
        return manual[0], True

    return None, False


def select_top(findings: List[Dict], n: int = 3) -> List[Dict]:
    """Return up to n distinct paste-ready findings, ranked by severity then module priority."""
    eligible = [
        f for f in findings
        if f.get("severity") in _ELIGIBLE_SEVERITIES and f.get("primary_command")
    ]
    eligible.sort(key=_sort_key)
    return eligible[:n]
