#!/usr/bin/env python3
"""Clone GTFOBins repo, parse YAML, and write data/gtfobins.json.

New GTFOBins format (2024+):
  - Files in _gtfobins/ are extensionless (e.g. "vim", "bash").
  - Each file is a YAML document (--- ... delimiters).
  - Structure: functions -> <type> -> list of items, each with:
      code: |-          (base command)
      contexts:
        sudo:           (null = base code applies)
        suid:
          code: |-      (optional override for this context)
        capabilities:
          code: |-
          list: [CAP_SETUID, ...]
        unprivileged:
  Only sudo, suid, and capabilities contexts are extracted.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Optional

GTFOBINS_REPO = "https://github.com/GTFOBins/GTFOBins.github.io"
TARGET_TYPES = {"sudo", "suid", "capabilities"}
# Only collect commands from these function types; file-read/network/etc. are not privesc.
RELEVANT_FUNCTION_TYPES = {"shell", "command", "inherit"}
OUTPUT_FILE = Path(__file__).parent.parent / "data" / "gtfobins.json"


# ---------------------------------------------------------------------------
# Git helpers
# ---------------------------------------------------------------------------

def clone_repo(dest: Path) -> None:
    """Clone the GTFOBins repository (shallow) into dest."""
    print(f"Cloning {GTFOBINS_REPO} ...")
    result = subprocess.run(
        ["git", "clone", "--depth=1", GTFOBINS_REPO, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"ERROR: git clone failed:\n{result.stderr}", file=sys.stderr)
        sys.exit(1)
    print("Clone complete.")


# ---------------------------------------------------------------------------
# YAML parsing
# ---------------------------------------------------------------------------

def extract_yaml(text: str) -> Optional[str]:
    """Return the YAML body from a GTFOBins file, or None if not found.

    Handles both '--- ... ---' front matter and '--- ... ...' documents.
    """
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i, line in enumerate(lines[1:], start=1):
        if line.strip() in ("---", "..."):
            return "\n".join(lines[1:i])
    # No closing marker: treat entire file (after opening ---) as YAML
    return "\n".join(lines[1:])


def _save_ctx(
    current_ctx: Optional[str],
    collecting: bool,
    code_lines: List[str],
    overrides: Dict[str, Optional[str]],
) -> None:
    """Flush accumulated context-specific code into overrides (in-place)."""
    if current_ctx in TARGET_TYPES and collecting and code_lines:
        code = "\n".join(code_lines).strip()
        if code:
            overrides[current_ctx] = code


def parse_yaml(yaml_text: str) -> Dict[str, List[str]]:
    """Parse a GTFOBins YAML body and return {context_type: [commands]}.

    State machine tracking indentation levels:
      indent 0  : top-level keys (functions:, comment:, ...)
      indent 2  : function type keys (shell:, sudo:, ...) and list items (- )
      indent 4  : item-level fields (code:, contexts:, comment:, sender:, ...)
      indent 6  : base code content  |  context keys (sudo:, suid:, ...)
      indent 8  : context sub-fields (code:, list:, shell:, ...)
      indent 10+: context-specific code content
    """
    result: Dict[str, List[str]] = {}
    lines = yaml_text.splitlines()

    in_functions: bool = False
    item_active: bool = False

    # Base code for the current item
    base_code: List[str] = []
    collecting_base: bool = False

    # Contexts for the current item
    in_contexts: bool = False
    current_ctx: Optional[str] = None
    ctx_overrides: Dict[str, Optional[str]] = {}  # ctx -> None (use base) or override
    ctx_code: List[str] = []
    collecting_ctx: bool = False

    # Function type tracking (shell, file-read, command, ...)
    current_function_type: str = ""  # most recently seen function type header
    item_function_type: str = ""     # function type of the currently active item

    def emit_item() -> None:
        """Emit commands from the completed item into result, then reset."""
        nonlocal base_code, collecting_base
        nonlocal in_contexts, current_ctx, ctx_overrides, ctx_code, collecting_ctx
        nonlocal item_function_type

        # Flush any pending context code
        _save_ctx(current_ctx, collecting_ctx, ctx_code, ctx_overrides)

        base = "\n".join(base_code).strip()
        # Only emit commands from relevant function types (shell/command give privesc shells).
        if item_function_type in RELEVANT_FUNCTION_TYPES:
            for ctx, override in ctx_overrides.items():
                if ctx in TARGET_TYPES:
                    cmd = override if override is not None else base
                    if cmd:
                        result.setdefault(ctx, []).append(cmd)

        # Reset all per-item state
        base_code = []
        collecting_base = False
        in_contexts = False
        current_ctx = None
        ctx_overrides = {}
        ctx_code = []
        collecting_ctx = False
        item_function_type = ""

    for line in lines:
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" ")) if stripped else -1

        # ── Phase: locate functions: ───────────────────────────────────────
        if not in_functions:
            if stripped == "functions:":
                in_functions = True
            continue

        # Exit functions block on any top-level key
        if indent == 0 and stripped:
            break

        # ── Function type header at indent 2 (e.g. "  shell:", "  file-read:") ───
        if indent == 2 and not stripped.startswith("- "):
            current_function_type = stripped.rstrip(":")
            continue

        # ── New list item at indent 2 ──────────────────────────────────────
        # Lines like "  - code: |-" or "  - binary: false"
        if indent == 2 and stripped.startswith("- "):
            if item_active:
                emit_item()
            item_active = True
            item_function_type = current_function_type  # record this item's type
            rest = stripped[2:]  # drop the "- " prefix
            if re.match(r"code:\s*\|", rest):
                collecting_base = True
            continue

        if not item_active:
            continue

        # ── Still collecting base code (content at indent 6+) ─────────────
        if collecting_base:
            if indent >= 6:
                base_code.append(line[6:])
                continue
            collecting_base = False  # indent dropped → block ended; fall through

        # ── Item-level fields at indent 4 ─────────────────────────────────
        if indent == 4:
            if in_contexts:
                # Leaving contexts block: flush any pending context code
                _save_ctx(current_ctx, collecting_ctx, ctx_code, ctx_overrides)
                ctx_code = []
                collecting_ctx = False
                in_contexts = False
                current_ctx = None

            if stripped == "contexts:":
                in_contexts = True
            elif re.match(r"code:\s*\|", stripped):
                collecting_base = True
            continue

        # ── Inside contexts block ──────────────────────────────────────────
        if not in_contexts:
            continue

        # Context keys at indent 6  (e.g. "      sudo:")
        if indent == 6 and stripped:
            # Flush code accumulated for the previous context
            _save_ctx(current_ctx, collecting_ctx, ctx_code, ctx_overrides)
            ctx_code = []
            collecting_ctx = False

            if stripped.endswith(":"):
                current_ctx = stripped[:-1]
                if current_ctx in TARGET_TYPES:
                    ctx_overrides[current_ctx] = None  # default: use base code
            else:
                current_ctx = None
            continue

        # Context sub-fields at indent 8  (code:, list:, shell:, ...)
        if indent == 8 and current_ctx:
            if re.match(r"code:\s*\|", stripped):
                # Save any code collected before this (shouldn't happen normally)
                _save_ctx(current_ctx, collecting_ctx, ctx_code, ctx_overrides)
                ctx_code = []
                collecting_ctx = True
            elif collecting_ctx and ctx_code:
                # Non-code field encountered while collecting → save and stop
                _save_ctx(current_ctx, collecting_ctx, ctx_code, ctx_overrides)
                ctx_code = []
                collecting_ctx = False
            else:
                collecting_ctx = False
            continue

        # Context-specific code content at indent 10+
        if indent >= 10 and current_ctx and collecting_ctx:
            ctx_code.append(line[10:])
            continue

    if item_active:
        emit_item()

    return result


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

def process_file(file_path: Path) -> Optional[tuple]:
    """Return (binary_name, commands_dict) from a GTFOBins file, or None."""
    try:
        text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        print(f"WARNING: cannot read {file_path}: {exc}", file=sys.stderr)
        return None

    yaml_body = extract_yaml(text)
    if not yaml_body:
        return None

    commands = parse_yaml(yaml_body)
    if not commands:
        return None

    # Stem works for both "vim" (no ext) and "vim.md" (old format)
    return file_path.stem, commands


def build_database(gtfobins_dir: Path) -> Dict[str, Dict[str, List[str]]]:
    """Parse all binary files in gtfobins_dir and return the combined database."""
    db: Dict[str, Dict[str, List[str]]] = {}

    # Support old (.md) and new (extensionless) formats
    files = sorted(
        f for f in gtfobins_dir.iterdir()
        if f.is_file() and f.suffix in ("", ".md")
    )
    print(f"Parsing {len(files)} files ...")

    skipped = 0
    for file_path in files:
        result = process_file(file_path)
        if result is None:
            skipped += 1
            continue
        name, commands = result
        db[name] = commands

    if skipped:
        print(f"  (skipped {skipped} files with no relevant data)")
    return db


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Clone GTFOBins, parse YAML, and write data/gtfobins.json."""
    with tempfile.TemporaryDirectory() as tmpdir:
        repo_path = Path(tmpdir) / "GTFOBins"
        clone_repo(repo_path)

        gtfobins_dir = repo_path / "_gtfobins"
        if not gtfobins_dir.is_dir():
            print("ERROR: _gtfobins/ directory not found in cloned repo.", file=sys.stderr)
            sys.exit(1)

        db = build_database(gtfobins_dir)

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(db, fh, indent=2, sort_keys=True)
        fh.write("\n")

    print(f"Saved {len(db)} binaries to {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
