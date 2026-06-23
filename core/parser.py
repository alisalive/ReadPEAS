"""Parse raw LinPEAS/WinPEAS output into labeled sections."""

import re
import sys
from typing import Dict

# ── ANSI escape codes ────────────────────────────────────────────────────────
# Covers color/style codes (ESC[...m), cursor moves, and other sequences.
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]|\x1b[@-_][0-?]*[ -/]*[@-~]")


def strip_ansi(text: str) -> str:
    """Remove all ANSI escape sequences from text."""
    return _ANSI_RE.sub("", text)


# ── OS detection ─────────────────────────────────────────────────────────────
_LINUX_KEYWORDS = re.compile(
    r"linpeas|linux privilege escalation|linux local privilege",
    re.IGNORECASE,
)
_WINDOWS_KEYWORDS = re.compile(
    r"winpeas|windows privilege escalation|windows local privilege",
    re.IGNORECASE,
)


def detect_os(text: str) -> str:
    """Return 'linux' or 'windows' based on LinPEAS/WinPEAS header keywords."""
    # Only scan the first 4 KB — the banner is always near the top.
    header = text[:4096]
    if _WINDOWS_KEYWORDS.search(header):
        return "windows"
    return "linux"  # default; LinPEAS is far more common


# ── Section splitting ─────────────────────────────────────────────────────────
# LinPEAS uses two header formats (after ANSI stripping):
#
#   Narrow sub-section (most common in practice):
#     ╔══════════╣ Section Name
#
#   Wide chapter header (wraps sub-sections in full LinPEAS runs):
#     ╔═══════════════════╣ Chapter Name ╠═══════════════════╗
#
# Both are treated as section boundaries.  For wide headers the trailing
# ╠═══…═══╗ is stripped so the captured name is clean.
#
# Sub-section reference-link lines (╚ https://…) are plain content — they
# do NOT start with ╚[═]+╣, so they are never treated as boundaries.
#
# Unicode codepoints:  ╔ = U+2554  ╚ = U+255A  ═ = U+2550  ╣ = U+2563  ╠ = U+2560
_SECTION_RE = re.compile(
    r"^[╔]?[═]+╣[ \t]*(.+?)[ \t]*(?=[ \t]*╠|$)",
    re.MULTILINE,
)

# Matches ╚══════════╣ … sub-section header lines (NOT start-of-section markers)
_SUB_SECTION_RE = re.compile(
    r"^╚[═]+╣[ \t]*.+$\n?",
    re.MULTILINE,
)


def split_sections(text: str) -> Dict[str, str]:
    """Split LinPEAS output into {section_name: content} pairs.

    Both narrow sub-section headers (╔══════════╣ Name) and wide chapter
    headers (╔═════════════╣ Name ╠═════════════╗) are treated as section
    boundaries.  For wide headers the trailing ╠═══╗ is stripped from the
    captured name.  Reference-link lines (╚ https://…) are kept as content.
    """
    sections: Dict[str, str] = {}
    matches = list(_SECTION_RE.finditer(text))

    if not matches:
        return sections

    for i, match in enumerate(matches):
        name = match.group(1).strip()
        content_start = match.end()
        content_end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        content = text[content_start:content_end]
        # Strip ╚══════════╣ sub-section header lines while keeping their content.
        content = _SUB_SECTION_RE.sub("", content).strip()
        # When multiple headers share the same name, append rather than overwrite.
        if name in sections:
            sections[name] = sections[name] + "\n" + content
        else:
            sections[name] = content

    return sections


# ── Main entry point ──────────────────────────────────────────────────────────

def parse(text: str) -> Dict:
    """Parse raw LinPEAS/WinPEAS output and return a structured dict.

    Returns:
        {
            "os": "linux" | "windows",
            "sections": {"Section Name": "content", ...}
        }
    """
    clean = strip_ansi(text)
    return {
        "os": detect_os(clean),
        "sections": split_sections(clean),
    }


# ── CLI self-test ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python parser.py <linpeas_output.txt>")
        sys.exit(1)

    with open(sys.argv[1], encoding="utf-8", errors="replace") as fh:
        raw = fh.read()

    result = parse(raw)
    print(f"Detected OS : {result['os']}")
    print(f"Sections found ({len(result['sections'])}):")
    for name in result["sections"]:
        preview = result["sections"][name][:60].replace("\n", " ")
        print(f"  [{name}]  {preview!r}")
