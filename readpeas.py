"""ReadPEAS — CLI entry point for parsing LinPEAS/WinPEAS output."""

import argparse
import json
import sys

from core.extractor import extract
from output.terminal import print_results

_VERSION = "0.1.0"


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
        description="Parse LinPEAS/WinPEAS output and show privesc commands.",
    )
    parser.add_argument("-f", "--file", metavar="FILE", help="path to LinPEAS/WinPEAS output file")
    parser.add_argument(
        "-o", "--output",
        metavar="FORMAT",
        choices=["terminal", "json"],
        default="terminal",
        help="output format: terminal (default) or json",
    )
    parser.add_argument(
        "--only",
        metavar="SEVERITY",
        help="filter findings by severity: critical, high, info",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {_VERSION}")

    args = parser.parse_args()

    # ── Input ──────────────────────────────────────────────────────────────────
    if args.file:
        raw_text = _read_input(args.file)
    elif not sys.stdin.isatty():
        raw_text = sys.stdin.read()
    else:
        parser.print_usage(sys.stderr)
        sys.stderr.write("error: provide -f FILE or pipe input via stdin\n")
        sys.exit(1)

    # ── Process ────────────────────────────────────────────────────────────────
    result = extract(raw_text)

    if result.get("error") and result.get("total", 0) == 0:
        sys.stderr.write(f"[!] {result['error']}\n")
        sys.exit(1)

    # ── Output ─────────────────────────────────────────────────────────────────
    if args.output == "json":
        print(json.dumps(result, indent=2))
    else:
        print_results(result, only_severity=args.only)


if __name__ == "__main__":
    main()
