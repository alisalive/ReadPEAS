"""Regression tests: verify expected finding counts and severities for all sample files."""

import os
import pytest

from core.extractor import extract

# Each entry: (filename, expected_total, has_critical)
_SAMPLES = [
    ("vulnbox.txt",      34, True),
    ("overpass3.txt",    15, True),
    ("watcher.txt",      13, True),
    ("dogcat.txt",        9, True),
    ("plotted.txt",       8, True),
    ("rootme.txt",       10, True),
    ("lazyadmin.txt",     6, True),
    ("simplectf.txt",     5, True),
    ("anonymous.txt",     9, True),
    ("startup.txt",       7, True),
    ("brooklyn99.txt",    5, True),
    ("bountyhacker.txt",  6, True),
    ("internal.txt",      8, True),
    ("skynet.txt",        9, False),
    ("gamingserver.txt",  9, True),
    ("ohmywebserver.txt", 6, True),
    ("road.txt",          7, True),
    ("chillhack.txt",     6, True),
    ("kenobi.txt",        9, False),
]

_SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def _load(filename: str) -> str:
    path = os.path.join(_SAMPLES_DIR, filename)
    try:
        with open(path, encoding="utf-8") as fh:
            return fh.read()
    except UnicodeDecodeError:
        with open(path, encoding="latin-1") as fh:
            return fh.read()


@pytest.mark.parametrize("filename,expected_total,has_critical", _SAMPLES)
def test_finding_count(filename, expected_total, has_critical):
    raw = _load(filename)
    result = extract(raw)
    assert result["total"] == expected_total, (
        f"{filename}: expected {expected_total} findings, got {result['total']}"
    )


@pytest.mark.parametrize("filename,expected_total,has_critical", _SAMPLES)
def test_has_critical_finding(filename, expected_total, has_critical):
    raw = _load(filename)
    result = extract(raw)
    severities = {f["severity"] for f in result["findings"]}
    if has_critical:
        assert "CRITICAL" in severities, (
            f"{filename}: expected at least one CRITICAL finding"
        )


@pytest.mark.parametrize("filename,expected_total,has_critical", _SAMPLES)
def test_findings_sorted_by_severity(filename, expected_total, has_critical):
    _ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    raw = _load(filename)
    result = extract(raw)
    severities = [_ORDER.get(f["severity"], 99) for f in result["findings"]]
    assert severities == sorted(severities), (
        f"{filename}: findings are not sorted by severity"
    )
