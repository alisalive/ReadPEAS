"""Extract credentials/passwords found by LinPEAS in various sections."""

import re
from typing import Dict, List, Optional, Tuple

# ── Password extraction patterns ──────────────────────────────────────────────
# Each pattern must have exactly one capture group: the password value.

_PATTERNS: List[Tuple[str, re.Pattern]] = [
    # password = value  /  password: value  (generic)
    ("generic",     re.compile(r"\bpassw(?:or)?d\s*[=:]\s*['\"]?([^\s'\"#;,]{3,})['\"]?", re.IGNORECASE)),
    # DB_PASSWORD=value  /  DB_PASS=value
    ("db_env",      re.compile(r"\bDB_PASS(?:WORD)?\s*[=:]\s*['\"]?([^\s'\"#;,]{3,})['\"]?", re.IGNORECASE)),
    # PHP define('DB_PASSWORD', 'value')  or  define("DB_PASS", "value")
    ("php_define",  re.compile(r"define\s*\(\s*['\"](?:DB_)?PASS(?:WORD)?['\"],\s*['\"]([^'\"]{3,})['\"]", re.IGNORECASE)),
    # mysql -u user -pPASSWORD  (password immediately after -p with no space)
    ("mysql_cli",   re.compile(r"\bmysql\b.*?-p([A-Za-z0-9!@#$%^&*()\-_+={}\[\]]{3,})")),
    # SECRET_KEY = value  /  API_KEY: value
    ("secret_key",  re.compile(r"\b(?:SECRET|API)_(?:KEY|TOKEN)\s*[=:]\s*['\"]?([^\s'\"#;,]{6,})['\"]?", re.IGNORECASE)),
    # Ansible Vault hash: $ANSIBLE_VAULT;1.1;AES256
    ("ansible_vault", re.compile(r"(\$ANSIBLE_VAULT;[\d.]+;AES\d+)")),
]

# Cloud credential file paths that indicate exposed credentials.
_CLOUD_CRED_RE = re.compile(
    r"(/[^\s]+(?:\.aws/credentials|\.config/gcloud/[^\s]*))",
    re.IGNORECASE,
)

# Values to reject (common placeholders, empty strings, single-word non-secrets)
_PLACEHOLDER_VALUES = {
    "password", "passwd", "pass", "changeme", "change_me", "secret",
    "your_password", "your-password", "your_pass", "example", "placeholder",
    "xxx", "yyy", "zzz", "none", "null", "true", "false", "undefined",
    "1", "0", "yes", "no", "test", "demo", "sample", "foobar", "foo", "bar",
    "admin", "root", "user", "login", "password123", "123456", "qwerty",
    "default", "empty", "blank", "notset", "n/a", "na",
}

# Lines to skip entirely (documentation, URLs, shell prompts)
_SKIP_LINE_RE = re.compile(
    r"^\s*(?:#|//|;|https?://|\$\s+|echo\s+|cat\s+|grep\s+)",
    re.IGNORECASE,
)


def _is_placeholder(value: str) -> bool:
    """Return True if the value looks like a placeholder rather than a real credential."""
    stripped = value.strip("'\"").lower()
    if not stripped or len(stripped) < 3:
        return True
    if stripped in _PLACEHOLDER_VALUES:
        return True
    # Pure numeric short values (e.g. "0", "1", "42") are not passwords
    if stripped.isdigit() and len(stripped) < 5:
        return True
    # Looks like a variable reference: ${VAR} or $VAR
    if stripped.startswith("$") or stripped.startswith("<"):
        return True
    return False


def _shorten(line: str, maxlen: int = 60) -> str:
    """Return a truncated version of a line for display as context."""
    line = line.strip()
    return line[:maxlen] + "..." if len(line) > maxlen else line


def parse_credentials_section(section_text: str) -> List[Tuple[str, str]]:
    """Extract (password_value, context_snippet) pairs from LinPEAS section text.

    Deduplicates by password value; skips placeholders and blank values.
    Also detects Ansible Vault hashes and cloud credential file paths.
    """
    results: List[Tuple[str, str]] = []
    seen_passwords: set = set()

    for raw_line in section_text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _SKIP_LINE_RE.match(line):
            continue

        # Cloud credential file paths (bypass placeholder filter)
        cloud_m = _CLOUD_CRED_RE.search(line)
        if cloud_m:
            value = cloud_m.group(1)
            if value not in seen_passwords:
                seen_passwords.add(value)
                results.append((value, _shorten(line)))

        for _label, pattern in _PATTERNS:
            for m in pattern.finditer(line):
                value = m.group(1).strip("'\"")
                # Ansible vault hashes bypass the placeholder filter
                if not value.startswith("$ANSIBLE_VAULT;") and _is_placeholder(value):
                    continue
                if value in seen_passwords:
                    continue
                seen_passwords.add(value)
                context = _shorten(line)
                results.append((value, context))

    return results


def generate_commands(password: str) -> List[str]:
    """Generate credential reuse commands for a found password."""
    if password.startswith("$ANSIBLE_VAULT;"):
        return [
            f"# Ansible Vault encrypted secret found:",
            "# Save the vault content to vault.txt then crack:",
            "ansible2john vault.txt > hash.txt",
            "john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt",
            f"# Try credential reuse: su - <user>  |  password: {password}",
            f"# Or: ssh <user>@LHOST  with above password",
        ]
    return [
        f"su root  # try password: {password}",
        f"su $(whoami)  # try password: {password}",
        f"ssh root@localhost  # try password: {password}",
        f"ssh $(whoami)@localhost  # try password: {password}",
        f"# Try credential reuse: su - <user>  |  password: {password}",
        f"# Or: ssh <user>@LHOST  with above password",
    ]


def analyze(section_text: str) -> List[Dict]:
    """Analyze LinPEAS output sections for exposed credentials.

    Returns a HIGH finding for each unique non-placeholder password found.
    """
    findings: List[Dict] = []
    for password, context in parse_credentials_section(section_text):
        findings.append({
            "password": password,
            "context": context,
            "severity": "HIGH",
            "type": "credential",
            "commands": generate_commands(password),
        })
    return findings


# ── CLI self-test ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
╔══════════╣ Analyzing Http conf Files (limit 70)
/etc/apache2/sites-enabled/app.conf:
DB_PASSWORD=supersecret
password = secret123
api_key = ignored_because_too_short

╔══════════╣ Searching *password* or *credential* files in home (limit 70)
/home/ctf/.bash_history:mysql -u root -psecret123
/home/ctf/.bash_history:mysql -u root -pbackup_db_pass

╔══════════╣ Analyzing Backup Manager Files
$backup_password = "backup_hunter2"
define('DB_PASSWORD', 'wppassword99');

# This should be skipped (placeholder):
password = changeme
password = password
"""

    print("=== parse_credentials_section ===")
    creds = parse_credentials_section(SAMPLE)
    for pw, ctx in creds:
        print(f"  password={pw!r}  context={ctx!r}")

    print("\n=== analyze ===")
    for finding in analyze(SAMPLE):
        cmds = finding["commands"]
        print(
            f"[{finding['severity']}] {finding['type']} -> {finding['password']!r}"
            f"  ({finding['context']})  ({len(cmds)} cmd(s))"
        )
        print(f"  TRY FIRST: $ {cmds[0]}")
