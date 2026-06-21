# ReadPEAS - CLAUDE.md

## About
ReadPEAS is an offline Python tool that parses LinPEAS/WinPEAS output
and provides ready-to-use privesc commands for CTF players.
Rule-based, no AI, installable via pip.

## Hard rules
- NEVER run git commit, git push, or git add
- NEVER push anything to GitHub in any way
- Work with local files only
- All code, comments, output, and docs must be in English

## Token saving
- Run /init at the start of each session to load CLAUDE.md
- Run /compact after each module is complete
- Use /model to switch to claude-haiku-4-5 for simple tasks
- When context is full: /clear then --resume to continue
- Use Plan Mode (Shift+Tab) to confirm plan before writing code

## Phase plan
- Phase 1 (done): core + Linux critical (sudo, suid, capabilities)
- Phase 2 (done): Linux high (cron, writable passwd, PATH hijack, groups, ld_preload, nfs, etc.)
- Phase 3: Windows (WinPEAS)
- Phase 4 (partial): Polish — markdown export done; pip package pending

## Code standards
- Python 3.8+ compatible
- No external dependencies for Phase 1 (stdlib only)
- Each module must be independently testable
- Use type hints
- Docstrings: one sentence, English
- All variable names, comments, print output in English

## GTFOBins database format
binary_name -> sudo: [command1, command2]
binary_name -> suid: [command1]
binary_name -> capabilities: [command1]

## Severity order
CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO

## Current status
- [x] scripts/build_gtfobins.py
- [x] core/parser.py                  — sub-header (╚═══╣) stripping added
- [x] core/extractor.py
- [x] modules/linux/sudo.py
- [x] modules/linux/suid.py           — _KNOWN_SAFE set; unknown standard-path SUID → HIGH with note
- [x] modules/linux/capabilities.py
- [x] modules/linux/cron.py
- [x] modules/linux/writable_passwd.py
- [x] modules/linux/writable_cron.py  — skips "Contents of" headers to prevent false positives
- [x] modules/linux/path_hijack.py
- [x] modules/linux/groups.py
- [x] modules/linux/pythonpath.py
- [x] modules/linux/ld_preload.py     — TRY FIRST is gcc one-liner; files renamed to shell.c/shell.so
- [x] modules/linux/nfs.py
- [x] modules/linux/systemd_service.py
- [x] modules/linux/logrotate.py
- [x] modules/linux/mysql_udf.py
- [x] modules/linux/docker_sock.py
- [x] modules/linux/credentials.py    — reuse hint comment lines appended to commands
- [x] modules/linux/wildcard_injection.py  — tar * in cron scripts → HIGH; checkpoint exploit
- [x] output/terminal.py              — --ip/--port LHOST/LPORT substitution; suid note rendering
- [x] readpeas.py (CLI)               — --ip, --port flags; -o markdown export
