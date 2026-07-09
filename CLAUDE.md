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
- Phase 4 (done): Polish — markdown export, pip package (console entry point, positional
  file arg, `-f` deprecated alias), data/gtfobins.json packaged in built wheels, LICENSE
  (MIT), GitHub Actions CI (.github/workflows/tests.yml)

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
- [x] core/priority.py                — severity + module-priority ranking for default/--top output modes
- [x] core/dedup.py
- [x] modules/linux/ (27 modules)     — sudo, suid, capabilities, cron, writable_cron,
  writable_cron_d, writable_passwd, writable_exec_script, path_hijack, groups, pythonpath,
  ld_preload, nfs, systemd_service, logrotate, mysql_udf, docker_sock, docker_group,
  lxd_group, credentials, wildcard_injection, motd_writable, service_binary, ssh_keys,
  screen_exploit, tmux_socket, kernel_exploit
  (kernel_exploit.py: DirtyPipe/DirtyCow/PwnKit/Baron Samedit, curated CVEs only;
  sudo.py includes CVE-2019-14287 `sudo -u#-1` NOPASSWD bypass detection)
- [x] output/terminal.py              — --ip/--port LHOST/LPORT substitution; suid note
  rendering; default/--tldr/--top/--all output modes
- [x] readpeas.py (CLI)               — positional `file` arg (primary), `-f`/`--file` kept
  as deprecated alias; --ip, --port, --only, -o (terminal/json/markdown), --tldr, --top,
  --all, --version
- [x] pip packaging                   — pyproject.toml, `readpeas` console entry point,
  data/gtfobins.json bundled in built wheels (data/ is an included package with
  package-data = ["*.json"]), verified via `python3 -m build` + clean-venv wheel install
- [x] LICENSE                         — MIT, present at repo root
- [x] .github/workflows/tests.yml     — CI running pytest on Python 3.8 and 3.12
- Pytest: 260 tests passing (verify with `pytest tests/ -v`)
