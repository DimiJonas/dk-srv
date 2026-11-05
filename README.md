# dk-srv

The scripts that harden, watch and run my small Ubuntu server (a rented VPS) – the server behind
[Storybook](https://github.com/DimiJonas/storybook), a private photo journal, and a static home page.
Hardened by the CIS Benchmarks, measured with Ubuntu's own audit tool, and explained mechanism by
mechanism so that each one can be understood, checked and undone.

| Measurement (CIS Ubuntu 24.04 Level 1 Server, Ubuntu Pro's USG) | Score |
|---|---|
| Before the hardening | **72.2 %** |
| After, all rules | **92.4 %** |
| After, without the 13 risks accepted on purpose (each with its reason) | **100 %** |

- **[`SECURITY.md`](SECURITY.md)** – the scorecard: every CIS area for Ubuntu, nginx and
  PostgreSQL, what's done, what doesn't apply, the accepted risks and why
- **[`HARDENING.md`](HARDENING.md)** – every mechanism explained: what, why, where it lives, how to
  see it for yourself, how to undo it – and the lessons from the first rounds (what went wrong)
- [`setup-commands.txt`](setup-commands.txt) – a fresh server, step by step
- [`maintenance-commands.txt`](maintenance-commands.txt) – everyday commands, emergencies
- [`ROADMAP.md`](ROADMAP.md) – how it got here, and what's next

## What it does

**Hardening** ([`hardening/install-hardening.sh`](hardening/install-hardening.sh), in parts, each with
`--dry-run`; every changed file backed up)
- SSH with keys only, one user, strong algorithms only; PAM lockout and password rules
- a firewall for incoming **and outgoing** traffic; kernel network and memory hardening; no core
  dumps; rare filesystems, protocols and USB storage blocked
- auditd with the CIS rules (Level 2), locked until the next restart
- AIDE file integrity: every night, every change sorted into *explained* (package updates, changes
  made on purpose), *sensitive* (→ urgent phone notification) and *other*
- PostgreSQL by the CIS PostgreSQL benchmark (connection logging, pgAudit, least privilege)
- nginx: no answer for the bare IP address or unknown names, TLS 1.2/1.3 with AEAD ciphers only,
  connection and timeout limits, hardened static sites

**Watching**
- a nightly **security check**: known vulnerabilities (Ubuntu Pro `pro cves`, the apps' npm
  dependencies, Node.js releases) – installs fixes, and for what can't be fixed yet switches an app
  to its **maintenance page** or the whole web server into **lockdown**; and a **drift check**:
  is every hardening setting still in place?
- **phone notifications** (ntfy) for every SSH connection (by kind: terminal, file transfer, backup
  pull), banned attackers, unexplained file changes, security findings – and a weekly report

**Running apps and sites – without trusting them**
- everything root runs comes from **root-owned** places; an app's user can change the app, never
  what root runs
- an app registers itself with one settings file (`/etc/dk-srv/apps.d/<app>.conf`, parsed, never
  run); its root parts come from a root-owned partial clone of just its `ops/root/` folder
  (`dk-app-update`: shows what changed, asks, installs)
- static sites from their own repositories (`dk-site-update`): every file checked by its content,
  picture metadata removed, root-owned, served without scripts

## Layout

| Path | What |
|---|---|
| [`install.sh`](install.sh) | installs the commands, cron, log rotation, the SSH-login notification, fail2ban |
| [`bin/`](bin/) | the `dk-*` commands (copied to `/usr/local/sbin`) |
| [`lib/`](lib/) | shared functions: settings, apps and sites, the drift check, nginx changes with undo |
| [`hardening/`](hardening/) | the CIS hardening in parts, the tailoring for the audit, a fact sheet for reviews |
| [`nginx/`](nginx/) | the server-wide nginx part and the static-site template |
| [`fail2ban/`](fail2ban/) | scanner and rate-limit jails, with notifications |
| [`etc/`](etc/) | examples of the settings files (the real ones live only on the server) |
| [`migrate/`](migrate/) | the one-time move from the storybook repository's scripts |

On the server: `/opt/dk-srv` (this repository, owned by root), `/etc/dk-srv/` (settings – the ntfy
topic and the read token only there), `/var/lib/dk-srv/` (memory), `/var/log/dk-srv/` (logs).

Nothing in this repository belongs to one server: no domains, no addresses, no topic, no keys.
Examples use `example.org`. Written in bash and a little Python, for Ubuntu 24.04 LTS; tested with
shellcheck and in a sandbox before every deploy.

## Status

In daily use on one server. Next step: each app's backend as its own user (`ROADMAP.md`).

© All rights reserved. The code is public to read; there is no license for reuse.
