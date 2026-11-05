# dk-srv – Roadmap

| #   | Step                                                                               | Size | Depends on |
| --- | ---------------------------------------------------------------------------------- | ---- | ---------- |
| –   | ✅ Before dk-srv: security check, notifications, modes (storybook step 13)          | M    | –          |
| –   | ✅ Before dk-srv: hardening by the CIS guides (storybook step 15 and its follow-up) | M–L  | –          |
| 1   | ✅ Own repository: the server's scripts out of the storybook                        | M    | –          |
| 2   | Each app's backend as its own user (the storybook's first)                         | M    | 1          |
| –   | Later: own AppArmor profiles for nginx, PostgreSQL, Node.js (A6)                   | M    | –          |
| –   | Later: logs and notifications also off the server (A9)                             | S–M  | –          |
| –   | Later: CIS Ubuntu 24.04 v2.0.0, as soon as USG implements it (A11)                 | S    | –          |

---

## Before dk-srv (in the storybook repository)

The server's scripts grew inside the storybook's repository; their history is there
([ROADMAP.md](https://github.com/DimiJonas/storybook/blob/main/ROADMAP.md), steps 13 and 15).
In short:

- **Step 13 – security check, notifications, modes**: a nightly check of known vulnerabilities
  (Ubuntu's `pro cves`, npm audit, Node.js releases) that installs fixes, switches the app to a
  maintenance page for a critical hole in its libraries, or the whole web server off ("lockdown")
  for one in nginx/OpenSSL without a fix; phone notifications (ntfy) for SSH logins, bans, findings;
  a weekly report.
- **Step 15 – hardening by the guides**: CIS Ubuntu 24.04 Level 1 Server (plus chosen Level 2 rules),
  CIS NGINX, CIS PostgreSQL 16, measured with Ubuntu Pro's USG: **72.2 %** before (2026-11-02),
  **84.7 %** after the first deploy (2026-11-03), **92.4 %** after the follow-up (2026-11-05) – and
  **100 %** of the rules that apply here (the accepted risks, A1–A13, switched off in a tailoring
  file with a reason each). What went wrong on the way is in [HARDENING.md](HARDENING.md), "Lessons".

---

## 1. Own repository ✅

The storybook repository held three things that change for different reasons: the app, the
server's hardening, and a private page (the main domain's picture). Split into three:

| Repository | What | Visibility |
|---|---|---|
| `storybook` | the app; its root parts in `ops/root/` | public |
| `dk-srv` | everything that secures the server | public |
| `dk-home` | the main domain's static page and its picture | private |

**Decided:**

- prefix `dk-` for everything of the server: commands `dk-*`, `/etc/dk-srv`, `/var/lib/dk-srv`,
  `/var/log/dk-srv`, file names `…-dk-srv…` (the hardening renames its files from `…storybook…` and
  removes the old ones; `migrate/from-storybook.sh` moves the settings, memory and logs once)
- **only root can change what root runs**: dk-srv is a root-owned clone (`/opt/dk-srv`); before,
  root ran scripts from the app user's clone
- **the apps plug in** through `/etc/dk-srv/apps.d/<app>.conf` (`KEY=value`, parsed, never run):
  user, folders, address, npm folders, mode command, nginx sites, AIDE exclusions and sensitive
  places, backup logs, databases. The nightly check, the weekly report, the file integrity check,
  `dk-mode` and the hardening parts (auditd, aide, postgres) loop over the apps
- an app's root parts live in its `ops/root/` folder; **`dk-app-update <app>`** keeps a root-owned
  partial clone of just that folder (`git clone --filter=blob:none --no-checkout`, then
  `sparse-checkout set --no-cone /ops/root/`), shows the new commits and what changed, asks, then
  runs its `install.sh`
- an app's **mode command** (maintenance/normal/stop/start/status) is the app's; dk-srv keeps only
  the lockdown (`dk-mode`), which stops every app through its mode command
- **static sites** from their own repositories, the same workflow as the apps (push, then pull on
  the server): `/etc/dk-srv/sites.d/<name>.conf` and **`dk-site-update <name>`** – a root-owned
  clone, every file checked by its content, picture metadata removed, the folder swapped at once
- private repositories over https with a **fine-grained read-only token** (root-only file; its
  expiry in the weekly report); outgoing SSH stays closed once no clone uses it
- nothing server-specific in any repository (domains, topic, token); examples use `example.org`
- dk-srv public, no license (all rights reserved), like the storybook

**Built:** `install.sh`, `bin/dk-{notify,mode,security-check,weekly-report,ssh-notify,aide-check,
app-update,site-update}`, `lib/` (shared functions, nginx planning with undo), `nginx/` (the
server-wide part), `hardening/` (moved, renamed), `fail2ban/`, `migrate/from-storybook.sh`, the
documents ([HARDENING.md](HARDENING.md), [SECURITY.md](SECURITY.md), the command files).

**Measured after the move:** to do – both audits once more (the tailoring file is now
`/etc/dk-srv/usg-tailoring.xml`); nothing about the settings changed, only names and places.

---

## 2. Each app's backend as its own user

Today the storybook's backend runs as `appuser` – the same account that logs in by SSH and has
sudo. A hole in the app would give an attacker that account (and with the sudo password, root).

- a system user per app (e.g. `storybook`, no login shell, no sudo), owning only what the app
  writes (uploads, its logs); the code readable, not writable for it
- pm2 for that user (or a systemd unit per app), `APP_USER` in its `apps.d` file
- the database password and `server/.env` readable only by it
- the backups stay with the admin user (they only need the database dump and the photos)
- dk-srv: `as_user`, the drift check and AIDE for the new layout; `AllowUsers` stays `appuser`
