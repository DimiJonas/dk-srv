# dk-srv – Roadmap

| #   | Step                                                                               | Size | Depends on |
| --- | ---------------------------------------------------------------------------------- | ---- | ---------- |
| –   | ✅ Before dk-srv: security check, notifications, modes (storybook step 13)          | M    | –          |
| –   | ✅ Before dk-srv: hardening by the CIS guides (storybook step 15 and its follow-up) | M–L  | –          |
| 1   | ✅ Own repository: the server's scripts out of the storybook                        | M    | –          |
| 2   | ✅ Each app's backend as its own user, in a sandbox (the storybook's first)          | M    | 1          |
| –   | Later: the apps' database logins without a password (PostgreSQL "peer" login)      | S    | 2          |
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
  `/var/log/dk-srv`, file names `…-dk-srv…` (the server was moved once, with a migration script
  that's gone again since)
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
server-wide part), `hardening/` (moved, renamed), `fail2ban/`, the documents ([HARDENING.md](HARDENING.md), [SECURITY.md](SECURITY.md), the command files).

**Measured after the move** (2026-11-05, 23:50 and 23:52; the tailoring file is now
`/etc/dk-srv/usg-tailoring.xml`): all rules **92.7 %** (344 pass, 13 fail – exactly the 13 accepted
risks), with the accepted risks switched off **100 %** (344 pass, 0 fail). Nothing about the
settings changed, only names and places.

---

## 2. Each app's backend as its own user, in a sandbox ✅

Until now the storybook's backend ran as `appuser` – the account that logs in by SSH and has sudo.
A hole in the app would have given an attacker that account. Now (with the storybook's step 17):

- **every app has its own user**: a system user without password, shell or home folder, not in
  `sudo` – created by the app's `ops/root/install.sh`. `APP_USER` in its `apps.d` file
- **its code belongs to the admin user** (`DEPLOY_USER`, new key): it pulls, installs, builds; the
  app only reads it – so a hole in the app can't change the code it runs. The code lives outside
  the home folders (the storybook's: `/srv/storybook`): those are `750` (CIS)
- **it runs as a systemd service** (`SERVICE`, new key, instead of `PM2_PROCESS`) with a sandbox –
  the storybook's `systemd-analyze security`: **1.4 "OK"** (without the sandbox: 9.0 "UNSAFE");
  pm2 is gone. The nightly check restarts the service after a Node.js update (`systemctl
  try-restart`), the hardening part `postgres` after a PostgreSQL restart
- **checked every night** (`app_drift`, part of the drift check): the service runs as `APP_USER` –
  not root, not the admin –, that user has no login shell and isn't in an admin group, and the
  sandbox (`NoNewPrivileges`, `ProtectSystem=strict`) is still on
- **npm audit** runs as `DEPLOY_USER` (the code's owner)
- **the ntfy topic** is readable for the group **`dk-notify`** (created by `install.sh`; the admin
  user and the apps' users) – the setting `NOTIFY_GROUP` is gone
- the fact sheet shows each app's service, user and sandbox score
- **`dk-srv-update`**: dk-srv updates itself the same way as the apps and sites (pull, show, ask,
  install) – and names the hardening parts whose files or code changed (from git's hunk headers:
  the function each change is in), nginx, the tailoring file. It runs none of them itself ("ssh"
  and "pam" need a second session open)
- what was only needed once for the move from the storybook repository is gone: `migrate/`, the
  code that removed the old names, the notes renamed in other packages' files
