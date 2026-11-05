# Security of the server

How this server (Ubuntu 24.04 on a rented VPS, nginx, PostgreSQL) is secured, **measured against
published guides** – what is done, what doesn't apply, and which risks are accepted on purpose (with
the reason). The apps on it have their own document – the storybook's:
[storybook/docs/SECURITY.md](https://github.com/DimiJonas/storybook/blob/main/docs/SECURITY.md)
(OWASP ASVS for the app, its nginx site, its backups).

| Layer | Guide | How it's checked |
|---|---|---|
| Ubuntu 24.04 | [CIS Ubuntu Linux 24.04 LTS Benchmark](https://www.cisecurity.org/benchmark/ubuntu_linux), **Level 1 – Server** (plus chosen Level 2 rules) | Automatically: Ubuntu Pro's USG (`usg audit cis_level1_server`) |
| nginx and TLS | [CIS NGINX Benchmark](https://www.cisecurity.org/benchmark/nginx) (Level 1 Webserver); TLS: Mozilla "intermediate", [BSI TR-02102-2](https://www.bsi.bund.de/dok/TR-02102-en) | `nginx -T`, local TLS tests, SSL Labs |
| PostgreSQL 16 | [CIS PostgreSQL 16 Benchmark](https://www.cisecurity.org/benchmark/postgresql) (Level 1) | Settings, `pg_hba`, roles |

Status marks: ✅ done · ➖ doesn't apply here · ⚠️ accepted risk (reason below) · 🔜 planned

How each mechanism works, where it lives and how to check it yourself:
[`HARDENING.md`](HARDENING.md) (with the lessons from the first rounds).

## Result

| Measurement | CIS Level 1 Server (USG) | Rules |
|---|---|---|
| Before the hardening (2026-11-02) | **72.2 %** | 236 pass · 105 fail · 66 not applicable |
| After the hardening, all rules (2026-11-03) | **84.7 %** | 323 pass · 35 fail · 49 not applicable |
| After the hardening, with the accepted risks switched off ([tailoring](hardening/make-tailoring.py), 11 rules) (2026-11-03) | **90.7 %** | 323 pass · 24 fail · 49 not applicable |
| After the follow-up, all rules (2026-11-05) | **92.4 %** | 343 pass · 14 fail · 50 not applicable |
| After the follow-up, with the accepted risks switched off (13 rules, A12 and A13 added) (2026-11-05) | **99.6 %** | 343 pass · 1 fail · 50 not applicable |
| After the sysstat fix, with the accepted risks switched off (2026-11-05, 15:06) | **100 %** | 344 pass · 0 fail |
| After the move to dk-srv, all rules (2026-11-05, 23:50) | **92.7 %** | 344 pass · 13 fail · 50 not applicable |
| After the move to dk-srv, with the accepted risks switched off (2026-11-05, 23:52) | **100 %** | 344 pass · 0 fail · 50 not applicable |

The 14 failures of all rules on 2026-11-05 were the 13 accepted risks plus
`permissions_local_var_log`: sysstat (the performance history for `sar`) wrote a new file into
`/var/log/sysstat/` every day, readable for everyone – the one-time fix of the log rights didn't
last. Fixed the same day with sysstat's own setting `UMASK=0027` (and the nightly check now reports
log files more open than 640): the tailored audit afterwards passed every rule. These measurements
were made with the scripts' earlier home in the storybook repository. After the move to dk-srv
(renamed files, no changed setting) both audits were run again: the same 344 rules pass, and the
13 failures of all rules are exactly the 13 accepted risks below.

The 24 failures of 2026-11-03 and what the follow-up did about them (details in
[`HARDENING.md`](HARDENING.md), "Lessons"):

| Rules | Cause | Follow-up |
|---|---|---|
| `grub2_enable_apparmor` | `update-grub` never ran (a bug in the installer) | fixed: the installer checks `grub.cfg` itself |
| `sysctl_…_log_martians` (2), `sysctl_…_rp_filter` (2) | ufw's and procps' sysctl files set other values (ufw at every start) | fixed: contradicting lines commented out |
| `accounts_password_pam_*` (12) | the rules were in `pwquality.conf.d/`, the audit reads only `pwquality.conf` | fixed: moved into `pwquality.conf` |
| `has_nonlocal_mta`, `postfix_network_listening_disabled`, `ufw_rules_for_open_ports` | postfix, pulled in by AIDE's recommendations, listened on port 25 | fixed: removed (AIDE without recommendations) |
| `aide_periodic_checking_systemd_timer` | the check ran from cron; CIS wants a systemd timer | fixed: Ubuntu's `dailyaidecheck.timer` runs it |
| `service_apport_disabled` | Apport was disabled, not masked | fixed: masked |
| `aide_build_database` | USG looks for AIDE's old setting name `database=` | ⚠️ A12 |
| `file_permissions_ungroupowned` | one file in a read-only snap image | ⚠️ A13 |

USG implements the CIS Ubuntu 24.04 benchmark **v1.0.0** (profile from the SCAP Security Guide 0.1.78).
CIS published v2.0.0 in May 2026; rules that are new there aren't measured yet. How to measure again:
[`maintenance-commands.txt`](maintenance-commands.txt), "Measuring".

## What's protected, against whom

The server holds **private photos and texts** of a few people (the storybook), their logins, and
websites. Expected attackers: **internet-wide scanners and bots** (every public server, every day),
**password guessing**, **known vulnerabilities** in nginx/OpenSSL/Node.js/npm packages, a hole in
an app used to get further into the server, a **stolen or lost device** (phone, laptop), and – less
likely – someone **targeting** this server. Not in scope: attackers with access to the hosting
company's infrastructure.

Principles: as little as possible reachable from outside (nginx on 80/443, SSH with keys); every
layer assumes the one in front of it can fail; **only root can change what root runs** (root-owned
clones and copies; settings files parsed, never run); nothing secret or server-specific in any
repository (no domains, no topic, no keys); anything unusual sends a notification to the phone.

---

## 1. Ubuntu (CIS Level 1 – Server)

Applied by [`hardening/install-hardening.sh`](hardening/install-hardening.sh) in parts;
the values are the ones the CIS profile checks for. A nightly check reports if a setting changes
again (e.g. after an update) – see "Monitoring".

| CIS area | What's done | |
|---|---|---|
| 1.1 Filesystems | Rare filesystems (cramfs, freevxfs, hfs, hfsplus, jffs2, udf) and USB storage can't be loaded; `/dev/shm` and `/tmp` (own tmpfs) with `nodev,nosuid,noexec` | ✅ |
| 1.1 Partitions | Separate partitions for `/var`, `/var/log`, `/home` … | ⚠️ A1 |
| 1.3 AppArmor | Enabled on the kernel command line, `apparmor-utils` installed | ✅ |
| 1.3 AppArmor profiles | All profiles in enforce/complain mode | ⚠️ A6 |
| 1.4 Bootloader | `grub.cfg` only for root | ✅ |
| 1.4 Bootloader password | | ⚠️ A2 |
| 1.5 Process hardening | ASLR, ptrace scope, no core dumps (also not for setuid programs), Apport masked | ✅ |
| 1.6 Banners | Login banner without OS version (`/etc/issue`, `/etc/issue.net`) | ✅ |
| 2 Services | Only what's needed runs; telnet client and VMware tools removed; no mail server (the one AIDE's recommendations pulled in is removed); the rsync **daemon** masked | ✅ |
| 2 Updates | Automatic security updates never stop at a config file we changed: ours stays, the package's new version is saved as `.dpkg-dist` (listed in the weekly report) | ✅ |
| 2 rsync program | The backup copy needs it | ⚠️ A3 |
| 2 Time | systemd-timesyncd with explicit servers | ✅ |
| 2 cron/at | `cron.allow`/`at.allow`, strict rights on `/etc/crontab` and the cron folders | ✅ |
| 3 Network | No forwarding, redirects or source routing; martians logged; reverse path filter; SYN cookies; IPv6 router advertisements off (the IPv6 route is static) – the same values in every sysctl file (ufw's and procps' contradicting lines commented out); rare protocols (dccp, sctp, rds, tipc) can't be loaded | ✅ |
| 4 Firewall | ufw: incoming only SSH/HTTP/HTTPS, **outgoing only DNS, NTP, DHCP, HTTP/HTTPS** (updates, npm, notifications, map tiles, git over https), SSH out only while a clone still uses it, loopback rules, no routing; the nightly check reports any other open port | ✅ |
| 4 nftables rules | CIS lets you choose ufw *or* nftables – this server uses ufw | ➖ |
| 5.1 SSH | Keys only, no root login, `AllowUsers appuser`, MaxAuthTries 4, LoginGraceTime 60, MaxStartups 10:30:60, dead connections closed after 45 s, no forwarding (TCP, X11, agent), strong ciphers/MACs/key exchange only, banner, config files `600` | ✅ |
| 5.2 sudo | Own log (`/var/log/sudo.log`), `use_pty`, password again after 15 min | ✅ |
| 5.3 PAM | Passwords (in `pwquality.conf`): ≥ 14 characters with 4 character classes, no dictionary words (also when root sets one); **lockout for 15 min after 4 wrong passwords** (sudo, console); last 24 passwords can't be reused; no empty passwords (`nullok` removed) | ✅ |
| 5.3 su | Only members of the empty group `sugroup` – nobody; `sudo` is the way | ✅ |
| 5.4 Accounts | umask 027; idle shells close after 15 min (`TMOUT`); home folder `750`, `.ssh` `700`, dotfiles ≤ `740`; system accounts without login shell (`postgres`); new accounts locked 45 days after password expiry | ✅ |
| 5.4 Password expiry | Forced changes every 365 days | ⚠️ A4 |
| 6.1 Logging | journald on disk, compressed, **at most 1 GB** (it had grown to 2.2 GB), passed to rsyslog; log files not readable for others (also sysstat's daily files; checked nightly); dk-srv's and the apps' logs rotated hourly | ✅ |
| 6.2 Integrity (AIDE) | Database of all system files; checked every night by Ubuntu's systemd timer (05:40); **unexplained changes in sensitive places → urgent notification**, with what changed (content, rights, inode …) | ✅ |
| 6.2 AIDE database setting | USG's check looks for the old setting name | ⚠️ A12 |
| 6.3 auditd (Level 2) | Audit system from boot (`audit=1`), CIS rules: time, users/groups, sudo, logins, permission changes, refused access, mounts, deletions, AppArmor, kernel modules, setuid programs – plus the server's own: `/etc/dk-srv`, `/opt/dk-*`, `/usr/local/sbin`, SSH config and keys, nginx, cron, and every app's sensitive places (e.g. `/etc/storybook`); rules locked (`-e 2`) | ✅ |
| 6.3 auditd when the disk is full | CIS: stop the server | ⚠️ A5 |
| 7 File rights | `passwd`/`shadow`/`group`, no world-writable or unowned files (checked nightly, outside the snaps) | ✅ |
| 7 Unowned files in snaps | One file in a read-only snap image | ⚠️ A13 |

Also, beyond CIS: **Ubuntu Pro** (ESM security updates for all packages, Livepatch for the kernel),
automatic security updates with a nightly restart when needed, and fail2ban (SSH, the apps'
logins, scanners, rate limits).

## 2. nginx and TLS (CIS NGINX Benchmark)

The server-wide part: [`nginx/`](nginx/), installed by [`nginx/install-nginx.sh`](nginx/install-nginx.sh)
(checks with `nginx -t`, puts everything back if it fails). Each app's own sites (headers, methods,
rate limits for its API) are in the app's repository and document.

| Recommendation | What's done | |
|---|---|---|
| Run as an unprivileged user | Workers run as `www-data`; config and keys only writable/readable by root | ✅ |
| Hide the version | `server_tokens off` for all sites | ✅ |
| Default server | The bare IP address and unknown names get **no answer** (HTTP: connection closed; HTTPS: handshake refused before a certificate is shown) – Ubuntu's default site is switched off | ✅ |
| Only needed modules | Ubuntu's package with its standard modules | ⚠️ A7 |
| Request limits | Header/body/keep-alive timeouts 10 s, ≤ 50 connections per IP (all sites); body and rate limits per site | ✅ |
| Logging | Access and error logs; scanners and clients that hit rate limits are banned by fail2ban | ✅ |
| TLS protocols | **TLS 1.2 and 1.3 only** (`nginx.conf` and every site) | ✅ |
| Ciphers | ECDHE with AES-GCM / ChaCha20-Poly1305 only (forward secrecy, AEAD) – Mozilla "intermediate", within BSI TR-02102-2 | ✅ |
| Certificate | Let's Encrypt, ECDSA P-256, renewed automatically | ✅ |
| OCSP stapling | Let's Encrypt stopped OCSP in 2025 (responders off since 6 Aug 2025) | ➖ |
| HSTS | `max-age=31536000` (one year) | ✅ |
| Static sites | Root-owned files only, installed by `dk-site-update` after **every file is checked by its content** (only HTML, CSS, text, icons, JPEG/PNG/WebP; no SVG, no links, no hidden files, size limits); only GET/HEAD; only those types, everything else as download; CSP without scripts, `nosniff`; no symbolic links, no folder listings; picture metadata removed ([`HARDENING.md`](HARDENING.md), "Static sites") | ✅ |

## 3. PostgreSQL 16 (CIS PostgreSQL 16 Benchmark)

| Recommendation | What's done | |
|---|---|---|
| Listen only where needed | `localhost` only | ✅ |
| Authentication | `scram-sha-256` for network connections, `peer` locally; passwords stored as SCRAM | ✅ |
| Least privilege | Each app's account (the storybook's: `webapp`) is no superuser, can't create databases or roles; only it may connect to its app's databases (not `PUBLIC`) | ✅ |
| Logging | Connections and disconnections logged, with user, database and client | ✅ |
| pgAudit | Loaded; logs changes to structure (`ddl`) and to roles/rights (`role`) – not the normal reading and writing of the apps' data | ✅ |
| Data folder | `700`, owned by `postgres`; the `postgres` account has no login shell | ✅ |
| TLS for connections | Only local connections exist | ➖ |

## 4. Running apps and sites

| What | |
|---|---|
| Everything root runs comes from **root-owned** places (`/opt/dk-srv`, `/opt/dk-apps/<app>`, `/opt/dk-sites/<name>`, `/usr/local/sbin`) – an app's user can't change it | ✅ |
| Updates show the new commits (and for an app, what changed in its root folder) before anything runs | ✅ |
| The apps' and sites' settings (`apps.d`, `sites.d`) are `KEY=value` files that are **read, never run**; an app's mode command must be a root-owned program in `/usr/local/sbin` | ✅ |
| The server pulls with a **read-only, fine-grained token** (only the repositories it needs), in a root-only file; its expiry date is in the weekly report | ✅ |
| Each app's backend runs as its own unprivileged user | 🔜 (today the storybook's backend shares the admin user – ROADMAP.md) |

## 5. Monitoring (what sends a notification)

SSH connections – by kind: terminal login, file transfer, other command, backup pull (with the
key's name) · banned attackers · security findings (CVEs, npm) and maintenance mode/lockdown ·
**unexplained changes to sensitive files** (AIDE) · **hardening settings that changed** · the read
token about to expire · and a weekly report with all of it. The apps add their own (the storybook:
locked accounts, failed backups and restore tests). Details: [`README.md`](README.md), "Notifications".

---

## Accepted risks and known gaps

| | Risk | Why it's accepted |
|---|---|---|
| A1 | No separate partitions for `/var`, `/var/log`, `/home`, `/var/tmp` | A rented VPS has one disk; repartitioning means reinstalling. `/tmp` and `/dev/shm` have their own tmpfs with the CIS options; disk usage is in the weekly report, logs are size-limited |
| A2 | No bootloader password | Only the hosting company's web console reaches the boot menu (no physical access). Protect that account with a strong password and 2FA |
| A3 | `rsync` stays installed | The backup copy needs it. Its network daemon is masked; over SSH the backup key may only read the backups folder |
| A4 | No forced password change every 365 days | Current guidance ([NIST SP 800-63B](https://pages.nist.gov/800-63-4/sp800-63b.html)) advises against forced changes – they lead to weaker passwords. SSH works only with keys; the account password is only for sudo and the console, and is long and unique |
| A5 | auditd doesn't stop the server when its disk is full (CIS Level 2: `single`/`halt`) | The apps should keep running; auditd pauses recording instead (`SUSPEND`), its logs are size-limited (10 × 20 MB) and the disk is in the weekly report |
| A6 | Some AppArmor profiles are "unconfined" | Ubuntu 24.04 ships them that way on purpose (they only mark programs); nginx, PostgreSQL and Node.js run without own profiles – writing them is future work |
| A7 | nginx with Ubuntu's standard modules | Building nginx without modules means leaving Ubuntu's security updates; unused modules (mail, stream, …) aren't loaded by the config |
| A8 | (the storybook's: no second factor for its login – in its SECURITY.md) | |
| A9 | Logs and the AIDE database are only on the server | Someone who becomes root could change them. The notifications reach the phone right away (they can't be taken back), and the nightly checks would stop – which the weekly report shows |
| A10 | One server, no standby | Private apps: a failure means waiting, not losing data (the storybook's backups are on a second machine, restore tested monthly) |
| A11 | CIS Ubuntu v2.0.0 not yet measured | USG implements v1.0.0; the difference gets checked when USG updates |
| A12 | USG's rule "AIDE database built" (`aide_build_database`) fails | A false finding: USG's content (SCAP Security Guide 0.1.78) looks for the setting `database=file:` in `aide.conf`, but AIDE 0.18 calls it `database_in=` (the old name is deprecated). The database exists, is checked and renewed every night, and the nightly check reports if it's missing. Adding the old name only to please the check would bring a deprecation warning into every AIDE run |
| A13 | One file without an existing group: `/snap/core22/…/usr/bin/ssh-agent` (`file_permissions_ungroupowned`) | Snaps (here the base of the Livepatch snap) are read-only images – the file can't be changed; its group exists only inside the snap. The nightly check looks for unowned files on every local disk itself, leaving out only the snaps |

Rules switched off in the USG tailoring (so the second score measures only what applies):
A2 (`grub2_password`), A4 (`accounts_maximum_age_login_defs`, `accounts_password_set_max_life_existing`),
A3 (`package_rsync_removed`), A6 (`all_apparmor_profiles_in_enforce_complain_mode`), ufw instead of
nftables (`package_ufw_removed`, `nftables_rules_permanent`, `service_nftables_enabled`,
`set_nftables_loopback_traffic`), nginx itself (`package_nginx_removed`, `service_nginx_disabled`),
and since the follow-up A12 (`aide_build_database`) and A13 (`file_permissions_ungroupowned`).

## Reporting a problem

If you find a security problem in these scripts, please use GitHub's private vulnerability reporting
for this repository, or open an issue without details and ask for a private contact – thank you.
