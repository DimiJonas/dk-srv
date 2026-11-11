# Hardening, explained

A walk through every mechanism that secures this server: **what** it does and **why**, **where** it
lives, how to **see it for yourself**, and how to **change or undo** it. At the end, the **lessons**
from the first rounds: what went wrong, and why.

The other documents: [`SECURITY.md`](SECURITY.md) is the scorecard (every guide's rules, done or
accepted, the measured scores); [`README.md`](README.md) the overview;
[`maintenance-commands.txt`](maintenance-commands.txt) the everyday commands. All commands below
run **on the server**, as the admin user (`appuser`; `sudo` where shown).

Contents: [The big picture](#the-big-picture) · [Measuring](#measuring-cis-usg-tailoring-and-the-a-numbers) ·
[packages](#packages) · [ssh](#ssh) · [kernel](#kernel) · [accounts](#accounts) · [pam](#pam) ·
[logging](#logging) · [firewall](#firewall) · [auditd](#auditd) · [aide](#aide-file-integrity) ·
[postgres](#postgres) · [nginx](#nginx) · [Static sites](#static-sites) ·
[Apps on this server](#apps-on-this-server) · [Watching](#watching-the-nightly-checks) ·
[Lessons](#lessons-from-the-first-rounds)

---

## The big picture

dk-srv is the **server's** repository: everything that protects the machine as a whole. The apps
on it (today: the [storybook](https://github.com/DimiJonas/storybook)) and the static sites live in
their own repositories and plug in through small settings files ([below](#apps-on-this-server)).

| | Command | What it does |
|---|---|---|
| **Install** | `/opt/dk-srv/install.sh` | dk-srv's commands (`dk-*` in `/usr/local/sbin`), the nightly checks, notifications, log rotation, the PAM line for SSH logins, fail2ban |
| | `/opt/dk-srv/hardening/install-hardening.sh <part>` | the system settings, in parts (below) – each part can be run again, nothing changes twice; `--dry-run` shows what would change |
| | `/opt/dk-srv/nginx/install-nginx.sh` | nginx for the whole server: settings for all sites, default-deny, TLS, the static sites |
| | `dk-app-update <app>` | an app's root parts: its nginx sites, its mode command, its entry in `apps.d` |
| | `dk-site-update <name>` | a static site's files, checked and put on the web |
| | `dk-srv-update` | dk-srv itself: pull, show, ask, `install.sh` – and which hardening parts to run again |
| **Switch** | `dk-mode status`, `lockdown`, `normal` | lockdown: the whole web server off, every app's backend stopped |
| **Watch** | nightly security check (05:10), file integrity check (05:40), weekly report (Monday) | notify the phone when something changes or looks wrong |
| **Measure** | `usg audit` (Ubuntu Pro), `hardening/collect-facts.sh` | the CIS score; a read-only, anonymised fact sheet for a review |

**Only root can change what root runs.** Everything root runs comes from root-owned places: the
clone `/opt/dk-srv` (owned by root, updated with `sudo git pull`), the installed copies in
`/usr/local/sbin` and `/usr/local/lib/dk-srv`, and for each app a root-owned copy of just its root
folder (`/opt/dk-apps/<app>`). An app's own user can change the app's code – but nothing root runs
later. Before the split into three repositories (until November 2026), root ran scripts straight
from the app user's clone: whoever could write there could have become root (see
[Lessons](#lessons-from-the-first-rounds), 14).

How the installer changes files – three ways, in this order of preference:

1. **Its own file in a `.d/` folder** (`/etc/sysctl.d/60-dk-srv-cis.conf`,
   `/etc/ssh/sshd_config.d/00-dk-srv.conf`, `/etc/systemd/system/<unit>.d/60-dk-srv.conf`, …).
   Packages never touch these; deleting the file undoes the change.
2. **A marked block** at the end of a package's file (`# >>> dk-srv <name> … # <<< dk-srv <name>`),
   replaced on every run. Used where the setting must be in that very file (e.g. the password rules
   in `/etc/security/pwquality.conf`, because that's the only file the CIS audit reads).
3. **A line changed in place** (e.g. a contradicting line commented out), only where nothing else
   works – always with a note saying why.

Every file is **backed up** before it changes: `/var/backups/dk-srv-hardening/<date-time>/` (same
path inside). Every run is logged in `/var/log/dk-srv/hardening.log`, and the changed paths are
noted for the file integrity check, so it doesn't report them as unexplained.

```sh
sudo /opt/dk-srv/hardening/install-hardening.sh --dry-run all   # what would change now
sudo tail -30 /var/log/dk-srv/hardening.log                       # what changed, when
sudo ls /var/backups/dk-srv-hardening/                            # the backups of old files
```

---

## Measuring: CIS, USG, tailoring and the A-numbers

**CIS Benchmarks** are published hardening guides (one per system: Ubuntu, nginx, PostgreSQL …).
Each recommendation has a level: **Level 1** = sensible for every server, little impact;
**Level 2** = more protection, more impact. This server follows **Level 1 Server** plus a few chosen
Level 2 rules (auditd, pgAudit, AIDE alerts, the 15-minute shell timeout).

**USG** (Ubuntu Security Guide, part of Ubuntu Pro) checks the server against the CIS benchmark
automatically. It runs a few hundred small tests ("rules", e.g.
`sysctl_net_ipv4_conf_all_log_martians`), each with a result: **pass**, **fail**, **not applicable**
(e.g. a rule about a program that isn't installed) or **not selected** (not part of the profile). The
**score** is the weighted share of passes among pass + fail. USG only reads – it changes nothing.

**Tailoring** is USG's documented way to say "this rule doesn't apply to us, on purpose": a small
XML file that switches single rules off. `hardening/make-tailoring.py` writes it from USG's own
template, with a reason for every rule. An audit with the tailoring file measures only what we
actually want – but the audit **without** it stays the honest number, and both go into
`SECURITY.md`. Switching a rule off is never silent: each one is an **accepted risk** with a number
(**A1, A2, …**) in `SECURITY.md`, "Accepted risks", where the reason is written down.

An example – **A13**: the CIS rule "every file belongs to an existing group"
(`file_permissions_ungroupowned`) fails on this server because of exactly one file:
`/snap/core22/…/usr/bin/ssh-agent`. Snaps (here the base of the Livepatch snap) are **read-only
images**; inside them, ssh-agent belongs to a group that exists only inside the snap. The file can't
be changed, and it isn't a risk (a group number nobody on the server has). So the rule is switched
off in the tailoring (A13) – and so that real unowned files elsewhere would still be found, the
nightly check now runs the same search itself, leaving out only the snaps.

Not every failed rule is a real problem: USG's content (SCAP Security Guide 0.1.78) sometimes lags
behind the software. **A12**: AIDE 0.18 renamed its setting `database=` to `database_in=`, and USG
still looks for the old name – the database exists and is renewed every night.

```sh
sudo usg audit cis_level1_server                                        # all rules
sudo usg generate-tailoring cis_level1_server /tmp/usg-tailoring.xml     # USG's template
sudo python3 /opt/dk-srv/hardening/make-tailoring.py /tmp/usg-tailoring.xml /etc/dk-srv/usg-tailoring.xml
sudo usg audit --tailoring-file /etc/dk-srv/usg-tailoring.xml         # without the accepted risks
```
The last lines of each audit name the HTML report (`/var/lib/usg/usg-report-*.html`): open it
(copy it to the laptop) to see every rule with its description. When a rule fails and the reason
isn't obvious, the result XML often says more: for rules checked by a script it contains the
script's output (`<check-import>`), e.g. the file list of A13.

---

## packages

**What and why.** Less software, fewer holes:
- the **telnet** client (unencrypted) and the **VMware tools** (this is a KVM machine) are removed
- **Apport** (crash reports – they contain memory contents) is **masked**: `systemctl mask` links the
  unit to `/dev/null`, so nothing can start it again, not even another package. CIS checks for
  "masked"; "disabled" isn't enough. Its helpers (automatic upload, crash forwarding) go with it.
  The package stays: `ubuntu-server` depends on it.
- the **rsync daemon** (a network service) is masked; the `rsync` program stays (the backup copy)
- a **mail server** is removed if one was pulled in: AIDE recommends a mail program, which needs a
  mail server – postfix, listening on port 25 for the whole internet. Nothing here sends mail
  (notifications go to the phone), so postfix and bsd-mailx are purged – only if they were installed
  automatically and nothing else needs them (checked with a simulated purge first); otherwise
  postfix stays, but only on `127.0.0.1` (`inet_interfaces = loopback-only`).
- **updates keep our config files**: `/etc/apt/apt.conf.d/60-dk-srv-keep-config` – see
  [Lessons](#lessons-from-the-first-round), "Updates that stopped".

**See for yourself.**
```sh
systemctl is-enabled apport.service                 # masked
sudo ss -tlnp | grep -v 127.0.0                     # only :22, :80, :443 on the network
apt-config dump | grep -i '^dpkg::options'          # --force-confdef, --force-confold
find /etc -name '*.dpkg-dist' 2>/dev/null           # new package versions of files we changed
```
**Undo.** `sudo systemctl unmask apport.service`; `sudo rm /etc/apt/apt.conf.d/60-dk-srv-keep-config`.

## ssh

**What and why.** SSH is the only way in besides the website, so it's the most attacked door
(bots try passwords every minute). File: `/etc/ssh/sshd_config.d/00-dk-srv.conf` – in sshd the
**first** value wins, hence `00-`.
- only `appuser`, only with a **key** (no passwords, no root login, no empty passwords)
- at most 4 tries per connection, 60 s to log in, at most 10 unauthenticated connections at once
- a dead connection is closed after 45 s
- **no forwarding** (no tunnels, X11 or agent) – nothing here uses it; rsync, scp, sftp still work
- only modern ciphers, MACs and key exchanges; a login banner without the Ubuntu version
- root's `authorized_keys` moved away (root can't log in by SSH anyway)

**See for yourself.** `sudo sshd -T | grep -E '^(permitrootlogin|passwordauthentication|allowusers|maxauthtries|disableforwarding) '`

**Change.** Edit the file in the repository, deploy, run the part again – **keep an SSH session open**
until a new login worked. If `sshd -t` rejects the file, the installer puts the old one back.

## kernel

**What and why.**
- **Network settings** (`/etc/sysctl.d/60-dk-srv-cis.conf`): this server isn't a router – it
  forwards nothing, sends and accepts no ICMP redirects or source-routed packets (both can redirect
  traffic), logs packets with impossible sender addresses ("martians"), drops packets whose sender
  couldn't have come in on that interface (`rp_filter = 1`, against spoofing), uses SYN cookies
  (against connection floods); IPv6 router advertisements are ignored (the IPv6 route is static).
  **The same values in every other sysctl file**: lines in other files that set one of these keys to
  another value are commented out, with a note. Two packages have such lines: **ufw**
  (`/etc/ufw/sysctl.conf`, `log_martians=0`) and **procps** (`10-network-security.conf`,
  `rp_filter=2`). ufw applies its file at every start – which undid ours after every restart.
- **Memory and processes**: random addresses (ASLR), no peeking into other processes (ptrace),
  kernel addresses and `dmesg` hidden from users, no core dumps (`limits.d`, `coredump.conf.d` –
  a crashed program's memory can contain passwords or photos).
- **Modules** (`/etc/modprobe.d/dk-srv-cis.conf`): rare filesystems, USB storage and rare network
  protocols can't be loaded – less kernel code reachable. Not squashfs: snaps need it.
- **`/dev/shm` and `/tmp`** as their own tmpfs with `nodev,nosuid,noexec`: nothing can be run from
  there (a typical place for an attacker's download).
- **Kernel command line**: `apparmor=1 security=apparmor` (AppArmor, Ubuntu's program confinement,
  explicitly on) and `audit=1 audit_backlog_limit=8192` (the audit system records from the first
  moment of booting). Set in `/etc/default/grub.d/60-dk-srv-cis.cfg`; `update-grub` writes them
  into `/boot/grub/grub.cfg`. The installer checks grub.cfg itself and runs `update-grub` whenever the
  first boot entry lacks them. Takes effect after a restart.

**See for yourself.**
```sh
sysctl net.ipv4.conf.all.log_martians net.ipv4.conf.all.rp_filter     # 1 and 1
grep -n martians /etc/ufw/sysctl.conf                                  # commented out, with the note
cat /proc/cmdline                                                      # apparmor=1 … audit=1 …
findmnt /tmp; findmnt /dev/shm                                         # tmpfs, nodev,nosuid,noexec
modprobe -n -v usb-storage                                             # install /bin/false
```
**Undo.** Remove the file in `/etc/sysctl.d/`, `/etc/modprobe.d/` or `/etc/default/grub.d/` (then
`sudo update-grub`); the commented lines can be put back from the backup folder.

## accounts

**What and why.**
- **umask 027**: new files are readable by you and your group, not by everyone (`/etc/profile.d/`,
  `/etc/login.defs`, `/etc/bash.bashrc`, `/etc/profile`). See [Lessons](#lessons-from-the-first-round):
  this also applies to `sudo` – a file meant to be read by others needs `chmod` afterwards.
- **TMOUT=900**: a shell **waiting at its prompt** for 15 minutes closes itself, so a forgotten open
  session can't be used by someone else. A running program (`htop`, `journalctl -f`, a deploy)
  isn't interrupted – but an idle shell in **tmux** closes too, and with its last shell the tmux
  session ends. Read-only, so it can't be switched off by mistake (or by an intruder's script).
- home folder `750`, `.ssh` `700`, dotfiles at most `740`
- **cron and at** only for root (and appuser for cron); strict rights on the cron folders
- **`su` only for members of the empty group `sugroup`** – nobody. `sudo` is the way: it asks for the
  password and logs every command in `/var/log/sudo.log`; after 15 minutes it asks again.
- `postgres` has no login shell (`sudo -u postgres psql` still works)
- new accounts are locked 45 days after their password expired

**See for yourself.** `umask` (0027) · `echo $TMOUT` (900) · `sudo tail /var/log/sudo.log` ·
`cat /etc/cron.allow`

## pam

PAM decides how passwords are checked (sudo, console). The part asks before it starts: keep
`sudo -i` open in a second terminal until `sudo true` works in a new one.

**What and why.**
- **Password rules** (`pam_pwquality`): at least 14 characters, all 4 character classes, no long
  repetitions or sequences, no dictionary words – also when root sets a password. They are a
  marked block in **`/etc/security/pwquality.conf`** (PAM would also read `pwquality.conf.d/`, but the
  CIS audit doesn't – see Lessons).
- **Lockout** (`pam_faillock`, `/etc/security/faillock.conf`): after 4 wrong passwords within 15
  minutes, the account is locked for 15 minutes. Only passwords: the SSH key login still works.
- **History** (`pam_pwhistory`): the last 24 passwords can't be used again.
- **No empty passwords** (`nullok` removed).

These are switched on with Ubuntu's own tool, `pam-auth-update` (profiles in
`/usr/share/pam-configs/`), not by editing `/etc/pam.d/common-*` by hand – so package updates keep
working with them.

**See for yourself.**
```sh
sed -n '/>>> dk-srv cis/,/<<< dk-srv cis/p' /etc/security/pwquality.conf
grep -E 'faillock|pwquality|pwhistory' /etc/pam.d/common-auth /etc/pam.d/common-password
sudo faillock --user appuser          # failed attempts (after typos)
```

## logging

**What and why.** Logs are only useful if they exist when needed and don't fill the disk: the
journal is kept **on disk**, compressed, passed to rsyslog, and **limited to 1 GB**
(`/etc/systemd/journald.conf.d/`). Log files aren't readable for others. The time comes from named
time servers (`timesyncd.conf.d/`) – correct times matter for logs and certificates. dk-srv's
logs (and the apps' – each app adds a file to `/etc/dk-srv/logrotate.d/`) are rotated **every hour**,
so a log that suddenly grows is cut off within the hour (`etc/dk-srv.logrotate`). sysstat (the
performance history behind `sar`) writes a new file every day; its own setting `UMASK=0027` (a
marked block in `/etc/sysstat/sysstat`) makes those `640` too – a one-time `chmod` wouldn't last.
The nightly check reports any log file more open than `640`.

**See for yourself.** `journalctl --disk-usage` · `timedatectl timesync-status` ·
`sudo logrotate --debug --state /var/lib/dk-srv/logrotate.status /etc/dk-srv/logrotate.conf`

## firewall

**What and why.** ufw: **incoming** only SSH, HTTP, HTTPS (and the DHCP answer); **outgoing** only
what the server needs – DNS, time, DHCP, HTTP/HTTPS (updates, npm, notifications, map tiles), and
SSH only while some clone on the server still pulls over SSH (`git@github.com:…`) – with `https://`
everywhere, the rule is removed. If the server were ever taken over, it couldn't
simply talk to anything on the internet. Loopback rules: nothing from outside may pretend to come
from `127.0.0.1`. The part tests the connections afterwards.

**See for yourself.** `sudo ufw status verbose`
**Emergency.** `sudo ufw default allow outgoing` (all outgoing allowed again).

## auditd

**What and why** (Level 2). The kernel's audit system records security-relevant events: time
changes, user/group changes, sudo, logins, permission changes, refused file access, mounts,
deletions, kernel modules, every setuid program run by a person – and the places that matter here
(`/etc/dk-srv`, `/opt/dk-*`, `/usr/local/sbin`, SSH config and keys, nginx, cron, plus every app's
`AIDE_SENSITIVE` places, e.g. `/etc/storybook`). The rules are **locked**
(`-e 2`): not even root can change them until the next restart – an intruder can't quietly switch
recording off. Files: `/etc/audit/rules.d/60-…`, `61-…` (setuid programs), `99-…` (the lock). When
the disk is full, recording pauses instead of stopping the server (A5).

**See for yourself.**
```sh
sudo auditctl -s | head -3                       # enabled 2 = locked
sudo ausearch -k ssh-keys -i --start today       # by key: identity, logins, sudo_log_file, …
sudo aureport --summary
```
**Change.** Edit the rules in the repository, run the part, **restart** (the running rules are locked).

## aide (file integrity)

**What and why.** AIDE keeps checksums and attributes of all system files in a database
(`/var/lib/aide/aide.db`). Every night at **05:40** Ubuntu's `dailyaidecheck.timer` runs
`dk-aide-check` (two drop-ins change what Ubuntu's timer runs and when – CIS wants a systemd
timer). It compares the server with the database, renews the database, and sorts every change:
- **explained**: the file belongs to a package installed/updated/removed since the last check
  (`/var/log/dpkg.log`; for removed packages, the list of every package's files from the last check
  is kept – so an old kernel removed by `apt autoremove` isn't an alarm), or updates regenerate it
  (`ld.so.cache`, initrd, grub.cfg, the EFI boot files) and packages were updated, or an install
  script – or you – noted it as changed on purpose
- **sensitive**: unexplained, in a place an intruder would change (users, sudo, SSH, PAM, cron,
  systemd, nginx, `/etc/dk-srv`, the root-owned clones `/opt/dk-*`, programs, `/boot`, `/root`,
  websites in `/var/www`, and every app's `AIDE_SENSITIVE` places) → **urgent
  notification**
- **other**: unexplained elsewhere → log and weekly report

The log says **what** changed for every entry: `(content, size, mtime)` is a real change;
`(inode)` or only times usually is not. Left out entirely: places that change all the time
(uploads, backups, logs, caches, databases) and shell/editor histories (`.bash_history`,
`.viminfo`, …) – see `hardening/files/aide-90-dk-srv` and the apps' `AIDE_EXCLUDE`. The EFI partition (`/boot/efi`) is
checked **without inode numbers**: it's a FAT filesystem, which has none – Linux makes them up at
every mount, so every restart looked like a change.

**See for yourself.**
```sh
systemctl list-timers dailyaidecheck.timer            # next run 05:40
systemctl cat dailyaidecheck.service                  # Ubuntu's unit + our drop-in
sudo tail -30 /var/log/dk-srv/aide-check.log       # what changed, sorted
sudo dk-aide-check                             # run it now (a few minutes)
sudo aide --config /etc/aide/aide.conf -p f:/root/.viminfo   # which rule covers a path
```
**You changed a system file on purpose?** `sudo dk-aide-check expect /etc/the/file` – the next
check counts it as explained.

**Limits.** Someone who is already root could change the database too (A9) – AIDE finds changes made
by others, not by an intruder who knows about it. The notification reaches the phone at once.

## postgres

**What and why** (CIS PostgreSQL 16). PostgreSQL listens only on `localhost`; passwords are stored
as SCRAM; every connection and disconnection is logged (who, which database, from where);
**pgAudit** logs changes to the structure and to roles/rights – not the normal reading and writing
of an app's data (that would put its contents into the log). The databases come from the apps'
settings (`DATABASES`, `DB_OWNER`): only the app's account may connect to its databases; a
restore-test database (`DB_NO_AUDIT`, e.g. the storybook's `storybook_restoretest`) isn't audited.
File: `/etc/postgresql/16/main/conf.d/60-dk-srv-cis.conf`.

**See for yourself.** `sudo -u postgres psql -c 'SHOW pgaudit.log'` ·
`sudo tail /var/log/postgresql/postgresql-16-main.log`

## nginx

**What and why** (CIS NGINX). `nginx/install-nginx.sh` installs what belongs to the **whole
server**; each app installs its own sites (`dk-app-update`, from the app's repository). No domain
is stored in any repository – they're in the server's settings files.
- **default-deny**: requests for the bare IP address or unknown names get **no answer** – HTTP is
  closed (444), HTTPS refuses the handshake before a certificate is shown (scanners don't even
  learn the domain names). Ubuntu's default site is off.
- **all sites** (`conf.d/dk-srv-hardening.conf`): no version in headers, 10 s timeouts for slow
  clients, at most 50 connections per IP; TLS 1.2/1.3 only (`nginx.conf`)
- **the static sites**: one `static-<name>` per file in `/etc/dk-srv/sites.d/` – [next section](#static-sites)
- **the apps' sites** (e.g. the storybook: strict security headers, rate limits, its maintenance
  page): in the app's repository, installed by `dk-app-update`
- every change is checked together (`nginx -t`); if nginx doesn't accept it, every file and link is
  put back as it was

**See for yourself.** `sudo nginx -T | less` · `sudo /opt/dk-srv/nginx/install-nginx.sh --diff`

## Static sites

A website that is just files – e.g. the main domain showing one picture – must not become a way in,
even if someone swaps or removes its files. Its settings: `/etc/dk-srv/sites.d/<name>.conf`
(`NAME`, `ALIASES`, `CERT_NAME`, `REPO`, `SUBDIR` – see `etc/site.conf.example`). Its files come from
their own repository (a private one is fine), the same way as the apps' code: change them
on the laptop, push, then on the server `sudo dk-site-update <name>`.

`dk-site-update` keeps a root-owned clone (`/opt/dk-sites/<name>`, readable only by root – a private
site stays private), pulls, **checks every file**, and only then swaps the whole folder
`/var/www/<name>` at once. nginx serves it with `nginx/static-site.conf`.

| Worry | What prevents it |
|---|---|
| A file is swapped for a script, an HTML page or an SVG (which can contain scripts) | Only HTML, CSS, text, icons and JPEG/PNG/WebP pictures are accepted – each checked by its **content** (`file`), not by its name; anything else stops the update and nothing is installed. nginx serves only these types; SVG isn't one of them, and anything else would be sent as a **download** (`application/octet-stream`), never shown or run. |
| A file that is a picture *and* something else ("polyglot") | It's served as `image/jpeg` with `X-Content-Type-Options: nosniff` (browsers don't guess) and a **Content-Security-Policy without scripts** (`default-src 'none'`) – even an HTML page on this site can't run code. Pictures are rewritten by `exiftool`, which drops anything appended. |
| Someone changes the files on the server | The folder and files belong to **root** (755/644) – not to an app's user, not to nginx. A change not made by `dk-site-update` is an **urgent** AIDE notification (`/var/www` and `/opt/dk-sites` are "sensitive"). |
| Someone changes the files in the repository | They'd need the GitHub account (two-factor). The server only reads (a read-only token); `dk-site-update` shows the new commits; the checks above still apply. |
| A link to another file on the server (`/etc/passwd`) | The update refuses symbolic links; nginx follows none either (`disable_symlinks on`) – 404. |
| A picture is missing | A plain **404**; the page shows nothing in its place. No folder listing ever (`autoindex off`, a folder is a 404). |
| A photo gives away where it was taken | Its metadata (camera, date, **GPS**) is removed on the way to the web; only the rotation and the colour profile stay. The update stops if any GPS/XMP/IPTC data is left. (Strip it before committing too – the repository keeps the original.) |
| Other sites embed it, or it's put in a frame | `Cross-Origin-Resource-Policy: same-origin`, `X-Frame-Options: DENY`, `frame-ancestors 'none'`. |
| Uploads, forms, other methods | Only GET/HEAD (others: 405), body ≤ 1 KB, `form-action 'none'`. |
| A huge file fills the disk | At most 20 MB per file, 100 MB per site; hidden files and folders are refused. |

```sh
sudo dk-site-update <name> --check                     # pull and check only
sudo dk-site-update <name>                             # pull, check, install
sudo /opt/dk-srv/nginx/install-nginx.sh                # the first time: switch the site on in nginx
curl -sI https://<name>/picture.jpg | grep -iE 'content-type|content-security'
```

## Apps on this server

An app tells dk-srv about itself with one file, `/etc/dk-srv/apps.d/<app>.conf` (only `KEY=value`
lines – **read, never run**; `etc/app.conf.example` lists every key): its own user and service, its
code and who owns it, its address, its npm folders, its mode command, its nginx sites, its places to leave out of or watch in
the file integrity check, its backup log, its databases. The nightly check, the weekly report, the
file integrity check, `dk-mode` and the hardening parts (`auditd`, `aide`, `postgres`) read it.

The file is written by the app's own `ops/root/install.sh`, which root runs through
**`sudo dk-app-update <app>`**:
1. it keeps a **root-owned partial clone** of the app's repository with only its `ops/root/` folder
   (`/opt/dk-apps/<app>`: `git clone --filter=blob:none --no-checkout`, then
   `sparse-checkout set --no-cone /ops/root/` – an update there fetches nothing else)
2. it shows the new commits and what changed in `ops/root/`, and asks before running anything
3. it runs `ops/root/install.sh` from that copy, then writes the app's AIDE exclusions
   (`/etc/aide/aide.conf.d/91_dk-app-<app>`)

The app's **mode command** (`MODE_CMD`, e.g. `/usr/local/sbin/storybook-mode`) must be a root-owned
program in `/usr/local/sbin`; dk-srv refuses anything else. It answers `status --short`,
`maintenance`, `normal [--force]`, `stop`, `start`. The nightly check switches an app to maintenance
when its libraries have a critical vulnerability (with `MODE=auto`), and the whole server to
lockdown for a critical one in the server's own packages.

**Each app runs as its own user, in a sandbox.** Its user (`APP_USER`) is a system user: no
password, no shell (`nologin`), no home folder, not in `sudo` – the app's install script creates it.
Its code (`RUNTIME_DIR`, e.g. `/srv/storybook`) belongs to the admin user (`DEPLOY_USER`), who
pulls, installs and builds; the app only reads it, so a hole in the app can't change the code it
runs, nor reach the admin's SSH keys or backups. It runs as a systemd service (`SERVICE`):

| Sandbox setting | What it takes away |
|---|---|
| `ProtectSystem=strict` + `ReadWritePaths=` | the whole file system is read-only for it – except its own data (the storybook's photos) |
| `ProtectHome=yes` | `/home`, `/root` don't exist for it (that's why the code is in `/srv`) |
| `PrivateTmp=yes`, `PrivateDevices=yes` | its own empty `/tmp`; no disks or terminals in `/dev` |
| `NoNewPrivileges=yes`, `CapabilityBoundingSet=` (empty), `RestrictSUIDSGID=yes` | no way to more rights: setuid programs don't work, no capabilities |
| `ProtectKernel*`, `ProtectClock`, `ProtectControlGroups`, `ProtectHostname`, `ProtectProc=invisible` | kernel settings, modules, logs, the clock and other processes are off limits |
| `RestrictNamespaces`, `RestrictRealtime`, `LockPersonality`, `RemoveIPC`, `KeyringMode=private` | no containers of its own, no real-time scheduling, no leftovers between runs |
| `RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6`, `SystemCallFilter=@system-service ~@privileged` | only the network kinds and system calls a normal service uses ("not permitted" otherwise) |

`systemd-analyze security <service>` rates it: the storybook's **1.4 "OK"** (0 = locked down,
10 = unprotected; the same service without these lines: 9.0 "UNSAFE"). What's left is on purpose
and named in the file (network access, Node.js's run-time compiling, `/proc/cpuinfo`).
The nightly drift check (`app_drift`) reports if the service runs as another user, if its user got
a shell or an admin group, or if the sandbox was switched off.

```sh
systemctl show -p User -p NoNewPrivileges -p ProtectSystem storybook
systemd-analyze security storybook            # every setting, and the score at the end
sudo bash -c '. /usr/local/lib/dk-srv/security-lib.sh; app_drift'    # empty = all in place
```

The ntfy topic (`/etc/dk-srv/notify.conf`) is readable for the group `dk-notify` only: the admin
user and the apps' users, which send notifications too.

The app's own business stays in its repository: its backups (the storybook's are encrypted with
`age` to a public key, so the server can't read its own backups), its restore test, its code.

## Watching: the nightly checks

- **Security check** (05:10, `dk-security-check`): known vulnerabilities (Ubuntu `pro cves`, npm
  audit for every app's `NPM_DIRS`), updates, and the **drift check** (`hardening_drift` in
  `security-lib.sh`): is every installed part still as it was? It looks at SSH settings, sysctl
  values and contradicting lines in other sysctl files, the kernel command line (grub.cfg and the
  running one), `/dev/shm`, `/tmp`, home rights, `su`, sudo, files without an existing owner/group
  (not in snaps), PAM and the password rules, Apport masked, the keep-config file, ufw (active,
  outgoing denied, **no unexpected open ports**), auditd, AIDE (database, timer, last check),
  pgAudit, nginx default-deny, AppArmor, and every app's user and sandbox. A change → "Hardening
  changed" (once per change).
- **File integrity** (05:40): see [aide](#aide-file-integrity).
- **Weekly report** (Monday 08:00): all of it in one message – per app its mode, logins, backups and
  restore test, npm, certificate; the static sites; the days left on the read token
  (`GIT_TOKEN_EXPIRES`); and **config files for which an update brought a new version**
  (`*.dpkg-dist` – compare and delete them).
- **SSH logins** (`dk-ssh-notify`, from PAM): every login is a notification.
- **fail2ban**: bans scanners and clients that keep hitting the rate limits, and says so.

```sh
sudo bash -c '. /usr/local/lib/dk-srv/security-lib.sh; hardening_drift'    # empty = all in place
sudo dk-weekly-report --print
sudo dk-mode status
```

---

## Lessons from the first rounds

The first deploy (2026-11-03) left 35 rules failing (84.7 %); after the follow-up (2026-11-05) it
was 14 – the 13 accepted risks and one new one (lesson 12) – 92.4 %, or 99.6 % without the accepted
risks; with lesson 12 fixed, **100 %** without the accepted risks. What was behind them – useful far beyond this server:

1. **A pipe runs in a subshell.** `render file | put_text dest` looked fine, but in bash every part
   of a pipeline runs in its own subshell – what `put_text` remembered (the list of changed files)
   was gone afterwards. So the check "did the boot config change? then run update-grub" never saw
   the change, and AppArmor/audit never reached the kernel command line. Fix: `shopt -s lastpipe`
   (the last part runs in the script itself), and checking the **result** (grub.cfg) instead of
   remembering the action.
2. **Another program can undo a setting at every start.** ufw applies its own sysctl file whenever it
   starts – `log_martians=0`, overriding ours after every restart. The audit also reads every sysctl
   file, so all of them must agree.
3. **Check what the checker reads.** PAM reads `pwquality.conf.d/`, the CIS audit only
   `pwquality.conf`: the rules worked, the audit failed. AIDE 0.18 renamed `database=`, USG's content
   didn't (A12). The rule's source shows what it really tests.
4. **"Recommends" pulls in more than you asked for.** Installing AIDE brought a mail program, which
   brought a whole mail server listening on the internet. Hence `--no-install-recommends` for
   tools, and a look at `ss -tlnp` after every installation.
5. **A safer default can break something quietly.** umask 027 made `echo … | sudo tee
   /etc/storybook/backup.conf` (the storybook's backup key) create a file only root could read –
   and the backup, running as appuser, silently made **unencrypted** backups. Two lessons: files others must read get an
   explicit `chmod`; and a safety feature that can't work must **fail loudly**, never fall back.
6. **Not every filesystem has stable inodes.** FAT (the EFI partition) gets new inode numbers at
   every mount: after the restart, AIDE reported the boot loader as "changed". Knowing *which*
   attribute changed (now in the log) tells a harmless renumbering from a real change.
7. **Updates that stopped.** Changing a package's config file ("conffile") has a hidden cost: when an
   update brings a new version of that file, dpkg asks – and the automatic updates skip the whole
   package instead, including its security fixes. `--force-confdef --force-confold` keeps ours and
   saves theirs as `.dpkg-dist`, and the weekly report lists those.
8. **Idle timeouts are thorough.** `TMOUT` closes idle shells – also inside tmux, which then ends.
   Not a restart, just the timeout doing its job (`journalctl --list-boots` shows real restarts).
9. **Some findings can't be fixed, only explained.** A file in a read-only snap image (A13). The honest
   answer is an accepted risk with a reason – plus our own check for the cases that matter.
10. **Switching a timer on can start it at once.** `Persistent=true` means "catch up on a missed run":
    enabling the AIDE timer in the afternoon started a check right away – while the installer was
    building the database, so the check failed ("cannot get lock"). Now the database is built first,
    under the check's own lock, and a check that finds AIDE busy skips quietly.
11. **A skipped step can leave the old state switched on.** `install-nginx.sh` skipped the picture
    site because its new folder didn't exist yet – and the old config (serving a folder without a
    page: 403) stayed on, with only a line in a long output saying so. Now such warnings name the old
    config and are repeated at the end. Order: the site's files first (`dk-site-update`, it creates
    the folder), then `install-nginx.sh`.
12. **A one-time fix doesn't last when a program keeps making new files.** The log rights were fixed
    on 3 Nov – and sysstat wrote a new, world-readable file every day after. Fix the source (the
    program's own setting), and let the nightly check watch the result.
13. **Audit output is sensitive too.** USG's result files contain the host name, IP and MAC
    addresses; an older facts file contained the domain. They must never land in the repository
    (`.gitignore` now excludes them; `collect-facts.sh` anonymises).
14. **Who can write a script matters as much as what it does.** Root ran the hardening and the
    nightly checks straight from the app user's clone (`~/storybook/ops/…`). Anyone who got that
    user – through a hole in the app – could have edited a script and waited for root to run it. Now
    root runs only root-owned copies (`/opt/dk-srv`, `/opt/dk-apps/<app>`), and the app user stays
    the app user. The same thinking keeps the settings files **parsed, not sourced**: a `KEY=value`
    file that is `source`d is a script.
15. **Separate what changes for different reasons.** One repository held the app, the server and a
    private picture. Splitting them made the app publishable, the server reusable for more apps,
    and the private files private – and the interface between them (`apps.d`, `sites.d`) is now
    written down instead of hidden in paths.
16. **A shared account shares everything.** The storybook's backend ran as the admin user – the
    one with SSH keys, sudo and the backups. A hole in the app would have been a hole in all of
    that. Its own user, without a shell and in a sandbox, turns "the server" into "the photos and
    the app's database" – and `systemd-analyze security` makes the difference measurable
    (9.0 → 1.4).
17. **A safer default meets a new user.** The admin user's umask 027 (lesson 5 again) made the
    storybook's fresh clone `750`/`640` – and its new service user, being "others", couldn't even
    enter the folder: the service failed before its first line of code, with an empty log
    (`status=200/CHDIR` in `systemctl status`). Fixed with a group instead of opening it to
    everyone: the folders belong to the app's group with the setgid bit, so files created later
    inherit it. The sandbox test had umask 022 and missed it – test with the server's defaults.
