#!/bin/bash
# Installs dk-srv's commands, nightly checks and notifications – on the server, from the
# root-owned clone:
#
#   sudo /opt/dk-srv/install.sh
#
# Run it once, and again after every `git pull` in /opt/dk-srv. Safe to repeat: existing settings
# (/etc/dk-srv/*.conf) are kept.
#
# Why copies: the nightly checks run as root, so everything they run is copied to places only root
# can change (and /opt/dk-srv itself belongs to root – no app user can change what root runs):
#   /usr/local/sbin/dk-{notify,mode,security-check,weekly-report,ssh-notify,aide-check,
#                       app-update,site-update,srv-update}
#   /usr/local/lib/dk-srv/security-lib.sh, nginx-lib.sh, cves.py
#   /etc/dk-srv/dk-srv.conf        MODE=trial|auto, ADMIN_USER, GIT_TOKEN_EXPIRES
#   /etc/dk-srv/notify.conf        your ntfy topic – only here, never in a repository
#                                  (root:dk-notify, 640 – the group: the admin user and the apps'
#                                  users, which send notifications too)
#   /etc/dk-srv/apps.d/, sites.d/  one file per app (dk-app-update) / static site (by hand)
#   /etc/cron.d/dk-srv             nightly check 05:10, weekly report Monday 08:00, log rotation
#                                  every hour (the file integrity check at 05:40 is a systemd
#                                  timer: hardening/install-hardening.sh aide)
#   /etc/dk-srv/logrotate.conf     log rotation: sudo.log, /var/log/dk-srv/, the apps' files in
#                                  /etc/dk-srv/logrotate.d/
#   /etc/pam.d/sshd                one line: notification for every SSH login
#   /etc/fail2ban/…                the jails, the scanner filter, the notification action
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "Please run with sudo: sudo $0" >&2; exit 1; fi
HERE=$(cd "$(dirname "$0")" && pwd)
: "${DK_ETC:=/etc/dk-srv}"
warnings=()
step() { echo; echo "== $*"; }
warn() { echo "   WARNING: $*"; warnings+=("$*"); }
if [ "$(stat -c %U "$HERE")" != root ] || [ -n "$(find "$HERE" -maxdepth 2 -perm /022 -not -type l 2>/dev/null | head -1)" ]; then
  warn "$HERE isn't root-owned (or others can write in it) – root should only run code nobody else can change. Clone dk-srv as root to /opt/dk-srv (setup-commands.txt)"
fi

step "1. commands -> /usr/local/sbin, library -> /usr/local/lib/dk-srv (owned by root)"
for f in dk-notify dk-mode dk-security-check dk-weekly-report dk-ssh-notify dk-aide-check dk-app-update dk-site-update dk-srv-update; do
  install -o root -g root -m 755 "$HERE/bin/$f" "/usr/local/sbin/$f"
  echo "   $f"
done
install -d -o root -g root -m 755 /usr/local/lib/dk-srv
for f in security-lib.sh nginx-lib.sh cves.py; do install -o root -g root -m 644 "$HERE/lib/$f" "/usr/local/lib/dk-srv/$f"; done

step "2. settings in $DK_ETC"
install -d -o root -g root -m 755 "$DK_ETC" "$DK_ETC/apps.d" "$DK_ETC/sites.d" "$DK_ETC/logrotate.d"
if [ ! -e "$DK_ETC/dk-srv.conf" ]; then
  install -o root -g root -m 644 "$HERE/etc/dk-srv.conf.example" "$DK_ETC/dk-srv.conf"
  echo "   written: $DK_ETC/dk-srv.conf (MODE=trial, ADMIN_USER=appuser – check it: sudo nano $DK_ETC/dk-srv.conf)"
else
  echo "   $DK_ETC/dk-srv.conf exists ($(grep -E '^MODE=' "$DK_ETC/dk-srv.conf" || echo 'MODE=trial'))"
fi
. "$HERE/lib/security-lib.sh"
# who may read the topic: the group dk-notify – the admin user (its backups and scripts notify) and
# the apps' own users (added by their install scripts)
group=dk-notify
getent group "$group" > /dev/null || { groupadd --system "$group"; echo "   new group $group (may read the ntfy topic)"; }
if getent passwd "$ADMIN_USER" > /dev/null && ! id -nG "$ADMIN_USER" | tr ' ' '\n' | grep -qx "$group"; then
  usermod -aG "$group" "$ADMIN_USER"; echo "   $ADMIN_USER added to $group (applies from its next login)"
fi
conf="$DK_ETC/notify.conf"
if ! grep -qE '^NTFY_TOPIC=[A-Za-z0-9_-]{20,64}$' "$conf" 2>/dev/null; then
  echo "   Your ntfy topic is the long random name you subscribed to in the ntfy app"
  echo "   (e.g. dk-1f3a…; make one with: echo \"dk-\$(openssl rand -hex 16)\")."
  read -rp "   ntfy topic: " topic
  if ! [[ $topic =~ ^[A-Za-z0-9_-]{20,64}$ ]]; then
    echo "   That's not a usable topic (20–64 letters, digits, - or _). Nothing more changed; run again." >&2
    exit 1
  fi
  printf '# ntfy topic for the notifications – keep it secret (written by install.sh)\nNTFY_TOPIC=%s\n' "$topic" > "$conf"
  echo "   written: $conf"
else
  echo "   $conf exists (topic kept)"
fi
chown "root:$group" "$conf"; chmod 640 "$conf"
[ -e "$DK_ETC/git-credentials" ] && { chown root:root "$DK_ETC/git-credentials"; chmod 600 "$DK_ETC/git-credentials"; }

step "3. folders for logs and state"
install -d -o root -g adm -m 750 "$DK_LOG_DIR"
install -d -o root -g root -m 700 "$DK_STATE"

step "4. schedule (cron) and log rotation"
install -o root -g root -m 644 "$HERE/etc/dk-srv.cron" /etc/cron.d/dk-srv
echo "   nightly check 05:10, weekly report Monday 08:00, log rotation every hour"
install -o root -g root -m 644 "$HERE/etc/dk-srv.logrotate" "$DK_ETC/logrotate.conf"
if ! command -v logrotate >/dev/null; then
  warn "logrotate isn't installed: sudo apt install logrotate"
else
  # a dry run ("--debug" changes nothing) to find mistakes, e.g. a folder with wrong permissions
  lr_out=$(logrotate --debug --state "$DK_STATE/logrotate.status" "$DK_ETC/logrotate.conf" 2>&1 || true)
  if lr_errors=$(printf '%s\n' "$lr_out" | grep -iE '^error|: error'); then
    warn "the log rotation has a problem: $lr_errors"
  fi
fi
tz=$(timedatectl show -p Timezone --value 2>/dev/null || cat /etc/timezone 2>/dev/null || true)
if [ "$tz" != Europe/Berlin ]; then
  warn "the server's time zone is $tz, so these times are $tz times. For Berlin time: sudo timedatectl set-timezone Europe/Berlin && sudo systemctl restart cron"
fi
if command -v aide > /dev/null && [ ! -e /etc/systemd/system/dailyaidecheck.service.d/60-dk-srv.conf ]; then
  warn "the file integrity check (05:40) runs from Ubuntu's dailyaidecheck.timer – set it up: sudo $HERE/hardening/install-hardening.sh aide"
fi

step "5. notification for every SSH login (PAM)"
pam_line='session optional pam_exec.so quiet /usr/local/sbin/dk-ssh-notify'
if grep -qF "$pam_line" /etc/pam.d/sshd; then
  echo "   already there"
else
  cp -p /etc/pam.d/sshd "/etc/pam.d/sshd.before-dk-srv"
  printf '\n# dk-srv: notification for every SSH login (bin/dk-ssh-notify)\n%s\n' "$pam_line" >> /etc/pam.d/sshd
  echo "   added to /etc/pam.d/sshd (the previous version: /etc/pam.d/sshd.before-dk-srv)"
fi

step "6. fail2ban: scanner jail, login-rate-limit jail with a notification"
if command -v fail2ban-client >/dev/null 2>&1; then
  backup=$(mktemp -d)
  cp -p /etc/fail2ban/jail.d/dk-srv.local "$backup/" 2>/dev/null || true
  install -o root -g root -m 644 "$HERE/fail2ban/action.d/dk-notify.conf" /etc/fail2ban/action.d/dk-notify.conf
  install -o root -g root -m 644 "$HERE/fail2ban/filter.d/dk-scanners.conf" /etc/fail2ban/filter.d/dk-scanners.conf
  install -o root -g root -m 644 "$HERE/fail2ban/jail.d/dk-srv.local" /etc/fail2ban/jail.d/dk-srv.local
  if fail2ban-client -t >/dev/null 2>&1; then
    systemctl restart fail2ban && echo "   fail2ban restarted (jails: dk-scanners, nginx-limit-req)"
  else
    warn "fail2ban didn't accept the new config (sudo fail2ban-client -t shows why) – the previous jail file was put back"
    rm -f /etc/fail2ban/jail.d/dk-srv.local
    cp -p "$backup"/*.local /etc/fail2ban/jail.d/ 2>/dev/null || true
  fi
  rm -rf "$backup"
else
  warn "fail2ban isn't installed: sudo apt install fail2ban, then run this again"
fi

step "7. checks"
pro_version=$(pro version 2>/dev/null | cut -d. -f1 || true)
if [ -z "$pro_version" ] || [ "$pro_version" -lt 35 ]; then
  warn "the Ubuntu Pro client is too old for 'pro cves' (needs 35+): sudo apt install ubuntu-pro-client"
else
  echo "   pro client $(pro version 2>/dev/null) ok"
fi
[ -e /etc/nginx/sites-available/default-deny ] || warn "nginx's base config isn't installed: sudo $HERE/nginx/install-nginx.sh"
[ -n "$(apps)" ] || echo "   no apps registered yet (sudo dk-app-update <app> https://…)"

# the file integrity check shouldn't report what this script just changed
printf '%s\n' /usr/local/sbin /usr/local/lib/dk-srv /etc/cron.d "$DK_ETC" /etc/pam.d/sshd \
  /etc/pam.d/sshd.before-dk-srv /etc/fail2ban /etc/group /etc/gshadow "$HERE" >> "$DK_STATE/aide-expected"

step "8. test notification"
if /usr/local/sbin/dk-notify "Test from the dk-srv install" \
     "install.sh just ran on the server – notifications work. (No action needed.)" low white_check_mark 2>/dev/null; then
  echo "   sent – it should be on your phone within a few seconds"
else
  warn "the test notification couldn't be sent – see: journalctl -t dk-notify"
fi

echo
if [ ${#warnings[@]} -eq 0 ]; then echo "Done."; else echo "Done, with ${#warnings[@]} warning(s):"; printf ' - %s\n' "${warnings[@]}"; fi
echo "Nightly check: $(grep -E '^MODE=' "$DK_ETC/dk-srv.conf" || echo MODE=trial) (change: sudo nano $DK_ETC/dk-srv.conf)"
echo "Status: sudo dk-mode status · run the check now: sudo dk-security-check"
