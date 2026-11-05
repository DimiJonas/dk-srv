#!/bin/bash
# One-time move from the storybook repository's own server scripts (ops/security, ops/hardening,
# before 2026-11) to dk-srv – on the server, after cloning dk-srv to /opt/dk-srv (setup-commands.txt,
# "Moving from the storybook's scripts"):
#
#   sudo /opt/dk-srv/migrate/from-storybook.sh --dry-run    show what it would do
#   sudo /opt/dk-srv/migrate/from-storybook.sh              do it
#
# It moves the server's settings, memory and logs to dk-srv's places and runs dk-srv's install.sh,
# which replaces the old commands (storybook-notify, -security-check, … -> dk-*), cron, the PAM
# line and fail2ban:
#   /etc/storybook/notify.conf               -> /etc/dk-srv/notify.conf
#   /etc/storybook/security-check.conf       -> /etc/dk-srv/dk-srv.conf (MODE kept)
#   /etc/storybook/usg-tailoring.xml         -> /etc/dk-srv/usg-tailoring.xml
#   STATIC_SITE=… in /etc/storybook/site.conf -> /etc/dk-srv/sites.d/<name>.conf
#   /var/lib/storybook/*                     -> /var/lib/dk-srv/ (only the app's mode stays)
#   /var/log/storybook/*                     -> /var/log/dk-srv/
# The app's own settings stay where they are (/etc/storybook/site.conf, backup.conf, uploads/,
# clientbuild/). Afterwards (it prints them): the hardening parts again (they rename their files),
# the storybook's root parts (dk-app-update), the static site, nginx, a restart.
# Safe to run again: what's already moved is left alone.
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then echo "Please run with sudo: sudo $0 $*" >&2; exit 1; fi
HERE=$(cd "$(dirname "$0")/.." && pwd)
dry=no; [ "${1:-}" = --dry-run ] && dry=yes
OLD_ETC=/etc/storybook OLD_STATE=/var/lib/storybook OLD_LOG=/var/log/storybook
NEW_ETC=/etc/dk-srv NEW_STATE=/var/lib/dk-srv NEW_LOG=/var/log/dk-srv
say() { echo "   $*"; }
act() { if [ "$dry" = yes ]; then say "would: $*"; else "$@"; fi; }
[ "$dry" = yes ] && echo "DRY RUN – nothing is changed."
admin=${SUDO_USER:-appuser}
[ "$admin" = root ] && admin=appuser

echo "== 1. settings: $OLD_ETC -> $NEW_ETC"
act install -d -o root -g root -m 755 "$NEW_ETC" "$NEW_ETC/apps.d" "$NEW_ETC/sites.d" "$NEW_ETC/logrotate.d"
if [ -e "$OLD_ETC/notify.conf" ] && [ ! -e "$NEW_ETC/notify.conf" ]; then
  say "notify.conf (the ntfy topic) moved"; act mv "$OLD_ETC/notify.conf" "$NEW_ETC/notify.conf"
fi
if [ ! -e "$NEW_ETC/dk-srv.conf" ]; then
  mode=$(sed -nE 's/^[[:space:]]*MODE[[:space:]]*=[[:space:]]*([a-z]+).*/\1/p' "$OLD_ETC/security-check.conf" 2>/dev/null | tail -1)
  say "dk-srv.conf written: MODE=${mode:-trial}, ADMIN_USER=$admin, NOTIFY_GROUP=$admin"
  if [ "$dry" = no ]; then
    sed -e "s/^MODE=.*/MODE=${mode:-trial}/" -e "s/^ADMIN_USER=.*/ADMIN_USER=$admin/" -e "s/^NOTIFY_GROUP=.*/NOTIFY_GROUP=$admin/" \
      "$HERE/etc/dk-srv.conf.example" > "$NEW_ETC/dk-srv.conf"
    chmod 644 "$NEW_ETC/dk-srv.conf"
  fi
fi
[ -e "$OLD_ETC/security-check.conf" ] && { say "security-check.conf removed (its MODE is in dk-srv.conf)"; act rm -f "$OLD_ETC/security-check.conf"; }
if [ -e "$OLD_ETC/usg-tailoring.xml" ] && [ ! -e "$NEW_ETC/usg-tailoring.xml" ]; then
  say "usg-tailoring.xml moved"; act mv "$OLD_ETC/usg-tailoring.xml" "$NEW_ETC/usg-tailoring.xml"
fi
[ -e "$OLD_ETC/logrotate.conf" ] && { say "logrotate.conf removed (dk-srv's: $NEW_ETC/logrotate.conf, the storybook's: logrotate.d/storybook)"; act rm -f "$OLD_ETC/logrotate.conf"; }

echo "== 2. static sites: STATIC_SITE lines -> $NEW_ETC/sites.d/"
cert=$(sed -nE 's/^[[:space:]]*CERT_NAME[[:space:]]*=[[:space:]]*([A-Za-z0-9._-]+).*/\1/p' "$OLD_ETC/site.conf" 2>/dev/null | tail -1)
while read -r name folder aliases; do
  [ -n "$name" ] || continue
  if [ -e "$NEW_ETC/sites.d/$name.conf" ]; then say "$name: already in sites.d"; continue; fi
  say "$name -> $NEW_ETC/sites.d/$name.conf (REPO= still empty – fill it in, see below)"
  [ "$folder" = "/var/www/$name" ] || say "   NOTE: it was served from $folder; dk-srv serves /var/www/$name (dk-site-update fills it)"
  if [ "$dry" = no ]; then
    printf '%s\n' "# static site (moved from STATIC_SITE in $OLD_ETC/site.conf by migrate/from-storybook.sh)" \
      "NAME=$name" "ALIASES=\"$aliases\"" "CERT_NAME=$cert" "# where dk-site-update gets the files from, e.g. https://github.com/<you>/<repo>" \
      "REPO=" "SUBDIR=site" > "$NEW_ETC/sites.d/$name.conf"
    chmod 644 "$NEW_ETC/sites.d/$name.conf"
  fi
done < <(sed -nE 's/^[[:space:]]*STATIC_SITE[[:space:]]*=[[:space:]]*([^#]*).*/\1/p' "$OLD_ETC/site.conf" 2>/dev/null)
if grep -qE '^[[:space:]]*STATIC_SITE' "$OLD_ETC/site.conf" 2>/dev/null; then
  say "STATIC_SITE lines in $OLD_ETC/site.conf commented out"
  act sed -i -E 's/^([[:space:]]*STATIC_SITE.*)$/# (moved to \/etc\/dk-srv\/sites.d\/) \1/' "$OLD_ETC/site.conf"
fi

echo "== 3. memory: $OLD_STATE -> $NEW_STATE (the storybook's own mode stays)"
act install -d -o root -g root -m 700 "$NEW_STATE"
if [ -d "$OLD_STATE" ]; then
  for f in "$OLD_STATE"/*; do
    [ -e "$f" ] || continue
    b=${f##*/}
    case "$b" in
      mode) continue ;;                               # the storybook's maintenance mode: the app's
      npm-server|npm-client|check.lock|aide.lock) act rm -f "$f"; continue ;;   # renewed by the next check
    esac
    if [ -e "$NEW_STATE/$b" ]; then say "$b: already there"; continue; fi
    say "$b"; act mv "$f" "$NEW_STATE/$b"
  done
fi

echo "== 4. logs: $OLD_LOG -> $NEW_LOG"
act install -d -o root -g adm -m 750 "$NEW_LOG"
if [ -d "$OLD_LOG" ]; then
  for f in "$OLD_LOG"/*; do
    [ -e "$f" ] || continue
    [ -e "$NEW_LOG/${f##*/}" ] && continue
    act mv "$f" "$NEW_LOG/"
  done
  [ "$dry" = no ] && rmdir "$OLD_LOG" 2>/dev/null && say "$OLD_LOG removed (empty)"
fi

if [ "$dry" = no ]; then
  # (for the file integrity check: all this was on purpose)
  printf '%s\n' "$OLD_ETC" "$NEW_ETC" "$OLD_STATE" "$NEW_STATE" >> "$NEW_STATE/aide-expected"
  echo "== 5. dk-srv's commands, cron, log rotation, PAM, fail2ban (install.sh)"
  "$HERE/install.sh"
fi

cat <<EOF

Next (setup-commands.txt, "Moving from the storybook's scripts"):
  1. the storybook's root parts (registers it in apps.d – the hardening parts use that):
       sudo dk-app-update storybook https://github.com/<you>/storybook
  2. the hardening parts again – they rename their files (…storybook… -> …dk-srv…):
       sudo $HERE/hardening/install-hardening.sh --dry-run all
       sudo $HERE/hardening/install-hardening.sh packages ssh kernel accounts logging firewall postgres
       sudo $HERE/hardening/install-hardening.sh pam        (root shell open in a second terminal)
       sudo $HERE/hardening/install-hardening.sh auditd aide   (aide last: rebuilds its database)
  3. the static site: fill in REPO= in $NEW_ETC/sites.d/<name>.conf, then
       sudo dk-site-update <name> && sudo $HERE/nginx/install-nginx.sh
  4. sudo reboot (the audit rules are locked until then), then: sudo dk-mode status
EOF
