#!/bin/bash
# Installs the server's own nginx configuration – on the server:
#
#   sudo /opt/dk-srv/nginx/install-nginx.sh          show what changes, install, check, reload nginx
#   sudo /opt/dk-srv/nginx/install-nginx.sh --diff   only show what would change
#
# What belongs to the whole server (the apps install their own sites: dk-app-update):
#   /etc/nginx/conf.d/dk-srv-hardening.conf      settings for all sites (nginx/http-hardening.conf)
#   /etc/nginx/sites-available/default-deny      no answer for the bare IP address or unknown names
#                                                (nginx/default-deny.conf) – switched on; Ubuntu's
#                                                "default" site is switched off
#   /etc/nginx/sites-available/static-<name>     one hardened static site per /etc/dk-srv/sites.d/
#                                                <name>.conf (nginx/static-site.conf), served from
#                                                /var/www/<name> – its files come from dk-site-update
# and in /etc/nginx/nginx.conf only TLS 1.2 and 1.3 are allowed. Everything is checked together
# (nginx -t); if nginx doesn't accept it, every file and link is put back as it was.
#
# /etc/dk-srv/sites.d/<name>.conf (etc/site.conf.example):
#   NAME=example.org                the site's address – must be in the certificate
#   ALIASES="www.example.org"       other names, only redirected to https://NAME
#   CERT_NAME=example.org           the certificate's folder in /etc/letsencrypt/live/
#   REPO=https://github.com/…       where dk-site-update gets the files from
#   SUBDIR=site                     the folder in the repository that holds them
set -euo pipefail

: "${NGINX_DIR:=/etc/nginx}"
: "${LETSENCRYPT_DIR:=/etc/letsencrypt}"
: "${DK_LIB:=/usr/local/lib/dk-srv}"
if [ "$(id -u)" -ne 0 ]; then echo "Please run with sudo: sudo $0 $*" >&2; exit 1; fi
only_diff=""
case "${1:-}" in --diff) only_diff=--diff ;; "") ;; *) echo "Usage: sudo $0 [--diff]" >&2; exit 1 ;; esac
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib/security-lib.sh
. "$DK_LIB/security-lib.sh"
# shellcheck source=../lib/nginx-lib.sh
. "$DK_LIB/nginx-lib.sh"

warnings=()
warn() { echo "   WARNING: $*"; warnings+=("$*"); }
valid_domain() { [[ $1 =~ ^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$ ]]; }
work=$(mktemp -d); trap 'rm -rf "$work"' EXIT

# --- settings for all sites (without the ones nginx.conf already sets – a second one would fail)
cp "$HERE/http-hardening.conf" "$work/http-hardening.conf"
for d in $(grep -oE '^[a-z_]+' "$work/http-hardening.conf" | sort -u); do
  if grep -qE "^[[:space:]]*${d}[[:space:]]" "$NGINX_DIR/nginx.conf" 2>/dev/null; then
    sed -i -E "s/^(${d}[[:space:]].*)$/# (set in nginx.conf) \1/" "$work/http-hardening.conf"
    echo "   note: $d is set in nginx.conf – that value stays"
  fi
done
plan_file "$NGINX_DIR/conf.d/dk-srv-hardening.conf" "$work/http-hardening.conf"

# --- default-deny instead of Ubuntu's default site
cp "$HERE/default-deny.conf" "$work/default-deny"
plan_file "$NGINX_AVAILABLE/default-deny" "$work/default-deny"
plan_link default-deny
plan_unlink default

# --- only TLS 1.2 and 1.3, also for sites that don't set it themselves
if grep -qE '^[[:space:]]*ssl_protocols[^;]*TLSv1(\.1)?[[:space:];]' "$NGINX_DIR/nginx.conf" 2>/dev/null; then
  sed -E 's/^([[:space:]]*)ssl_protocols[^;]*;.*/\1ssl_protocols TLSv1.2 TLSv1.3; # dk-srv: no TLS 1.0\/1.1 (CIS NGINX)/' "$NGINX_DIR/nginx.conf" > "$work/nginx.conf"
  plan_file "$NGINX_DIR/nginx.conf" "$work/nginx.conf"
fi

# --- static sites (/etc/dk-srv/sites.d/<name>.conf)
for site in $(sites); do
  name=$(site_get "$site" NAME); cert=$(site_get "$site" CERT_NAME); aliases=$(site_get "$site" ALIASES)
  root="/var/www/$name"
  if [ "$name" != "$site" ] || ! valid_domain "$name"; then warn "sites.d/$site.conf: NAME must be the file's name and a domain – skipped"; continue; fi
  [[ $cert =~ ^[A-Za-z0-9._-]+$ ]] || { warn "site $name: CERT_NAME missing – skipped"; continue; }
  cert_names=$(openssl x509 -noout -ext subjectAltName -in "$LETSENCRYPT_DIR/live/$cert/fullchain.pem" 2>/dev/null | grep -oE 'DNS:[^,[:space:]]+' | cut -c5- || true)
  if ! printf '%s\n' "$cert_names" | grep -qxF "$name"; then warn "site $name isn't in the certificate $cert – skipped (add it with certbot first)"; continue; fi
  ok_aliases=""
  for a in $aliases; do valid_domain "$a" && ok_aliases+=" $a" || warn "site $name: \"$a\" isn't a name – left out"; done
  if [ ! -e "$root/index.html" ]; then
    warn "site $name: no $root/index.html yet – the site answers 404 until there is one (sudo dk-site-update $name)"
  fi
  sed -e "/^[[:space:]]*#/!{s#@NAME@#$name#g; s#@ROOT@#$root#g; s#@CERT@#$cert#g; s#@ALIASES@#$ok_aliases#g;}" \
    "$HERE/static-site.conf" > "$work/static-$name"
  plan_file "$NGINX_AVAILABLE/static-$name" "$work/static-$name"
  plan_link "static-$name"
done

nginx_apply $only_diff
if [ ${#warnings[@]} -gt 0 ]; then echo; echo "${#warnings[@]} warning(s):"; printf ' - %s\n' "${warnings[@]}"; fi
