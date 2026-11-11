# shellcheck shell=bash
# Shared parts of the dk-srv commands (dk-security-check, dk-mode, dk-weekly-report, dk-aide-check,
# dk-app-update, dk-site-update, and the apps' own mode commands). Installed by install.sh to
# /usr/local/lib/dk-srv/security-lib.sh (owned by root) and read by those scripts – not run on its
# own.
#
# Every path can be changed with an environment variable of the same name (only used for testing).
# shellcheck disable=SC2034 # MODE, ADMIN_HOME … are used by the scripts that read this file

: "${DK_ETC:=/etc/dk-srv}"
: "${DK_STATE:=/var/lib/dk-srv}"
: "${DK_LOG_DIR:=/var/log/dk-srv}"
: "${NGINX_DIR:=/etc/nginx}"
: "${NOTIFY_BIN:=/usr/local/sbin/dk-notify}"
: "${CVES_PY:=/usr/local/lib/dk-srv/cves.py}"
: "${DK_TEST:=}"
APPS_DIR="$DK_ETC/apps.d"
SITES_DIR="$DK_ETC/sites.d"

# --- settings: /etc/dk-srv/dk-srv.conf (see etc/dk-srv.conf.example) --------------------------
# conf_get FILE KEY – the value of KEY=… (last one wins; quotes and a trailing comment removed).
# The files are read, never run (`.`): only KEY=value lines count.
conf_get() {
  [ -r "$1" ] || return 0
  sed -nE "s/^[[:space:]]*$2[[:space:]]*=[[:space:]]*(.*)$/\1/p" "$1" | tail -1 \
    | sed -E 's/[[:space:]]+#.*$//; s/[[:space:]]+$//; s/^"(.*)"$/\1/'"; s/^'(.*)'$/\1/"
}
MODE=$(conf_get "$DK_ETC/dk-srv.conf" MODE)
case "$MODE" in auto|trial) ;; *) MODE=trial ;; esac
ADMIN_USER=$(conf_get "$DK_ETC/dk-srv.conf" ADMIN_USER)
: "${ADMIN_USER:=appuser}"
ADMIN_HOME=$(getent passwd "$ADMIN_USER" 2>/dev/null | cut -d: -f6)
: "${ADMIN_HOME:=/home/$ADMIN_USER}"
GIT_TOKEN_EXPIRES=$(conf_get "$DK_ETC/dk-srv.conf" GIT_TOKEN_EXPIRES)

log() { printf '%s %s\n' "$(date '+%F %T')" "$*"; }

# notify "Title" "Message" [priority] [tags] – never fails
notify() {
  log "notify: $1 – $(printf '%s' "$2" | head -1)"
  "$NOTIFY_BIN" "$@" >/dev/null 2>&1 || true
}

need_root() {
  if [ -z "$DK_TEST" ] && [ "$(id -u)" -ne 0 ]; then
    echo "Please run this with sudo: sudo $(basename "$0") $*" >&2
    exit 1
  fi
}

# as_user USER COMMAND… – runs a command as another user (npm belongs to the code's owner)
as_user() {
  local user=$1; shift
  if [ -n "$DK_TEST" ]; then "$@"; return; fi
  local home; home=$(getent passwd "$user" | cut -d: -f6)
  runuser -u "$user" -- env HOME="$home" PATH=/usr/local/bin:/usr/bin:/bin "$@"
}

# HTTP status code of an address ("000" = no answer)
http_code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$1" 2>/dev/null || true; }

# --- the apps (/etc/dk-srv/apps.d/<app>.conf, written by each app's ops/root/install.sh) -------
# Keys (see etc/app.conf.example): APP_USER SERVICE RUNTIME_DIR DEPLOY_USER SITE_URL LOGIN_PATH NPM_DIRS
# NODE MODE_CMD NGINX_SITES AIDE_EXCLUDE AIDE_SENSITIVE BACKUP_LOG RESTORE_TEST_LOG DATABASES
# DB_OWNER DB_NO_AUDIT
apps() {
  local f
  for f in "$APPS_DIR"/*.conf; do
    [ -f "$f" ] || continue
    f=${f##*/}; f=${f%.conf}
    [[ $f =~ ^[a-z0-9][a-z0-9-]*$ ]] && echo "$f"
  done
}
app_get() { conf_get "$APPS_DIR/$1.conf" "$2"; }

# The app's mode command – run only if it's a root-owned program in /usr/local/sbin that nobody
# else can change (the app file names it; root must never run something an app user could replace)
app_mode_cmd() {
  local cmd; cmd=$(app_get "$1" MODE_CMD)
  [ -n "$cmd" ] || return 1
  [[ $cmd =~ ^/usr/local/sbin/[a-z0-9-]+$ ]] || return 1
  if [ -z "$DK_TEST" ]; then
    [ -x "$cmd" ] && [ "$(stat -c %u "$cmd")" = 0 ] && [ -z "$(find "$cmd" -perm /022 2>/dev/null)" ] || return 1
  fi
  echo "$cmd"
}
# app_service APP – the app's systemd service (SERVICE=…), only a plain unit name
app_service() {
  local svc; svc=$(app_get "$1" SERVICE)
  [[ $svc =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || return 1
  echo "$svc"
}
# app_main_pid APP – the process ID of the app's running service (empty if it's not running)
app_main_pid() {
  local svc pid; svc=$(app_service "$1") || return 0
  pid=$(systemctl show -p MainPID --value "$svc" 2>/dev/null)
  [ -n "$pid" ] && [ "$pid" != 0 ] && echo "$pid"
  return 0
}
# app_restart APP – restarts the app's service (if it's running; returns 1 if that fails)
app_restart() {
  local svc; svc=$(app_service "$1") || return 1
  systemctl try-restart "$svc"
}
# app_mode APP – normal | maintenance | stopped | ? (asks the app's mode command)
app_mode() {
  local cmd; cmd=$(app_mode_cmd "$1") || { echo "?"; return; }
  "$cmd" status --short 2>/dev/null | head -1 || echo "?"
}

# --- static sites (/etc/dk-srv/sites.d/<name>.conf: NAME ALIASES CERT_NAME REPO SUBDIR) ---------
sites() {
  local f
  for f in "$SITES_DIR"/*.conf; do
    [ -f "$f" ] || continue
    f=${f##*/}; echo "${f%.conf}"
  done
}
site_get() { conf_get "$SITES_DIR/$1.conf" "$2"; }

# normal | lockdown (the whole web server off – dk-mode)
server_mode() {
  if [ "$(systemctl is-enabled nginx 2>/dev/null)" = masked ]; then echo lockdown; else echo normal; fi
}

# --- remembering what was already reported (so the same problem isn't sent every night) -------
# keys are free text without tabs, e.g. "cve nginx CVE-2026-1234"
already_reported() { [ -f "$DK_STATE/reported" ] && grep -qxF "$1" "$DK_STATE/reported"; }
mark_reported() {
  mkdir -p "$DK_STATE"
  already_reported "$1" || printf '%s\n' "$1" >> "$DK_STATE/reported"
}

# --- the checks (used by the nightly check and by `dk-mode normal`) -------------------------------

# Packages that face the internet: a severe hole in these without a fix -> lockdown
FACING='^(nginx|nginx-.*|libnginx-mod-.*|openssl|libssl[0-9].*)$'

# Ubuntu's known problems: "package priority origin cve" per line (origin "-" = no fix yet).
# Writes nothing and returns 1 if `pro cves` doesn't work.
pro_cves() {
  local out
  out=$(pro cves "$@" 2>/dev/null) || return 1
  printf '%s\n' "$out" | awk 'NR == 1 && $1 == "Package" { next } NF >= 4 && $4 ~ /^(CVE|USN)-/ { print $1, $2, $3, $4 }'
}

# Severe problems without a fix in internet-facing packages: "package priority cve" per line;
# returns 1 if `pro cves` doesn't work
facing_unfixable() {
  local list
  list=$(pro_cves --unfixable) || return 1
  printf '%s\n' "$list" | awk -v re="$FACING" '$1 ~ re && ($2 == "high" || $2 == "critical") { print $1, $2, $4 }'
}

# nginx/OpenSSL packages with an update waiting
facing_upgradable() {
  apt list --upgradable 2>/dev/null | awk -F/ 'NR > 1 { print $1 }' | grep -E "$FACING" || true
}

# npm audit of one folder of an app (only what's used when running): "critical high moderate low"
# plus the names of the affected packages; returns 1 if npm audit didn't answer
npm_audit() {   # npm_audit APP DIR
  local app=$1 dir=$2 user root json
  # as the code's owner (DEPLOY_USER; it installed the packages), not the app's service user
  user=$(app_get "$app" DEPLOY_USER); [ -n "$user" ] || user=$(app_get "$app" APP_USER)
  root=$(app_get "$app" RUNTIME_DIR)
  [ -n "$user" ] && [ -d "$root/$dir" ] || return 1
  json=$(cd "$root/$dir" && as_user "$user" npm audit --omit=dev --json 2>/dev/null) || true
  printf '%s' "$json" | python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    counts = data["metadata"]["vulnerabilities"]
except Exception:
    sys.exit(1)
names = {s: sorted(n for n, v in data.get("vulnerabilities", {}).items() if v.get("severity") == s)
         for s in ("critical", "high")}
print(counts.get("critical", 0), counts.get("high", 0), counts.get("moderate", 0), counts.get("low", 0),
      ",".join(names["critical"]) or "-", ",".join(names["high"]) or "-")
'
}

# Remembers the problems found now as accepted (false alarms that don't matter here), so the
# nightly check doesn't switch maintenance/lockdown on again for them. New problems still do.
# The list: /var/lib/dk-srv/accepted (delete a line to un-accept).
# Used by `dk-security-check --accept`, `dk-mode normal --force` and the apps' `… normal --force`.
accept_current() {
  local list cve app dir result key
  mkdir -p "$DK_STATE"
  touch "$DK_STATE/accepted"
  if list=$(facing_unfixable); then
    for cve in $(echo "$list" | awk '{ print $3 }'); do
      grep -qxF "cve $cve" "$DK_STATE/accepted" || echo "cve $cve" >> "$DK_STATE/accepted"
    done
  fi
  for app in $(apps); do
    for dir in $(app_get "$app" NPM_DIRS); do
      if result=$(npm_audit "$app" "$dir") && [ "$(echo "$result" | cut -d' ' -f1)" -gt 0 ]; then
        key="npm $app/$dir $(echo "$result" | cut -d' ' -f5)"
        grep -qxF "$key" "$DK_STATE/accepted" || echo "$key" >> "$DK_STATE/accepted"
      fi
    done
  done
  echo "Accepted (won't switch maintenance mode/lockdown on again):"
  if [ -s "$DK_STATE/accepted" ]; then sed 's/^/  /' "$DK_STATE/accepted"; else echo "  nothing"; fi
}

# --- is the hardening still in place? -----------------------------------------------------------
# Prints one line per setting that's no longer as hardening/install-hardening.sh left it
# ("what: detail"), for the parts that were installed ($DK_STATE/hardening-parts). Nothing = all fine.
# Updates of Ubuntu packages can occasionally undo a setting (e.g. pam-auth-update) – this finds it.
hardening_drift() {
  local parts="$DK_STATE/hardening-parts" v
  [ -s "$parts" ] || return 0
  has() { grep -qx "$1" "$parts"; }
  if has ssh; then
    local sshd; sshd=$(sshd -T 2>/dev/null)
    for kv in "permitrootlogin no" "passwordauthentication no" "maxauthtries 4" "x11forwarding no" \
              "allowtcpforwarding no" "disableforwarding yes" "allowusers $ADMIN_USER"; do
      printf '%s\n' "$sshd" | grep -qx "$kv" || echo "SSH: ${kv%% *} is no longer \"${kv#* }\""
    done
  fi
  if has kernel; then
    for kv in net.ipv4.ip_forward=0 net.ipv4.conf.all.send_redirects=0 net.ipv4.conf.all.accept_redirects=0 \
              net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.log_martians=1 fs.suid_dumpable=0 kernel.randomize_va_space=2; do
      v=$(sysctl -n "${kv%%=*}" 2>/dev/null) || continue
      [ "$v" = "${kv#*=}" ] || echo "kernel: ${kv%%=*} is $v, not ${kv#*=}"
    done
    findmnt -kno OPTIONS /dev/shm 2>/dev/null | grep -q noexec || echo "kernel: /dev/shm without noexec"
    sysctl_contradicting
    local want="apparmor=1 security=apparmor"; has auditd && want+=" audit=1 audit_backlog_limit=8192"
    v=$(cmdline_missing "$want" "$(grep -m1 -E '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg 2>/dev/null)")
    if [ -n "$v" ]; then echo "kernel: /boot/grub/grub.cfg boots without $v (sudo update-grub)"
    else
      v=$(cmdline_missing "$want" "$(cat /proc/cmdline 2>/dev/null)")
      [ -z "$v" ] || echo "kernel: running without $v – it's in grub.cfg, takes effect after the next restart"
    fi
    if findmnt -kn /tmp > /dev/null 2>&1; then
      findmnt -kno OPTIONS /tmp | grep -q noexec || echo "kernel: /tmp without noexec"
    elif [ "$(stat -c %Y /etc/fstab)" -lt "$(date -d "$(uptime -s)" +%s)" ]; then
      echo "kernel: /tmp isn't its own tmpfs (see /etc/fstab)"
    fi
  fi
  if has accounts; then
    [ "$(stat -c %a "$ADMIN_HOME")" = 750 ] || echo "accounts: $ADMIN_HOME is $(stat -c %a "$ADMIN_HOME"), not 750"
    [ ! -d "$ADMIN_HOME/.ssh" ] || [ "$(stat -c %a "$ADMIN_HOME/.ssh")" = 700 ] || echo "accounts: $ADMIN_HOME/.ssh is $(stat -c %a "$ADMIN_HOME/.ssh"), not 700"
    grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sugroup' /etc/pam.d/su || echo "accounts: su is no longer restricted (/etc/pam.d/su)"
    [ -z "$(getent group sugroup | cut -d: -f4)" ] || echo "accounts: the group sugroup has members: $(getent group sugroup | cut -d: -f4)"
    [ -e /etc/sudoers.d/60-dk-srv-cis ] || echo "accounts: /etc/sudoers.d/60-dk-srv-cis is missing"
    [ -s /root/.ssh/authorized_keys ] && echo "accounts: root has an SSH key again (/root/.ssh/authorized_keys)"
    v=$(unowned_files | head -5 | paste -sd' ')
    [ -z "$v" ] || echo "files without an existing owner or group (CIS 7.1): $v"
  fi
  if has pam; then
    grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth || echo "PAM: the lockout after wrong passwords is gone (common-auth)"
    grep -q pam_pwquality /etc/pam.d/common-password || echo "PAM: the password quality check is gone (common-password)"
    grep -qw nullok /etc/pam.d/common-auth /etc/pam.d/common-password && echo "PAM: empty passwords allowed again (nullok)"
    grep -qE '^[[:space:]]*minlen[[:space:]]*=[[:space:]]*14' /etc/security/pwquality.conf 2>/dev/null && grep -qx 'enforce_for_root' /etc/security/pwquality.conf \
      || echo "PAM: the password rules are gone from /etc/security/pwquality.conf"
  fi
  if has packages; then
    if [ -e /usr/share/apport/apport ] || systemctl cat apport.service > /dev/null 2>&1; then
      [ "$(systemctl is-enabled apport.service 2>/dev/null)" = masked ] || echo "packages: Apport (apport.service) isn't masked"
    fi
    [ -e /etc/apt/apt.conf.d/60-dk-srv-keep-config ] || echo "packages: /etc/apt/apt.conf.d/60-dk-srv-keep-config is missing (updates may stop at changed config files)"
  fi
  if has logging; then
    v=$(open_log_files | head -5 | paste -sd' ')
    [ -z "$v" ] || echo "logging: files in /var/log readable for others or writable for the group (CIS 6.1, at most 640): $v"
  fi
  if has firewall; then
    v=$(ufw status verbose 2>/dev/null)
    printf '%s\n' "$v" | grep -q '^Status: active' || echo "firewall: ufw is not active"
    printf '%s\n' "$v" | grep -q 'deny (outgoing)' || echo "firewall: outgoing traffic is allowed again"
    v=$(network_listeners | paste -sd' ')
    [ -z "$v" ] || echo "network: unexpected open port(s) (only SSH, HTTP, HTTPS expected): $v"
  fi
  if has auditd; then
    systemctl is-active --quiet auditd || echo "auditd: not running"
  fi
  if has aide; then
    [ -s /var/lib/aide/aide.db ] || echo "AIDE: no database"
    { [ "$(systemctl is-enabled dailyaidecheck.timer 2>/dev/null)" = enabled ] && systemctl is-active --quiet dailyaidecheck.timer 2>/dev/null; } \
      || echo "AIDE: dailyaidecheck.timer isn't enabled and active (the nightly check doesn't run)"
    if [ -s "$DK_STATE/aide-history" ]; then
      v=$(tail -1 "$DK_STATE/aide-history" | cut -d' ' -f1)
      [ "$(( ($(date +%s) - $(date -d "$v" +%s)) / 86400 ))" -le 2 ] || echo "AIDE: last check on $v"
    fi
  fi
  if has postgres; then
    v=$(sudo -u postgres psql -XAtc "SHOW shared_preload_libraries" 2>/dev/null) || v="?"
    [[ $v == *pgaudit* ]] || [ "$v" = "?" ] || echo "PostgreSQL: pgAudit isn't loaded"
  fi
  if [ -e "$NGINX_DIR/sites-available/default-deny" ]; then
    [ -e "$NGINX_DIR/sites-enabled/default" ] && echo "nginx: Ubuntu's default site is switched on again"
    [ -L "$NGINX_DIR/sites-enabled/default-deny" ] || echo "nginx: default-deny is switched off"
  fi
  command -v aa-enabled > /dev/null && [ "$(aa-enabled 2>/dev/null)" != Yes ] && echo "AppArmor: not enabled"
  app_drift
  return 0
}

# Every app's service still runs as the app's own user – not root, not the admin user – and that
# user still can't log in or use sudo; the service's sandbox is still switched on. One line per problem.
app_drift() {
  local a svc user shell
  for a in $(apps); do
    svc=$(app_service "$a") || continue
    user=$(app_get "$a" APP_USER)
    [ "$(systemctl show -p User --value "$svc" 2>/dev/null)" = "$user" ] || echo "$a: $svc doesn't run as $user any more"
    case "$user" in root|"$ADMIN_USER"|"") echo "$a: APP_USER is \"$user\" – the app must have its own user" ;; esac
    shell=$(getent passwd "$user" | cut -d: -f7)
    [[ $shell == */nologin || $shell == */false ]] || echo "$a: $user can log in (shell: ${shell:-none})"
    id -nG "$user" 2>/dev/null | tr ' ' '\n' | grep -qxE 'sudo|admin|adm' && echo "$a: $user is in an admin group ($(id -nG "$user"))"
    [ "$(systemctl show -p NoNewPrivileges --value "$svc" 2>/dev/null)" = yes ] && \
      [ "$(systemctl show -p ProtectSystem --value "$svc" 2>/dev/null)" = strict ] || echo "$a: the sandbox of $svc is off (NoNewPrivileges/ProtectSystem)"
  done
}

# cmdline_missing "PARAM …" "LINE" – the parameters that aren't words of LINE
cmdline_missing() {
  local p out=""
  for p in $1; do [[ " $2 " == *[[:space:]]"$p"[[:space:]]* ]] || out+="$p "; done
  printf '%s' "${out% }"
}

# Our sysctl keys set to another value in another sysctl file (slashes or dots), e.g. after an
# update brought back ufw's or procps' file: "kernel: FILE sets KEY to VALUE (ours: VALUE)"
: "${SYSCTL_OURS:=/etc/sysctl.d/60-dk-srv-cis.conf}"
: "${SYSCTL_FILES:=/etc/sysctl.conf /etc/ufw/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf}"
sysctl_contradicting() {
  local f real seen=" "
  [ -r "$SYSCTL_OURS" ] || return 0
  # shellcheck disable=SC2086 # (the list holds globs)
  for f in $SYSCTL_FILES; do
    [ -f "$f" ] || continue
    real=$(readlink -f "$f")
    [ "$real" = "$(readlink -f "$SYSCTL_OURS")" ] && continue
    [[ $seen == *" $real "* ]] && continue; seen+="$real "
    awk -v file="$real" '
      function norm(s) { sub(/=.*/, "", s); gsub(/[[:space:]]/, "", s); sub(/^-/, "", s); gsub("/", ".", s); return s }
      function val(s)  { sub(/^[^=]*=/, "", s); gsub(/[[:space:]]/, "", s); return s }
      NR == FNR { if ($0 !~ /^[[:space:]]*[#;]/ && $0 ~ /=/) want[norm($0)] = val($0); next }
      $0 !~ /^[[:space:]]*[#;]/ && $0 ~ /=/ && (norm($0) in want) && val($0) != want[norm($0)] {
        printf "kernel: %s sets %s to %s (ours: %s – run the part kernel again)\n", file, norm($0), val($0), want[norm($0)] }' "$SYSCTL_OURS" "$real"
  done
}

# Listening network ports other than SSH (22), HTTP (80), HTTPS (443) and the DHCP clients (UDP 68,
# 546): "tcp/25 (master)" per line. Only addresses reachable from the network count (not 127.x, ::1).
network_listeners() {
  ss -Htulnp 2>/dev/null | awk '{
      proto = $1; local = $5; port = local; sub(/.*:/, "", port); addr = local; sub(/:[^:]*$/, "", addr)
      if (addr ~ /^(127\.|\[::1\]|::1)/ || addr ~ /%lo$/) next
      if (proto == "tcp" && (port == 22 || port == 80 || port == 443)) next
      if (proto == "udp" && (port == 68 || port == 546)) next
      name = ""; if (match($0, /\(\("[^"]+"/)) name = " (" substr($0, RSTART + 3, RLENGTH - 4) ")"
      key = proto "/" port name; if (!(key in seen)) { seen[key] = 1; print key } }'
}

# Files on the local disks whose owner or group doesn't exist (CIS 7.1.12/13), like the CIS audit
# looks for them – but not inside the snaps (/snap/…: read-only images; core22's ssh-agent belongs
# to a group that only exists inside the snap, accepted risk A13).
unowned_files() {
  local nodev m
  nodev=$(awk '/nodev/ { print $2 }' /proc/filesystems 2>/dev/null | paste -sd,)
  { findmnt -n -l -k -it "$nodev" -o TARGET 2>/dev/null; findmnt -kn -o TARGET,FSTYPE /tmp 2>/dev/null | awk '$2 == "tmpfs" { print $1 }'; } \
    | sort -u | while read -r m; do
      case "$m" in /snap|/snap/*|/var/snap/*) continue ;; esac
      timeout 600 find "$m" -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | grep -vE '^/snap/' | head -5
    done
}

# Files in /var/log more open than 640 (CIS 6.1.4.1), with the exceptions the CIS audit makes on
# Ubuntu 24.04 (login records, apt's history, cloud-init's log …)
: "${VAR_LOG:=/var/log}"
open_log_files() {
  find "$VAR_LOG" -type f -perm /0137 ! -name 'history.log*' ! -name 'eipp.log.xz*' ! -name '[bw]tmp' ! -name '[bw]tmp.*' \
    ! -name '[bw]tmp-*' ! -name 'lastlog' ! -name 'lastlog.*' ! -name 'cloud-init.log*' ! -name 'localmessages*' \
    ! -name 'waagent.log*' -print 2>/dev/null | sort
}

# --- the root-owned clones (dk-srv itself, the apps' root parts, the static sites) ------------------
# git_root DIR ARGS… – git as root in a root-owned clone; the read token for private repositories
# (/etc/dk-srv/git-credentials, root only) is used when it exists
git_root() {
  local dir=$1; shift
  if [ -r "$DK_ETC/git-credentials" ]; then
    git -C "$dir" -c credential.helper= -c "credential.helper=store --file=$DK_ETC/git-credentials" "$@"
  else
    git -C "$dir" "$@"
  fi
}
# git_follow DIR – brings a root-owned clone to what its repository has now. Not `git pull`: these
# clones are never changed on the server, and a rewritten history (a force push, e.g. after
# removing a file from all commits with git filter-repo) must not make the update stuck.
git_follow() {
  local dir=$1 branch
  branch=$(git -C "$dir" rev-parse --abbrev-ref HEAD) || return 1
  git_root "$dir" fetch -q origin "$branch" || return 1
  if ! git -C "$dir" merge-base --is-ancestor HEAD FETCH_HEAD 2>/dev/null; then
    echo "   note: the repository's history was rewritten (force push) – taking it as it is now"
  fi
  git_root "$dir" reset -q --hard FETCH_HEAD && git -C "$dir" clean -qfdx   # (a partial clone fetches files here: token)
}
# git_clone URL DIR [ARGS…] – the first clone (same token rule)
git_clone() {
  local url=$1 dir=$2; shift 2
  if [ -r "$DK_ETC/git-credentials" ]; then
    git -c credential.helper= -c "credential.helper=store --file=$DK_ETC/git-credentials" clone -q "$@" "$url" "$dir"
  else
    git clone -q "$@" "$url" "$dir"
  fi
}
# a repository address dk-srv accepts: https only (no ssh: the firewall keeps outgoing SSH closed)
valid_repo_url() { [[ $1 =~ ^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$ ]] || [[ -n $DK_TEST && $1 == file://* ]]; }
