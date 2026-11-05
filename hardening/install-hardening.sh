#!/bin/bash
# Hardens the server by CIS Ubuntu 24.04 Level 1 (plus chosen Level 2 rules and the CIS PostgreSQL
# benchmark) – SECURITY.md, HARDENING.md. On the server, from the root-owned clone:
#
#   sudo /opt/dk-srv/hardening/install-hardening.sh --dry-run all     show what would change
#   sudo /opt/dk-srv/hardening/install-hardening.sh <part> [<part> …] change it
#
# Parts, in the order to apply them (each can be run on its own, and again – nothing changes twice):
#   packages   remove what isn't needed (telnet client, VMware tools, the mail server AIDE pulled in),
#              Apport masked, rsync daemon off, package updates keep our changed config files
#   ssh        sshd settings, login banner, root's SSH key moved away       (keep a session open!)
#   kernel     network/memory settings (and the same values in every other sysctl file), unused
#              kernel modules, /dev/shm and /tmp options, no core dumps, AppArmor (and audit) on
#              the kernel command line                                     (full effect after a restart)
#   accounts   umask 027, idle shells close after 15 min, home folder rights, cron/at, su only for
#              root, sudo log, postgres without login shell
#   pam        password quality, lockout after 4 wrong passwords, password history, no empty
#              passwords                                     (keep a root shell open: sudo -i)
#   logging    journald (on disk, 1 GB at most, to rsyslog), time servers, log file rights (also
#              for sysstat's daily files)
#   firewall   outgoing traffic only for what the server needs, loopback rules
#   auditd     the audit system with the CIS rules (Level 2)            (rules locked until restart)
#   aide       file integrity database; Ubuntu's daily AIDE timer runs bin/dk-aide-check
#   postgres   connection logging, pgAudit, no access for others, the restore-test database
#   all        everything above, in that order
#
# Every file is backed up before it changes (/var/backups/dk-srv-hardening/<date-time>/, same
# path inside), and the changed paths are noted for the file integrity check. Run
# `sudo /opt/dk-srv/install.sh` afterwards (it sets up the nightly checks). Files of the names
# before dk-srv (…storybook…) are removed when their dk-srv counterpart is installed.
set -euo pipefail
# `… | put_text` and `… | set_block` must run in this shell, not in a subshell – otherwise what they
# note in changed_paths (for update-grub, the AIDE rebuild and the file integrity check) is lost
# (that's how update-grub was skipped in the first run, HARDENING.md "Lessons")
shopt -s lastpipe

if [ "$(id -u)" -ne 0 ]; then echo "Please run with sudo: sudo $0 $*" >&2; exit 1; fi
HERE=$(cd "$(dirname "$0")" && pwd)
FILES="$HERE/files"
# the administrator (dk-srv.conf: ADMIN_USER), the apps (apps.d) – from dk-srv's library
DK_LIB_SRC="$(dirname "$HERE")/lib/security-lib.sh"
# shellcheck source=../lib/security-lib.sh
. "$DK_LIB_SRC"
id "$ADMIN_USER" > /dev/null 2>&1 || { echo "User $ADMIN_USER (ADMIN_USER in /etc/dk-srv/dk-srv.conf) doesn't exist." >&2; exit 1; }
BACKUP_ROOT=/var/backups/dk-srv-hardening/$(date +%F-%H%M%S)
ALL_PARTS="packages ssh kernel accounts pam logging firewall auditd aide postgres"

dry=no parts=()
for a in "$@"; do
  case "$a" in
    --dry-run) dry=yes ;;
    all) parts+=($ALL_PARTS) ;;
    packages|ssh|kernel|accounts|pam|logging|firewall|auditd|aide|postgres) parts+=("$a") ;;
    *) awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2 ;;
  esac
done
[ ${#parts[@]} -gt 0 ] || { awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next } NR > 1 { exit }' "$0"; exit 2; }

warnings=()
step() { echo; echo "== $*"; }
say() { echo "   $*"; }
warn() { echo "   WARNING: $*"; warnings+=("$*"); }
act() { if [ "$dry" = yes ]; then say "would run: $*"; else "$@"; fi; }
# (for the file integrity check: what these commands change is expected)
note_changed() { [ "$dry" = yes ] || changed_paths+=("$@"); }
changed_paths=()

# backup PATH – a copy before it changes (once per run)
backup() {
  [ -e "$1" ] || [ -L "$1" ] || return 0
  [ -e "$BACKUP_ROOT$1" ] && return 0
  mkdir -p "$BACKUP_ROOT$(dirname "$1")" && cp -a "$1" "$BACKUP_ROOT$1"
}
# render FILE – the repository file with @ADMIN_USER@ / @ADMIN_HOME@ filled in
render() { sed -e "s#@ADMIN_USER@#$ADMIN_USER#g" -e "s#@ADMIN_HOME@#$ADMIN_HOME#g" "$1"; }
# put CONTENT_FILE DEST MODE [OWNER:GROUP] – install if different (shows the difference)
put() {
  local src=$1 dest=$2 mode=$3 owner=${4:-root:root}
  if [ -e "$dest" ] && cmp -s "$src" "$dest" && [ "$(stat -c '%a %U:%G' "$dest")" = "$mode $owner" ]; then
    say "unchanged: $dest"; return 0
  fi
  if [ -e "$dest" ]; then say "changes: $dest"; diff -u "$dest" "$src" | tail -n +3 | sed 's/^/      /' || true
  else say "new: $dest"; fi
  [ "$dry" = yes ] && return 0
  backup "$dest"
  install -d -m 755 "$(dirname "$dest")"
  install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$src" "$dest"
  changed_paths+=("$dest")
}
# put_text DEST MODE [OWNER:GROUP] < content
put_text() { local t; t=$(mktemp); cat > "$t"; put "$t" "$@"; rm -f "$t"; }
# set_block FILE NAME < content – a marked block at the end of a file (replaced on the next run)
set_block() {
  local file=$1 name=$2 t; t=$(mktemp)
  # (also removes the block of the name before dk-srv: "# >>> storybook <name>")
  { [ -e "$file" ] && sed -e "/^# >>> storybook $name/,/^# <<< storybook $name/d" -e "/^# >>> dk-srv $name/,/^# <<< dk-srv $name/d" "$file"
    echo "# >>> dk-srv $name (hardening/install-hardening.sh – don't edit inside)"
    cat
    echo "# <<< dk-srv $name"; } > "$t"
  put "$t" "$file" "$(stat -c '%a' "$file" 2>/dev/null || echo 644)" "$(stat -c '%U:%G' "$file" 2>/dev/null || echo root:root)"
  rm -f "$t"
}
# retire PATH… – a file of the name before dk-srv: backed up and removed (its dk-srv counterpart is
# installed in the same part)
retire() { local p; for p in "$@"; do [ -e "$p" ] || [ -L "$p" ] || continue
  say "removing $p (old name – now ${p//storybook/dk-srv})"; [ "$dry" = yes ] || { backup "$p"; rm -f "$p"; changed_paths+=("$p"); }; done; }
# rename_notes FILE… – the notes our earlier versions left in other packages' files (lines we
# commented out or added) still named the storybook's files; they get dk-srv's names. Only the
# note changes, never a setting.
OLD_NOTES=(
  's|# storybook: commented out – /etc/sysctl.d/60-storybook-cis.conf sets it (CIS, ops/hardening)|# dk-srv: commented out – /etc/sysctl.d/60-dk-srv-cis.conf sets it (CIS, dk-srv hardening)|'
  's|# storybook (CIS 5.3.3.4)|# dk-srv (CIS 5.3.3.4)|'
)
rename_notes() { local f e; for f in "$@"; do [ -f "$f" ] || continue
  grep -qE '# storybook(:| \(CIS)' "$f" || continue
  say "notes in $f: storybook's names -> dk-srv's (only comments)"
  [ "$dry" = yes ] && continue
  backup "$f"; for e in "${OLD_NOTES[@]}"; do sed -i "$e" "$f"; done; changed_paths+=("$f"); done; }
# chmod_to MODE PATH… / chown_to OWNER PATH… – only when different
chmod_to() { local m=$1; shift; for p in "$@"; do [ -e "$p" ] || continue
  if [ "$(stat -c '%a' "$p")" != "${m#0}" ]; then say "rights $(stat -c '%a' "$p") -> $m: $p"; [ "$dry" = yes ] || { backup "$p"; chmod "$m" "$p"; changed_paths+=("$p"); }; fi; done; }
chown_to() { local o=$1; shift; for p in "$@"; do [ -e "$p" ] || continue
  if [ "$(stat -c '%U:%G' "$p")" != "$o" ]; then say "owner $(stat -c '%U:%G' "$p") -> $o: $p"; [ "$dry" = yes ] || { chown "$o" "$p"; changed_paths+=("$p"); }; fi; done; }
apt_install() {   # apt_install [--no-install-recommends] PACKAGE…
  local missing=() extra=()
  [ "${1:-}" = --no-install-recommends ] && { extra=(--no-install-recommends); shift; }
  for p in "$@"; do dpkg-query -W -f='${Status}' "$p" 2>/dev/null | grep -q "ok installed" || missing+=("$p"); done
  [ ${#missing[@]} -eq 0 ] && return 0
  say "installing: ${missing[*]}"
  [ "$dry" = yes ] && return 0
  if [ -z "${APT_UPDATED:-}" ]; then apt-get update -qq; APT_UPDATED=1; fi
  # (never stop to ask: keep existing configuration files)
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${extra[@]}" -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold \
    "${missing[@]}" < /dev/null > /dev/null || { warn "couldn't install ${missing[*]}"; return 1; }
}
installed() { dpkg-query -W -f='${Status}' "$1" 2>/dev/null | grep -q "ok installed"; }
confirm() {  # confirm "question" – in a dry run or without a terminal: no
  [ "$dry" = yes ] && return 0
  [ -t 0 ] || { warn "needs a confirmation in a terminal – skipped"; return 1; }
  local answer; read -rp "   $1 [y/N] " answer; [[ $answer =~ ^[yYjJ]$ ]]
}

# --------------------------------------------------------------------------------------------------
part_packages() {
  step "packages: remove what isn't needed"
  for p in inetutils-telnet telnet; do
    if installed "$p"; then say "removing $p (unencrypted remote login client)"; act env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$p" < /dev/null; fi
  done
  if [ "$(systemd-detect-virt 2>/dev/null || true)" != vmware ]; then
    for p in open-vm-tools; do
      if installed "$p"; then say "removing $p (VMware tools – this isn't a VMware machine)"; act env DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq "$p" < /dev/null; fi
    done
  fi
  apt_install apparmor-utils
  mail_server
  # Apport collects crash reports (with memory contents). CIS checks that it's masked – "disabled"
  # alone isn't enough (anything could start it again). Its helpers (automatic upload, the crash
  # forwarding socket) go with it. Not removed: the package ubuntu-server depends on it.
  local u state
  for u in apport.service apport-autoreport.path apport-autoreport.timer apport-forward.socket; do
    state=$(systemctl is-enabled "$u" 2>/dev/null || true)
    case "$state" in masked|""|not-found) continue ;; esac
    say "$u masked (Apport, crash reports)"; act systemctl mask --now "$u"; note_changed /etc/systemd/system
  done
  [ -e /etc/default/apport ] && grep -q '^enabled=1' /etc/default/apport && { say "/etc/default/apport: enabled=0"; [ "$dry" = yes ] || { backup /etc/default/apport; sed -i 's/^enabled=1/enabled=0/' /etc/default/apport; changed_paths+=(/etc/default/apport); }; }
  # the rsync program stays (the backup copy needs it), its network service doesn't
  if [ "$(systemctl is-enabled rsync.service 2>/dev/null || true)" != masked ] && systemctl cat rsync.service >/dev/null 2>&1; then
    say "rsync daemon (service) masked – rsync over SSH still works"; act systemctl mask --now rsync.service; note_changed /etc/systemd/system
  fi

  step "packages: updates keep our changed configuration files"
  # Some files changed here belong to packages ("conffiles": /etc/ufw/sysctl.conf, /etc/sysctl.d/…,
  # /etc/security/pwquality.conf, /etc/nginx/nginx.conf, /etc/issue, …). When an update brings a new
  # version of such a file, dpkg would stop and ask – and the automatic updates skip the whole
  # package instead, security fixes included. This file makes dpkg keep our version without asking
  # and put the package's new one next to it as <file>.dpkg-dist (the weekly report lists those).
  put "$FILES/apt-60-dk-srv-keep-config" /etc/apt/apt.conf.d/60-dk-srv-keep-config 644
  retire /etc/apt/apt.conf.d/60-storybook-keep-config
}

# A mail server: AIDE's packages recommend a mail program (bsd-mailx), and that pulled in postfix,
# which listens on port 25 for the whole internet (ufw blocks it, but CIS wants no mail server
# listening there). Nothing on this server sends mail – notifications go to the phone (ntfy).
mail_server() {
  installed postfix || return 0
  local auto sim others extra p
  auto=$(apt-mark showauto postfix 2>/dev/null || true)
  # what would a purge of postfix and bsd-mailx take with it? Only those two, nothing else.
  sim=$(apt-get -s purge postfix bsd-mailx 2>/dev/null || true)
  others=$(printf '%s\n' "$sim" | awk '($1 == "Remv" || $1 == "Purg") && $2 != "postfix" && $2 != "bsd-mailx" { print $2 }')
  extra=$(printf '%s\n' "$sim" | awk '$1 == "Inst" { print $2 }')
  if [ "$auto" = postfix ] && [ -z "$others" ] && [ -z "$extra" ]; then
    say "removing postfix and bsd-mailx (mail server pulled in by AIDE's recommendations; nothing here sends mail)"
    if [ "$dry" = no ]; then
      # (for the file integrity check: the files of these packages disappear on purpose)
      for p in postfix bsd-mailx; do
        installed "$p" || continue
        while IFS= read -r f; do [ -d "$f" ] || changed_paths+=("$f"); done < <(dpkg -L "$p" 2>/dev/null)
      done
      changed_paths+=(/etc/postfix /var/spool/postfix /var/lib/postfix /etc/mailname /etc/aliases /etc/aliases.db /etc/systemd/system)
      DEBIAN_FRONTEND=noninteractive apt-get purge -y -qq postfix bsd-mailx < /dev/null > /dev/null || { warn "couldn't remove postfix"; return 1; }
    fi
  else
    # installed on purpose, or something else needs it: keep it, but only for this machine
    if [ "$auto" != postfix ]; then say "postfix was installed on purpose – kept, but only for this machine"
    else say "postfix is needed by: ${others//$'\n'/ }${extra//$'\n'/ } – kept, but only for this machine"; fi
    if [ "$(postconf -h inet_interfaces 2>/dev/null || true)" != loopback-only ]; then
      say "postfix: inet_interfaces = loopback-only (port 25 not on the network)"
      if [ "$dry" = no ]; then backup /etc/postfix/main.cf; postconf -e inet_interfaces=loopback-only; systemctl restart postfix || warn "postfix didn't restart"; changed_paths+=(/etc/postfix/main.cf); fi
    fi
  fi
}

part_ssh() {
  step "ssh: SSH server settings"
  say "Keep this SSH session open until a NEW login has worked."
  render "$FILES/sshd-00-dk-srv.conf" | put_text /etc/ssh/sshd_config.d/00-dk-srv.conf 600
  retire /etc/ssh/sshd_config.d/00-storybook.conf
  put "$FILES/issue.net" /etc/issue.net 644
  put "$FILES/issue.net" /etc/issue 644
  chmod_to 600 /etc/ssh/sshd_config
  for f in /etc/ssh/sshd_config.d/*.conf; do chmod_to 600 "$f"; done
  if [ "$dry" = no ]; then
    if ! sshd -t; then
      warn "sshd doesn't accept the new settings – putting the old file back"
      if [ -e "$BACKUP_ROOT/etc/ssh/sshd_config.d/00-dk-srv.conf" ]; then cp -a "$BACKUP_ROOT/etc/ssh/sshd_config.d/00-dk-srv.conf" /etc/ssh/sshd_config.d/; else rm -f /etc/ssh/sshd_config.d/00-dk-srv.conf; fi
      return 1
    fi
    systemctl reload ssh 2>/dev/null || systemctl restart ssh
    say "applied (running sessions stay). Now, in a NEW terminal on your computer: ssh ${ADMIN_USER}@<server>"
  fi
  # root never logs in by SSH (PermitRootLogin no) – its key isn't needed
  if [ -s /root/.ssh/authorized_keys ]; then
    say "root's SSH key moved to $BACKUP_ROOT/root/.ssh/ (root can't log in by SSH anyway)"
    [ "$dry" = yes ] || { backup /root/.ssh/authorized_keys; rm -f /root/.ssh/authorized_keys; changed_paths+=(/root/.ssh/authorized_keys); }
  fi
}

part_kernel() {
  step "kernel: network and memory settings"
  local t; t=$(mktemp)
  # IPv6 router advertisements: only switch them off if the IPv6 route isn't learned from them
  if ip -6 route show default 2>/dev/null | grep -q 'proto ra'; then
    sed '/@ACCEPT_RA@/d' "$FILES/sysctl-60-dk-srv-cis.conf" > "$t"
    warn "the IPv6 default route comes from router advertisements – accept_ra stays on (accepted risk)"
  else
    sed 's/@ACCEPT_RA@//' "$FILES/sysctl-60-dk-srv-cis.conf" > "$t"
  fi
  put "$t" /etc/sysctl.d/60-dk-srv-cis.conf 644
  retire /etc/sysctl.d/60-storybook-cis.conf
  # The same keys with another value in other files: commented out there. ufw applies its own
  # /etc/ufw/sysctl.conf at every start and reload (log_martians=0 – that undid ours after every
  # restart), procps ships rp_filter=2, and the CIS audit checks every file: all must agree.
  sysctl_contradictions "$t"
  # shellcheck disable=SC2086
  rename_notes $SYSCTL_FILES_GLOB
  rm -f "$t"
  if [ "$dry" = no ]; then
    sysctl --system > /dev/null
    # a later file (e.g. 99-sysctl.conf) could set something else – check what's in effect now
    local key value now
    while IFS='=' read -r key value; do
      [[ $key =~ ^[[:space:]]*(#|$) ]] && continue
      key=${key//[[:space:]]/}; value=${value//[[:space:]]/}
      if ! now=$(sysctl -n "$key" 2>/dev/null); then say "($key doesn't exist on this kernel)"; continue; fi
      [ "$now" = "$value" ] || warn "$key is $now, not $value – another file in /etc/sysctl.d/ overrides it"
    done < /etc/sysctl.d/60-dk-srv-cis.conf
  fi

  step "kernel: modules, /dev/shm and /tmp, core dumps"
  put "$FILES/modprobe-dk-srv-cis.conf" /etc/modprobe.d/dk-srv-cis.conf 644
  put "$FILES/limits-60-dk-srv-cis.conf" /etc/security/limits.d/60-dk-srv-cis.conf 644
  put "$FILES/coredump-60-dk-srv-cis.conf" /etc/systemd/coredump.conf.d/60-dk-srv-cis.conf 644
  retire /etc/modprobe.d/storybook-cis.conf /etc/security/limits.d/60-storybook-cis.conf /etc/systemd/coredump.conf.d/60-storybook-cis.conf
  # /dev/shm: nothing may be run from there; /tmp: its own space in memory (tmpfs), same options.
  # (A real /tmp partition, if there is one, stays as it is.)
  local fstab_t tmp_line="tmpfs /tmp tmpfs defaults,rw,nosuid,nodev,noexec,relatime,size=25%,mode=1777 0 0"
  fstab_t=$(mktemp)
  if grep -E '^[^#[:space:]]+[[:space:]]+/tmp[[:space:]]' /etc/fstab | grep -qvE '^tmpfs[[:space:]]'; then
    tmp_line="# (/tmp has its own partition – left as it is)"
  fi
  grep -vE '^tmpfs[[:space:]]+/(dev/shm|tmp)[[:space:]]' /etc/fstab \
    | grep -vE '^# (>>> (storybook|dk-srv) kernel|<<< (storybook|dk-srv) kernel)' > "$fstab_t" || true
  printf '%s\n' "# >>> dk-srv kernel (hardening/install-hardening.sh, CIS 1.1.2): no device files, setuid or programs" \
    "tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0" "$tmp_line" "# <<< dk-srv kernel" >> "$fstab_t"
  put "$fstab_t" /etc/fstab 644; rm -f "$fstab_t"
  if [ "$dry" = no ]; then
    systemctl daemon-reload
    mount -o remount /dev/shm 2>/dev/null || warn "couldn't apply the /dev/shm options now – they apply after the restart"
    findmnt -kn /tmp > /dev/null || say "/tmp becomes its own tmpfs after the next restart"
  fi

  step "kernel: AppArmor (and audit) on the kernel command line"
  ensure_boot_cmdline
}

# sysctl_contradictions OURS – comments out lines in the other sysctl files that set one of our keys
# (dots or slashes: net.ipv4.x = net/ipv4/x) to another value, with a note. Files that are links
# (99-sysctl.conf -> ../sysctl.conf) are changed once, at their real place.
SYSCTL_FILES_GLOB='/etc/sysctl.conf /etc/ufw/sysctl.conf /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf'
sysctl_contradictions() {
  local ours=$1 f real seen=" " out n
  for f in $SYSCTL_FILES_GLOB; do
    [ -f "$f" ] || continue
    real=$(readlink -f "$f")
    [ "$real" = /etc/sysctl.d/60-dk-srv-cis.conf ] && continue
    [[ $seen == *" $real "* ]] && continue; seen+="$real "
    out=$(mktemp)
    n=$(awk -v note="  # dk-srv: commented out – /etc/sysctl.d/60-dk-srv-cis.conf sets it (CIS, dk-srv hardening)" -v changes="$out.n" '
      function norm(s) { sub(/=.*/, "", s); gsub(/[[:space:]]/, "", s); sub(/^-/, "", s); gsub("/", ".", s); return s }
      function val(s)  { sub(/^[^=]*=/, "", s); gsub(/[[:space:]]/, "", s); return s }
      NR == FNR { if ($0 !~ /^[[:space:]]*[#;]/ && $0 ~ /=/) want[norm($0)] = val($0); next }
      $0 !~ /^[[:space:]]*[#;]/ && $0 ~ /=/ && (norm($0) in want) && val($0) != want[norm($0)] { print "#" $0 note; n++; next }
      { print }
      END { print n + 0 > changes }' "$ours" "$real" > "$out"; cat "$out.n"; rm -f "$out.n")
    if [ "$n" -gt 0 ]; then
      say "$real: $n line(s) contradict ours – commented out:"
      diff "$real" "$out" | sed -n 's/^< /      was: /p' || true
      [ "$dry" = yes ] || { backup "$real"; cat "$out" > "$real"; changed_paths+=("$real"); }
    fi
    rm -f "$out"
  done
}

# The kernel command line: apparmor=1 security=apparmor (CIS 1.3), and audit=1
# audit_backlog_limit=8192 once auditd's rules are installed (CIS 6.3, Level 2). They are set in
# /etc/default/grub.d/60-dk-srv-cis.cfg; update-grub writes them into /boot/grub/grub.cfg – run
# whenever grub.cfg's first entry (the one that boots) doesn't have them, not only when our file
# changed (in the first run of step 15 it was never run).
ensure_boot_cmdline() {
  local audit="" params missing
  [ -e /etc/audit/rules.d/60-dk-srv-cis.rules ] || [ -e /etc/audit/rules.d/60-storybook-cis.rules ] && audit=" audit=1 audit_backlog_limit=8192"
  params="apparmor=1 security=apparmor$audit"
  sed "s/@AUDIT@/$audit/" "$FILES/grub-60-dk-srv-cis.cfg" | put_text /etc/default/grub.d/60-dk-srv-cis.cfg 644
  retire /etc/default/grub.d/60-storybook-cis.cfg
  if ! command -v update-grub > /dev/null; then warn "update-grub not found – the kernel command line isn't set"; return 0; fi
  missing=$(grub_missing "$params")
  if [ -z "$missing" ]; then say "unchanged: /boot/grub/grub.cfg boots with $params"; return 0; fi
  say "/boot/grub/grub.cfg boots without: $missing – update-grub"
  [ "$dry" = yes ] && return 0
  update-grub > /dev/null 2>&1 || { warn "update-grub failed (run it by hand to see why: sudo update-grub)"; return 1; }
  note_changed /boot/grub
  missing=$(grub_missing "$params")
  if [ -z "$missing" ]; then say "boot configuration updated (takes effect after the restart; check then: cat /proc/cmdline)"
  else warn "after update-grub, /boot/grub/grub.cfg still lacks: $missing (does another file in /etc/default/grub.d/ set GRUB_CMDLINE_LINUX without \$GRUB_CMDLINE_LINUX?)"; fi
}
# grub_missing "PARAM …" – the ones not on the first "linux" line of grub.cfg (what the CIS audit checks)
grub_missing() {
  local first p out=""
  first=$(grep -m1 -E '^[[:space:]]*linux[[:space:]]' /boot/grub/grub.cfg 2>/dev/null || true)
  for p in $1; do [[ " $first " == *[[:space:]]"$p"[[:space:]]* ]] || out+="$p "; done
  printf '%s' "${out% }"
}

part_accounts() {
  step "accounts: umask, idle shells, home folder"
  put "$FILES/profile-60-dk-srv-cis.sh" /etc/profile.d/60-dk-srv-cis.sh 644
  retire /etc/profile.d/60-storybook-cis.sh
  if grep -qE '^UMASK[[:space:]]+027' /etc/login.defs; then say "unchanged: /etc/login.defs UMASK 027"
  else say "/etc/login.defs: UMASK 027"; [ "$dry" = yes ] || { backup /etc/login.defs; sed -i -E 's/^UMASK[[:space:]].*/UMASK\t\t027/' /etc/login.defs; changed_paths+=(/etc/login.defs); }; fi
  echo "umask 027" | set_block /etc/bash.bashrc umask
  echo "umask 027" | set_block /etc/profile umask
  if [ "$(useradd -D | sed -n 's/^INACTIVE=//p')" != 45 ]; then say "new accounts: locked 45 days after their password expired"; act useradd -D -f 45; note_changed /etc/default/useradd; fi
  chmod_to 750 "$ADMIN_HOME"
  chmod_to 700 "$ADMIN_HOME/.ssh"
  chmod_to 600 "$ADMIN_HOME/.ssh/authorized_keys"
  for f in "$ADMIN_HOME"/.[!.]*; do [ -f "$f" ] && [ ! -L "$f" ] || continue
    m=$(stat -c '%a' "$f"); want=$(printf '%o' $(( 0$m & 0740 ))); [ "$m" = "$want" ] || chmod_to "$want" "$f"; done
  # postgres is a service account: no login shell (sudo -u postgres psql still works)
  if [ "$(getent passwd postgres | cut -d: -f7)" = /bin/bash ]; then say "postgres: no login shell"; act usermod -s /usr/sbin/nologin postgres; note_changed /etc/passwd /etc/passwd-; fi

  step "accounts: cron and at only for root (and $ADMIN_USER for cron)"
  chmod_to 600 /etc/crontab
  chmod_to 700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
  local cron_group=root; getent group crontab > /dev/null && cron_group=crontab
  printf 'root\n%s\n' "$ADMIN_USER" | put_text /etc/cron.allow 640 "root:$cron_group"
  [ -e /etc/cron.deny ] && { say "removing /etc/cron.deny (cron.allow decides)"; [ "$dry" = yes ] || { backup /etc/cron.deny; rm -f /etc/cron.deny; }; }
  if [ -e /usr/bin/at ]; then
    printf 'root\n' | put_text /etc/at.allow 640 root:root
    [ -e /etc/at.deny ] && { chown_to root:root /etc/at.deny; chmod_to 640 /etc/at.deny; }
  fi

  step "accounts: su only for root, sudo log"
  getent group sugroup > /dev/null || { say "new empty group sugroup (nobody may use su)"; act groupadd sugroup; note_changed /etc/group /etc/group- /etc/gshadow /etc/gshadow-; }
  rename_notes /etc/pam.d/su
  if grep -qE '^[[:space:]]*auth[[:space:]]+required[[:space:]]+pam_wheel\.so.*group=sugroup' /etc/pam.d/su; then say "unchanged: /etc/pam.d/su"
  else
    say "/etc/pam.d/su: only members of sugroup (nobody) may use su – sudo is the way"
    [ "$dry" = yes ] || { backup /etc/pam.d/su
      sed -i '0,/^[[:space:]]*auth[[:space:]].*pam_rootok\.so/{//a auth       required   pam_wheel.so use_uid group=sugroup # dk-srv (CIS 5.3.3.4)
}' /etc/pam.d/su; changed_paths+=(/etc/pam.d/su); }
  fi
  local t; t=$(mktemp); cp "$FILES/sudoers-60-dk-srv-cis" "$t"
  if visudo -cqf "$t"; then put "$t" /etc/sudoers.d/60-dk-srv-cis 440; retire /etc/sudoers.d/60-storybook-cis; else warn "sudo rule file not valid – skipped"; fi
  rm -f "$t"
  [ -e /var/log/sudo.log ] || { say "new: /var/log/sudo.log"; [ "$dry" = yes ] || install -m 600 -o root -g root /dev/null /var/log/sudo.log; }
}

part_pam() {
  step "pam: password quality, lockout, history"
  say "Changes how passwords are checked (sudo, console). Before continuing, open a SECOND"
  say "terminal and run 'sudo -i' there, and keep it open until 'sudo true' works in a new one."
  confirm "Is a root shell open in another terminal?" || { say "skipped"; return 0; }
  apt_install libpam-pwquality libpam-modules
  # the rules as a block in pwquality.conf itself (the CIS audit doesn't read pwquality.conf.d/)
  set_block /etc/security/pwquality.conf cis < "$FILES/pwquality-dk-srv-cis.conf"
  local old=/etc/security/pwquality.conf.d/60-dk-srv-cis.conf
  if [ -e "$old" ]; then
    say "removing $old (its rules are in pwquality.conf now)"
    [ "$dry" = yes ] || { backup "$old"; rm -f "$old"; changed_paths+=("$old"); }
  fi
  printf '%s\n' "deny = 4" "unlock_time = 900" "fail_interval = 900" | set_block /etc/security/faillock.conf lockout
  for f in faillock faillock_notify pwhistory; do put "$FILES/pam-configs/$f" "/usr/share/pam-configs/$f" 644; done
  if grep -q '\bnullok\b' /usr/share/pam-configs/unix 2>/dev/null; then
    say "no login with an empty password (nullok removed from /usr/share/pam-configs/unix)"
    [ "$dry" = yes ] || { backup /usr/share/pam-configs/unix; sed -i -E 's/[[:space:]]+nullok\b//g' /usr/share/pam-configs/unix; changed_paths+=(/usr/share/pam-configs/unix); }
  fi
  if [ "$dry" = no ]; then
    for f in common-auth common-account common-password common-session common-session-noninteractive; do backup "/etc/pam.d/$f"; done
    if ! DEBIAN_FRONTEND=noninteractive pam-auth-update --enable unix faillock faillock_notify pwquality pwhistory; then
      warn "pam-auth-update refused (were /etc/pam.d/common-* edited by hand?) – nothing changed in them"; return 1
    fi
    changed_paths+=(/etc/pam.d/common-auth /etc/pam.d/common-account /etc/pam.d/common-password)
    grep -q 'pam_faillock.so preauth' /etc/pam.d/common-auth && grep -q 'pam_faillock.so authfail' /etc/pam.d/common-auth \
      && grep -q pam_pwquality /etc/pam.d/common-password && grep -q pam_pwhistory /etc/pam.d/common-password \
      && ! grep -q '\bnullok\b' /etc/pam.d/common-auth /etc/pam.d/common-password \
      && say "PAM configuration in place" || warn "PAM configuration incomplete – check /etc/pam.d/common-*"
    say "Now in a NEW terminal: ssh in, then 'sudo -k; sudo true' must ask for the password and work."
    say "If it doesn't: in the root shell copy the files back from $BACKUP_ROOT/etc/pam.d/"
  fi
}

part_logging() {
  step "logging: journald, time servers, log file rights"
  put "$FILES/journald-60-dk-srv-cis.conf" /etc/systemd/journald.conf.d/60-dk-srv-cis.conf 644
  put "$FILES/timesyncd-60-dk-srv-cis.conf" /etc/systemd/timesyncd.conf.d/60-dk-srv-cis.conf 644
  retire /etc/systemd/journald.conf.d/60-storybook-cis.conf /etc/systemd/timesyncd.conf.d/60-storybook-cis.conf
  if [ "$dry" = no ]; then
    systemctl restart systemd-journald
    journalctl --vacuum-size=1G > /dev/null 2>&1 || true
    systemctl restart systemd-timesyncd 2>/dev/null || true
  fi
  # sysstat (performance history for `sar`) writes a new file in /var/log/sysstat/ every day –
  # readable for everyone unless its own setting says otherwise (sa1/sa2 set the umask from it; a
  # one-time chmod doesn't last: on 2026-11-05 that was the last failing CIS rule)
  if [ -e /etc/sysstat/sysstat ]; then
    echo "UMASK=0027" | set_block /etc/sysstat/sysstat cis
  fi
  # log files: not readable for everyone, not writable for the group (except the login records,
  # which have their own rules)
  local n=0
  while IFS= read -r -d '' f; do
    n=$((n + 1)); [ "$dry" = yes ] || chmod g-wx,o-rwx "$f"
  done < <(find /var/log -type f \( -perm /o+rwx -o -perm /g+wx \) ! -name 'wtmp*' ! -name 'btmp*' ! -name 'lastlog*' ! -path '/var/log/journal/*' -print0 2>/dev/null)
  say "log files made private: $n"
}

part_firewall() {
  step "firewall: outgoing only what's needed, loopback rules"
  command -v ufw > /dev/null || { warn "ufw isn't installed"; return 1; }
  local rules=(
    "allow in on lo"
    "allow out on lo"
    "deny in from 127.0.0.0/8"
    "deny in from ::1"
    "allow in proto udp from any port 67 to any port 68 comment DHCP-client"
    "allow out 53 comment DNS"
    "allow out 123/udp comment time-sync"
    "allow out 80/tcp comment http-updates"
    "allow out 443/tcp comment https-updates-npm-ntfy-maps"
    "allow out proto udp to any port 67 comment DHCP-client"
  )
  # git over SSH (a repository address starting with git@ or ssh://): port 22 outgoing too – looked
  # for in dk-srv's clones and the apps' copies; with https:// everywhere, the rule goes
  local origin d ssh_remote=""
  for d in /opt/dk-srv /opt/dk-apps/* /opt/dk-sites/* $(for a in $(apps); do app_get "$a" RUNTIME_DIR; done); do
    [ -d "$d/.git" ] || continue
    origin=$(git -c safe.directory='*' -C "$d" remote get-url origin 2>/dev/null || true)
    [[ $origin == git@* || $origin == ssh://* ]] && ssh_remote+="$d "
  done
  if [ -n "$ssh_remote" ]; then
    rules+=("allow out 22/tcp comment git-over-ssh")
    say "pulled over SSH: ${ssh_remote% } – outgoing SSH stays allowed (switch to https:// to close it)"
  elif ufw status 2>/dev/null | grep -qE '^22/tcp +ALLOW OUT'; then
    say "no repository is pulled over SSH any more – the outgoing SSH rule is removed"
    if [ "$dry" = no ]; then ufw delete allow out 22/tcp > /dev/null 2>&1 || warn "couldn't remove the outgoing SSH rule (sudo ufw status numbered)"; fi
  fi
  say "rules: ${#rules[@]} (see: sudo ufw status verbose)"
  if [ "$dry" = yes ]; then printf '      %s\n' "${rules[@]}"; say "would set: default deny outgoing, deny routed"; return 0; fi
  for r in "${rules[@]}"; do
    # shellcheck disable=SC2086
    ufw $r > /dev/null 2>&1 || { [[ $r == *::1* ]] && say "(no IPv6 rule: $r)" || warn "ufw $r failed"; }
  done
  ufw default deny routed > /dev/null || warn "ufw default deny routed failed"
  ufw default deny outgoing > /dev/null || { warn "ufw default deny outgoing failed"; return 1; }
  ufw reload > /dev/null || warn "ufw reload failed"
  note_changed /etc/ufw /etc/default/ufw
  # does the server still reach what it needs?
  local failed=()
  getent hosts archive.ubuntu.com > /dev/null || failed+=("DNS")
  curl -s -o /dev/null --max-time 15 http://archive.ubuntu.com/ubuntu/ || failed+=("Ubuntu updates (http)")
  curl -s -o /dev/null --max-time 15 https://registry.npmjs.org/ || failed+=("npm (https)")
  curl -s -o /dev/null --max-time 15 https://ntfy.sh/ || failed+=("ntfy (https)")
  curl -s -o /dev/null --max-time 15 -A 'Storybook/1.0' https://tile.openstreetmap.org/0/0/0.png || failed+=("map pictures (https)")
  if [ ${#failed[@]} -eq 0 ]; then say "checked: DNS, updates, npm, notifications and maps still work"
  else warn "not reachable any more: ${failed[*]} – to allow all outgoing again: sudo ufw default allow outgoing"; fi
}

part_auditd() {
  step "auditd: the audit system with the CIS rules"
  apt_install auditd audispd-plugins
  # (rules for programs and places that don't exist here are left out – auditctl would stop at them)
  # (+ each app's sensitive places, AIDE_SENSITIVE in its apps.d file: key app-<app>)
  { render "$FILES/audit-60-dk-srv-cis.rules" | awk '{ p = ""
      if (match($0, /-F path=[^ ]+/)) p = substr($0, RSTART + 8, RLENGTH - 8)
      else if (match($0, /^-w [^ ]+/)) p = substr($0, RSTART + 3, RLENGTH - 3)
      if (p != "" && system("test -e \"" p "\"") != 0) next
      print }'
    for a in $(apps); do for p in $(app_get "$a" AIDE_SENSITIVE); do
      [[ $p =~ ^/[A-Za-z0-9._/@-]+$ ]] && [ -e "$p" ] && echo "-w $p -p wa -k app-$a"; done; done; } \
    | put_text /etc/audit/rules.d/60-dk-srv-cis.rules 640
  # every setuid/setgid program, when run by a person (CIS 6.3.3.6)
  { echo "## Installed by dk-srv hardening/install-hardening.sh: every program that runs with more rights"
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort | while read -r p; do
      echo "-a always,exit -F path=$p -F perm=x -F auid>=1000 -F auid!=unset -k privileged"; done; } \
    | put_text /etc/audit/rules.d/61-dk-srv-privileged.rules 640
  put "$FILES/audit-99-dk-srv-finalize.rules" /etc/audit/rules.d/99-dk-srv-finalize.rules 640
  retire /etc/audit/rules.d/60-storybook-cis.rules /etc/audit/rules.d/61-storybook-privileged.rules /etc/audit/rules.d/99-storybook-finalize.rules
  # its own log: at most 10 × 20 MB; when the disk gets full it pauses recording (CIS wants the
  # server to stop – we prefer the apps keep running; accepted, see SECURITY.md, A5)
  if [ -e /etc/audit/auditd.conf ] && [ "$dry" = no ]; then
    backup /etc/audit/auditd.conf
    local k v
    for kv in "max_log_file=20" "num_logs=10" "max_log_file_action=ROTATE" "space_left_action=SYSLOG" \
              "admin_space_left_action=SUSPEND" "disk_full_action=SUSPEND" "disk_error_action=SYSLOG"; do
      k=${kv%%=*} v=${kv#*=}
      if grep -qE "^${k}[[:space:]]*=" /etc/audit/auditd.conf; then sed -i -E "s/^${k}[[:space:]]*=.*/$k = $v/" /etc/audit/auditd.conf
      else echo "$k = $v" >> /etc/audit/auditd.conf; fi
    done
    changed_paths+=(/etc/audit/auditd.conf)
  fi
  if [ "$dry" = no ]; then
    systemctl enable --now auditd > /dev/null 2>&1 || true
    note_changed /etc/systemd/system
    if auditctl -s 2>/dev/null | grep -q 'enabled 2'; then
      say "the running rules are locked (-e 2): the new ones take effect after the next restart"
    else
      augenrules --load > /dev/null 2>&1 && say "rules loaded: $(auditctl -l | grep -vc '^No rules')" || warn "augenrules --load failed (see: sudo augenrules --check)"
    fi
    # audit=1 on the kernel command line (from the start of booting)
    ensure_boot_cmdline
  fi
}
part_aide() {
  step "aide: file integrity database"
  # (without the recommended mail program – it pulls in a mail server; nothing here sends mail)
  apt_install --no-install-recommends aide aide-common
  render "$FILES/aide-90-dk-srv" | put_text /etc/aide/aide.conf.d/90_dk-srv 644
  retire /etc/aide/aide.conf.d/90_storybook
  if [ "$dry" = no ] && ! aide --config /etc/aide/aide.conf --config-check > /dev/null 2>&1; then
    warn "AIDE doesn't accept its configuration (see: sudo aide --config /etc/aide/aide.conf --config-check)"; return 1
  fi

  # The database first, then the timer: switching the timer on starts a check right away when
  # 05:40 was missed (Persistent=true) – that check and aideinit must not run at the same time (on
  # 2026-11-05 they did: "cannot get lock for file aide.db.new"). aideinit holds the check's own
  # lock, so a check started meanwhile skips quietly.
  if [ "$dry" = no ]; then
    if [ ! -s /var/lib/aide/aide.db ] || [[ " ${changed_paths[*]} " == *" /etc/aide/aide.conf.d/90_dk-srv "* ]]; then
      say "building the database – checksums of all system files, takes 5–20 minutes …"
      mkdir -p "$DK_STATE"
      if flock -w 3600 "$DK_STATE/aide.lock" aideinit -y -f > /dev/null 2>&1; then say "database: /var/lib/aide/aide.db"
      else warn "aideinit failed (see: sudo aideinit -y -f)"; fi
    else
      say "database exists (renewed by every nightly check)"
    fi
  fi

  step "aide: Ubuntu's daily timer runs dk-srv's check"
  # CIS 6.2 wants the check started by a systemd timer (Ubuntu's dailyaidecheck.timer, enabled and
  # active). Two drop-ins change what it runs and when: dk-aide-check (sorts the changes,
  # notifies the phone) instead of Ubuntu's script (mails root), at 05:40. The service unit itself
  # stays Ubuntu's ("static"), the timer is enabled.
  put "$FILES/aide-dailyaidecheck.service.conf" /etc/systemd/system/dailyaidecheck.service.d/60-dk-srv.conf 644
  put "$FILES/aide-dailyaidecheck.timer.conf" /etc/systemd/system/dailyaidecheck.timer.d/60-dk-srv.conf 644
  retire /etc/systemd/system/dailyaidecheck.service.d/60-storybook.conf /etc/systemd/system/dailyaidecheck.timer.d/60-storybook.conf
  local u next
  if [ "$dry" = no ]; then
    systemctl daemon-reload
    for u in dailyaidecheck.service dailyaidecheck.timer; do
      [ "$(systemctl is-enabled "$u" 2>/dev/null || true)" = masked ] && { say "unmasking $u"; systemctl unmask "$u" > /dev/null; }
    done
    systemctl enable --now dailyaidecheck.timer > /dev/null 2>&1 || warn "couldn't switch on dailyaidecheck.timer"
    note_changed /etc/systemd/system
    if [ "$(systemctl is-enabled dailyaidecheck.timer 2>/dev/null)" = enabled ] && systemctl is-active --quiet dailyaidecheck.timer; then
      next=$(systemctl list-timers --all --no-legend dailyaidecheck.timer 2>/dev/null | awk '{ print $1, $2, $3; exit }')
      say "dailyaidecheck.timer: on, every night at 05:40${next:+ (next: $next)}"
    else
      warn "dailyaidecheck.timer isn't enabled and active (see: systemctl status dailyaidecheck.timer)"
    fi
  else
    say "would switch on dailyaidecheck.timer (05:40, runs dk-aide-check)"
  fi
}

part_postgres() {
  step "postgres: logging, pgAudit, access"
  local ver; ver=$(pg_lsclusters -h 2>/dev/null | awk '$2 == "main" { print $1; exit }')
  [ -n "$ver" ] || { warn "no PostgreSQL cluster \"main\" found"; return 1; }
  apt_install "postgresql-$ver-pgaudit"
  put "$FILES/postgresql-60-dk-srv-cis.conf" "/etc/postgresql/$ver/main/conf.d/60-dk-srv-cis.conf" 644 postgres:postgres
  retire "/etc/postgresql/$ver/main/conf.d/60-storybook-cis.conf"
  if [ "$dry" = yes ]; then say "would restart PostgreSQL if its settings changed; each app's databases: only its owner may connect"; return 0; fi
  if [[ " ${changed_paths[*]} " == *"/conf.d/60-dk-srv-cis.conf "* ]]; then
    say "restarting PostgreSQL (a few seconds) …"
    systemctl restart "postgresql@$ver-main" || { warn "PostgreSQL didn't restart – the new settings are in /etc/postgresql/$ver/main/conf.d/60-dk-srv-cis.conf (remove it and restart)"; return 1; }
    sleep 2
    restarted=yes
  fi
  psql_() { sudo -u postgres psql -X -q -v ON_ERROR_STOP=1 "$@"; }
  # (pgAudit works from shared_preload_libraries alone – no CREATE EXTENSION in an app's database,
  # so its dumps stay restorable by the app's own account)
  # each app's databases (DATABASES, DB_OWNER, DB_NO_AUDIT in its apps.d file): created if missing
  # (e.g. a restore-test database), and only the owner may connect – not every account (CIS)
  local a db owner
  for a in $(apps); do
    owner=$(app_get "$a" DB_OWNER)
    [[ $owner =~ ^[a-z_][a-z0-9_]*$ ]] || continue
    for db in $(app_get "$a" DATABASES); do
      [[ $db =~ ^[a-z_][a-z0-9_]*$ ]] || { warn "$a: \"$db\" isn't a database name"; continue; }
      if ! psql_ -tAc "SELECT 1 FROM pg_database WHERE datname = '$db'" | grep -q 1; then
        psql_ -c "CREATE DATABASE $db OWNER $owner" && say "new database $db (owner $owner)" || { warn "couldn't create $db"; continue; }
      fi
      psql_ -c "REVOKE ALL ON DATABASE $db FROM PUBLIC" -c "GRANT CONNECT, TEMPORARY ON DATABASE $db TO $owner" || warn "couldn't change the rights of $db"
    done
    for db in $(app_get "$a" DB_NO_AUDIT); do
      [[ $db =~ ^[a-z_][a-z0-9_]*$ ]] && { psql_ -c "ALTER DATABASE $db SET pgaudit.log = 'none'" || warn "couldn't set pgaudit.log for $db"; }
    done
  done
  say "pgAudit: $(psql_ -tAc "SHOW pgaudit.log" 2>/dev/null || echo '?'); connection logging: $(psql_ -tAc 'SHOW log_connections')"
  # the apps' connections were cut by the restart: start them fresh
  if [ "${restarted:-no}" = yes ]; then
    local proc user
    for a in $(apps); do
      proc=$(app_get "$a" PM2_PROCESS); user=$(app_get "$a" APP_USER)
      [ -n "$proc" ] && [ -n "$user" ] || continue
      if as_user "$user" pm2 restart "$proc" > /dev/null 2>&1; then say "$a restarted"; else warn "couldn't restart $a – as $user: pm2 restart $proc"; fi
    done
  fi
}

# --------------------------------------------------------------------------------------------------
[ "$dry" = yes ] && echo "DRY RUN – nothing is changed."
for p in "${parts[@]}"; do "part_$p" || warn "part $p stopped early"; done

if [ "$dry" = no ] && [ ${#changed_paths[@]} -gt 0 ]; then
  mkdir -p "$DK_STATE"
  # remember which parts are in place (the nightly check watches them) and which files changed on
  # purpose (the file integrity check doesn't report those)
  for p in "${parts[@]}"; do grep -qx "$p" "$DK_STATE/hardening-parts" 2>/dev/null || echo "$p" >> "$DK_STATE/hardening-parts"; done
  printf '%s\n' "${changed_paths[@]}" >> "$DK_STATE/aide-expected"
  mkdir -p /var/log/dk-srv
  { echo "$(date '+%F %T') parts: ${parts[*]}; backup: $BACKUP_ROOT"; printf '   %s\n' "${changed_paths[@]}"; } >> /var/log/dk-srv/hardening.log
  echo; echo "Backup of the old files: $BACKUP_ROOT"
elif [ "$dry" = no ]; then
  for p in "${parts[@]}"; do grep -qx "$p" "$DK_STATE/hardening-parts" 2>/dev/null || echo "$p" >> "$DK_STATE/hardening-parts"; done
fi
echo
if [ ${#warnings[@]} -eq 0 ]; then echo "Done."; else echo "Done, with ${#warnings[@]} warning(s):"; printf ' - %s\n' "${warnings[@]}"; fi
