#!/bin/bash
# Collects the facts for a hardening review – on the server:
#
#   sudo /opt/dk-srv/hardening/collect-facts.sh
#
# READ-ONLY: it only looks (settings, permissions, open ports, …) and changes nothing. It writes
# one text file into your home folder (only you can read it) to send for the review:
#   ~/dk-srv-facts-<date>.txt
#
# Never in the file: the apps' .env files, /etc/dk-srv/notify.conf (ntfy topic), the read token,
# password hashes, keys. Made anonymous before writing: every domain of the server (the apps'
# addresses, the static sites, the certificates' names) becomes example.com (example2.com, …) – with
# its subdomains kept (storybook.example.com); the server's name becomes "server", public IP
# addresses become <ip>.
#
# What it covers: Ubuntu (CIS Ubuntu 24.04 Level 1 Server), SSH, nginx and TLS (CIS NGINX,
# Mozilla/BSI TLS), PostgreSQL (CIS PostgreSQL 16), dk-srv itself, each app in /etc/dk-srv/apps.d/
# (its files, processes, backups), the static sites, and – if it was run – the result of the USG CIS
# audit (sudo usg audit cis_level1_server).
set -uo pipefail   # no -e: a missing tool is noted, the collection goes on

if [ "$(id -u)" -ne 0 ]; then echo "Please run with sudo: sudo $0" >&2; exit 1; fi
HERE=$(cd "$(dirname "$0")" && pwd)
# shellcheck source=../lib/security-lib.sh
. "$(dirname "$HERE")/lib/security-lib.sh"
WHO=${SUDO_USER:-$ADMIN_USER}
WHO_HOME=$(getent passwd "$WHO" | cut -d: -f6)
OUT="$WHO_HOME/dk-srv-facts-$(date +%F).txt"
RAW=$(mktemp); trap 'rm -f "$RAW"' EXIT
exec 3>"$RAW"

section() { printf '\n\n########## %s\n' "$*" >&3; }
run() {   # run "label" command… – output (or why not) into the file
  local label=$1; shift
  printf '\n--- %s\n' "$label" >&3
  if ! command -v "$1" >/dev/null 2>&1; then echo "(not installed: $1)" >&3; return; fi
  timeout 120 "$@" >&3 2>&1 || echo "(exit code $?)" >&3
}
sh_() { run "$1" bash -c "$2"; }
psql_() { sudo -u postgres psql -X -A -F ' | ' -P footer=off -c "$1" 2>&1; }

echo "Collecting (read-only, takes a minute or two) …"

section "System"
sh_ "Ubuntu, kernel, virtualisation" 'lsb_release -ds; uname -r; systemd-detect-virt || true; uptime -p'
sh_ "Ubuntu Pro services" 'pro status 2>/dev/null | grep -E "^[a-z0-9-]+ +(yes|no|enabled|disabled|n/a|—)" || echo "(pro not available)"'
sh_ "reboot needed?" '[ -e /var/run/reboot-required ] && cat /var/run/reboot-required* || echo no'
sh_ "restarts (the last boots)" 'journalctl --list-boots --no-pager 2>/dev/null | tail -5'
sh_ "installed kernels" 'dpkg-query -W -f="\${Status} \${Package} \${Version}\n" "linux-image-*" 2>/dev/null | awk "/ok installed/ {print \$4, \$5}"'
sh_ "updates waiting" 'apt list --upgradable 2>/dev/null | tail -n +2 | wc -l'
sh_ "automatic updates" 'cat /etc/apt/apt.conf.d/20auto-upgrades 2>/dev/null; grep -HE "^[^/]*(Automatic-Reboot|Allowed-Origins|Origins-Pattern|\"\\$\\{distro_id\\})" /etc/apt/apt.conf.d/5* 2>/dev/null | sed "s#^/etc/apt/apt.conf.d/##" | head -30; echo "--- DPkg::Options (keep changed config files):"; apt-config dump 2>/dev/null | grep -i "^DPkg::Options"'
sh_ "time sync" 'timedatectl show -p Timezone -p NTP -p NTPSynchronized; systemctl is-active systemd-timesyncd chrony 2>/dev/null'

section "Filesystems and kernel (CIS 1.1, 1.5, 3.3)"
sh_ "mounts (/, /tmp, /var, /var/tmp, /var/log, /home, /dev/shm)" 'for m in / /tmp /var /var/tmp /var/log /var/log/audit /home /dev/shm; do printf "%-16s " "$m"; findmnt -kn -o FSTYPE,OPTIONS --target "$m" 2>/dev/null | head -1 || echo "-"; findmnt -kn "$m" >/dev/null 2>&1 || echo "    (not its own mount)"; done; swapon --show'
sh_ "kernel modules CIS wants off (loaded? / blocked?)" 'for m in cramfs freevxfs hfs hfsplus jffs2 udf usb-storage squashfs overlay dccp sctp rds tipc; do printf "%-12s loaded=%s  modprobe=%s\n" "$m" "$(lsmod | grep -qw "${m//-/_}" && echo yes || echo no)" "$(modprobe -n -v "$m" 2>&1 | tail -1)"; done'
sh_ "sysctl" 'sysctl net.ipv4.ip_forward net.ipv4.conf.all.send_redirects net.ipv4.conf.default.send_redirects net.ipv4.conf.all.accept_redirects net.ipv4.conf.default.accept_redirects net.ipv4.conf.all.secure_redirects net.ipv4.conf.default.secure_redirects net.ipv4.conf.all.accept_source_route net.ipv4.conf.default.accept_source_route net.ipv4.conf.all.log_martians net.ipv4.conf.default.log_martians net.ipv4.conf.all.rp_filter net.ipv4.conf.default.rp_filter net.ipv4.icmp_echo_ignore_broadcasts net.ipv4.icmp_ignore_bogus_error_responses net.ipv4.tcp_syncookies net.ipv6.conf.all.forwarding net.ipv6.conf.all.accept_ra net.ipv6.conf.default.accept_ra net.ipv6.conf.all.accept_redirects net.ipv6.conf.default.accept_redirects net.ipv6.conf.all.accept_source_route kernel.randomize_va_space kernel.yama.ptrace_scope kernel.kptr_restrict kernel.dmesg_restrict fs.suid_dumpable fs.protected_hardlinks fs.protected_symlinks fs.protected_fifos fs.protected_regular kernel.unprivileged_bpf_disabled 2>&1'
sh_ "sysctl files" 'ls -la /etc/sysctl.d/ /etc/sysctl.conf 2>&1; grep -hvE "^\s*(#|;|$)" /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null'
sh_ "sysctl lines in ufw's and procps' files (ufw applies its file at every start)" 'grep -HnE "martians|rp_filter|redirects" /etc/ufw/sysctl.conf /etc/sysctl.d/10-network-security.conf 2>/dev/null'
sh_ "kernel command line (running, and what grub.cfg boots next)" 'echo "running: $(cat /proc/cmdline)"; echo "grub.cfg: $(grep -m1 -E "^[[:space:]]*linux[[:space:]]" /boot/grub/grub.cfg | sed -E "s/^[[:space:]]+//")"; for p in apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192; do printf "%-28s running=%s grub.cfg=%s\n" "$p" "$(grep -qw -- "$p" /proc/cmdline && echo yes || echo no)" "$(grep -m1 -E "^[[:space:]]*linux[[:space:]]" /boot/grub/grub.cfg | grep -qw -- "$p" && echo yes || echo no)"; done; echo "--- /etc/default/grub.d:"; grep -H "GRUB_CMDLINE" /etc/default/grub /etc/default/grub.d/*.cfg 2>/dev/null'
sh_ "firmware and EFI partition" '[ -d /sys/firmware/efi ] && echo "booted with: EFI" || echo "booted with: BIOS"; findmnt -kn -o TARGET,FSTYPE,OPTIONS /boot/efi 2>/dev/null || echo "(no /boot/efi mount)"; find /boot/efi -maxdepth 3 2>/dev/null | head -20'
sh_ "core dumps" 'grep -hvE "^\s*(#|$)" /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null | grep -i core; systemctl is-active apport 2>/dev/null; grep -hE "^(Storage|ProcessSizeMax)" /etc/systemd/coredump.conf /etc/systemd/coredump.conf.d/* 2>/dev/null; dpkg -l systemd-coredump 2>/dev/null | grep ^ii'
sh_ "AppArmor" 'aa-status 2>/dev/null | head -8 || echo "(aa-status not available)"; cat /sys/module/apparmor/parameters/enabled 2>/dev/null'
sh_ "bootloader config permissions" 'stat -c "%a %U:%G %n" /boot/grub/grub.cfg 2>&1; grep -c "^password" /boot/grub/grub.cfg 2>/dev/null; grep -h "^set superusers" /boot/grub/grub.cfg 2>/dev/null | sed "s/=.*/=…/"'

section "Services, ports, packages (CIS 2)"
sh_ "listening ports" 'ss -tulpnH'
sh_ "running services" 'systemctl list-units --type=service --state=running --no-legend --no-pager | awk "{print \$1}"'
sh_ "enabled services" 'systemctl list-unit-files --type=service --state=enabled --no-legend --no-pager | awk "{print \$1}"'
sh_ "timers" 'systemctl list-timers --all --no-legend --no-pager | awk "{print \$(NF-1), \$NF}"'
sh_ "packages CIS asks about (installed ones)" 'dpkg-query -W -f="\${Status} \${Package}\n" avahi-daemon cups isc-dhcp-server slapd nfs-kernel-server bind9 vsftpd apache2 dovecot-core samba squid snmpd nis rsync talk telnet telnetd rsh-client ldap-utils xserver-xorg-core ftp tnftp postfix exim4 xinetd autofs 2>/dev/null | grep "install ok installed" | awk "{print \$NF}"'
sh_ "mail server listening only locally?" 'ss -ltnH "( sport = :25 or sport = :465 or sport = :587 )"; echo "--- mail packages (installed automatically?):"; for p in postfix bsd-mailx; do dpkg-query -W -f="\${Status}" "$p" 2>/dev/null | grep -q "ok installed" && echo "$p installed$(apt-mark showauto "$p" | grep -q . && echo ", automatically")"; done; true'
sh_ "Apport (crash reports) units" 'for u in apport.service apport-autoreport.path apport-autoreport.timer apport-forward.socket; do printf "%-28s %s %s\n" "$u" "$(systemctl is-enabled "$u" 2>/dev/null)" "$(systemctl is-active "$u" 2>/dev/null)"; done'
sh_ "config files with a newer package version waiting (*.dpkg-dist, *.ucf-dist)" 'find /etc -xdev \( -name "*.dpkg-dist" -o -name "*.ucf-dist" -o -name "*.dpkg-new" -o -name "*.dpkg-old" \) 2>/dev/null | sort; true'

section "Firewall and fail2ban (CIS 4)"
sh_ "ufw" 'ufw status verbose 2>&1'
sh_ "nftables / iptables present" 'dpkg-query -W -f="\${Status} \${Package}\n" nftables iptables iptables-persistent 2>/dev/null | grep "ok installed"'
sh_ "fail2ban jails" 'for j in $(fail2ban-client status 2>/dev/null | sed -n "s/.*Jail list:\s*//p" | tr "," " "); do printf "%-20s bantime=%s findtime=%s maxretry=%s\n" "$j" "$(fail2ban-client get $j bantime)" "$(fail2ban-client get $j findtime)" "$(fail2ban-client get $j maxretry)"; done'

section "SSH (CIS 5.1)"
sh_ "sshd effective settings" 'out=$(sshd -T 2>&1); printf "%s\n" "$out" | grep -qiE "^permitrootlogin " || printf "%s\n" "$out" | head -3; printf "%s\n" "$out" | grep -iE "^(port|listenaddress|addressfamily|permitrootlogin|passwordauthentication|kbdinteractiveauthentication|pubkeyauthentication|authenticationmethods|permitemptypasswords|permituserenvironment|hostbasedauthentication|ignorerhosts|maxauthtries|maxsessions|maxstartups|logingracetime|clientaliveinterval|clientalivecountmax|x11forwarding|allowtcpforwarding|allowagentforwarding|disableforwarding|gssapiauthentication|usepam|loglevel|banner|ciphers|macs|kexalgorithms|hostkeyalgorithms|pubkeyacceptedalgorithms|allowusers|allowgroups|denyusers|denygroups) " | sort'
sh_ "sshd config files" 'ls -la /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ 2>&1; stat -c "%a %U:%G %n" /etc/ssh/ssh_host_*_key 2>&1'
sh_ "SSH keys of the administrator (count and types, no keys)" "awk '{print \$1}' \"$ADMIN_HOME/.ssh/authorized_keys\" 2>/dev/null | sort | uniq -c; stat -c '%a %U:%G %n' \"$ADMIN_HOME/.ssh\" \"$ADMIN_HOME/.ssh/authorized_keys\" 2>&1; ls /root/.ssh/authorized_keys 2>/dev/null && awk '{print \"root:\", \$1}' /root/.ssh/authorized_keys"

section "Accounts, sudo, PAM (CIS 5.2-5.4)"
sh_ "accounts with a login shell" 'awk -F: "(\$7 !~ /(nologin|false|sync|shutdown|halt)\$/){print \$1, \$3, \$7}" /etc/passwd'
sh_ "UID 0 accounts; accounts without password" 'awk -F: "(\$3==0){print \"uid0:\", \$1}" /etc/passwd; awk -F: "(\$2==\"\"){print \"EMPTY PASSWORD:\", \$1}" /etc/shadow'
sh_ "password status of login accounts (P=set, L=locked, NP=none)" 'for u in $(awk -F: "(\$7 !~ /(nologin|false|sync|shutdown|halt)\$/){print \$1}" /etc/passwd); do passwd -S "$u"; done'
sh_ "sudo rules (no secrets in them)" 'grep -rhvE "^\s*(#|$)" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; getent group sudo'
sh_ "password and login settings" 'grep -hE "^\s*(PASS_MAX_DAYS|PASS_MIN_DAYS|PASS_WARN_AGE|UMASK|ENCRYPT_METHOD|SHA_CRYPT_)" /etc/login.defs; grep -hvE "^\s*(#|$)" /etc/security/pwquality.conf /etc/security/pwquality.conf.d/* /etc/security/faillock.conf 2>/dev/null; grep -hE "pam_(pwquality|faillock|pwhistory|unix)" /etc/pam.d/common-* 2>/dev/null'
sh_ "default umask, shell timeout" 'grep -hE "^\s*(umask|readonly TMOUT|TMOUT=|export TMOUT)" /etc/profile /etc/profile.d/*.sh /etc/bash.bashrc 2>/dev/null'
sh_ "su restricted?" 'grep -hE "^\s*auth\s+required\s+pam_wheel" /etc/pam.d/su || echo "(no pam_wheel line)"'

section "Logging and auditing (CIS 6)"
sh_ "journald" 'grep -hvE "^\s*(#|$)" /etc/systemd/journald.conf /etc/systemd/journald.conf.d/*.conf 2>/dev/null; journalctl --disk-usage 2>/dev/null; ls -ld /var/log/journal 2>&1'
sh_ "rsyslog" 'systemctl is-active rsyslog 2>/dev/null; dpkg-query -W -f="\${Status} \${Package}\n" rsyslog 2>/dev/null'
sh_ "auditd" 'systemctl is-active auditd 2>/dev/null; auditctl -s 2>/dev/null | head -5; echo "rules loaded: $(auditctl -l 2>/dev/null | grep -vc "^No rules")"; grep -hvE "^\s*(#|$)" /etc/audit/auditd.conf 2>/dev/null | grep -E "max_log_file|space_left_action|admin_space_left_action|disk_full_action|num_logs"'
sh_ "AIDE (file integrity)" 'dpkg-query -W -f="\${Status} \${Package} \${Version}\n" aide aide-common 2>/dev/null; for u in dailyaidecheck.service dailyaidecheck.timer; do printf "%-24s %s %s\n" "$u" "$(systemctl is-enabled "$u" 2>/dev/null)" "$(systemctl is-active "$u" 2>/dev/null)"; done; systemctl show -p ExecStart --value dailyaidecheck.service 2>/dev/null | grep -o "path=[^ ;]*"; systemctl list-timers --all --no-pager 2>/dev/null | grep -i aide; ls -la /var/lib/aide/ 2>/dev/null; echo "--- last checks:"; tail -4 /var/lib/dk-srv/aide-history 2>/dev/null; true'
sh_ "log folder permissions (files more open than 640, like the CIS audit – without its exceptions)" 'find /var/log -type f -perm /0137 ! -name "history.log*" ! -name "eipp.log.xz*" ! -name "[bw]tmp" ! -name "[bw]tmp.*" ! -name "[bw]tmp-*" ! -name "lastlog" ! -name "lastlog.*" ! -name "cloud-init.log*" ! -name "localmessages*" ! -name "waagent.log*" -printf "%m %u:%g %p\n" 2>/dev/null | head -20; stat -c "%a %U:%G %n" /var/log /var/log/dk-srv 2>&1; grep -H "^UMASK" /etc/sysstat/sysstat 2>/dev/null'

section "Permissions (CIS 7)"
sh_ "passwd, shadow, group, gshadow, cron" 'stat -c "%a %U:%G %n" /etc/passwd /etc/passwd- /etc/shadow /etc/shadow- /etc/group /etc/gshadow /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d 2>&1; ls /etc/cron.allow /etc/cron.deny /etc/at.allow /etc/at.deny 2>&1'
sh_ "world-writable files and unowned files (local disks)" 'find / -xdev \( -path /proc -o -path /sys -o -path /run \) -prune -o -type f -perm -0002 -print 2>/dev/null | head -20; echo "--- world-writable folders without sticky bit:"; find / -xdev -type d -perm -0002 ! -perm -1000 -print 2>/dev/null | head -20; echo "--- unowned (every local disk and /tmp, like the CIS audit; /snap = read-only snap images, A13):"; { findmnt -n -l -k -it "$(awk "/nodev/ { print \$2 }" /proc/filesystems | paste -sd,)" -o TARGET; findmnt -kn -o TARGET,FSTYPE /tmp | awk "\$2 == \"tmpfs\" { print \$1 }"; } | sort -u | while read -r m; do find "$m" -xdev \( -nouser -o -nogroup \) -print 2>/dev/null | head -10; done | sort -u | head -30'
sh_ "SUID/SGID programs (count, unusual ones)" 'find / -xdev -type f -perm /6000 2>/dev/null | grep -vE "^/usr/(bin|sbin|lib)/" | head -20; echo "total: $(find / -xdev -type f -perm /6000 2>/dev/null | wc -l)"'
sh_ "login banners" 'for f in /etc/issue /etc/issue.net /etc/motd; do echo "[$f]"; cat "$f" 2>/dev/null | head -5; done'

section "nginx and TLS (CIS NGINX, Mozilla/BSI TLS)"
sh_ "version and build" 'nginx -V 2>&1 | tr " " "\n" | grep -E "^(nginx|built|--with|--without|--user|--group)" | head -60'
sh_ "processes (master as root, workers as www-data)" 'ps -o user=,args= -C nginx'
sh_ "effective config (nginx -T)" 'nginx -T 2>/dev/null'
sh_ "permissions" 'stat -c "%a %U:%G %n" /etc/nginx /etc/nginx/nginx.conf /etc/nginx/sites-available/* /etc/letsencrypt/live /etc/letsencrypt/archive 2>&1; for k in /etc/letsencrypt/archive/*/privkey*.pem; do stat -c "%a %U:%G %n" "$k"; done 2>/dev/null'
# the first app's address for the TLS tests (the same nginx serves all sites)
DOMAIN=""
for a in $(apps); do DOMAIN=$(app_get "$a" SITE_URL | sed -E 's#^https?://##; s#/.*##'); [ -n "$DOMAIN" ] && break; done
[ -n "$DOMAIN" ] || DOMAIN=$(sites | head -1)
if [ -n "$DOMAIN" ]; then
  sh_ "TLS protocols offered (expect: 1.0 and 1.1 no, 1.2 and 1.3 yes)" "for p in tls1 tls1_1 tls1_2 tls1_3; do printf '%-8s ' \$p; if echo | openssl s_client -connect 127.0.0.1:443 -servername '$DOMAIN' -\$p -cipher 'DEFAULT@SECLEVEL=0' >/dev/null 2>&1; then echo yes; else echo no; fi; done"
  sh_ "TLS 1.2 cipher suites offered" "for c in \$(openssl ciphers -s -tls1_2 'ALL:@SECLEVEL=0' | tr ':' ' '); do echo | openssl s_client -connect 127.0.0.1:443 -servername '$DOMAIN' -tls1_2 -cipher \"\$c@SECLEVEL=0\" >/dev/null 2>&1 && echo \"  \$c\"; done"
  sh_ "certificate" "echo | openssl s_client -connect 127.0.0.1:443 -servername '$DOMAIN' 2>/dev/null | openssl x509 -noout -subject -issuer -dates -ext subjectAltName -text 2>&1 | grep -vE '^ {16}[0-9a-f:]+$' | grep -E 'subject=|issuer=|notBefore|notAfter|DNS:|Public Key Algorithm|Public-Key'"
  sh_ "plain HTTP and unknown names" "curl -sI --resolve '$DOMAIN:80:127.0.0.1' http://$DOMAIN/ | head -3; echo '--- by IP (no name):'; curl -skI https://127.0.0.1/ | head -3; curl -sI http://127.0.0.1/ | head -3"
  sh_ "methods (TRACE, OPTIONS, DELETE on /)" "for m in TRACE OPTIONS DELETE; do printf '%-8s ' \$m; curl -sk -o /dev/null -w '%{http_code}\n' -X \$m --resolve '$DOMAIN:443:127.0.0.1' https://$DOMAIN/; done"
else
  echo -e "\n--- TLS checks skipped: no app or site registered (/etc/dk-srv/apps.d, sites.d)" >&3
fi
for site in $(sites); do
  sh_ "static site $site (sites.d: settings, files, answers)" "grep -vE '^\s*(#|$)' '$SITES_DIR/$site.conf'; ls -laR '/var/www/$site' 2>&1 | head -20; for u in / /index.html /style.css /picture.jpg /does-not-exist; do printf '  %-16s ' \"\$u\"; curl -sk -o /dev/null -w '%{http_code} %{content_type}\\n' --resolve '$site:443:127.0.0.1' 'https://$site'\"\$u\"; done; echo '--- headers:'; curl -skI --resolve '$site:443:127.0.0.1' 'https://$site/' | grep -iE 'content-security|nosniff|x-frame|cross-origin|strict-transport'"
done

section "PostgreSQL (CIS PostgreSQL 16)"
sh_ "version, cluster" 'sudo -u postgres psql -XAtc "select version()"; pg_lsclusters 2>/dev/null'
run "settings" bash -c "$(declare -f psql_); psql_ \"select name, setting from pg_settings where name in ('listen_addresses','port','password_encryption','ssl','ssl_min_protocol_version','log_connections','log_disconnections','log_line_prefix','log_statement','log_min_messages','log_min_error_statement','log_error_verbosity','log_hostname','logging_collector','log_destination','log_directory','log_file_mode','log_truncate_on_rotation','log_rotation_age','log_rotation_size','log_timezone','shared_preload_libraries','unix_socket_directories','unix_socket_permissions','data_directory','client_min_messages','debug_print_parse','debug_print_rewritten','debug_print_plan','debug_pretty_print','log_replication_commands','session_preload_libraries','temp_file_limit','idle_session_timeout','statement_timeout') order by name\""
run "pg_hba rules" bash -c "$(declare -f psql_); psql_ \"select line_number, type, database, user_name, address, netmask, auth_method, error from pg_hba_file_rules order by line_number\""
run "roles (no passwords – only whether stored as SCRAM)" bash -c "$(declare -f psql_); psql_ \"select rolname, rolsuper as super, rolcreaterole as createrole, rolcreatedb as createdb, rolcanlogin as login, rolreplication as repl, rolbypassrls as bypassrls, rolconnlimit as connlimit, rolvaliduntil as valid_until, coalesce(rolpassword like 'SCRAM-SHA-256\\\$%', false) as scram, (rolpassword is null) as no_password from pg_authid where rolname !~ '^pg_' order by 1\""
run "databases and their access rights" bash -c "$(declare -f psql_); psql_ \"select datname, pg_get_userbyid(datdba) as owner, datacl from pg_database order by 1\""
for a in $(apps); do
  db=$(app_get "$a" DATABASES | awk '{print $1}'); [[ $db =~ ^[a-z_][a-z0-9_]*$ ]] || continue
  run "schemas in $a's database $db and their access rights" bash -c "sudo -u postgres psql -X -A -F ' | ' -P footer=off -d $db -c \"select nspname, pg_get_userbyid(nspowner) as owner, nspacl from pg_namespace where nspname !~ '^(pg_|information_schema)' order by 1\" 2>&1"
  run "extensions in $db" bash -c "sudo -u postgres psql -XAtc \"select extname, extversion from pg_extension\" -d $db 2>&1"
done
sh_ "data folder and config permissions" 'd=$(sudo -u postgres psql -XAtc "show data_directory"); stat -c "%a %U:%G %n" "$d" /etc/postgresql/*/main /etc/postgresql/*/main/*.conf 2>&1; ls -la /etc/postgresql/*/main/conf.d/ 2>/dev/null'
sh_ "PostgreSQL packages (pgaudit?)" 'dpkg -l | grep -E "^ii\s+postgresql" | awk "{print \$2, \$3}"'

section "dk-srv (settings, clones, nightly checks)"
sh_ "settings and registered apps/sites (no secrets)" "grep -vE '^\s*(#|$)' '$DK_ETC/dk-srv.conf' 2>&1; stat -c '%a %U:%G %n' '$DK_ETC' '$DK_ETC'/* '$DK_ETC'/apps.d/* '$DK_ETC'/sites.d/* 2>/dev/null; for f in '$DK_ETC'/apps.d/*.conf; do [ -f \"\$f\" ] && { echo \"--- \$f\"; grep -vE '^\s*(#|$)' \"\$f\"; }; done"
sh_ "root-owned clones (owner, rights, remote, last commit)" 'for d in /opt/dk-srv /opt/dk-apps/* /opt/dk-sites/*; do [ -d "$d/.git" ] || continue; echo "$(stat -c "%a %U:%G" "$d") $d  $(git -c safe.directory="*" -C "$d" remote get-url origin)  $(git -c safe.directory="*" -C "$d" log -1 --format="%h %cs %s")"; git -c safe.directory="*" -C "$d" sparse-checkout list 2>/dev/null | sed "s/^/   sparse: /"; done'
sh_ "nightly checks" 'grep -vE "^\s*(#|$)" /etc/cron.d/dk-srv 2>/dev/null; ls -la /var/lib/dk-srv 2>/dev/null | head -30; echo "--- hardening parts installed: $(paste -sd" " /var/lib/dk-srv/hardening-parts 2>/dev/null)"; echo "--- old names left (before dk-srv):"; ls -d /usr/local/sbin/storybook-* /usr/local/lib/storybook /etc/cron.d/storybook /var/lib/storybook /var/log/dk-srv /etc/*/*storybook* /etc/*/*/*storybook* 2>/dev/null; echo "--- drift check now:"; bash -c ". /usr/local/lib/dk-srv/security-lib.sh && hardening_drift" 2>/dev/null || echo "(dk-srv not installed)"'

for a in $(apps); do
  section "App $a (/etc/dk-srv/apps.d/$a.conf)"
  user=$(app_get "$a" APP_USER); dir=$(app_get "$a" RUNTIME_DIR); bl=$(app_get "$a" BACKUP_LOG)
  [[ $user =~ ^[a-z_][a-z0-9_-]*$ ]] || continue
  uhome=$(getent passwd "$user" | cut -d: -f6)
  sh_ "mode, Node.js, pm2" "$(app_mode_cmd "$a" 2>/dev/null || echo true) status 2>&1 | head -5; node -v; runuser -u '$user' -- env HOME='$uhome' PATH=/usr/local/bin:/usr/bin:/bin pm2 ls 2>&1 | sed -E 's/[[:space:]]+/ /g' | head -12"
  sh_ "processes run as" "ps -o user=,args= -C node | sed -E 's#(/home/[^/]+)#~#g' | head -5"
  sh_ "permissions of its files and secrets (only looked at, not read)" "stat -c '%a %U:%G %n' '$uhome' '$dir' '$dir'/*/.env '$uhome/.pgpass' $(app_get "$a" AIDE_SENSITIVE) 2>&1; for p in $(app_get "$a" AIDE_SENSITIVE); do stat -c '%a %U:%G %n' \"\$p\"/* 2>/dev/null; done"
  sh_ "repository state (the app user's copy)" "runuser -u '$user' -- git -C '$dir' status --short 2>&1 | head -10; runuser -u '$user' -- git -C '$dir' log --oneline -1; runuser -u '$user' -- git -C '$dir' remote get-url origin"
  if [ -n "$bl" ]; then
    bdir=$(dirname "$bl")
    sh_ "backups (folder, newest files, schedule, encrypted?)" "stat -c '%a %U:%G %n' '$bdir' '$bdir'/* 2>&1 | head -8; ls -lt '$bdir/db' 2>/dev/null | head -4; du -sh '$bdir'/* 2>/dev/null; grep -HnE 'backup\.sh' /etc/crontab /etc/cron.d/* 2>/dev/null; crontab -u '$user' -l 2>/dev/null | grep -n 'backup\.sh'; tail -2 '$bl' 2>/dev/null; true"
  fi
done

section "USG CIS audit (if run: sudo usg audit cis_level1_server)"
latest=$(ls -t /var/lib/usg/usg-results-*.xml 2>/dev/null | head -1)
if [ -n "$latest" ]; then
  run "result of $(basename "$latest")" python3 -I -c '
import sys, collections, xml.etree.ElementTree as ET
rules = collections.defaultdict(list); score = None
for ev, el in ET.iterparse(sys.argv[1]):
    tag = el.tag.rsplit("}", 1)[-1]
    if tag == "rule-result":
        res = next((c.text for c in el if c.tag.rsplit("}", 1)[-1] == "result"), "?")
        rules[res].append(el.get("idref", "?").replace("xccdf_org.ssgproject.content_rule_", ""))
        el.clear()
    elif tag == "score" and score is None:
        score = el.text
print("score:", score)
for res, ids in sorted(rules.items()):
    print(f"{res}: {len(ids)}")
for res in ("fail", "error", "unknown"):
    for i in sorted(set(rules.get(res, []))):
        print(f"  {res.upper():5} {i}")
' "$latest"
else
  echo -e "\n--- (no USG result found in /var/lib/usg/)" >&3
fi

exec 3>&-
# --- anonymise and write -----------------------------------------------------------------------
host=$(hostname -s); fqdn=$(hostname -f 2>/dev/null || hostname)
public_ips=$(ip -o addr show 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | grep -vE '^(127\.|::1$|fe80:)' | sort -u)
sed_args=()
# every domain of the server: the apps' addresses, the static sites and their other names, the
# certificates' folders – each "parent" domain (the last two parts, e.g. your-domain.de) becomes
# example.com, example2.com, … (subdomains stay: storybook.your-domain.de -> storybook.example.com)
names=$( { for a in $(apps); do app_get "$a" SITE_URL | sed -E 's#^https?://##; s#[:/].*##'; done
           for s in $(sites); do echo "$s"; site_get "$s" ALIASES | tr ' ' '\n'; site_get "$s" CERT_NAME; done
           ls /etc/letsencrypt/live 2>/dev/null | grep -v README
           sed -nE 's/^[[:space:]]*(DOMAIN|CERT_NAME)[[:space:]]*=[[:space:]]*([A-Za-z0-9.-]+).*/\2/p' /etc/*/site.conf 2>/dev/null; } \
         | grep -E '^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$' | awk -F. '{ print $(NF-1) "." $NF }' | sort -u)
n=0
for name in $names; do
  n=$((n + 1)); [ "$n" = 1 ] && to=example.com || to="example$n.com"
  sed_args+=(-e "s#${name//./\\.}#$to#g")
done
for ip in $public_ips; do sed_args+=(-e "s#${ip//./\\.}#<ip>#g"); done
[ -n "$fqdn" ] && [ "$fqdn" != "$host" ] && sed_args+=(-e "s#${fqdn//./\\.}#server#g")
# (a generic name like "ubuntu" stays – replacing it would garble package names)
case "$host" in ""|ubuntu|localhost|debian|server) ;; *) sed_args+=(-e "s#\\b${host}\\b#server#g") ;; esac
{
  echo "# dk-srv hardening facts – $(date '+%F %T') – read-only collection (hardening/collect-facts.sh)"
  if [ ${#sed_args[@]} -gt 0 ]; then sed "${sed_args[@]}" "$RAW"; else cat "$RAW"; fi
} > "$OUT"
chown "$WHO:$WHO" "$OUT"; chmod 600 "$OUT"
echo "Written: $OUT ($(wc -l < "$OUT") lines)"
echo "Look through it if you like, then send it for the review."
