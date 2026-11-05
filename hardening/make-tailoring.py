#!/usr/bin/env python3
"""USG tailoring for the server (SECURITY.md, "Accepted risks").

CIS rules that don't fit this server are switched off in a "tailoring file" – USG's documented way –
so the audit measures what's left. Every rule switched off here is listed with its reason in
SECURITY.md. On the server:

  sudo usg generate-tailoring cis_level1_server /tmp/usg-tailoring.xml
  sudo python3 /opt/dk-srv/hardening/make-tailoring.py /tmp/usg-tailoring.xml /etc/dk-srv/usg-tailoring.xml
  sudo usg audit --tailoring-file /etc/dk-srv/usg-tailoring.xml

(The first audit without tailoring stays the honest "before" number; both scores go into SECURITY.md.)
The file is edited as text, so everything else USG wrote stays exactly as it was. The new file is
noted for the file integrity check (/var/lib/dk-srv/aide-expected), so it isn't reported.
"""
import os
import re
import sys

PREFIX = 'xccdf_org.ssgproject.content_rule_'
# rule -> reason (short; the full reasons are in SECURITY.md)
OFF = {
    'grub2_password': 'console only through the hosting account; no physical access',
    'accounts_maximum_age_login_defs': 'no forced password changes (NIST SP 800-63B); SSH only with keys',
    'accounts_password_set_max_life_existing': 'same as accounts_maximum_age_login_defs',
    'package_rsync_removed': 'the backup copy needs rsync (its daemon is masked)',
    'package_ufw_removed': 'ufw is the firewall of this server (CIS allows ufw or nftables)',
    'nftables_rules_permanent': 'ufw is the firewall (nftables rules are written by ufw)',
    'service_nftables_enabled': 'ufw is the firewall',
    'set_nftables_loopback_traffic': 'ufw is the firewall (loopback rules are set in ufw)',
    'package_nginx_removed': 'nginx is the web server of this server',
    'service_nginx_disabled': 'nginx is the web server of this server',
    'all_apparmor_profiles_in_enforce_complain_mode': "Ubuntu ships some profiles as 'unconfined' on purpose",
    'aide_build_database': "A12: AIDE 0.18 calls the setting database_in=; USG's check (SSG 0.1.78) looks for "
                           "the old name database= – the database exists and is renewed every night",
    'file_permissions_ungroupowned': "A13: the only hit is inside a read-only snap image (core22's ssh-agent, "
                                     "a group that exists only in the snap); the nightly check covers everything else",
}
EXPECTED = '/var/lib/dk-srv/aide-expected'


def main(src, dest):
    text = open(src, encoding='utf-8').read()
    m = re.search(r'<(\w+:)?Profile\b', text)
    if not m:
        sys.exit(f'{src}: no <Profile> found – is it a file from "usg generate-tailoring"?')
    ns = m.group(1) or ''
    end = text.find(f'</{ns}Profile>')
    if end < 0:
        sys.exit(f'{src}: no </{ns}Profile> found')
    added = []
    for rule, reason in OFF.items():
        rid = PREFIX + rule
        pattern = re.compile(r'(<' + re.escape(ns) + r'select\b[^>]*\bidref="' + re.escape(rid) + r'"[^>]*\bselected=")(true|false)(")')
        if pattern.search(text):
            text = pattern.sub(r'\1false\3', text)
        else:
            added.append(f'  <{ns}select idref="{rid}" selected="false"/><!-- {reason} -->\n')
    if added:
        end = text.find(f'</{ns}Profile>')
        text = text[:end] + ''.join(added) + text[end:]
    with open(dest, 'w', encoding='utf-8') as f:
        f.write(text)
    if os.path.isdir(os.path.dirname(EXPECTED)) and os.access(os.path.dirname(EXPECTED), os.W_OK):
        with open(EXPECTED, 'a', encoding='utf-8') as f:
            f.write(os.path.abspath(dest) + '\n')
    print(f'{dest}: {len(OFF)} rules switched off ({len(added)} added, {len(OFF) - len(added)} changed)')
    for rule, reason in OFF.items():
        print(f'  - {rule}: {reason}')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
