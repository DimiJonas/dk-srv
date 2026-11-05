# Installed by dk-srv hardening/install-hardening.sh (part "accounts") as
# /etc/profile.d/60-dk-srv-cis.sh. CIS Ubuntu 24.04 Level 1.
# New files are readable only by you and your group (umask 027), and a shell that sits idle for
# 15 minutes closes itself (TMOUT) – a forgotten open SSH session can't be used by someone else.
umask 027
if ! readonly -p 2>/dev/null | grep -q ' TMOUT='; then
    TMOUT=900
    readonly TMOUT
    export TMOUT
fi
