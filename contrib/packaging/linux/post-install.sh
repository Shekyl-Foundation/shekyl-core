#!/bin/sh
# Run by the .deb and the .rpm after install and after upgrade (fpm
# --after-install / --after-upgrade), once pre-install.sh has refused any
# shekyl account that is a login.
#
# It applies what the package declares: the account (shekyl.sysusers) and
# /etc/shekyl (shekyl.tmpfiles); places each network's settings file when
# none is there; then reloads systemd so the units it ships (shekyld@.service,
# shekyl.slice and the tunnel's) are known. It neither enables, starts nor
# restarts the daemon: the operator runs `systemctl enable --now
# shekyld@<network>` and, after an upgrade, `systemctl restart
# shekyld@<network>`.
set -e

systemd-sysusers shekyl.conf
systemd-tmpfiles --create shekyl.conf

# Each public network's settings file, when the operator has none: the
# shipped rendering, every option commented out, root:shekyl 0640
# (INPUT_GRAMMAR.md IG-Q64). An upgrade never overwrites a file that is
# there, so this is a copy, not a dpkg conffile, and a release that adds
# rows prompts no one. The unit's ExecStartPre checks the file before each
# start; this script does not, because the directories the check reads do
# not exist yet.
for shipped in /usr/share/shekyl/shekyld-*.toml; do
    target="/etc/shekyl/${shipped##*/}"
    if [ ! -e "$target" ]; then
        install -m 0640 -o root -g shekyl "$shipped" "$target"
    fi
done

if [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
