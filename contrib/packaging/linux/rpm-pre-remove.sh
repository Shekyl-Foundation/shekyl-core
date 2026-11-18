#!/bin/sh
# Run by the .rpm before it is erased (fpm --before-remove; fpm runs it on
# erase only, not when an upgrade removes the old version). The .deb gets
# the same from fpm's systemd hook for the unit --deb-systemd names: the
# daemon is stopped and disabled before its files go. The account and
# /etc/shekyl are kept (INPUT_GRAMMAR.md IG-Q64, Purge).
set -e

if [ -d /run/systemd/system ]; then
    systemctl disable --now shekyld.service
fi
