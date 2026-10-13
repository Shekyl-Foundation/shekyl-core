#!/bin/sh
# Run by the .deb after install and after upgrade (fpm --after-install /
# --after-upgrade): the package ships a slice unit beside the service, and
# a unit file systemd has not been told about is not a slice a service can
# join. fpm's own systemd hook enables and starts the service; this makes
# sure the slice is known first and after every upgrade of either file.
set -e
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload || true
fi
