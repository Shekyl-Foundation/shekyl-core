#!/bin/sh
# Copyright (c) 2026, The Shekyl Foundation
# BSD-3-Clause
#
# The owner's socket is this account's session directory, /run/user/<uid>
# (shekyl-os-account). A container has none, and /run is not the image's.
# Create it, mode 0700, owned by shekyl, then run the daemon as that
# account. `docker exec -u shekyl` resolves the same directory.

set -eu
uid=$(id -u shekyl)
gid=$(id -g shekyl)
install -d -m 0700 -o "$uid" -g "$gid" "/run/user/$uid"
exec runuser -u shekyl -- shekyld "$@"
