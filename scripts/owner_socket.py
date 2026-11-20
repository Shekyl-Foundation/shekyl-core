#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# The owner's socket directory a harness names for each daemon it starts.
#
# A daemon run as its user serves that user on a socket in a directory only
# that account can reach (RPC_CHANNEL.md §7.1). With no session directory,
# as on a CI runner, it refuses to start unless it is named one
# (`rpc-socket-dir`, INPUT_GRAMMAR.md IG-Q104), and two daemons of one
# network and instance in one directory are one too many: the second
# refuses. So every harness names a private directory per daemon, made
# here: mode 0700, this account's, short enough for the socket path limit
# (108 bytes on Linux, 104 on macOS), and removed when the harness exits.
#
# `scripts/ci/check_owner_socket_launchers.py` fails a regtest spawn that
# does not name one.

"""A private directory for one daemon's owner socket."""

import atexit
import shutil
import tempfile

# The daemon's own flag.
FLAG = "--rpc-socket-dir"


def argv(tag):
    """`[FLAG, <a new private directory>]` for one daemon, `tag` naming it."""
    # mkdtemp makes the directory 0700 and this account's. Under /tmp, not
    # $TMPDIR: macOS's per-user TMPDIR is about 49 bytes, which with the
    # socket's 38 leaves too little of the 104 for a tag.
    directory = tempfile.mkdtemp(prefix=f"shekyl-{tag}-", dir="/tmp")
    atexit.register(shutil.rmtree, directory, ignore_errors=True)
    return [FLAG, directory]
