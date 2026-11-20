#!/usr/bin/env bash
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
#
# with_small_disk.sh CMD...: run CMD with SHEKYL_SMALL_DISK naming a 1 MiB
# tmpfs, for the full-disk live-daemon gate
# (engine::regtest_e2e::full_disk::a_full_disk_stops_the_daemon_with_an_error_line_and_a_failed_exit).
#
# CI does not use this: build.yml mounts the tmpfs on the job container
# (`options: --tmpfs`) and sets SHEKYL_SMALL_DISK on the gate step. This is
# for a developer's run, which has no such container and no root.
#
# Without root a mount needs a user namespace, and inside one the real
# root's directories (`/`, `/home`, `/run`) read as owned by nobody. The
# daemon refuses a configuration file under a directory that neither root
# nor its own account owns, so the gate cannot run on the host's tree
# there. The command therefore runs as the namespace's root in a private
# tree: `/` and `/tmp` are tmpfs of its own, and `/usr`, `/etc`, `/home`
# and the rest are the host's, bound in. Nothing outside the namespace is
# mounted or changed, and the tree goes when the command exits.
#
# Paths the command names must be absolute and under a bound directory:
# the command starts in `/`, and a binary in the host's /tmp is not
# visible inside.
#
# Linux only: it needs unprivileged user namespaces (`unshare -Urm`).

set -euo pipefail

SIZE="${SHEKYL_SMALL_DISK_SIZE:-1m}"

[ "$#" -gt 0 ] || {
  echo "usage: $0 CMD [ARG...]" >&2
  exit 2
}

# The subject first (rule 47): a namespace that cannot mount is the one
# failure this script can have, and it is named here rather than left to
# the gate's own message about a missing SHEKYL_SMALL_DISK.
unshare -Urm true 2>/dev/null || {
  echo "FATAL: this host does not allow an unprivileged user namespace (unshare -Urm)." >&2
  echo "Mount a small tmpfs as root instead and name it:" >&2
  echo "  mount -t tmpfs -o size=$SIZE tmpfs /mnt/shekyl-small-disk" >&2
  echo "  SHEKYL_SMALL_DISK=/mnt/shekyl-small-disk $*" >&2
  exit 1
}

exec unshare -Urm --propagation private bash -euo pipefail -c '
size=$1
shift
# The daemon refuses a configuration file under a group-writable directory,
# and a developer umask of 002 would make /run one.
umask 022
root=$(mktemp -d)
mount -t tmpfs -o size=64m,mode=755 tmpfs "$root"
for dir in usr bin sbin lib lib32 lib64 libx32 etc proc dev sys home opt var; do
  [ -e "/$dir" ] || continue
  if [ -L "/$dir" ]; then
    ln -s "$(readlink "/$dir")" "$root/$dir"
  else
    mkdir "$root/$dir"
    mount --rbind "/$dir" "$root/$dir"
  fi
done
mkdir -p "$root/tmp" "$root/run/user/0" "$root/small-disk"
chmod 700 "$root/run/user/0"
mount -t tmpfs -o size=1g,mode=1777 tmpfs "$root/tmp"
mount -t tmpfs -o "size=$size" tmpfs "$root/small-disk"
# HOME stays, so cargo and rustup find their directories. The harness
# takes its private configuration directory from XDG_RUNTIME_DIR first.
export TMPDIR=/tmp XDG_RUNTIME_DIR=/run/user/0
export SHEKYL_SMALL_DISK=/small-disk
status=0
/usr/sbin/chroot "$root" "$@" || status=$?
# Leave the mount before detaching it. The tmpfs mounts die with this
# namespace; the host directory mktemp made would otherwise stay in /tmp.
cd /
umount -l "$root" || true
rm -rf "$root"
exit "$status"
' with_small_disk "$SIZE" "$@"
