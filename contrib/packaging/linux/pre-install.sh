#!/bin/sh
# Run by the .deb and the .rpm before their files are unpacked, on install
# and on upgrade (fpm --before-install / --before-upgrade).
#
# shekyld.service runs as the account shekyl, which shekyl.sysusers
# declares. systemd-sysusers keeps an account that already exists, so an
# existing shekyl that is a person's login would become the daemon's
# account, with that login's rights: a compromised daemon could act as an
# administrator (Rick, 2026-11-18, as on FreeBSD 2026-11-14). This refuses
# such an account, and a shekyl group another account belongs to, before
# anything is installed. The refusal names the rename that frees the name.
set -e

refuse() {
    echo "shekyl: refused: $1." >&2
    echo "shekyl: the daemon runs as the account shekyl, so it must be a" >&2
    echo "shekyl: system account that is no one's login. Rename the login" >&2
    echo "shekyl: and its group, and any sudo rule that names it, then" >&2
    echo "shekyl: install again; the package then creates shekyl itself:" >&2
    echo "shekyl:   usermod -l <name> -d /home/<name> -m shekyl" >&2
    echo "shekyl:   groupmod -n <name> shekyl" >&2
    exit 1
}

if getent passwd shekyl >/dev/null 2>&1; then
    shell="$(getent passwd shekyl | cut -d: -f7)"
    case "$shell" in
        */nologin | */false) ;;
        *) refuse "the account shekyl is a login (shell $shell)" ;;
    esac
    for group in $(id -nG shekyl); do
        case "$group" in
            sudo | wheel | admin) refuse "the account shekyl is in the group $group" ;;
        esac
    done
    if command -v sudo >/dev/null 2>&1; then
        rules="$(LC_ALL=C sudo -n -l -U shekyl 2>&1)" || :
        case "$rules" in
            *"is not allowed to run sudo"*) ;;
            *"may run the following commands"*) refuse "sudo lets the account shekyl run commands (sudo -l -U shekyl)" ;;
            *) refuse "sudo could not say what the account shekyl may run: $(printf '%s' "$rules" | tail -n 1)" ;;
        esac
    fi
fi

if getent group shekyl >/dev/null 2>&1; then
    gid="$(getent group shekyl | cut -d: -f3)"
    members="$(getent group shekyl | cut -d: -f4)"
    for member in $(printf '%s' "$members" | tr ',' ' '); do
        [ "$member" = shekyl ] || refuse "the group shekyl has the member $member"
    done
    primary="$(getent passwd | awk -F: -v g="$gid" '$4 == g && $1 != "shekyl" { print $1; exit }')"
    [ -z "$primary" ] || refuse "the group shekyl is the primary group of $primary"
fi
