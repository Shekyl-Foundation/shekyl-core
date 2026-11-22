#!/bin/sh
# Run by the .deb and the .rpm before their files are unpacked, on install
# and on upgrade (fpm --before-install / --before-upgrade).
#
# shekyld@.service runs as the account shekyl and shekyl-rpc-tunnel.service
# as shekyl-tunnel, which shekyl.sysusers declares. systemd-sysusers keeps
# an account that already exists, so an existing shekyl or shekyl-tunnel
# that is a person's login would become a service's account, with that
# login's rights: a compromised daemon or tunnel could act as an
# administrator (Rick, 2026-11-18, as on FreeBSD 2026-11-14; the tunnel's
# account, 2026-11-21). This refuses such an account, and a group of that
# name another account belongs to, before anything is installed. The
# refusal names the rename that frees the name.
set -e

# refuse ACCOUNT REASON
refuse() {
    echo "shekyl: refused: $2." >&2
    echo "shekyl: a Shekyl service runs as the account $1, so it must be a" >&2
    echo "shekyl: system account that is no one's login. Rename the login" >&2
    echo "shekyl: and its group, and any sudo rule that names it, then" >&2
    echo "shekyl: install again; the package then creates $1 itself:" >&2
    echo "shekyl:   usermod -l <name> -d /home/<name> -m $1" >&2
    echo "shekyl:   groupmod -n <name> $1" >&2
    exit 1
}

# check ACCOUNT: refuses an existing ACCOUNT that is a login or may
# administer, and a group ACCOUNT that anyone else belongs to.
check() {
    account="$1"
    if getent passwd "$account" >/dev/null 2>&1; then
        shell="$(getent passwd "$account" | cut -d: -f7)"
        case "$shell" in
            */nologin | */false) ;;
            *) refuse "$account" "the account $account is a login (shell $shell)" ;;
        esac
        for group in $(id -nG "$account"); do
            case "$group" in
                sudo | wheel | admin) refuse "$account" "the account $account is in the group $group" ;;
            esac
        done
        if command -v sudo >/dev/null 2>&1; then
            rules="$(LC_ALL=C sudo -n -l -U "$account" 2>&1)" || :
            case "$rules" in
                *"is not allowed to run sudo"*) ;;
                *"may run the following commands"*) refuse "$account" "sudo lets the account $account run commands (sudo -l -U $account)" ;;
                *) refuse "$account" "sudo could not say what the account $account may run: $(printf '%s' "$rules" | tail -n 1)" ;;
            esac
        fi
    fi

    if getent group "$account" >/dev/null 2>&1; then
        gid="$(getent group "$account" | cut -d: -f3)"
        members="$(getent group "$account" | cut -d: -f4)"
        for member in $(printf '%s' "$members" | tr ',' ' '); do
            [ "$member" = "$account" ] || refuse "$account" "the group $account has the member $member"
        done
        primary="$(getent passwd | awk -F: -v g="$gid" -v a="$account" '$4 == g && $1 != a { print $1; exit }')"
        [ -z "$primary" ] || refuse "$account" "the group $account is the primary group of $primary"
    fi
}

check shekyl
check shekyl-tunnel
