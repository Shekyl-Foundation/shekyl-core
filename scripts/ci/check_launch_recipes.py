#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The recipe gate (DAEMON_CONFIG_CUTOVER.md DC-Q8, §5.2): the launchers that
ship or that provision the fleet say only what the daemon's table says.

Five checks over an enumerated set of files:

1. Every `--flag` a unit's `ExecStart` passes to `shekyld` is a row of the
   table (the generated fragment `docs/generated/shekyld_options.md`, which
   a `shekyl-daemon-config` test holds equal to the table). A command-line
   row is fine there; a file-only row is not.
2. A unit that names `--data-dir` names `/var/lib/<StateDirectory>`, and a
   unit that names `--log-file` names a file under `/var/log/<LogsDirectory>`:
   the paths systemd creates and the paths the daemon writes are one pair,
   not two that happen to agree today. A `--service` unit's data home (its
   `--data-dir`, or else the daemon's default: `SERVICE_DATA_HOME` in
   `rust/shekyl-rpc-rendezvous/src/place.rs` under `LINUX_SERVICE_PARENT`
   in `rust/shekyl-process/src/platform.rs`) is `/var/lib/<StateDirectory>`
   at `StateDirectoryMode=0700`, the mode the daemon checks.
3. Every key the fleet's generators write into a node's TOML
   (`echo "key = …"` lines) is a row the file accepts, and the generator's
   default roots are the fleet units' `StateDirectory` and `LogsDirectory`.
4. A unit has no session directory, so its daemon either runs as the
   machine's service instance (`--service`), names no socket directory and
   has the service's rendezvous directory, `/run/shekyl`
   (`RuntimeDirectory=shekyl`, `RuntimeDirectoryMode=0755`), or names
   `--rpc-socket-dir /run/<RuntimeDirectory>` with
   `RuntimeDirectoryMode=0700` (RPC_CHANNEL.md §7.1; INPUT_GRAMMAR.md
   IG-Q104, IG-Q105). Neither is a daemon that refuses to start.
5. The FreeBSD rc.d script holds the same contract, in rc.d's shape
   (RPC_CHANNEL.md §7.1; Rick, 2026-11-14). Its `supervise` branch is the
   command daemon(8) runs, and the words after `supervise` are shekyld's
   arguments: each is a command-line row, `--service` is present, and
   `--rpc-socket-dir` is absent. `start_precmd` names a function, and the
   directories are created in that function's body — an uncalled function
   does not count. The data home is `SERVICE_DATA_HOME` under
   `FREEBSD_SERVICE_PARENT`, made at mode 0700 (a `--data-dir`, when one
   is given, names it); the log directory is mode 0750; and the rendezvous
   directory is the path of `FREEBSD_SERVICE_RENDEZVOUS` in
   `rust/shekyl-rpc-rendezvous/src/place.rs`, at the shipped unit's
   `RuntimeDirectoryMode`. daemon(8) is not passed
   `-r` or `-R`: FreeBSD 14 restarts every termination under those flags,
   including a clean exit. The script's `restart_seconds` equals the
   shipped unit's `RestartSec`, and that unit is `Restart=on-failure`.
   The daemon creates none of these directories; it checks them.
6. The RPC tunnel's unit and rc.d script (RPC_CHANNEL.md §8; Rick,
   2026-11-16) run `shekyl-rpc-tunnel` with only command-line rows of its
   own table (`rust/shekyl-rpc-tunnel/src/table.rs`), as its own account
   `shekyl-tunnel`, never the daemon's `shekyl` and never root; name a
   configuration file; keep its key (`--rpc-key-file`) in its own state
   directory, `/var/lib/<StateDirectory>` at mode 0700 (`/var/db/...` made
   0700 by the rc.d prestart), and its log in its own log directory; and
   pass `--listen`, if they pass it, as a loopback address. The unit is
   `Restart=on-failure`, and the rc.d script's restart loop and clean-exit
   rule are the daemon script's, at the tunnel unit's `RestartSec`. The
   unit carries the hardening set (Rick, 2026-11-16), each directive at its
   ruled value (`TUNNEL_HARDENING`).

Exit 0 when every check holds; 1 naming each failure; 2 on a subject that
could not be read (rule 47: a gate asserts its own subject).
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import sys
import tempfile
from pathlib import Path

TABLE_FRAGMENT = "docs/generated/shekyld_options.md"
PLATFORM_RS = "rust/shekyl-process/src/platform.rs"
# The service's rendezvous rows and its data home's name, defined once for
# the daemon and every client (`shekyl_rpc_rendezvous::service_rendezvous`).
PLACE_RS = "rust/shekyl-rpc-rendezvous/src/place.rs"
# The constant `service_rendezvous()` returns on FreeBSD (in PLACE_RS). The
# gate reads the paths from the source so the launchers and the daemon
# cannot diverge.
FREEBSD_RENDEZVOUS_CONST = "FREEBSD_SERVICE_RENDEZVOUS"
# The parents `service_parent()` returns on Linux and FreeBSD (in
# PLATFORM_RS), and the data home's leaf under them (in PLACE_RS).
LINUX_PARENT_CONST = "LINUX_SERVICE_PARENT"
FREEBSD_PARENT_CONST = "FREEBSD_SERVICE_PARENT"
DATA_HOME_CONST = "SERVICE_DATA_HOME"

SHIPPED_UNIT = "contrib/packaging/linux/shekyld.service"
UNITS = [
    SHIPPED_UNIT,
    "utils/fleet/skl-node@.service",
    "utils/fleet/skl-clearnet@.service",
]

# FreeBSD's rc.d scripts (check 5).
RC_SCRIPTS = [
    "contrib/packaging/freebsd/shekyld",
]

# generator -> (the units whose directories it must agree with)
GENERATORS = {
    "utils/fleet/gen_host_configs.sh": ["utils/fleet/skl-node@.service", "utils/fleet/skl-clearnet@.service"],
    "utils/fleet/run_arm.sh": [],
}

# The service account the rc.d script creates its directories as.
SERVICE_ACCOUNT = "shekyl"
# The data home is the account's alone. The rendezvous mode is the shipped
# unit's RuntimeDirectoryMode, not a second number here.
DATA_HOME_MODE = "0700"
LOG_DIRECTORY_MODE = "0750"
# The tunnel (check 6).
TUNNEL_TABLE_RS = "rust/shekyl-rpc-tunnel/src/table.rs"
TUNNEL_UNIT = "contrib/packaging/linux/shekyl-rpc-tunnel.service"
TUNNEL_RC = "contrib/packaging/freebsd/shekyl-rpc-tunnel"
TUNNEL_BINARY = "/usr/local/bin/shekyl-rpc-tunnel"
# Its own account (Rick, 2026-11-16): never the daemon's, never root.
TUNNEL_ACCOUNT = "shekyl-tunnel"
# The tunnel unit's hardening set, each at its ruled value (Rick,
# 2026-11-16). shekyld's unit is not held to it: RandomX's JIT needs W^X
# off.
TUNNEL_HARDENING = {
    "NoNewPrivileges": "true",
    "ProtectSystem": "strict",
    "ProtectHome": "true",
    "PrivateTmp": "true",
    "CapabilityBoundingSet": "",
    "RestrictAddressFamilies": "AF_INET AF_INET6 AF_UNIX",
    "PrivateDevices": "true",
    "ProtectKernelTunables": "true",
    "ProtectKernelModules": "true",
    "ProtectKernelLogs": "true",
    "ProtectControlGroups": "true",
    "ProtectClock": "true",
    "ProtectHostname": "true",
    "RestrictNamespaces": "true",
    "RestrictRealtime": "true",
    "RestrictSUIDSGID": "true",
    "LockPersonality": "true",
    "MemoryDenyWriteExecute": "true",
    "SystemCallFilter": "@system-service",
    "SystemCallArchitectures": "native",
    "UMask": "0077",
}
# daemon(8) flags that restart a clean exit. The script's own loop is the
# on-failure policy; these must not also be set.
DAEMON_RESTART_FLAGS = ("-r", "-R", "--restart", "--restart-delay")


def rows(table_text: str) -> dict[str, str]:
    """name -> where ("command line" | "file" | "both")."""
    out: dict[str, str] = {}
    for m in re.finditer(r"^\| `([a-z][a-z0-9-]*)` \| .*? \| .*? \| (command line|file|both) \|", table_text, flags=re.M):
        out[m.group(1)] = m.group(2)
    dev = re.search(r"<!-- development rows[^:]*: (.*?) -->", table_text)
    if dev:
        for name in re.findall(r"(?:^|; )([a-z][a-z0-9-]*) \(", dev.group(1)):
            out.setdefault(name, "both")
    return out


def tunnel_rows(table_rs: str) -> dict[str, str]:
    """The tunnel's table, from its source: name -> where."""
    where = {"Cli": "command line", "Both": "both", "File": "file"}
    out: dict[str, str] = {}
    for m in re.finditer(r'^\s*row\("([a-z][a-z0-9-]*)",.*\bSurface::(Cli|Both|File)\b', table_rs, flags=re.M):
        out[m.group(1)] = where[m.group(2)]
    return out


def unit_fields(text: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        fields[key.strip()] = value.strip()
    return fields


def exec_flags(exec_start: str) -> tuple[list[str], dict[str, str]]:
    """(flags in order, flag -> the value word after it)."""
    words = shlex.split(exec_start)
    flags: list[str] = []
    values: dict[str, str] = {}
    for i, w in enumerate(words):
        if w.startswith("--"):
            name = w[2:].split("=", 1)[0]
            flags.append(name)
            if "=" in w:
                values[name] = w.split("=", 1)[1]
            elif i + 1 < len(words) and not words[i + 1].startswith("--"):
                values[name] = words[i + 1]
    return flags, values


def command_line_rows(
    rel: str, where: str, flags: list[str], live: dict[str, str], table: str = "the daemon's table"
) -> list[str]:
    """Flags that are not command-line rows of `table`."""
    errors: list[str] = []
    for flag in flags:
        place = live.get(flag)
        if place is None:
            errors.append(f"{rel}: {where} passes `--{flag}`, which is not a row of {table}")
        elif place == "file":
            errors.append(f"{rel}: {where} passes `--{flag}`, a file-only row")
    return errors


def check_unit(rel: str, text: str, live: dict[str, str], service_home: str) -> list[str]:
    errors: list[str] = []
    fields = unit_fields(text)
    exec_start = fields.get("ExecStart")
    if not exec_start or "shekyld" not in exec_start:
        return [f"{rel}: no ExecStart that runs shekyld"]
    flags, values = exec_flags(exec_start)
    errors.extend(command_line_rows(rel, "ExecStart", flags, live))
    state = fields.get("StateDirectory")
    logs = fields.get("LogsDirectory")
    if "data-dir" in values:
        if not state:
            errors.append(f"{rel}: ExecStart names --data-dir but the unit has no StateDirectory")
        elif values["data-dir"] != f"/var/lib/{state}":
            errors.append(f"{rel}: --data-dir {values['data-dir']} is not /var/lib/{state} (StateDirectory)")
    if "log-file" in values:
        if not logs:
            errors.append(f"{rel}: ExecStart names --log-file but the unit has no LogsDirectory")
        elif str(Path(values["log-file"]).parent) != f"/var/log/{logs}":
            errors.append(f"{rel}: --log-file {values['log-file']} is not under /var/log/{logs} (LogsDirectory)")
    runtime = fields.get("RuntimeDirectory")
    if "service" in flags:
        if "rpc-socket-dir" in values:
            errors.append(f"{rel}: ExecStart names --service and --rpc-socket-dir; a service is given no socket directory")
        if runtime != "shekyl" or fields.get("RuntimeDirectoryMode") != "0755":
            errors.append(f"{rel}: a --service unit needs the service's rendezvous directory: RuntimeDirectory=shekyl with RuntimeDirectoryMode=0755")
        if "data-dir" not in values and state and f"/var/lib/{state}" != service_home:
            errors.append(
                f"{rel}: a --service unit's data home is the daemon's default {service_home}, "
                f"but StateDirectory makes /var/lib/{state}"
            )
        if not state:
            errors.append(f"{rel}: a --service unit has no StateDirectory for its data home")
        elif fields.get("StateDirectoryMode") != DATA_HOME_MODE:
            errors.append(
                f"{rel}: the service's data home /var/lib/{state} is not StateDirectoryMode={DATA_HOME_MODE}"
            )
    elif "rpc-socket-dir" not in values:
        errors.append(f"{rel}: ExecStart names neither --service nor --rpc-socket-dir; a unit has no session directory, so the daemon would refuse to start")
    elif not runtime:
        errors.append(f"{rel}: ExecStart names --rpc-socket-dir but the unit has no RuntimeDirectory")
    elif values["rpc-socket-dir"] != f"/run/{runtime}":
        errors.append(f"{rel}: --rpc-socket-dir {values['rpc-socket-dir']} is not /run/{runtime} (RuntimeDirectory)")
    elif fields.get("RuntimeDirectoryMode") != "0700":
        errors.append(f"{rel}: the socket directory /run/{runtime} is not RuntimeDirectoryMode=0700")
    return errors


def assignment(text: str, name: str) -> str | None:
    """The value of a `name=value` or `name="value"` line."""
    m = re.search(rf'^{re.escape(name)}=(?:"([^"]*)"|(\S+))', text, flags=re.M)
    if not m:
        return None
    return m.group(1) if m.group(1) is not None else m.group(2)


def function_body(text: str, name: str) -> str | None:
    """The body of `name()`, braces excluded, or None when it is absent."""
    m = re.search(rf"^{re.escape(name)}\(\)\n\{{", text, flags=re.M)
    if not m:
        return None
    depth = 1
    i = m.end()
    start = i
    while i < len(text) and depth:
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
        i += 1
    if depth:
        return None
    return text[start : i - 1]


def made_dirs(body: str, account: str = SERVICE_ACCOUNT) -> dict[str, str]:
    """directory -> mode, for each `install -d -o ACCOUNT -g ACCOUNT -m MODE DIR`."""
    pattern = rf"^\s*install -d -o {re.escape(account)} -g {re.escape(account)} -m (\d{{4}}) (/\S+)"
    return dict((d, mode) for mode, d in re.findall(pattern, body, flags=re.M))


def string_constant(text: str, name: str) -> str | None:
    """The value of `[pub] const NAME: &str = "…";`, or None when the constant is absent."""
    m = re.search(rf'^(?:pub(?:\([a-z]+\))? )?const {re.escape(name)}: &str = "([^"]+)";', text, flags=re.M)
    return m.group(1) if m else None


def supervise_call(text: str) -> str | None:
    """The function the `supervise` branch calls, or None when the branch is absent."""
    m = re.search(
        r'^if \[ "\$\{1:-\}" = "supervise" \]; then\n\tshift\n\t(\w+) "\$@"\nfi\n',
        text,
        flags=re.M,
    )
    return m.group(1) if m else None


def check_rc_script(
    rel: str,
    text: str,
    live: dict[str, str],
    rendezvous: str,
    data_home: str,
    shipped: dict[str, str],
) -> list[str]:
    errors: list[str] = []
    line = assignment(text, "command_args")
    if line is None:
        return [f"{rel}: no command_args line"]
    words = line.split()
    if "supervise" not in words:
        return [f"{rel}: command_args does not run the supervise branch"]
    at = words.index("supervise")
    daemon_words = words[:at]
    for flag in DAEMON_RESTART_FLAGS:
        if flag in daemon_words:
            errors.append(
                f"{rel}: daemon(8) is passed {flag}; it restarts a clean exit, and shekyld_supervise is the on-failure policy"
            )
    called = supervise_call(text)
    if called is None:
        return errors + [f"{rel}: no supervise branch calls its function"]
    body = function_body(text, called)
    if body is None:
        return errors + [f"{rel}: {called}() is called and not defined"]
    binary = re.search(r"^\s*(/usr/local/bin/shekyld) \"\$@\" &", body, flags=re.M)
    if binary is None:
        errors.append(f"{rel}: {called}() does not run /usr/local/bin/shekyld")
    shekyld_line = " ".join(words[at + 1 :])
    flags, values = exec_flags(shekyld_line)
    errors.extend(command_line_rows(rel, "the command line", flags, live))
    if "service" in flags and "rpc-socket-dir" in values:
        errors.append(f"{rel}: the command line names --service and --rpc-socket-dir; a service is given no socket directory")
    restart = re.search(r"^\s*restart_seconds=(\d+)\s*$", body, flags=re.M)
    unit_restart = shipped.get("Restart")
    unit_delay = shipped.get("RestartSec")
    if unit_restart != "on-failure" or not unit_delay:
        errors.append(f"{rel}: the shipped unit's restart policy is not Restart=on-failure with RestartSec")
    elif restart is None:
        errors.append(f"{rel}: {called}() sets no restart_seconds")
    elif restart.group(1) != unit_delay:
        errors.append(
            f"{rel}: restart_seconds is {restart.group(1)}, not the shipped unit's RestartSec={unit_delay}"
        )
    if not re.search(r'case "\$status" in\n\s*0 \| 129 \| 130 \| 141 \| 143\) exit 0 ;;\n\s*esac\n', body):
        errors.append(
            f"{rel}: {called}() retries a clean exit; exit 0, or death by SIGHUP, SIGINT, SIGTERM or SIGPIPE "
            "(the shipped unit's Restart=on-failure counts them clean), must end the supervisor"
        )
    hook = assignment(text, "start_precmd")
    rc_name = assignment(text, "name")
    if hook is None or rc_name is None:
        return errors + [f"{rel}: start_precmd does not name a function"]
    prestart = hook.replace("${name}", rc_name)
    pre_body = function_body(text, prestart)
    if pre_body is None:
        return errors + [f"{rel}: start_precmd names {prestart}(), which is not defined"]
    made = made_dirs(pre_body)
    if "data-dir" in values and values["data-dir"] != data_home:
        errors.append(f"{rel}: --data-dir {values['data-dir']} is not the service's data home {data_home}")
    mode = made.get(data_home)
    if mode is None:
        errors.append(f"{rel}: the service's data home {data_home} is not made by {prestart}()")
    elif mode != DATA_HOME_MODE:
        errors.append(f"{rel}: the data home {data_home} is made at mode {mode}, not {DATA_HOME_MODE}")
    if "log-file" in values:
        parent = str(Path(values["log-file"]).parent)
        mode = made.get(parent)
        if mode is None:
            errors.append(f"{rel}: --log-file {values['log-file']} is in {parent}, which {prestart}() does not make")
        elif mode != LOG_DIRECTORY_MODE:
            errors.append(f"{rel}: the log directory {parent} is made at mode {mode}, not {LOG_DIRECTORY_MODE}")
    runtime_mode = shipped.get("RuntimeDirectoryMode")
    if "service" not in flags:
        errors.append(f"{rel}: the command line does not pass --service; a service script has no session directory")
    elif not runtime_mode:
        errors.append(f"{rel}: the shipped unit sets no RuntimeDirectoryMode for the rendezvous directory")
    elif made.get(rendezvous) != runtime_mode:
        errors.append(
            f"{rel}: a --service script needs the service's rendezvous directory: "
            f"{rendezvous} made at mode {runtime_mode}"
        )
    return errors


def loopback_listen(rel: str, values: dict[str, str]) -> list[str]:
    """A `--listen` is a loopback address and a port (RT-14)."""
    if "listen" not in values:
        return []
    host = values["listen"].rsplit(":", 1)[0].strip("[]")
    try:
        if ipaddress.ip_address(host).is_loopback:
            return []
    except ValueError:
        pass
    return [f"{rel}: --listen {values['listen']} is not a loopback address; the tunnel serves its consumers on this host only"]


def check_tunnel_unit(rel: str, text: str, rows: dict[str, str]) -> list[str]:
    errors: list[str] = []
    fields = unit_fields(text)
    exec_start = fields.get("ExecStart")
    if not exec_start or TUNNEL_BINARY not in exec_start:
        return [f"{rel}: no ExecStart that runs {TUNNEL_BINARY}"]
    flags, values = exec_flags(exec_start)
    errors.extend(command_line_rows(rel, "ExecStart", flags, rows, "the tunnel's table"))
    for key in ("User", "Group"):
        if fields.get(key) != TUNNEL_ACCOUNT:
            errors.append(f"{rel}: {key}={fields.get(key)}; the tunnel runs as its own account {TUNNEL_ACCOUNT}, never {SERVICE_ACCOUNT} and never root")
    if "config-file" not in values:
        errors.append(f"{rel}: ExecStart names no --config-file; the tunnel's node, bundle and listener live there")
    state = fields.get("StateDirectory")
    if not state:
        errors.append(f"{rel}: no StateDirectory for the tunnel's key")
    else:
        if fields.get("StateDirectoryMode") != DATA_HOME_MODE:
            errors.append(f"{rel}: the tunnel's state directory /var/lib/{state} is not StateDirectoryMode={DATA_HOME_MODE}")
        key = values.get("rpc-key-file")
        if key is None:
            errors.append(f"{rel}: ExecStart names no --rpc-key-file in the state directory")
        elif str(Path(key).parent) != f"/var/lib/{state}":
            errors.append(f"{rel}: --rpc-key-file {key} is not in /var/lib/{state} (StateDirectory)")
    logs = fields.get("LogsDirectory")
    if "log-file" in values and (not logs or str(Path(values["log-file"]).parent) != f"/var/log/{logs}"):
        errors.append(f"{rel}: --log-file {values['log-file']} is not under /var/log/<LogsDirectory>")
    errors.extend(loopback_listen(rel, values))
    if fields.get("Restart") != "on-failure" or not fields.get("RestartSec"):
        errors.append(f"{rel}: the tunnel's unit is not Restart=on-failure with RestartSec")
    for key, value in TUNNEL_HARDENING.items():
        if fields.get(key) != value:
            errors.append(f"{rel}: {key}={fields.get(key)}; the hardening set is {key}={value}")
    return errors


def check_tunnel_rc(rel: str, text: str, rows: dict[str, str], unit: dict[str, str]) -> list[str]:
    errors: list[str] = []
    line = assignment(text, "command_args")
    if line is None:
        return [f"{rel}: no command_args line"]
    words = line.split()
    if "supervise" not in words:
        return [f"{rel}: command_args does not run the supervise branch"]
    at = words.index("supervise")
    daemon_words = words[:at]
    if "-u" not in daemon_words or daemon_words[daemon_words.index("-u") + 1 :][:1] != [TUNNEL_ACCOUNT]:
        errors.append(f"{rel}: daemon(8) does not run the tunnel as {TUNNEL_ACCOUNT}; never {SERVICE_ACCOUNT} and never root")
    for flag in DAEMON_RESTART_FLAGS:
        if flag in daemon_words:
            errors.append(f"{rel}: daemon(8) is passed {flag}; it restarts a clean exit")
    called = supervise_call(text)
    if called is None:
        return errors + [f"{rel}: no supervise branch calls its function"]
    body = function_body(text, called)
    if body is None:
        return errors + [f"{rel}: {called}() is called and not defined"]
    if not re.search(rf'^\s*{re.escape(TUNNEL_BINARY)} "\$@" &', body, flags=re.M):
        errors.append(f"{rel}: {called}() does not run {TUNNEL_BINARY}")
    flags, values = exec_flags(" ".join(words[at + 1 :]))
    errors.extend(command_line_rows(rel, "the command line", flags, rows, "the tunnel's table"))
    if "config-file" not in values:
        errors.append(f"{rel}: the command line names no --config-file")
    errors.extend(loopback_listen(rel, values))
    restart = re.search(r"^\s*restart_seconds=(\d+)\s*$", body, flags=re.M)
    if restart is None or restart.group(1) != unit.get("RestartSec"):
        errors.append(f"{rel}: restart_seconds is not the tunnel unit's RestartSec={unit.get('RestartSec')}")
    if not re.search(r'case "\$status" in\n\s*0 \| 129 \| 130 \| 141 \| 143\) exit 0 ;;\n\s*esac\n', body):
        errors.append(f"{rel}: {called}() retries a clean exit")
    hook = assignment(text, "start_precmd")
    rc_name = assignment(text, "name")
    if hook is None or rc_name is None:
        return errors + [f"{rel}: start_precmd does not name a function"]
    prestart = hook.replace("${name}", rc_name)
    pre_body = function_body(text, prestart)
    if pre_body is None:
        return errors + [f"{rel}: start_precmd names {prestart}(), which is not defined"]
    made = made_dirs(pre_body, TUNNEL_ACCOUNT)
    key = values.get("rpc-key-file")
    if key is None:
        errors.append(f"{rel}: the command line names no --rpc-key-file")
    else:
        key_dir = str(Path(key).parent)
        if made.get(key_dir) != DATA_HOME_MODE:
            errors.append(f"{rel}: the key's directory {key_dir} is not made at mode {DATA_HOME_MODE} as {TUNNEL_ACCOUNT} by {prestart}()")
    if "log-file" in values:
        parent = str(Path(values["log-file"]).parent)
        if made.get(parent) != LOG_DIRECTORY_MODE:
            errors.append(f"{rel}: the log directory {parent} is not made at mode {LOG_DIRECTORY_MODE} by {prestart}()")
    return errors


def check_generator(rel: str, text: str, live: dict[str, str], units: dict[str, dict[str, str]]) -> list[str]:
    errors: list[str] = []
    keys = re.findall(r'echo\s+\\?"([a-z][a-z0-9-]*) = ', text)
    if not keys:
        return [f"{rel}: emits no `key = ` line — the pattern is wrong or the generator moved"]
    for key in keys:
        where = live.get(key)
        if where is None:
            errors.append(f"{rel}: writes `{key} = …`, which is not a row of the daemon's table")
        elif where == "command line":
            errors.append(f"{rel}: writes `{key} = …`, a command-line-only row, into a file")
    roots = dict(re.findall(r'^(DATA_ROOT|LOG_ROOT)="\$\{[A-Z_]+:-([^}]+)\}"', text, flags=re.M))
    for unit_rel, fields in units.items():
        state = fields.get("StateDirectory", "").split("/%i", 1)[0]
        logs = fields.get("LogsDirectory", "")
        if "DATA_ROOT" in roots and state and roots["DATA_ROOT"] != f"/var/lib/{state}":
            errors.append(f"{rel}: DATA_ROOT defaults to {roots['DATA_ROOT']}, not /var/lib/{state} ({unit_rel} StateDirectory)")
        if "LOG_ROOT" in roots and logs and roots["LOG_ROOT"] != f"/var/log/{logs}":
            errors.append(f"{rel}: LOG_ROOT defaults to {roots['LOG_ROOT']}, not /var/log/{logs} ({unit_rel} LogsDirectory)")
    return errors


def check(
    repo: Path,
    units: list[str],
    generators: dict[str, list[str]],
    rc_scripts: list[str] | None = None,
    shipped_unit: str | None = None,
    tunnel: tuple[str, str] | None = None,
) -> list[str]:
    errors: list[str] = []
    try:
        live = rows((repo / TABLE_FRAGMENT).read_text(encoding="utf-8"))
    except OSError as e:
        return [f"cannot read {TABLE_FRAGMENT}: {e}"]
    if len(live) < 10:
        return [f"{TABLE_FRAGMENT} names {len(live)} rows — the fragment or the pattern is wrong"]
    sources: dict[str, str] = {}
    for rel in (PLATFORM_RS, PLACE_RS):
        try:
            sources[rel] = (repo / rel).read_text(encoding="utf-8")
        except OSError as e:
            return [f"cannot read {rel}: {e}"]
    constants: dict[str, str] = {}
    for rel, name in (
        (PLACE_RS, FREEBSD_RENDEZVOUS_CONST),
        (PLATFORM_RS, LINUX_PARENT_CONST),
        (PLATFORM_RS, FREEBSD_PARENT_CONST),
        (PLACE_RS, DATA_HOME_CONST),
    ):
        value = string_constant(sources[rel], name)
        if value is None:
            return [f"{rel}: {name} is not a string constant — the gate has no path to check"]
        constants[name] = value
    linux_home = f"{constants[LINUX_PARENT_CONST]}/{constants[DATA_HOME_CONST]}"
    freebsd_home = f"{constants[FREEBSD_PARENT_CONST]}/{constants[DATA_HOME_CONST]}"
    unit_texts: dict[str, dict[str, str]] = {}
    for rel in units:
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {rel}: {e}")
            continue
        unit_texts[rel] = unit_fields(text)
        errors.extend(check_unit(rel, text, live, linux_home))
    for rel, unit_rels in generators.items():
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {rel}: {e}")
            continue
        errors.extend(check_generator(rel, text, live, {u: unit_texts[u] for u in unit_rels if u in unit_texts}))
    scripts = rc_scripts or []
    if scripts:
        if shipped_unit is None or shipped_unit not in unit_texts:
            errors.append(f"no shipped unit is loaded — the rc.d check has no RestartSec to read ({shipped_unit})")
            shipped: dict[str, str] = {}
        else:
            shipped = unit_texts[shipped_unit]
        rendezvous = constants[FREEBSD_RENDEZVOUS_CONST]
        for rel in scripts:
            try:
                text = (repo / rel).read_text(encoding="utf-8")
            except OSError as e:
                errors.append(f"cannot read {rel}: {e}")
                continue
            errors.extend(check_rc_script(rel, text, live, rendezvous, freebsd_home, shipped))
    if tunnel is not None:
        try:
            tunnel_live = tunnel_rows((repo / TUNNEL_TABLE_RS).read_text(encoding="utf-8"))
        except OSError as e:
            return errors + [f"cannot read {TUNNEL_TABLE_RS}: {e}"]
        if len(tunnel_live) < 10:
            return errors + [f"{TUNNEL_TABLE_RS} names {len(tunnel_live)} rows — the table or the pattern is wrong"]
        unit_rel, rc_rel = tunnel
        try:
            unit_text = (repo / unit_rel).read_text(encoding="utf-8")
            rc_text = (repo / rc_rel).read_text(encoding="utf-8")
        except OSError as e:
            return errors + [f"cannot read the tunnel's launchers: {e}"]
        errors.extend(check_tunnel_unit(unit_rel, unit_text, tunnel_live))
        errors.extend(check_tunnel_rc(rc_rel, rc_text, tunnel_live, unit_fields(unit_text)))
    if not units and not generators and not scripts and tunnel is None:
        errors.append("no unit, rc.d script, or generator is listed — the gate has no subject")
    return errors


def selftest() -> int:
    table = (
        "| Option | Kind | Default | Where | Runtime | Description |\n|---|---|---|---|---|---|\n"
        "| `network` | word | `mainnet` | command line | no | x |\n"
        "| `config-file` | path | — | command line | no | x |\n"
        "| `data-dir` | path | — | both | no | x |\n"
        "| `log-file` | path | — | both | no | x |\n"
        "| `log-level` | word | `warn` | both | yes | x |\n"
        "| `clearnet-listen` | list | — | both | no | x |\n"
        "| `rpc-admin-listen` | list | — | both | no | x |\n"
        "| `tor` | word | `managed` | both | no | x |\n"
        "| `tor-socks` | endpoint | — | both | no | x |\n"
        "| `notify-block` | command | — | file | no | x |\n"
        "| `console` | switch | — | command line | no | x |\n"
        "| `service` | switch | — | command line | no | x |\n"
        "| `rpc-socket-dir` | path | — | both | no | x |\n"
        "<!-- development rows, live on the named networks only and not in --help: dev-difficulty (regtest) -->\n"
    )
    unit_ok = (
        "[Service]\nExecStart=/usr/local/bin/shekyld --service --log-file /var/log/shekyl/shekyld.log\n"
        "RuntimeDirectory=shekyl\nRuntimeDirectoryMode=0755\nStateDirectory=shekyl\nStateDirectoryMode=0700\nLogsDirectory=shekyl\n"
        "Restart=on-failure\nRestartSec=30\n"
    )
    fleet_ok = (
        "[Service]\nExecStart=/usr/local/bin/shekyld --network stagenet --config-file /etc/f/node-%i.toml --rpc-socket-dir /run/f/%i\n"
        "RuntimeDirectory=f/%i\nRuntimeDirectoryMode=0700\nStateDirectory=f/%i\nLogsDirectory=f\n"
    )
    gen_ok = (
        'DATA_ROOT="${DATA_ROOT:-/var/lib/f}"\nLOG_ROOT="${LOG_ROOT:-/var/log/f}"\n'
        '    echo "data-dir = \\"$DATA_ROOT/$i\\""\n    echo "log-level = \\"info\\""\n    echo "tor = \\"off\\""\n'
    )
    cases = [
        ("agreeing recipes pass", unit_ok, fleet_ok, gen_ok, []),
        ("a dead flag on ExecStart is named", unit_ok.replace("--log-file", "--non-interactive --log-file"), fleet_ok, gen_ok, ["`--non-interactive`, which is not a row"]),
        ("a file-only row on ExecStart is named", unit_ok.replace("--log-file", "--notify-block x --log-file"), fleet_ok, gen_ok, ["`--notify-block`, a file-only row"]),
        ("a service data dir on StateDirectory passes", unit_ok.replace("--service ", "--service --data-dir /var/lib/shekyl "), fleet_ok, gen_ok, []),
        ("a data dir off StateDirectory is named", unit_ok.replace("--service ", "--service --data-dir /srv/shekyl "), fleet_ok, gen_ok, ["is not /var/lib/shekyl (StateDirectory)"]),
        ("a service StateDirectory off the daemon's data home is named", unit_ok.replace("\nStateDirectory=shekyl", "\nStateDirectory=other"), fleet_ok, gen_ok, ["the daemon's default /var/lib/shekyl, but StateDirectory makes /var/lib/other"]),
        ("a service data home not 0700 is named", unit_ok.replace("StateDirectoryMode=0700", "StateDirectoryMode=0755"), fleet_ok, gen_ok, ["is not StateDirectoryMode=0700"]),
        ("a service unit without a StateDirectory is named", unit_ok.replace("\nStateDirectory=shekyl\nStateDirectoryMode=0700", ""), fleet_ok, gen_ok, ["has no StateDirectory for its data home"]),
        ("a log file off LogsDirectory is named", unit_ok.replace("/var/log/shekyl/shekyld.log", "/var/log/other/shekyld.log"), fleet_ok, gen_ok, ["is not under /var/log/shekyl (LogsDirectory)"]),
        ("a dead key written by a generator is named", unit_ok, fleet_ok, gen_ok.replace('"tor = ', '"no-igd = '), ["`no-igd = …`, which is not a row"]),
        ("a command-line row written into a file is named", unit_ok, fleet_ok, gen_ok.replace('"tor = ', '"network = '), ["`network = …`, a command-line-only row"]),
        ("a generator root off the fleet unit is named", unit_ok, fleet_ok, gen_ok.replace("/var/lib/f", "/var/lib/g"), ["DATA_ROOT defaults to /var/lib/g"]),
        ("a unit with neither service nor a socket directory is named", unit_ok.replace("--service ", ""), fleet_ok, gen_ok, ["names neither --service nor --rpc-socket-dir"]),
        ("a service unit without the rendezvous directory is named", unit_ok.replace("RuntimeDirectoryMode=0755", "RuntimeDirectoryMode=0700"), fleet_ok, gen_ok, ["needs the service's rendezvous directory"]),
        ("a service given a socket directory is named", unit_ok.replace("--service ", "--service --rpc-socket-dir /run/shekyl "), fleet_ok, gen_ok, ["a service is given no socket directory"]),
        ("a socket directory off RuntimeDirectory is named", unit_ok, fleet_ok.replace("--rpc-socket-dir /run/f/%i", "--rpc-socket-dir /run/g/%i"), gen_ok, ["is not /run/f/%i (RuntimeDirectory)"]),
        ("a socket directory not 0700 is named", unit_ok, fleet_ok.replace("RuntimeDirectoryMode=0700", "RuntimeDirectoryMode=0755"), gen_ok, ["is not RuntimeDirectoryMode=0700"]),
    ]
    rc_ok = (
        "name=shekyld\n"
        'start_precmd="${name}_prestart"\n'
        'command_args="-f -S -T ${name} -P ${pidfile} -u shekyl /bin/sh /usr/local/etc/rc.d/shekyld supervise'
        ' --service --log-file /var/log/shekyl/shekyld.log ${shekyld_args}"\n'
        "shekyld_supervise()\n"
        "{\n"
        "\trestart_seconds=30\n"
        '\t/usr/local/bin/shekyld "$@" &\n'
        '\tcase "$status" in\n'
        "\t0 | 129 | 130 | 141 | 143) exit 0 ;;\n"
        "\tesac\n"
        "}\n"
        'if [ "${1:-}" = "supervise" ]; then\n'
        "\tshift\n"
        '\tshekyld_supervise "$@"\n'
        "fi\n"
        "shekyld_prestart()\n"
        "{\n"
        "\tinstall -d -o shekyl -g shekyl -m 0755 /var/run/shekyl || return 1\n"
        "\tinstall -d -o shekyl -g shekyl -m 0700 /var/db/shekyl || return 1\n"
        "\tinstall -d -o shekyl -g shekyl -m 0750 /var/log/shekyl || return 1\n"
        "}\n"
    )
    platform_ok = (
        'const FREEBSD_SERVICE_RENDEZVOUS: &str = "/var/run/shekyl";\n'
        'const LINUX_SERVICE_PARENT: &str = "/var/lib";\n'
        'const FREEBSD_SERVICE_PARENT: &str = "/var/db";\n'
    )
    paths_ok = 'const SERVICE_DATA_HOME: &str = "shekyl";\n'

    def place_of(platform: str) -> str:
        """The rendezvous crate's fixture for a platform fixture: the
        rendezvous row as that fixture spells it, and the data home's name.
        One fixture text carries a case's edit to either file."""
        return platform + paths_ok

    rc_cases = [
        ("an agreeing rc.d script passes", rc_ok, platform_ok, unit_ok, []),
        ("a dead flag on the rc.d command line is named", rc_ok.replace("--log-file", "--detach --log-file"), platform_ok, unit_ok, ["`--detach`, which is not a row"]),
        ("an rc.d data home the prestart function does not make is named", rc_ok.replace("-m 0700 /var/db/shekyl", "-m 0700 /var/db/other"), platform_ok, unit_ok, ["the service's data home /var/db/shekyl is not made by shekyld_prestart()"]),
        ("an rc.d --data-dir naming the data home passes", rc_ok.replace("--service ", "--service --data-dir /var/db/shekyl "), platform_ok, unit_ok, []),
        ("an rc.d --data-dir off the data home is named", rc_ok.replace("--service ", "--service --data-dir /var/db/other "), platform_ok, unit_ok, ["--data-dir /var/db/other is not the service's data home /var/db/shekyl"]),
        ("an rc.d data home off the platform constant is named", rc_ok, platform_ok.replace('"/var/db"', '"/var/other"'), unit_ok, ["the service's data home /var/other/shekyl is not made"]),
        ("a unit data home off the platform constant is named", rc_ok, platform_ok.replace('"/var/lib"', '"/srv"'), unit_ok, ["the daemon's default /srv/shekyl, but StateDirectory makes /var/lib/shekyl"]),
        ("a missing data-home constant is refused", rc_ok, platform_ok.replace("LINUX_SERVICE_PARENT", "LINUX_PARENT"), unit_ok, ["LINUX_SERVICE_PARENT is not a string constant"]),
        ("an rc.d data home not 0700 is named", rc_ok.replace("-m 0700 /var/db/shekyl", "-m 0750 /var/db/shekyl"), platform_ok, unit_ok, ["made at mode 0750, not 0700"]),
        ("an rc.d log directory the prestart function does not make is named", rc_ok.replace("-m 0750 /var/log/shekyl", "-m 0750 /var/log/other"), platform_ok, unit_ok, ["which shekyld_prestart() does not make"]),
        ("an rc.d log directory not 0750 is named", rc_ok.replace("-m 0750 /var/log/shekyl", "-m 0777 /var/log/shekyl"), platform_ok, unit_ok, ["made at mode 0777, not 0750"]),
        ("an rc.d script without --service is named", rc_ok.replace("--service ", ""), platform_ok, unit_ok, ["does not pass --service"]),
        ("an rc.d script given a socket directory is named", rc_ok.replace("--service ", "--service --rpc-socket-dir /var/run/shekyl "), platform_ok, unit_ok, ["a service is given no socket directory"]),
        ("an rc.d script without the rendezvous directory is named", rc_ok.replace("-m 0755 /var/run/shekyl", "-m 0700 /var/run/shekyl"), platform_ok, unit_ok, ["/var/run/shekyl made at mode 0755"]),
        ("an rc.d rendezvous path off the platform constant is named", rc_ok, platform_ok.replace("/var/run/shekyl", "/var/run/other"), unit_ok, ["/var/run/other made at mode 0755"]),
        ("an rc.d script that runs no shekyld is named", rc_ok.replace("/usr/local/bin/shekyld", "/usr/local/bin/other"), platform_ok, unit_ok, ["does not run /usr/local/bin/shekyld"]),
        ("an rc.d script whose prestart is not the called function is named", rc_ok.replace('start_precmd="${name}_prestart"', 'start_precmd="${name}_other"'), platform_ok, unit_ok, ["shekyld_other()"]),
        ("an rc.d supervise branch that calls no function is named", rc_ok.replace('\tshekyld_supervise "$@"\n', "\t:\n"), platform_ok, unit_ok, ["no supervise branch calls its function"]),
        ("an rc.d script that restarts a clean exit is named", rc_ok.replace("0 | 129 | 130 | 141 | 143) exit 0", "0 | 129 | 130 | 141 | 143) :"), platform_ok, unit_ok, ["retries a clean exit"]),
        ("an rc.d script that restarts a death by SIGTERM is named", rc_ok.replace("0 | 129 | 130 | 141 | 143)", "0 | 129 | 130 | 141)"), platform_ok, unit_ok, ["retries a clean exit"]),
        ("an rc.d script that passes daemon -R is named", rc_ok.replace("-f -S", "-f -R 30 -S"), platform_ok, unit_ok, ["daemon(8) is passed -R"]),
        ("an rc.d restart delay off the shipped unit is named", rc_ok.replace("restart_seconds=30", "restart_seconds=5"), platform_ok, unit_ok, ["restart_seconds is 5, not the shipped unit's RestartSec=30"]),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs" / "generated").mkdir(parents=True)
        (repo / TABLE_FRAGMENT).write_text(table)
        (repo / "u").mkdir()
        (repo / "rust" / "shekyl-process" / "src").mkdir(parents=True)
        (repo / PLATFORM_RS).write_text(platform_ok)
        (repo / "rust" / "shekyl-rpc-rendezvous" / "src").mkdir(parents=True)
        (repo / PLACE_RS).write_text(place_of(platform_ok))
        shipped = "u/shipped.service"
        for title, unit, fleet, gen, expect in cases:
            (repo / "u" / "shipped.service").write_text(unit)
            (repo / "u" / "fleet@.service").write_text(fleet)
            (repo / "u" / "gen.sh").write_text(gen)
            errors = check(repo, ["u/shipped.service", "u/fleet@.service"], {"u/gen.sh": ["u/fleet@.service"]})
            ok = (not errors) if not expect else len(errors) == len(expect) and all(any(e in err for err in errors) for e in expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        for title, script, platform, unit, expect in rc_cases:
            (repo / "u" / "shipped.service").write_text(unit)
            (repo / "u" / "fleet@.service").write_text(fleet_ok)
            (repo / "u" / "gen.sh").write_text(gen_ok)
            (repo / "u" / "rc").write_text(script)
            (repo / PLATFORM_RS).write_text(platform)
            (repo / PLACE_RS).write_text(place_of(platform))
            errors = check(repo, ["u/shipped.service", "u/fleet@.service"], {"u/gen.sh": ["u/fleet@.service"]}, ["u/rc"], shipped)
            ok = (not errors) if not expect else len(errors) == len(expect) and all(any(e in err for err in errors) for e in expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        t_table = "".join(
            f'    row("{name}", Kind::Path, Default::Unset, Surface::{where}, "x"),\n'
            for name, where in (
                ("help", "Cli"), ("version", "Cli"), ("network", "Cli"), ("config-file", "Cli"),
                ("daemon-endpoint", "Both"), ("daemon-bundle-file", "Both"), ("rpc-key-file", "Both"),
                ("rpc-grant", "Both"), ("listen", "Both"), ("log-file", "Both"), ("log-level", "Both"),
                ("rpc-key-create", "Cli"),
            )
        )
        t_unit = (
            "[Service]\nExecStart=/usr/local/bin/shekyl-rpc-tunnel --config-file /etc/shekyl/t.toml"
            " --rpc-key-file /var/lib/shekyl-tunnel/k.key --log-file /var/log/shekyl-tunnel/t.log\n"
            "User=shekyl-tunnel\nGroup=shekyl-tunnel\nStateDirectory=shekyl-tunnel\nStateDirectoryMode=0700\n"
            "LogsDirectory=shekyl-tunnel\nRestart=on-failure\nRestartSec=30\n"
            + "".join(f"{key}={value}\n" for key, value in TUNNEL_HARDENING.items())
        )
        t_rc = (
            "name=shekyl_rpc_tunnel\n"
            'start_precmd="${name}_prestart"\n'
            'command_args="-f -S -T shekyl-rpc-tunnel -P ${pidfile} -u shekyl-tunnel /bin/sh /usr/local/etc/rc.d/shekyl-rpc-tunnel supervise'
            ' --config-file /usr/local/etc/shekyl/t.toml --rpc-key-file /var/db/shekyl-tunnel/k.key'
            ' --log-file /var/log/shekyl-tunnel/t.log ${shekyl_rpc_tunnel_args}"\n'
            "shekyl_rpc_tunnel_supervise()\n{\n\trestart_seconds=30\n"
            '\t/usr/local/bin/shekyl-rpc-tunnel "$@" &\n'
            '\tcase "$status" in\n\t0 | 129 | 130 | 141 | 143) exit 0 ;;\n\tesac\n}\n'
            'if [ "${1:-}" = "supervise" ]; then\n\tshift\n\tshekyl_rpc_tunnel_supervise "$@"\nfi\n'
            "shekyl_rpc_tunnel_prestart()\n{\n"
            "\tinstall -d -o shekyl-tunnel -g shekyl-tunnel -m 0700 /var/db/shekyl-tunnel || return 1\n"
            "\tinstall -d -o shekyl-tunnel -g shekyl-tunnel -m 0750 /var/log/shekyl-tunnel || return 1\n}\n"
        )
        tunnel_cases = [
            ("agreeing tunnel launchers pass", t_unit, t_rc, []),
            ("a tunnel unit run as the daemon's account is named", t_unit.replace("User=shekyl-tunnel", "User=shekyl"), t_rc, ["User=shekyl; the tunnel runs as its own account"]),
            ("a tunnel unit run as root is named", t_unit.replace("Group=shekyl-tunnel", "Group=root"), t_rc, ["Group=root"]),
            ("a tunnel key outside the state directory is named", t_unit.replace("/var/lib/shekyl-tunnel/k.key", "/etc/k.key"), t_rc, ["is not in /var/lib/shekyl-tunnel (StateDirectory)"]),
            ("a tunnel state directory not 0700 is named", t_unit.replace("StateDirectoryMode=0700", "StateDirectoryMode=0755"), t_rc, ["is not StateDirectoryMode=0700"]),
            ("a dead flag on the tunnel unit is named", t_unit.replace("--config-file", "--detach --config-file"), t_rc, ["`--detach`, which is not a row of the tunnel's table"]),
            ("a tunnel unit without a configuration file is named", t_unit.replace("--config-file /etc/shekyl/t.toml ", ""), t_rc, ["names no --config-file"]),
            ("a tunnel listening off loopback is named", t_unit.replace("--log-file", "--listen 192.0.2.7:1 --log-file"), t_rc, ["is not a loopback address"]),
            ("a loopback tunnel listener passes", t_unit.replace("--log-file", "--listen [::1]:1 --log-file"), t_rc, []),
            ("a tunnel rc.d script run as the daemon's account is named", t_unit, t_rc.replace("-u shekyl-tunnel", "-u shekyl"), ["does not run the tunnel as shekyl-tunnel"]),
            ("a tunnel key directory the prestart makes 0755 is named", t_unit, t_rc.replace("-m 0700 /var/db/shekyl-tunnel", "-m 0755 /var/db/shekyl-tunnel"), ["is not made at mode 0700 as shekyl-tunnel"]),
            ("a tunnel rc.d restart delay off its unit is named", t_unit, t_rc.replace("restart_seconds=30", "restart_seconds=5"), ["restart_seconds is not the tunnel unit's RestartSec=30"]),
            ("a tunnel unit with W^X off is named", t_unit.replace("MemoryDenyWriteExecute=true", "MemoryDenyWriteExecute=false"), t_rc, ["MemoryDenyWriteExecute=false; the hardening set is MemoryDenyWriteExecute=true"]),
            ("a tunnel unit without a capability bound is named", t_unit.replace("CapabilityBoundingSet=\n", ""), t_rc, ["CapabilityBoundingSet=None; the hardening set is CapabilityBoundingSet="]),
            ("a tunnel unit with a wider address set is named", t_unit.replace("AF_INET AF_INET6 AF_UNIX", "AF_INET AF_INET6 AF_UNIX AF_NETLINK"), t_rc, ["the hardening set is RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX"]),
            ("a tunnel rc.d script that runs another binary is named", t_unit, t_rc.replace('/usr/local/bin/shekyl-rpc-tunnel "$@"', '/usr/local/bin/shekyld "$@"'), ["does not run /usr/local/bin/shekyl-rpc-tunnel"]),
        ]
        (repo / "rust" / "shekyl-rpc-tunnel" / "src").mkdir(parents=True)
        (repo / TUNNEL_TABLE_RS).write_text(t_table)
        (repo / PLATFORM_RS).write_text(platform_ok)
        (repo / PLACE_RS).write_text(place_of(platform_ok))
        for title, unit, rc, expect in tunnel_cases:
            (repo / "u" / "tunnel.service").write_text(unit)
            (repo / "u" / "tunnel-rc").write_text(rc)
            errors = check(repo, [], {}, tunnel=("u/tunnel.service", "u/tunnel-rc"))
            ok = (not errors) if not expect else len(errors) == len(expect) and all(any(e in err for err in errors) for e in expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        errors = check(repo, [], {})
        ok = bool(errors) and any("no subject" in e for e in errors)
        print(f"{'ok' if ok else 'FAIL'}: an empty subject is refused" + ("" if ok else f" — got {errors}"))
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    repo = Path(__file__).resolve().parents[2]
    errors = check(repo, UNITS, GENERATORS, RC_SCRIPTS, SHIPPED_UNIT, (TUNNEL_UNIT, TUNNEL_RC))
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2 if any("cannot read" in e or "pattern is wrong" in e or "no subject" in e or "not a string constant" in e for e in errors) else 1
    print(
        f"launch recipes: {len(UNITS)} unit(s), {len(RC_SCRIPTS)} rc.d script(s) and {len(GENERATORS)} generator(s) "
        "say only what the daemon's table says; the tunnel's unit and rc.d script only what its table says"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
