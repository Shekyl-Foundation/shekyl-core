#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""The recipe gate (DAEMON_CONFIG_CUTOVER.md DC-Q8, §5.2): the launchers that
ship or that provision the fleet say only what the daemon's table says.

Three checks over an enumerated set of files:

1. Every `--flag` a unit's `ExecStart` passes to `shekyld` is a row of the
   table (the generated fragment `docs/generated/shekyld_options.md`, which
   a `shekyl-daemon-config` test holds equal to the table). A command-line
   row is fine there; a file-only row is not.
2. A unit that names `--data-dir` names `/var/lib/<StateDirectory>`, and a
   unit that names `--log-file` names a file under `/var/log/<LogsDirectory>`:
   the paths systemd creates and the paths the daemon writes are one pair,
   not two that happen to agree today.
3. Every key the fleet's generators write into a node's TOML
   (`echo "key = …"` lines) is a row the file accepts, and the generator's
   default roots are the fleet units' `StateDirectory` and `LogsDirectory`.

Exit 0 when every check holds; 1 naming each failure; 2 on a subject that
could not be read (rule 47: a gate asserts its own subject).
"""

from __future__ import annotations

import re
import shlex
import sys
import tempfile
from pathlib import Path

TABLE_FRAGMENT = "docs/generated/shekyld_options.md"

UNITS = [
    "contrib/packaging/linux/shekyld.service",
    "utils/fleet/skl-node@.service",
    "utils/fleet/skl-clearnet@.service",
]

# generator -> (the units whose directories it must agree with)
GENERATORS = {
    "utils/fleet/gen_host_configs.sh": ["utils/fleet/skl-node@.service", "utils/fleet/skl-clearnet@.service"],
    "utils/fleet/run_arm.sh": [],
}


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


def check_unit(rel: str, text: str, live: dict[str, str]) -> list[str]:
    errors: list[str] = []
    fields = unit_fields(text)
    exec_start = fields.get("ExecStart")
    if not exec_start or "shekyld" not in exec_start:
        return [f"{rel}: no ExecStart that runs shekyld"]
    flags, values = exec_flags(exec_start)
    for flag in flags:
        where = live.get(flag)
        if where is None:
            errors.append(f"{rel}: ExecStart passes `--{flag}`, which is not a row of the daemon's table")
        elif where == "file":
            errors.append(f"{rel}: ExecStart passes `--{flag}`, a file-only row")
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


def check(repo: Path, units: list[str], generators: dict[str, list[str]]) -> list[str]:
    errors: list[str] = []
    try:
        live = rows((repo / TABLE_FRAGMENT).read_text(encoding="utf-8"))
    except OSError as e:
        return [f"cannot read {TABLE_FRAGMENT}: {e}"]
    if len(live) < 10:
        return [f"{TABLE_FRAGMENT} names {len(live)} rows — the fragment or the pattern is wrong"]
    unit_texts: dict[str, dict[str, str]] = {}
    for rel in units:
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {rel}: {e}")
            continue
        unit_texts[rel] = unit_fields(text)
        errors.extend(check_unit(rel, text, live))
    for rel, unit_rels in generators.items():
        try:
            text = (repo / rel).read_text(encoding="utf-8")
        except OSError as e:
            errors.append(f"cannot read {rel}: {e}")
            continue
        errors.extend(check_generator(rel, text, live, {u: unit_texts[u] for u in unit_rels if u in unit_texts}))
    if not units and not generators:
        errors.append("no unit and no generator is listed — the gate has no subject")
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
        "<!-- development rows, live on the named networks only and not in --help: dev-difficulty (regtest) -->\n"
    )
    unit_ok = (
        "[Service]\nExecStart=/usr/local/bin/shekyld --data-dir /var/lib/shekyl --log-file /var/log/shekyl/shekyld.log\n"
        "StateDirectory=shekyl\nLogsDirectory=shekyl\n"
    )
    fleet_ok = "[Service]\nExecStart=/usr/local/bin/shekyld --network stagenet --config-file /etc/f/node-%i.toml\nStateDirectory=f/%i\nLogsDirectory=f\n"
    gen_ok = (
        'DATA_ROOT="${DATA_ROOT:-/var/lib/f}"\nLOG_ROOT="${LOG_ROOT:-/var/log/f}"\n'
        '    echo "data-dir = \\"$DATA_ROOT/$i\\""\n    echo "log-level = \\"info\\""\n    echo "tor = \\"off\\""\n'
    )
    cases = [
        ("agreeing recipes pass", unit_ok, fleet_ok, gen_ok, []),
        ("a dead flag on ExecStart is named", unit_ok.replace("--data-dir", "--non-interactive --data-dir"), fleet_ok, gen_ok, ["`--non-interactive`, which is not a row"]),
        ("a file-only row on ExecStart is named", unit_ok.replace("--data-dir", "--notify-block x --data-dir"), fleet_ok, gen_ok, ["`--notify-block`, a file-only row"]),
        ("a data dir off StateDirectory is named", unit_ok.replace("/var/lib/shekyl", "/srv/shekyl"), fleet_ok, gen_ok, ["is not /var/lib/shekyl (StateDirectory)"]),
        ("a log file off LogsDirectory is named", unit_ok.replace("/var/log/shekyl/shekyld.log", "/var/log/other/shekyld.log"), fleet_ok, gen_ok, ["is not under /var/log/shekyl (LogsDirectory)"]),
        ("a dead key written by a generator is named", unit_ok, fleet_ok, gen_ok.replace('"tor = ', '"no-igd = '), ["`no-igd = …`, which is not a row"]),
        ("a command-line row written into a file is named", unit_ok, fleet_ok, gen_ok.replace('"tor = ', '"network = '), ["`network = …`, a command-line-only row"]),
        ("a generator root off the fleet unit is named", unit_ok, fleet_ok, gen_ok.replace("/var/lib/f", "/var/lib/g"), ["DATA_ROOT defaults to /var/lib/g"]),
    ]
    failures = 0
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs" / "generated").mkdir(parents=True)
        (repo / TABLE_FRAGMENT).write_text(table)
        (repo / "u").mkdir()
        for title, unit, fleet, gen, expect in cases:
            (repo / "u" / "shipped.service").write_text(unit)
            (repo / "u" / "fleet@.service").write_text(fleet)
            (repo / "u" / "gen.sh").write_text(gen)
            errors = check(repo, ["u/shipped.service", "u/fleet@.service"], {"u/gen.sh": ["u/fleet@.service"]})
            ok = (not errors) if not expect else len(errors) == len(expect) and all(any(e in err for err in errors) for e in expect)
            print(f"{'ok' if ok else 'FAIL'}: {title}" + ("" if ok else f" — got {errors}"))
            failures += 0 if ok else 1
        errors = check(repo, [], {})
        ok = bool(errors)
        print(f"{'ok' if ok else 'FAIL'}: an empty subject is refused")
        failures += 0 if ok else 1
    return 1 if failures else 0


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        return selftest()
    repo = Path(__file__).resolve().parents[2]
    errors = check(repo, UNITS, GENERATORS)
    if errors:
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        return 2 if any("cannot read" in e or "pattern is wrong" in e or "no subject" in e for e in errors) else 1
    print(f"launch recipes: {len(UNITS)} unit(s) and {len(GENERATORS)} generator(s) say only what the daemon's table says")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
