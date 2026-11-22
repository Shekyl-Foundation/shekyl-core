#!/usr/bin/env python3
# Copyright (c) 2026, The Shekyl Foundation
#
# All rights reserved.
# BSD-3-Clause
"""A nightly leg whose inputs have not changed since it last passed is skipped.

The nightly workflows (`nightly.yml`, `nightly-live-daemon-slow.yml`) test
`main` and `dev` every night. `main` moves only at a release, so most nights
its legs re-test a commit that already passed: on 2026-11-21 the `main` legs
of the two workflows took 587 runner-minutes, every one of them on
07c8abba5f, which had passed the night before. Ruled 2026-11-22: one
mechanism for every nightly workflow.

A leg's key is the SHA-256 of what decides its verdict:

  - the commit it tests (the branch's head when the run is planned; the leg
    checks out that commit, not the branch);
  - the workflow file the run uses (its blob at the run's workflow commit);
  - the toolchain pin (`rust/rust-toolchain.toml`) and the pinned test
    chains (`rust/shekyl-chain-forge/chains/hosted.toml`), each its blob at
    the tested commit;
  - the runner image (`ImageOS` and `ImageVersion` of the planning job's
    runner), and for a job in a container, that image's digest;
  - the leg itself (its job and matrix values).

A leg is skipped when an earlier run relies for it: a scheduled run of the
same workflow on the default branch, created less than `MAX_AGE` ago, whose
keys artifact holds the same key for that leg and in which that leg's job
concluded `success`. Only GitHub's record of the job decides "passed": a
skipped leg is never relied on (it has no job, so no `success`), and no file
a run writes can claim a pass. `MAX_AGE` is under a week, so every leg runs
in full at least once a week whatever its key (the ruled weekly run). Late
starts (six to eight hours here, 2026-11) are why it is an age and not a
weekday.

Everything fails toward running: a dispatched run runs every leg it selects;
a leg whose key cannot be computed runs; a job this file does not name fails
`--check`; and if the planner itself does not succeed, the workflow falls
back to its full matrices.

Never skipped, whatever the key (`NEVER`): a job that draws fresh
randomness by design (a fuzzer, a property test with no fixed seed), a job
whose verdict is about an outside host, and a measurement series (a benchmark:
each night is new data). Environment a job fetches at run time by a pin (the
toolchain through rustup, packages through apt in a container) is treated as
part of the image: not in the key beyond the image's identity, and bounded
by the weekly run.

  nightly_skip.py --plan --workflow FILE   decide this run's legs (in the
                                           workflow's `plan` job); writes
                                           the matrices to GITHUB_OUTPUT,
                                           the keys to nightly-keys.json and
                                           a summary naming each skipped
                                           leg's run
  nightly_skip.py --check                  hold each workflow to the wiring
  nightly_skip.py --selftest
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import subprocess
import sys
import urllib.request
import zipfile
from datetime import datetime, timedelta, timezone

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_workflows_parse import StrictLoader  # noqa: E402

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
WORKFLOWS = os.path.join(ROOT, ".github", "workflows")

# The workflows this mechanism plans, and in each the jobs never skipped,
# with why. Every other job but `plan` and `report-red` takes its matrix
# from the planner (--check).
SUBJECTS = {
    "nightly.yml": {
        "proptest-exhaustive": "fresh randomness by design: 200,000 property cases a night "
                               "with no fixed seed, so each night tests new cases",
        "bench-full": "a measurement series: each night is new data on the runner, not a "
                      "verdict on the code",
        "bench-full-drift": "reads bench-full's capture from the same run",
    },
    "nightly-live-daemon-slow.yml": {},
}
PLANNER = "plan"
REPORTER = "report-red"
KEYS_ARTIFACT = "nightly-keys"
TOOLCHAIN = "rust/rust-toolchain.toml"
CHAINS = "rust/shekyl-chain-forge/chains/hosted.toml"
# A planned job's matrix: the planner's output, or when the planner did
# not succeed, the full matrix written here.
MATRIX = re.compile(
    r"^\$\{\{ fromJSON\(needs\.plan\.outputs\['([a-z0-9-]+)'\] \|\| '(\{.*\})'\) \}\}$"
)

# Under a week, with room for a start that drifts later night to night, so
# a leg skipped six nights runs on the seventh.
MAX_AGE = timedelta(days=6, hours=12)

# The key's components, in order; a missing one makes the leg run.
COMPONENTS = ("leg", "commit", "workflow", "toolchain", "chains", "image", "container")


def stamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def key_of(components: dict[str, str]) -> str | None:
    """The leg's key, or None when a component is unknown (the leg runs)."""
    if any(not components.get(name) for name in COMPONENTS):
        return None
    canonical = json.dumps({name: components[name] for name in COMPONENTS}, sort_keys=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def changed(now: dict[str, str], then: dict[str, str]) -> list[str]:
    return [name for name in COMPONENTS if now.get(name) != then.get(name)]


def decide(legs: list[dict], candidates: list[dict], now: datetime, event: str,
           default_branch: str) -> list[dict]:
    """Each leg's decision.

    `legs`: {name, components, never} (`never`, a reason, or None).
    `candidates`: earlier runs of this workflow, newest first:
    {id, url, event, branch, created_at, keys: {name: {key, components}} or
    None, conclusions: {job name: conclusion}}.
    Returns each leg with `run` (bool), `reason`, and when skipped `relies`
    (the run's url).
    """
    out = []
    for leg in legs:
        name = leg["name"]
        key = key_of(leg["components"])
        decision = {"name": name, "key": key, "components": leg["components"], "run": True}
        if event != "schedule":
            decision["reason"] = f"a {event} run runs every leg it selects"
        elif leg.get("never"):
            decision["reason"] = f"never skipped: {leg['never']}"
        elif key is None:
            missing = [c for c in COMPONENTS if not leg["components"].get(c)]
            decision["reason"] = f"the key is incomplete ({', '.join(missing)} unknown)"
        else:
            last_pass = None
            for run in candidates:
                if run.get("event") != "schedule" or run.get("branch") != default_branch:
                    continue
                if run.get("conclusions", {}).get(name) != "success":
                    continue
                kept = (run.get("keys") or {}).get(name)
                if not kept:
                    continue
                last_pass = last_pass or (run, kept)
                if now - stamp(run["created_at"]) >= MAX_AGE:
                    continue
                if kept.get("key") == key:
                    decision.update(run=False, relies=run["url"],
                                    reason=f"passed with this key in {run['url']}")
                    break
            if decision["run"]:
                if last_pass is None:
                    decision["reason"] = "no scheduled run in reach passed it with a recorded key"
                else:
                    run, kept = last_pass
                    diff = changed(leg["components"], kept.get("components") or {})
                    if diff:
                        decision["reason"] = f"changed since {run['url']}: {', '.join(diff)}"
                    else:
                        decision["reason"] = (f"the last run that passed it with this key, "
                                              f"{run['url']}, is {MAX_AGE.days} or more days old "
                                              f"(the weekly full run)")
        out.append(decision)
    return out


def gh(path: str) -> object:
    out = subprocess.run(["gh", "api", path], check=True, capture_output=True, text=True).stdout
    return json.loads(out)


def gh_pages(path: str, field: str) -> list:
    sep = "&" if "?" in path else "?"
    items, page = [], 1
    while True:
        chunk = gh(f"{path}{sep}per_page=100&page={page}")[field]
        items += chunk
        if len(chunk) < 100:
            return items
        page += 1


def planned_jobs(doc: dict) -> dict[str, tuple[str, list[dict]]]:
    """Each planned job: (its output name, its full matrix's entries)."""
    out = {}
    for name, job in doc["jobs"].items():
        matrix = ((job.get("strategy") or {}).get("matrix")) if isinstance(job, dict) else None
        m = MATRIX.match(matrix) if isinstance(matrix, str) else None
        if m:
            out[name] = (m.group(1), json.loads(m.group(2))["include"])
    return out


def leg_name(job: str, entry: dict) -> str:
    """The job's `name:`, `<job> (<values>)`, its matrix values but the commit."""
    return f"{job} ({', '.join(str(v) for k, v in entry.items() if k != 'sha')})"


def blob(repo: str, path: str, ref: str) -> str:
    try:
        return gh(f"repos/{repo}/contents/{path}?ref={ref}")["sha"]
    except (subprocess.CalledProcessError, KeyError, json.JSONDecodeError):
        return ""


def image_digest(image: str) -> str:
    """A Docker Hub image's manifest digest, or "" (the leg then runs)."""
    m = re.fullmatch(r"(?:library/)?([a-z0-9._-]+):([A-Za-z0-9._-]+)", image)
    if not m:
        return ""
    name, tag = f"library/{m.group(1)}", m.group(2)
    try:
        auth = f"https://auth.docker.io/token?service=registry.docker.io&scope=repository:{name}:pull"
        with urllib.request.urlopen(auth, timeout=20) as r:
            token = json.load(r)["token"]
        req = urllib.request.Request(
            f"https://registry-1.docker.io/v2/{name}/manifests/{tag}", method="HEAD",
            headers={"Authorization": f"Bearer {token}", "Accept": ", ".join((
                "application/vnd.oci.image.index.v1+json",
                "application/vnd.docker.distribution.manifest.list.v2+json"))})
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.headers.get("Docker-Content-Digest", "")
    except (OSError, ValueError, KeyError):
        return ""


def candidates(repo: str, workflow_file: str, default_branch: str, now: datetime) -> list[dict]:
    """Earlier scheduled runs in reach, newest first, with their jobs and keys."""
    runs = gh(f"repos/{repo}/actions/workflows/{workflow_file}/runs"
              f"?event=schedule&branch={default_branch}&status=completed&per_page=20")
    out = []
    for run in runs["workflow_runs"]:
        if now - stamp(run["created_at"]) >= MAX_AGE + timedelta(days=1):
            continue
        jobs = gh_pages(f"repos/{repo}/actions/runs/{run['id']}/jobs", "jobs")
        keys = None
        for art in gh(f"repos/{repo}/actions/runs/{run['id']}/artifacts")["artifacts"]:
            if art["name"] == KEYS_ARTIFACT and not art.get("expired"):
                raw = subprocess.run(["gh", "api", f"repos/{repo}/actions/artifacts/{art['id']}/zip"],
                                     check=True, capture_output=True).stdout
                with zipfile.ZipFile(io.BytesIO(raw)) as z:
                    keys = json.loads(z.read(f"{KEYS_ARTIFACT}.json"))
        out.append({"id": run["id"], "url": run["html_url"], "event": run["event"],
                    "branch": run["head_branch"], "created_at": run["created_at"],
                    "keys": keys, "conclusions": {j["name"]: j["conclusion"] for j in jobs}})
    return out


def plan(workflow_file: str) -> int:
    env = os.environ
    repo = env["GITHUB_REPOSITORY"]
    event = env["GITHUB_EVENT_NAME"]
    default_branch = env["DEFAULT_BRANCH"]
    ref_input = env.get("INPUT_REF", "")
    # The file the run uses. The `job` context names the workflow this job
    # is defined in, which for a called workflow is its own file and commit,
    # not the caller's (`github.workflow_sha` is the caller's; there is no
    # `github.job_workflow_sha`: the main-calls-dev probe, 2026-11-22).
    job_ctx = json.loads(env.get("JOB_CONTEXT") or "{}")
    wf_sha = job_ctx.get("workflow_sha") or env["GITHUB_WORKFLOW_SHA"]
    wf_path = job_ctx.get("workflow_file_path") or workflow_file
    now = datetime.now(timezone.utc)
    with open(os.path.join(ROOT, workflow_file)) as f:
        doc = yaml.load(f, Loader=StrictLoader)
    never = SUBJECTS[os.path.basename(workflow_file)]
    workflow_blob = blob(repo, wf_path, wf_sha)
    image = f"{env.get('ImageOS', '')}/{env.get('ImageVersion', '')}".strip("/")
    if "/" not in image:
        image = ""
    commits: dict[str, str] = {}
    legs, entries = [], {}
    for job, (output, full) in planned_jobs(doc).items():
        container = (doc["jobs"][job].get("container") or {})
        container = container.get("image", "") if isinstance(container, dict) else container
        digest = image_digest(container) if container else "none"
        seen = set()
        for entry in full:
            entry = dict(entry)
            if ref_input:
                entry["branch"] = ref_input
            name = leg_name(job, entry)
            if name in seen:
                continue
            seen.add(name)
            branch = entry["branch"]
            if branch not in commits:
                try:
                    commits[branch] = gh(f"repos/{repo}/commits/{branch}")["sha"]
                except (subprocess.CalledProcessError, KeyError):
                    commits[branch] = ""
            sha = commits[branch]
            entry["sha"] = sha or branch
            entries[name] = (job, output, entry)
            legs.append({"name": name, "never": never.get(job), "components": {
                "leg": name, "commit": sha, "workflow": workflow_blob,
                "toolchain": blob(repo, TOOLCHAIN, sha) if sha else "",
                "chains": blob(repo, CHAINS, sha) if sha else "",
                "image": image, "container": digest}})
    # Earlier runs of the workflow the schedule started (the caller's, when
    # this one is called): GITHUB_WORKFLOW_REF is `<repo>/<path>@<ref>`.
    run_file = os.path.basename(env.get("GITHUB_WORKFLOW_REF", workflow_file).split("@", 1)[0])
    prior = candidates(repo, run_file, default_branch, now) if event == "schedule" else []
    decisions = decide(legs, prior, now, event, default_branch)
    matrices: dict[str, list[dict]] = {output: [] for _, (output, _) in planned_jobs(doc).items()}
    for d in decisions:
        job, output, entry = entries[d["name"]]
        if d["run"]:
            matrices[output].append(entry)
    with open(env["GITHUB_OUTPUT"], "a") as out:
        for output, include in matrices.items():
            out.write(f"{output}={json.dumps({'include': include}, separators=(',', ':'))}\n")
    with open(f"{KEYS_ARTIFACT}.json", "w") as f:
        json.dump({d["name"]: {"key": d["key"], "components": d["components"]} for d in decisions},
                  f, indent=1, sort_keys=True)
    lines = [f"### Nightly legs planned ({event})", "",
             "| Leg | Runs | Why |", "|---|---|---|"]
    for d in decisions:
        lines.append(f"| {d['name']} | {'yes' if d['run'] else 'skipped'} | {d['reason']} |")
    for job, why in never.items():
        lines.append(f"| {job} (every leg) | yes | never skipped: {why} |")
    skipped = [d for d in decisions if not d["run"]]
    lines += ["", f"{len(decisions) - len(skipped)} planned legs run, {len(skipped)} skipped; "
              f"a skipped leg relies on the run named beside it, where it passed with the same key."]
    text = "\n".join(lines) + "\n"
    print(text)
    if env.get("GITHUB_STEP_SUMMARY"):
        with open(env["GITHUB_STEP_SUMMARY"], "a") as f:
            f.write(text)
    return 0


def wiring_problems(filename: str, doc: object, never: dict[str, str]) -> list[str]:
    """How `doc` departs from the planner's wiring (empty when it holds)."""
    if not isinstance(doc, dict) or not isinstance(doc.get("jobs"), dict):
        return [f"{filename}: no jobs mapping"]
    jobs = doc["jobs"]
    if PLANNER not in jobs:
        return [f"{filename}: no `{PLANNER}` job: every leg runs every night"]
    problems = []
    outputs = (jobs[PLANNER].get("outputs") or {}) if isinstance(jobs[PLANNER], dict) else {}
    planned = planned_jobs(doc)
    for name in sorted(set(never) - set(jobs)):
        problems.append(f"{filename}: `{name}` is listed as never skipped but is not a job here")
    for name, job in jobs.items():
        if name in (PLANNER, REPORTER) or name in never:
            continue
        if name not in planned:
            problems.append(f"{filename}: `{name}` is neither planned (its matrix from "
                            f"needs.plan.outputs, with the full matrix as the fallback) nor "
                            f"listed as never skipped, with why")
            continue
        output, full = planned[name]
        needs = job.get("needs", [])
        needs = [needs] if isinstance(needs, str) else needs
        if PLANNER not in needs:
            problems.append(f"{filename}: `{name}` does not need `{PLANNER}`")
        cond = str(job.get("if", ""))
        guard = "needs.plan.outputs['%s'] != '{\"include\":[]}'" % name
        if not cond.startswith("${{ !cancelled() && ") or guard not in cond:
            problems.append(f"{filename}: `{name}`'s `if` must start `!cancelled() &&` (a failed "
                            f"planner runs it) and hold `{guard}` (no empty matrix)")
        if output != name or outputs.get(name) != "${{ steps.plan.outputs['%s'] }}" % name:
            problems.append(f"{filename}: `{name}` reads a planner output `{PLANNER}` does not "
                            f"pass on as `{name}`")
        if {e.get("branch") for e in full} != {"main", "dev"}:
            problems.append(f"{filename}: `{name}`'s fallback matrix does not cover main and dev")
        refs = [st.get("with", {}).get("ref") for st in job.get("steps", [])
                if isinstance(st, dict) and "actions/checkout" in str(st.get("uses", ""))]
        if refs != ["${{ matrix.sha || matrix.branch }}"]:
            problems.append(f"{filename}: `{name}` must check out the commit its key names "
                            f"(`ref: ${{{{ matrix.sha || matrix.branch }}}}`), once")
        dims = list(full[0]) if full else []
        want_name = f"{name} ({', '.join('${{ matrix.%s }}' % d for d in dims)})"
        if job.get("name") != want_name:
            problems.append(f"{filename}: `{name}`'s name must be `{want_name}`: the planner and "
                            f"the reporter read the leg by it")
    return problems


def check() -> int:
    problems = []
    for filename, never in SUBJECTS.items():
        path = os.path.join(WORKFLOWS, filename)
        if not os.path.exists(path):
            problems.append(f"{filename}: missing (renamed? update SUBJECTS)")
            continue
        with open(path) as f:
            problems += wiring_problems(filename, yaml.load(f, Loader=StrictLoader), never)
    for p in problems:
        print(f"FAIL: {p}")
    if problems:
        return 1
    print(f"nightly skip: {', '.join(SUBJECTS)} plan every job but the never-skipped "
          f"({sum(len(n) for n in SUBJECTS.values())}, each with why); a failed planner runs "
          f"every leg; each planned leg checks out the commit its key names")
    return 0


def selftest() -> int:
    failures = []
    now = datetime(2026, 11, 22, 11, 0, tzinfo=timezone.utc)

    def comps(**over):
        base = {"leg": "slow-gates (main, slow)", "commit": "07c8abba5f", "workflow": "wf1",
                "toolchain": "tc1", "chains": "ch1", "image": "ubuntu24/20261116.1",
                "container": "sha256:aa"}
        base.update(over)
        return base

    leg_name = "slow-gates (main, slow)"

    def prior(components, *, days=1.0, event="schedule", branch="main", conclusion="success",
              keyed=True, run_id=1):
        return {
            "id": run_id, "url": f"run/{run_id}", "event": event, "branch": branch,
            "created_at": (now - timedelta(days=days)).isoformat(),
            "keys": ({leg_name: {"key": key_of(components), "components": components}}
                     if keyed else None),
            "conclusions": {} if conclusion is None else {leg_name: conclusion},
        }

    def expect(label, legs, candidates, want_run, event="schedule", reason_has=""):
        got = decide(legs, candidates, now, event, "main")[0]
        if got["run"] != want_run or reason_has not in got.get("reason", ""):
            failures.append(f"{label}: run={got['run']} reason={got.get('reason')!r}")
        else:
            print(f"selftest ok: {label}")

    same = comps()
    leg = [{"name": leg_name, "components": same, "never": None}]
    expect("a matching key from last night skips, naming the run", leg, [prior(same)], False,
           reason_has="run/1")
    for name in ("commit", "workflow", "toolchain", "chains", "image", "container", "leg"):
        expect(f"a changed {name} runs, and is named", [{"name": leg_name,
               "components": comps(**{name: "changed"}), "never": None}], [prior(same)], True,
               reason_has=name)
    expect("a match older than the weekly bound runs (the weekly full run)", leg,
           [prior(same, days=6.6)], True, reason_has="weekly")
    expect("a match inside the weekly bound still skips", leg, [prior(same, days=6.4)], False)
    expect("a run with no keys artifact is not relied on", leg, [prior(same, keyed=False)], True)
    expect("a dispatched run is not relied on", leg, [prior(same, event="workflow_dispatch")], True)
    expect("a run on another branch is not relied on", leg, [prior(same, branch="dev")], True)
    expect("a leg skipped in the earlier run is not relied on", leg,
           [prior(same, conclusion=None)], True)
    expect("a leg that failed in the earlier run is not relied on", leg,
           [prior(same, conclusion="failure")], True)
    expect("a skip relies on the run that executed, past a later skip", leg,
           [prior(same, days=1, conclusion=None, run_id=2), prior(same, days=2, run_id=1)], False,
           reason_has="run/1")
    expect("a dispatched run runs every leg", leg, [prior(same)], True, event="workflow_dispatch")
    expect("a never-skipped job runs on a matching key",
           [{"name": leg_name, "components": same, "never": "fresh randomness"}], [prior(same)],
           True, reason_has="never")
    expect("an unknown component runs the leg",
           [{"name": leg_name, "components": comps(container=""), "never": None}], [prior(same)],
           True, reason_has="container")
    if key_of(comps()) != key_of(dict(reversed(list(comps().items())))):
        failures.append("the key depends on the components' order")

    full = '{"include":[{"branch":"main"},{"branch":"dev"}]}'
    good = {"jobs": {
        "plan": {"outputs": {"a": "${{ steps.plan.outputs['a'] }}"}},
        "a": {"name": "a (${{ matrix.branch }})", "needs": ["plan"],
              "if": "${{ !cancelled() && needs.plan.outputs['a'] != '{\"include\":[]}' }}",
              "strategy": {"matrix": "${{ fromJSON(needs.plan.outputs['a'] || '%s') }}" % full},
              "steps": [{"uses": "actions/checkout@v5",
                         "with": {"ref": "${{ matrix.sha || matrix.branch }}"}}]},
        "fuzz": {"steps": []},
        "report-red": {}}}

    def wiring(label, edit, never, want):
        import copy
        doc = copy.deepcopy(good)
        edit(doc)
        got = len(wiring_problems("w.yml", doc, never))
        if (got > 0) != want:
            failures.append(f"{label}: {got} problem(s)")
        else:
            print(f"selftest ok: {label}")

    nv = {"fuzz": "fresh randomness"}
    wiring("the wiring holds", lambda d: None, nv, False)
    wiring("a job neither planned nor never-skipped fails", lambda d: None, {}, True)
    wiring("a never-skipped job that is gone fails", lambda d: d["jobs"].pop("fuzz"), nv, True)
    wiring("no planner fails", lambda d: d["jobs"].pop("plan"), nv, True)
    wiring("a planned job not needing the planner fails",
           lambda d: d["jobs"]["a"].__setitem__("needs", []), nv, True)
    wiring("a planned job whose `if` drops !cancelled() fails (a failed planner would skip it)",
           lambda d: d["jobs"]["a"].__setitem__("if", d["jobs"]["a"]["if"].replace(
               "!cancelled() && ", "")), nv, True)
    wiring("a planned job with no empty-matrix guard fails",
           lambda d: d["jobs"]["a"].__setitem__("if", "${{ !cancelled() && true }}"), nv, True)
    wiring("a planned job checking out the branch, not the keyed commit, fails",
           lambda d: d["jobs"]["a"]["steps"][0]["with"].__setitem__("ref", "${{ matrix.branch }}"),
           nv, True)
    wiring("a planner output not passed on fails",
           lambda d: d["jobs"]["plan"].__setitem__("outputs", {}), nv, True)
    wiring("a fallback matrix without dev fails",
           lambda d: d["jobs"]["a"]["strategy"].__setitem__("matrix",
               d["jobs"]["a"]["strategy"]["matrix"].replace(',{"branch":"dev"}', "")), nv, True)
    wiring("a leg renamed fails", lambda d: d["jobs"]["a"].__setitem__("name", "a"), nv, True)
    for f in failures:
        print(f"SELFTEST FAIL: {f}")
    if failures:
        return 1
    print("SELFTEST PASS: a matching key skips and names the run it relies on; each changed "
          "component runs the leg; the weekly bound, a missing keys artifact, a dispatched or "
          "other-branch run, and a skipped or failed leg are never relied on; a dispatch and a "
          "never-skipped job run every time; an unknown component runs the leg; a job neither "
          "planned nor never-skipped, a planner missing or not passed on, a planned job a failed "
          "planner would skip or that checks out the branch, a fallback short of a branch, and a "
          "renamed leg each fail the wiring check")
    return 0


def main(argv: list[str]) -> int:
    if argv == ["--selftest"]:
        return selftest()
    if argv == ["--check"]:
        return check()
    if len(argv) == 3 and argv[0] == "--plan" and argv[1] == "--workflow":
        return plan(argv[2])
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
