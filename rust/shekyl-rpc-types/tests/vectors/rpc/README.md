# RPC oracle vectors (C++ epee provenance)

Each `<method>_<case>_v1.json` is the **byte output of epee's
`store_t_to_json`** over the C++ `COMMAND_RPC_<METHOD>::response` built from
fixed facts — captured by a `tests/unit_tests/rpc_oracle_vectors.cpp` that lives only in the
commit that precedes each method's C++ deletion (RK-1 onward,
`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.5). The Rust parity tests
(`../../rpc_parity.rs`) feed the same fixed facts to the native handlers and
assert **parsed** equality (RK-D4: key order and whitespace are epee's, not
the contract's; `KV_SERIALIZE_OPT` omissions are part of the contract and
are mirrored by `skip_serializing_if`).

**The JSON files are LF; the `.bin` files are byte-exact.** That split is the
whole rule, and it follows from what each is for. `RK-D4` says whitespace is
not part of the wire contract and the parity suite compares *parsed* values,
so for JSON nothing reads these bytes as bytes — the line endings were epee's
CRLF only because that is what the capture happened to emit. For `.bin`, the
bytes **are** the contract, and their harnesses compare them byte for byte.

This directory is `-text` in `.gitattributes` so git never rewrites EOL, which
`.bin` requires. That also means git will not normalise a CRLF a Windows
editor introduces, so `json_vectors_are_lf` keeps the JSON from drifting back.

Ruled 2026-09-05. The earlier rule kept the JSON at epee's exact bytes for
provenance — "the oracle's output, modulo edits" being a weaker pin than the
oracle's output. True, but a weaker pin only costs something if something
leans on the strength, and nothing did: the values are what every test reads,
and `RK-W` redesigns this wire on purpose. A tool normalising the captures was
caught in review and reverted; on inspection the property it violated had no
consumer, so it was retired deliberately rather than defended by habit.

The emitter is deleted with the structs it captures, so each slice writes its
own and takes it away again; these files are the oracle's memory. **RK-5b was
the most recent slice to run one** (`get_last_block_header`,
`get_block_header_by_hash`, `get_block_headers_range`, `hard_fork_info`,
`get_fee_estimate`), and it is gone with those structs too. To read one, or
to see how a capture was set up, check out the commit that added
`tests/unit_tests/rpc_oracle_vectors.cpp` in the slice you care about —
`git log --diff-filter=A --follow -- tests/unit_tests/rpc_oracle_vectors.cpp`
lists every one of them.

Once a method's C++ is deleted there is nothing left to capture from *for that
method*, so a later shape change to it cannot be re-captured and must be argued
from the `_v1` / `_v2` pair instead (see
`v2_is_v1_minus_exactly_the_two_retired_members`, which does exactly that for
RK-4c's two). That is a per-method fact, not a date: a slice whose structs are
still standing can and must still capture.

**"Cannot be re-captured" is not "must not be changed."** Byte-exactness with
epee was never a requirement — every consumer of this daemon is first-party
and ships with it, so the vectors exist to prove a *deliberate* shape change
is the only change, not to freeze the shape. RK-5b is the worked example: it
changes `get_block_header_by_hash` on purpose (a deleted request field, a
per-element found discriminator, a refusal where there was a silent blank) and
carries `CORE_RPC_VERSION` 3.27 for it. A later slice reading only the
paragraph above could inherit the constraint backwards and treat an
un-recapturable method as frozen; it is not. **A `_v2` is derived, never authored.** Each pair carries a delta test that
re-derives `_v2` from `_v1`, so a hand-edited `_v2` fails rather than standing
as its own authority — demonstrated, not assumed: changing
`get_fee_estimate_v2.json`'s `quantization_mask` and `hard_fork_info_v2.json`'s
renamed field both turn their delta tests red. Three delta shapes exist, and
RK-5b added the third:

- **subtraction** — `_v2` is `_v1` minus exactly these fields
  (`v2_is_v1_minus_exactly_the_two_retired_members`,
  `fee_v2_is_v1_minus_exactly_the_redundant_scalar`)
- **substitution** — `_v1` with one value replaced
  (`the_get_version_chain_differs_by_exactly_the_version_at_every_link`,
  which walks every link of that chain rather than its newest pair)
- **transform, plus a named extension** — for a change of *shape*, where no
  subtraction from `_v1` produces `_v2`. `by_hash_v2_is_v1_reshaped_into_slots`
  writes the reshaping as code; the cases `_v1` structurally cannot express —
  a slot with no header, because the C++ returned an error and discarded the
  batch — are asserted separately in
  `a_missing_slot_is_the_case_v1_could_not_express`, so the extension is named
  rather than hidden inside a shape comparison.

**Never hand-edit a vector.** A wire
change is a decision with a `CORE_RPC_VERSION` bump, recorded in the design
doc, and gets a new `_v2` file beside the old one.

`get_version_synced_v2.json` is a pair of the second kind. Its `_v1` is a
faithful C++ capture; the constant it reports is not re-capturable, because
`CORE_RPC_VERSION` **moved to Rust** (`shekyl-rpc-types::chain`) and C++ no
longer defines it. So the bump that RK-4c's wire change earned (3.24 → 3.25)
cannot be recorded by re-running the emitter, and hand-editing `_v1` would
destroy the one property that makes it an oracle. The `_v2` is instead held
honest by `the_get_version_chain_differs_by_exactly_the_version_at_every_link`,
which substitutes the live constant across every consecutive pair and requires
each result to equal its successor exactly — so a file may differ from its
predecessor by that constant and by nothing else, no link may be skipped, and
the newest may not go stale against the constant. It replaced a per-pair test
that was renamed at each bump, which is how a chain with a missing vector
passed.
