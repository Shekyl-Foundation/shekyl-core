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

The files are epee's bytes exactly — including its CRLF line endings —
and this directory is `-text` in `.gitattributes` so no checkout rewrites
them (the same rule `docs/test_vectors/` uses). `-text` stops **git**. A
tool can still rewrite the bytes, and the parsed-equality suite will not
notice (serde accepts both endings). `v1_oracle_vectors_keep_epees_crlf`
is the check the attribute cannot be. Whitespace is not part of the
contract (RK-D4); the bytes are kept faithful because a vector that is
"the oracle's output, modulo edits" is a weaker pin than one that is the
oracle's output.

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
  (`get_version_v2_is_v1_with_only_the_version_bumped`)
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
honest by `get_version_v2_is_v1_with_only_the_version_bumped`, which
substitutes the live constant into `_v1` and requires the result to equal
`_v2` exactly — so the file may differ from the C++ capture by that constant
and by nothing else, and it cannot silently go stale against the constant
either.
