# RPC oracle vectors (C++ epee provenance)

Each `<method>_<case>_v1.json` is the **byte output of epee's
`store_t_to_json`** over the C++ `COMMAND_RPC_<METHOD>::response` built from
fixed facts — captured by `tests/unit_tests/rpc_oracle_vectors.cpp` in the
commit that precedes each method's C++ deletion (RK-1 onward,
`docs/design/DAEMON_RPC_KV_CUTOVER.md` §3.5). The Rust parity tests
(`../../rpc_parity.rs`) feed the same fixed facts to the native handlers and
assert **parsed** equality (RK-D4: key order and whitespace are epee's, not
the contract's; `KV_SERIALIZE_OPT` omissions are part of the contract and
are mirrored by `skip_serializing_if`).

The files are epee's bytes exactly — including its CRLF line endings —
and this directory is `-text` in `.gitattributes` so no checkout rewrites
them (the same rule `docs/test_vectors/` uses). Whitespace is not part of
the contract (RK-D4); the bytes are kept faithful because a vector that is
"the oracle's output, modulo edits" is a weaker pin than one that is the
oracle's output.

The emitter is deleted with the structs it captures, so each slice writes its
own and takes it away again; these files are the oracle's memory. **RK-5a was
the most recent slice to run one** (`sync_info`, `/get_net_stats`,
`/get_peer_list`, `get_connections`), and it is gone with those structs too.

Once a method's C++ is deleted there is nothing left to capture from *for that
method*, so a later shape change to it cannot be re-captured and must be argued
from the `_v1` / `_v2` pair instead (see
`v2_is_v1_minus_exactly_the_two_retired_members`, which does exactly that for
RK-4c's two). That is a per-method fact, not a date: a slice whose structs are
still standing can and must still capture. **Never hand-edit a vector.** A wire
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
