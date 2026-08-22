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

The emitter is deleted with the structs it captures; these files are the
oracle's memory. **Never hand-edit a vector.** A wire change is a decision
with a `CORE_RPC_VERSION` bump, recorded in the design doc, and gets a new
`_v2` file beside the old one.
