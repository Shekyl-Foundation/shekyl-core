## Fish shell completions for Shekyl

This folder has basic Fish completions for `shekyld` and `shekyl-wallet-rpc`.
To use them, put those files (or symlink them) inside
`~/.config/fish/completions/` or wherever your Fish completion files are (see
[https://fishshell.com/docs/current/completions.html#where-to-put-completions](https://fishshell.com/docs/current/completions.html#where-to-put-completions))

There is deliberately no wallet-CLI completion: this tree builds no wallet CLI
binary. The inherited `monero-wallet-cli.fish` was removed rather than renamed
for that reason — a completion file for a binary that does not exist misleads
silently, where an absent one does nothing.

**Removed flags are checked; the rest are not.** Every completion here was
cross-checked against `src/common/removed_flags.cpp`, and the fifteen that
advertised deliberately-removed flags — the whole `--rpc-ssl-*` family and
`--rpc-login`, retired under `removed_reason::rpc_tls_auth` — were dropped.
That registry is authoritative, so this check is cheap to repeat when it grows.

**What is still not verified:** that the *surviving* flags match the current
CLIs in spelling, arity and meaning. They are a convenience, not a spec — if a
completion disagrees with `--help`, `--help` is right. Retargeting these was
chosen over deleting them; a full flag audit was not part of that choice, and
implying otherwise would be the more expensive error.
