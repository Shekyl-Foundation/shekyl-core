## Fish shell completions for Shekyl

This folder has basic Fish completions for `shekyld` and `shekyl-wallet-rpc`.
To use them, put those files (or symlink them) inside
`~/.config/fish/completions/` or wherever your Fish completion files are (see
[https://fishshell.com/docs/current/completions.html#where-to-put-completions](https://fishshell.com/docs/current/completions.html#where-to-put-completions))

There is deliberately no wallet-CLI completion: this tree builds no wallet CLI
binary. The inherited `monero-wallet-cli.fish` was removed rather than renamed
for that reason — a completion file for a binary that does not exist misleads
silently, where an absent one does nothing.

**Caveat, stated rather than implied:** these were inherited and the flag lists
have not been re-verified against the current CLIs. They are a convenience, not
a spec — if a completion disagrees with `--help`, `--help` is right. Retargeting
them was chosen over deleting them; auditing every flag was not part of that
choice.
