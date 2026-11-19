- **One owner for the per-account root.** `shekyl-os-account` now names the
  per-account root of rule 83 IG-13 (`PER_ACCOUNT_ROOT_NAME`,
  `per_account_root_in`, `per_account_root`), reads the account's home
  (`account_home`, moved from `shekyl-process`), makes the root as the
  daemon makes it (`ensure_per_account_root`, owner-only on Windows) and
  names the wallet directory in it (`wallet_dir_in`). The daemon's
  configuration and the rendezvous read the name there instead of each
  writing `.shekyl`/`Shekyl`, and `shekyl-rpc-rendezvous` loses its
  `data_home`. The GUI wallet takes its default wallet folder from it
  (`~/.shekyl/wallets`, `%LOCALAPPDATA%\Shekyl\wallets`), so the GUI pin
  (`scripts/ci/gui_wallet_core_deps.toml`) gains `shekyl-os-account`.
- **The CLI's default paths are in the per-account root.** `shekyl-cli`'s
  default wallet directory is `wallets/<network>` in the per-account root,
  read from the account interface: on Windows it was
  `%USERPROFILE%\.shekyl\wallets\<network>`, outside the root, and on
  every platform it read `HOME`. Its shell history moves from
  `XDG_DATA_HOME`/`%LOCALAPPDATA%\shekyl-cli\history.txt` to
  `shekyl-cli-history.txt` in the root. Both are made with the root made as
  the daemon makes it (`shekyl_os_account::make_account_dir`), and
  `shekyl-cli` no longer depends on `dirs`.
