#!/bin/bash

NETWORK_FLAG="${NETWORK_FLAG:---testnet}"
DAEMON_ADDR="${DAEMON_ADDR:-localhost:12029}"

rlwrap shekyl-wallet-cli --wallet-file wallet_05.bin --password "" "$NETWORK_FLAG" --trusted-daemon --daemon-address "$DAEMON_ADDR" --log-file wallet_05.log

