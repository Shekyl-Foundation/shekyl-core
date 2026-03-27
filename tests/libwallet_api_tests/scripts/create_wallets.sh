#!/bin/bash

NETWORK_FLAG="${NETWORK_FLAG:---testnet}"
DAEMON_ADDR="${DAEMON_ADDR:-localhost:12029}"

function create_wallet {
    wallet_name=$1
    echo 0 | shekyl-wallet-cli "$NETWORK_FLAG" --trusted-daemon --daemon-address "$DAEMON_ADDR" --generate-new-wallet "$wallet_name" --password "" --restore-height=1
}


create_wallet wallet_01.bin
create_wallet wallet_02.bin
create_wallet wallet_03.bin
create_wallet wallet_04.bin
create_wallet wallet_05.bin
create_wallet wallet_06.bin

# create_wallet wallet_m


