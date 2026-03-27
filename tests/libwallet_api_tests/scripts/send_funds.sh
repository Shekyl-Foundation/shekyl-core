#!/bin/bash

NETWORK_FLAG="${NETWORK_FLAG:---testnet}"
DAEMON_ADDR="${DAEMON_ADDR:-localhost:12029}"

function send_funds {
    local amount=$1
    local dest=$(cat "$2.address.txt")

    shekyl-wallet-cli --wallet-file wallet_m --password "" \
        "$NETWORK_FLAG" --trusted-daemon --daemon-address "$DAEMON_ADDR" --log-file wallet_m.log \
        --command transfer "$dest" "$amount"
}


function seed_wallets {
    local amount=$1
    send_funds $amount wallet_01.bin
    send_funds $amount wallet_02.bin
    send_funds $amount wallet_03.bin
    send_funds $amount wallet_04.bin
    send_funds $amount wallet_05.bin
    send_funds $amount wallet_06.bin
}

seed_wallets 1
seed_wallets 2
seed_wallets 5
seed_wallets 10
seed_wallets 20
seed_wallets 50
seed_wallets 100



