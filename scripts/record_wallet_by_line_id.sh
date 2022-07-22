#!/usr/bin/env bash

near call $(cat neardev/dev-account) record_wallet_by_line_id \
    '{"signature": "'$1'", "line_id": "'$2'", "wallet": "'$3'", "expire": '$4'}' \
    --accountId $ACCOUNT_ID
