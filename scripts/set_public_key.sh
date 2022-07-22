#!/usr/bin/env bash
#
near call $(cat neardev/dev-account) set_public_key \
    '{"public_key": "'$1'"}' \
    --accountId $ACCOUNT_ID
