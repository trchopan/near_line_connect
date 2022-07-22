#!/usr/bin/env bash

near call $(cat neardev/dev-account) get_line_id '{"wallet": "'$1'"}' --accountId $ACCOUNT_ID
