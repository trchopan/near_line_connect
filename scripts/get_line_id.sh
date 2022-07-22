#!/usr/bin/env bash

near view $(cat neardev/dev-account) get_line_id '{"wallet": "'$1'"}'
