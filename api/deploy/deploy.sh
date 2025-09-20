#!/bin/bash

set -e
set -u
set -o pipefail
set -x

cargo build --target x86_64-unknown-linux-gnu --release

sudo systemctl stop vibecheckapi

sudo cp deploy/vibecheckapi.service /etc/systemd/system/vibecheckapi.service

sudo systemctl daemon-reload

sudo systemctl start vibecheckapi
