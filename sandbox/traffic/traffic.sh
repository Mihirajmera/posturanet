#!/usr/bin/env bash
# Opens one TCP connection to the sandbox bastion on port 22 (an ACCEPT in the flow logs).
# Nothing is sent and no login happens. Schedule with cron, e.g.:
#   0 9-18 * * * /path/to/traffic.sh 203.0.113.10
set -u
ip="${1:?usage: traffic.sh <bastion-public-ip> [port]}"
port="${2:-22}"
timeout 3 bash -c "</dev/tcp/${ip}/${port}" 2>/dev/null || true
