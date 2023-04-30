#!/usr/bin/env bash

set -m

challenge_base="/opt/chal"

socks="$(mktemp -d)"

cleanup() {
  trap "" INT TERM EXIT
  kill $(jobs -p) 2>/dev/null || true
  rm -rf "${socks}"
}

trap cleanup INT TERM EXIT

qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -display none -semihosting-config enable=on,target=native -serial unix:"${socks}/consignee",server -kernel "${challenge_base}/consignee" &
qemu-system-arm -cpu cortex-m3 -machine lm3s6965evb -display none -semihosting-config enable=on,target=native -serial unix:"${socks}/sender",server -serial unix:"${socks}/consignee" -kernel "${challenge_base}/courier" &
sleep .5
socat - UNIX-CONNECT:"${socks}/sender"
