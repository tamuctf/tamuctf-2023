#!/bin/bash

set -m

workdir="$(mktemp -d)"

cleanup() {
  trap "" INT TERM EXIT
  kill $(jobs -p) 2>/dev/null || true
  cd /
  rm -rf "${workdir}"
}

trap cleanup INT TERM EXIT

cd "${workdir}"
ln -s /var/www
mkdir tmp
mkdir socks

export SERVER_ADDR="${PWD}/socks/server.sock"

web-lto >& /dev/null &

while true; do
  sleep 10
  /usr/bin/flag-uploader >& /dev/null
done &

sleep .5
socat - UNIX-CONNECT:"${workdir}/socks/server.sock"
