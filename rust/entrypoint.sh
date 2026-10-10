#!/bin/sh
set -e

SOCKET_PATH="${BIFROST_IPC_PATH:-/run/bifrost/ipc.sock}"

echo "Waiting for Unix socket at ${SOCKET_PATH}..."
while [ ! -S "${SOCKET_PATH}" ]; do
    sleep 1
done
echo "Socket found, starting bifrost-resolver..."

exec /usr/local/bin/bifrost-resolver
