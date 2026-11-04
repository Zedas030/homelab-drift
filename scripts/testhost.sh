#!/bin/bash
# Start/stop a throw-away SSH test host (Docker container) - for the end-to-end test and for trying out a second host.
#
#   ./scripts/testhost.sh start <pubkey-file> [port] [name]   build the image with this key and start the container
#   ./scripts/testhost.sh stop [name]                         remove container and image
#
# The container only listens on 127.0.0.1:<port> (default 2222), so it is not reachable from the network.
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"
CMD="${1-}"
case "$CMD" in
  start)
    KEYFILE="$2"; PORT="${3:-2222}"; NAME="${4:-drift-testhost}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker build -q -f "$SRC/tests/e2e/Dockerfile.testhost" --build-arg PUBKEY="$(cat "$KEYFILE")" -t "$NAME:latest" "$SRC" >/dev/null
    docker run -d --name "$NAME" --hostname "$NAME" -p "127.0.0.1:$PORT:22" --restart no \
      --memory 128m --cpus 0.5 --label homelab-drift=testhost "$NAME:latest" >/dev/null
    for _ in $(seq 1 30); do
      docker exec "$NAME" pgrep -x sshd >/dev/null 2>&1 && break; sleep 0.5
    done
    echo "Test host $NAME is running on 127.0.0.1:$PORT"
    ;;
  stop)
    NAME="${2:-drift-testhost}"
    docker rm -f "$NAME" >/dev/null 2>&1 || true
    docker rmi -f "$NAME:latest" >/dev/null 2>&1 || true
    echo "Test host $NAME removed"
    ;;
  *) echo "Usage: $0 start <pubkey-file> [port] [name] | stop [name]"; exit 2 ;;
esac
