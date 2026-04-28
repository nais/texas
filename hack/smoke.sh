#!/usr/bin/env bash
# Smoke test for a built Texas image.
#
# Verifies that the image:
#   1. Starts and binds the API + probe ports
#   2. Serves /healthz with HTTP 200
#   3. Runs as non-root
#   4. Shuts down cleanly on SIGTERM within a reasonable timeout
#
# Usage: hack/smoke.sh <image-ref> [platform]
#   e.g. hack/smoke.sh ghcr.io/nais/texas:sha-abc1234
#        hack/smoke.sh ghcr.io/nais/texas:sha-abc1234 linux/arm64

set -euo pipefail

image="${1:?usage: $0 <image-ref> [platform]}"
platform="${2:-}"
container="texas-smoke-$$"
api_port=13000
probe_port=13001

platform_args=()
if [[ -n "$platform" ]]; then
  platform_args=(--platform "$platform")
fi

cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "==> Starting $image${platform:+ ($platform)}"
docker run -d --rm \
  "${platform_args[@]}" \
  --name "$container" \
  -e BIND_ADDRESS="0.0.0.0:3000" \
  -e PROBE_BIND_ADDRESS="0.0.0.0:3001" \
  -p "${api_port}:3000" \
  -p "${probe_port}:3001" \
  "$image" >/dev/null

echo "==> Waiting for /healthz on :${probe_port}"
for i in $(seq 1 30); do
  if curl -fsS -o /dev/null "http://127.0.0.1:${probe_port}/healthz" 2>/dev/null; then
    echo "    ready after ${i}s"
    break
  fi
  if ! docker ps -q --filter "name=$container" | grep -q .; then
    echo "FAIL: container exited during startup" >&2
    docker logs "$container" >&2 || true
    exit 1
  fi
  sleep 1
done

# Final check (also fails the script if the loop above timed out)
status=$(curl -fsS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${probe_port}/healthz")
if [[ "$status" != "200" ]]; then
  echo "FAIL: /healthz returned $status" >&2
  docker logs "$container" >&2
  exit 1
fi
echo "==> /healthz OK"

echo "==> Verifying non-root user"
if uid=$(docker exec "$container" id -u 2>/dev/null) && [[ -n "$uid" ]]; then
  : # got uid from `id`
else
  # Distroless: no `id` binary. Fall back to image config.
  uid=$(docker inspect --format '{{.Config.User}}' "$image")
fi
if [[ "$uid" == "0" || "$uid" == "root" || -z "$uid" ]]; then
  echo "FAIL: container runs as root (uid='$uid')" >&2
  exit 1
fi
echo "    running as uid=$uid"

echo "==> Sending SIGTERM and checking graceful shutdown"
docker stop --time 10 "$container" >/dev/null
# If we got here, docker stop succeeded within the timeout.
echo "    shutdown clean"

echo "==> SMOKE OK"
