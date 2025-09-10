#!/bin/sh
set -e

# Read config from environment (docker-compose passes these)
SERVER_URL="${SERVER_URL:-http://app:8000}"
METRICS_INTERVAL="${METRICS_INTERVAL:-5}"
HASH_ENABLE="${HASH_ENABLE:-true}"
HASH_DIRS="${HASH_DIRS:-/host}"
HASH_INTERVAL="${HASH_INTERVAL:-3600}"
AGENT_MAX_SIZE_MB="${AGENT_MAX_SIZE_MB:-100}"
AGENT_MAX_FILES="${AGENT_MAX_FILES:-5000}"
AGENT_WORKERS="${AGENT_WORKERS:-4}"

echo "[agent] server: $SERVER_URL"
echo "[agent] metrics interval: ${METRICS_INTERVAL}s"
echo "[agent] hashing: $HASH_ENABLE; dirs: $HASH_DIRS (every ${HASH_INTERVAL}s)"

# Start the agent (the Python code already runs forever with internal loops)
if [ "$HASH_ENABLE" = "true" ]; then
  # NOTE: we intentionally do not quote $HASH_DIRS so that space-separated dirs split into args
  # shellcheck disable=SC2086
  exec python -u agent_updated.py \
    --server "$SERVER_URL" \
    --metrics-interval "$METRICS_INTERVAL" \
    --hash \
    --hash-dirs $HASH_DIRS \
    --hash-interval "$HASH_INTERVAL" \
    --max-size-mb "$AGENT_MAX_SIZE_MB" \
    --max-files "$AGENT_MAX_FILES" \
    --workers "$AGENT_WORKERS"
else
  exec python -u agent_updated.py \
    --server "$SERVER_URL" \
    --metrics-interval "$METRICS_INTERVAL"
fi
