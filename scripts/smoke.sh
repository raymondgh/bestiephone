#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB_PATH="$(mktemp)"
SERVER_PID=""
SERVER_PGID=""

cleanup() {
  local exit_code=$?

  trap - EXIT ERR INT TERM

  if [[ -n "$SERVER_PGID" ]]; then
    # Ensure the entire process group is terminated.
    kill -- -"$SERVER_PGID" 2>/dev/null || true
  elif [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi

  if [[ -n "$SERVER_PID" ]]; then
    wait "$SERVER_PID" 2>/dev/null || true
  fi

  rm -f "$ROOT_DIR/server.pid" "$DB_PATH"

  exit "$exit_code"
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 1' ERR

export PC_DB_PATH="$DB_PATH"
export PC_SPOOL_TTL=5
export PC_SUPERVISOR_WINDOW=8
export PC_PENDING_WINDOW=5

PORT=${PC_SMOKE_PORT:-18080}
export PC_HTTP_ADDR="127.0.0.1:${PORT}"

if [[ "$PC_HTTP_ADDR" == :* ]]; then
  SERVER_URL="http://127.0.0.1${PC_HTTP_ADDR}"
else
  SERVER_URL="http://${PC_HTTP_ADDR}"
fi

pkill -f cmd/server >/dev/null 2>&1 || true
rm -f $ROOT_DIR/server.pid >/dev/null 2>&1 || true

echo "Starting server..."
(
  cd "$ROOT_DIR/server"
  exec go run ./cmd/server
) &
SERVER_PID=$!
if command -v ps >/dev/null 2>&1; then
  SERVER_PGID="$(ps -o pgid= "$SERVER_PID" 2>/dev/null | tr -d ' ' || true)"
fi
echo "$SERVER_PID" >"$ROOT_DIR/server.pid"

sleep 3

echo "Activating devices A and B"
RESP_A=$(curl -sS -X POST "$SERVER_URL/activate" -H 'Content-Type: application/json' -d '{"pair_id":"demo","side":"A","device_pub":{"x25519":"k"}}')
RESP_B=$(curl -sS -X POST "$SERVER_URL/activate" -H 'Content-Type: application/json' -d '{"pair_id":"demo","side":"B","device_pub":{"x25519":"k"}}')

DEVICE_A_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["device_id"])' <<<"$RESP_A")
DEVICE_A_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$RESP_A")
POLICY_VERSION=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["policy_version"])' <<<"$RESP_A")
DEVICE_B_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["device_id"])' <<<"$RESP_B")
DEVICE_B_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$RESP_B")

echo "Sending initial message A -> B"
FIRST_MSG=$(curl -sS -X POST "$SERVER_URL/messages/" \
  -H 'Content-Type: application/json' \
  -H "X-Device-ID: $DEVICE_A_ID" \
  -H "X-Device-Key: $DEVICE_A_KEY" \
  -d '{"pair_id":"demo","to":"'$DEVICE_B_ID'","recipients":["'$DEVICE_B_ID'"],"header":"demo","ciphertext":"hello","policy_version":'$POLICY_VERSION'}')
FIRST_MSG_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["message_id"])' <<<"$FIRST_MSG")

echo "Device B fetching inbox"
INBOX_B=$(curl -sS -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" "$SERVER_URL/inbox")
python3 - <<'PY' <<<"$INBOX_B"
import json,sys
items=json.loads(sys.stdin.read())["items"]
assert items, "Inbox empty"
print(f"Inbox count: {len(items)}")
PY

FETCH_B=$(curl -sS -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" "$SERVER_URL/messages/$FIRST_MSG_ID")
python3 - <<'PY' <<<"$FETCH_B"
import json,sys
msg=json.loads(sys.stdin.read())
assert msg["ciphertext"]=="hello"
print("Fetched message")
PY

curl -sS -X POST "$SERVER_URL/acks" -H 'Content-Type: application/json' -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" -d '{"message_id":"'$FIRST_MSG_ID'","state":"delivered"}' >/dev/null

echo "Request pairing token"
PAIR_TOKEN_RESP=$(curl -sS -X POST "$SERVER_URL/pairing/start" -H 'Content-Type: application/json' -H "X-Device-ID: $DEVICE_A_ID" -H "X-Device-Key: $DEVICE_A_KEY" -d '{"side":"A"}')
PAIR_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["pairing_token"])' <<<"$PAIR_TOKEN_RESP")

echo "Adding supervisor"
SUP_RESP=$(curl -sS -X POST "$SERVER_URL/supervisors/add" -H 'Content-Type: application/json' -d '{"pair_id":"demo","side":"A","pairing_token":"'$PAIR_TOKEN'","supervisor":{"display_name":"Parent"}}')
SUP_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["supervisor_id"])' <<<"$SUP_RESP")
SUP_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$SUP_RESP")

sleep 1
POLICY=$(curl -sS -H "X-Device-ID: $DEVICE_A_ID" -H "X-Device-Key: $DEVICE_A_KEY" "$SERVER_URL/policy")
POLICY_VERSION2=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["policy_version"])' <<<"$POLICY")

echo "Sending message requiring supervisor wraps"
SECOND_MSG=$(curl -sS -X POST "$SERVER_URL/messages/" \
  -H 'Content-Type: application/json' \
  -H "X-Device-ID: $DEVICE_A_ID" \
  -H "X-Device-Key: $DEVICE_A_KEY" \
  -d '{"pair_id":"demo","to":"'$DEVICE_B_ID'","recipients":["'$DEVICE_B_ID'","'$SUP_ID'"],"header":"demo2","ciphertext":"check","policy_version":'$POLICY_VERSION2'}')
SECOND_MSG_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["message_id"])' <<<"$SECOND_MSG")

sleep 1
SUP_INBOX=$(curl -sS -H "X-Supervisor-ID: $SUP_ID" -H "X-Supervisor-Key: $SUP_KEY" "$SERVER_URL/inbox")
python3 - <<'PY' <<<"$SUP_INBOX"
import json,sys
items=json.loads(sys.stdin.read())["items"]
assert items, "Supervisor inbox empty"
print("Supervisor inbox OK")
PY

sleep 10
echo "Checking purge behavior"
HTTP_CODE=$(curl -s -o "$ROOT_DIR/second_msg.json" -w "%{http_code}" -H "X-Supervisor-ID: $SUP_ID" -H "X-Supervisor-Key: $SUP_KEY" "$SERVER_URL/messages/$SECOND_MSG_ID")
if [[ "$HTTP_CODE" != "404" ]]; then
  echo "Expected 404 after purge, got $HTTP_CODE"
  exit 1
fi

echo "Smoke test passed"
