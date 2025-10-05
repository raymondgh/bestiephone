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

export PYTHONPATH="$ROOT_DIR/apps:${PYTHONPATH:-}"

eval "$(python3 - <<'PY'
import base64
from nacl import public, signing

def gen():
    sk = signing.SigningKey.generate()
    xsk = public.PrivateKey.generate()
    return {
        "ed25519": {
            "sk": base64.b64encode(sk.encode()).decode(),
            "pk": base64.b64encode(sk.verify_key.encode()).decode(),
        },
        "x25519": {
            "sk": base64.b64encode(xsk.encode()).decode(),
            "pk": base64.b64encode(xsk.public_key.encode()).decode(),
        },
    }

keys = {"A": gen(), "B": gen(), "P": gen()}
print(f"export DEV_A_ED25519_SK='{keys['A']['ed25519']['sk']}'")
print(f"export DEV_A_ED25519_PK='{keys['A']['ed25519']['pk']}'")
print(f"export DEV_A_X25519_SK='{keys['A']['x25519']['sk']}'")
print(f"export DEV_A_X25519_PK='{keys['A']['x25519']['pk']}'")
print(f"export DEV_B_ED25519_SK='{keys['B']['ed25519']['sk']}'")
print(f"export DEV_B_ED25519_PK='{keys['B']['ed25519']['pk']}'")
print(f"export DEV_B_X25519_SK='{keys['B']['x25519']['sk']}'")
print(f"export DEV_B_X25519_PK='{keys['B']['x25519']['pk']}'")
print(f"export PARENT_ED25519_SK='{keys['P']['ed25519']['sk']}'")
print(f"export PARENT_ED25519_PK='{keys['P']['ed25519']['pk']}'")
print(f"export PARENT_X25519_SK='{keys['P']['x25519']['sk']}'")
print(f"export PARENT_X25519_PK='{keys['P']['x25519']['pk']}'")
PY
)"

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

export PAIR_ID="demo"

echo "Activating devices A and B"
RESP_A=$(curl -sS -X POST "$SERVER_URL/activate" -H 'Content-Type: application/json' -d '{"pair_id":"'$PAIR_ID'","side":"A","device_pub":{"x25519_pub":"'$DEV_A_X25519_PK'","ed25519_pub":"'$DEV_A_ED25519_PK'"}}')
RESP_B=$(curl -sS -X POST "$SERVER_URL/activate" -H 'Content-Type: application/json' -d '{"pair_id":"'$PAIR_ID'","side":"B","device_pub":{"x25519_pub":"'$DEV_B_X25519_PK'","ed25519_pub":"'$DEV_B_ED25519_PK'"}}')

DEVICE_A_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["device_id"])' <<<"$RESP_A")
DEVICE_A_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$RESP_A")
DEVICE_B_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["device_id"])' <<<"$RESP_B")
DEVICE_B_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$RESP_B")
export DEVICE_A_ID DEVICE_A_KEY DEVICE_B_ID DEVICE_B_KEY

PAIR_TOKEN_RESP=$(curl -sS -X POST "$SERVER_URL/pairing/start" -H 'Content-Type: application/json' -H "X-Device-ID: $DEVICE_A_ID" -H "X-Device-Key: $DEVICE_A_KEY" -d '{"side":"A"}')
PAIR_TOKEN=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["pairing_token"])' <<<"$PAIR_TOKEN_RESP")

SUP_RESP=$(curl -sS -X POST "$SERVER_URL/supervisors/add" -H 'Content-Type: application/json' -d '{"pair_id":"'$PAIR_ID'","side":"A","pairing_token":"'$PAIR_TOKEN'","supervisor":{"display_name":"Parent","keys":{"x25519_pub":"'$PARENT_X25519_PK'","ed25519_pub":"'$PARENT_ED25519_PK'"}}}')
SUP_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["supervisor_id"])' <<<"$SUP_RESP")
SUP_KEY=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["api_key"])' <<<"$SUP_RESP")
POLICY_VERSION=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read()).get("policy_version", 1))' <<<"$SUP_RESP")
export SUP_ID SUP_KEY POLICY_VERSION

SECRET_MESSAGE="Secret hello"
export SECRET_MESSAGE

echo "Attempting plaintext message (should fail)"
PLAINTEXT_PAYLOAD=$(python3 - <<'PY'
import json
import os
from datetime import datetime, timezone

now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
payload = {
    "pair_id": os.environ["PAIR_ID"],
    "to": os.environ["DEVICE_B_ID"],
    "recipients": [os.environ["DEVICE_B_ID"], os.environ["SUP_ID"]],
    "header": {
        "msg_id": "plaintext-test",
        "from_device_id": os.environ["DEVICE_A_ID"],
        "policy_version": int(os.environ["POLICY_VERSION"]),
        "created_at": now,
        "enc": {"cipher": "xsalsa20poly1305", "wrap": "sealedbox", "ver": "v1"},
        "recipients": [
            {"type": "device", "id": os.environ["DEVICE_B_ID"]},
            {"type": "supervisor", "id": os.environ["SUP_ID"]},
        ],
        "sig_scheme": "ed25519:v1",
        "signature": "",
    },
    "ciphertext": "hello",
    "policy_version": int(os.environ["POLICY_VERSION"]),
}
print(json.dumps(payload))
PY
)
HTTP_CODE=$(curl -s -o "$ROOT_DIR/plain_attempt.json" -w "%{http_code}" \
  -X POST "$SERVER_URL/messages/" \
  -H 'Content-Type: application/json' \
  -H "X-Device-ID: $DEVICE_A_ID" \
  -H "X-Device-Key: $DEVICE_A_KEY" \
  -d "$PLAINTEXT_PAYLOAD")
if [[ "$HTTP_CODE" != "422" ]]; then
  echo "Expected plaintext rejection with 422, got $HTTP_CODE"
  cat "$ROOT_DIR/plain_attempt.json"
  exit 1
fi

KEYS_RESP=$(curl -sS -H "X-Device-ID: $DEVICE_A_ID" -H "X-Device-Key: $DEVICE_A_KEY" "$SERVER_URL/keys?pair_id=$PAIR_ID")
ENCRYPT_INPUT=$(cat <<JSON
{
  "keys": $KEYS_RESP,
  "plaintext": "$SECRET_MESSAGE",
  "signing_sk": "$DEV_A_ED25519_SK",
  "pair_id": "$PAIR_ID",
  "from_device_id": "$DEVICE_A_ID",
  "sender_side": "A"
}
JSON
)
export ENCRYPT_INPUT
MESSAGE_PAYLOAD=$(python3 - <<'PY'
import json
import os
from crypto_utils import encrypt_message

payload = json.loads(os.environ["ENCRYPT_INPUT"])
keys = payload["keys"]
sender_side = payload["sender_side"]
peer_side = "B" if sender_side == "A" else "A"
devices = keys.get("devices", {})
peer = devices.get(peer_side)
if not peer:
    raise SystemExit("peer device missing")
recipients = [
    {
        "type": "device",
        "id": peer.get("device_id"),
        "x25519_pub": peer.get("x25519_pub"),
        "ed25519_pub": peer.get("ed25519_pub", ""),
    }
]
for sup_list in keys.get("supervisors", {}).values():
    for sup in sup_list:
        recipients.append(
            {
                "type": "supervisor",
                "id": sup.get("account_id"),
                "x25519_pub": sup.get("x25519_pub"),
                "ed25519_pub": sup.get("ed25519_pub", ""),
            }
        )
envelope = {
    "from_device_id": payload["from_device_id"],
    "policy_version": keys.get("policy_version"),
    "recipients": recipients,
}
header, ciphertext = encrypt_message(payload["plaintext"], envelope, payload["signing_sk"])
out_payload = {
    "pair_id": payload["pair_id"],
    "to": peer.get("device_id"),
    "recipients": [r["id"] for r in recipients],
    "header": header,
    "ciphertext": ciphertext,
    "policy_version": keys.get("policy_version"),
}
print(json.dumps(out_payload))
PY
)
unset ENCRYPT_INPUT

ENCRYPT_HTTP=$(curl -s -o "$ROOT_DIR/encrypted_resp.json" -w "%{http_code}" \
  -X POST "$SERVER_URL/messages/" \
  -H 'Content-Type: application/json' \
  -H "X-Device-ID: $DEVICE_A_ID" \
  -H "X-Device-Key: $DEVICE_A_KEY" \
  -d "$MESSAGE_PAYLOAD")
if [[ "$ENCRYPT_HTTP" != "201" ]]; then
  echo "Encrypted send failed with $ENCRYPT_HTTP"
  cat "$ROOT_DIR/encrypted_resp.json"
  exit 1
fi
MESSAGE_ID=$(python3 -c 'import json,sys; print(json.loads(sys.stdin.read())["message_id"])' <"$ROOT_DIR/encrypted_resp.json")
export MESSAGE_ID

INBOX_B=$(curl -sS -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" "$SERVER_URL/inbox")
python3 - <<'PY' <<<"$INBOX_B"
import json
import os
import sys

items = json.loads(sys.stdin.read())["items"]
msg_id = os.environ["MESSAGE_ID"]
assert any(it["message_id"] == msg_id for it in items), "Inbox missing encrypted message"
print(f"Inbox count: {len(items)}")
PY

FETCH_B=$(curl -sS -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" "$SERVER_URL/messages/$MESSAGE_ID")
python3 - <<'PY' <<<"$FETCH_B"
import json,os,sys
from crypto_utils import decrypt_message
msg=json.loads(sys.stdin.read())
header=json.loads(msg["header"])
plaintext=decrypt_message(header, msg["ciphertext"], os.environ["DEV_B_X25519_SK"], recipient_id=os.environ["DEVICE_B_ID"])
assert plaintext == os.environ["SECRET_MESSAGE"], plaintext
print("Decrypted message matches")
PY

curl -sS -X POST "$SERVER_URL/acks" -H 'Content-Type: application/json' -H "X-Device-ID: $DEVICE_B_ID" -H "X-Device-Key: $DEVICE_B_KEY" -d '{"message_id":"'$MESSAGE_ID'","state":"delivered"}' >/dev/null

echo "Smoke test passed"
