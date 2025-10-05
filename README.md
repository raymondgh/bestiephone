# Pair Communicator — User Lifecycle & API Map

This document describes the end‑to‑end experience of a **pair‑only** children’s communicator with optional supervisors (parents/guardians). It is written in plain English and annotated with the exact API calls your server receives along the way. It finishes with endpoint catalogs for the server and clients.

---

## Core ideas (at a glance)
- **Pair‑only**: exactly two devices per pair (A ↔ B).
- **E2E encryption**: one ciphertext per message; header carries key‑wraps for recipients (peer device + any active supervisors on either side). Server never sees plaintext.
- **Directional supervision**: each side (A or B) can have zero or more supervisors. Server enforces that new messages include required supervisor wraps for the relevant side(s).
- **Retention**: keep ciphertext long enough for kid delivery (spool TTL, e.g., 48h). If a side has supervisors, keep up to 30 days for that side. After purge, retain signed header + hash + receipts only.
- **Governance safety**: pairing‑mode required for add/reset; one pending governance event per side; last supervisor on a side cannot remove themselves.

## Encryption model (v1)
- **Keys**: every device and supervisor holds an Ed25519 signing key and an X25519 key-exchange key. The prototype Streamlit apps generate and persist these seeds under `apps/seeds/` (e.g., `seeds/<pair>_<side>_device.json` or `seeds/parent_<pair>_<side>.json`).
- **Encrypt on send**: clients call `GET /keys?pair_id=…` to fetch the peer device and all required supervisors' public keys alongside the current `policy_version`. They mint a 32-byte content key, seal it to each recipient via X25519 sealed boxes, encrypt the plaintext with XSalsa20-Poly1305, and attach the wraps in the signed header.
- **Signatures**: headers include `sig_scheme` `ed25519:v1`. Clients build the canonical `pc-h1|…` payload (sorted recipients with wrap digests) and sign with their Ed25519 secret key. The server verifies signatures and rejects messages with missing wraps, bad base64, or mismatched recipients (`422 ENCRYPTION_REQUIRED` or `422 SIGNATURE_INVALID`).
- **Server stance**: the backend stores only ciphertext and signed headers. It enforces policy coverage and authenticity but never sees decrypted content.

---

## 1) Unbox & turn on (first boot)
You power up the two communicators. Each claims its side of the pair with the backend.

**Server calls:**
- Device A → `POST /activate` `{pair_id, side:"A", device_pub:{x25519, ed25519}}`
- Device B → `POST /activate` `{pair_id, side:"B", device_pub:{…}}`

**Server behavior:** binds each device to `pair_id`, issues a device API key and returns current `policy_version` (v1 = no supervisors).

**Outcome:** kids can talk immediately; no supervisor required to start.

---

## 2) Kid sends a message (A → B)
Kid A records and releases. The device encrypts once and addresses the ciphertext to the correct recipients.

**Device behavior:**
1) Build **signed header** with recipient list (always includes **Device B**, plus any required supervisors per policy) and a single **ciphertext** (E2E).
2) Send to server.

**Server calls:**
- Device A → `POST /messages` `{pair_id, from:"dev_A", to:"dev_B", policy_version, header, ciphertext}`
- On `409 POLICY_STALE`: Device A → `GET /policy` then retries `POST /messages`.
- Recipients poll: `GET /inbox?recipient_id=…`
- Recipient fetches: `GET /messages/{msg_id}?recipient_id=…`
- Recipient acknowledges: `POST /acks` `{recipient_id, msg_id, state:"delivered"}`

**Server behavior:** verifies A↔B membership, checks `policy_version`, ensures all **required recipients** are present. Queues the message for Device B and any active supervisors.

**Outcome:** B receives and plays; server retains according to spool/30‑day rules.

---

## 3) A parent links later (one‑time)
A parent wants a feed of **future** messages involving their kid. They put the kid’s device in pairing mode and add themselves.

**Steps:**
1) Parent presses the pairing‑mode button on Device A.
2) Device A requests a pairing token.
3) Parent app (via BLE/QR to the device) asks the device to add them as a supervisor.
4) Depending on policy (first supervisor or not), the add either auto‑approves or awaits same‑side approval; the other side can optionally fast‑approve.

**Server calls:**
- Device A → `POST /pairing/start` `{side:"A"}` → returns `{pairing_token}` (5‑min TTL)
- Device A → `POST /supervisors/add` `{pair_id, side:"A", pairing_token, supervisor:{account_id, keys:{x25519_pub, ed25519_pub}}}`
- If A already has supervisors: an A‑side supervisor approves → `POST /supervisors/approve` with Ed25519‑signed challenge
- Optional acceleration by B‑side → `POST /supervisors/fast_approve` `{pending_id}`
- Devices update policy on next send (or immediately after a `409 POLICY_STALE`) via `GET /policy`

**Outcome:** from this point forward, **every message that involves Kid A** includes the parent’s key (so the parent can fetch/decrypt within 30 days). Kid delivery is never gated on parent presence.

---

## 4) Removing a supervisor (same side)
Any A‑side supervisor can schedule removal of one or more A‑side supervisors.

**Server calls:**
- Supervisor → `POST /supervisors/remove` `{pair_id, side:"A", targets:[…]}` (24‑hour pending window)
- Server notifies targets and B‑side supervisors.
- At cutoff: policy updates (keys removed), `policy_version++`.

**Rules:**
- The **last remaining** A‑side supervisor **cannot remove themselves** (`403 LAST_SUPERVISOR`).
- During the pending window, devices still wrap to the soon‑to‑be‑removed key; **after cutoff**, that supervisor’s **fetch** is blocked (authorization decided at fetch‑time).

**Outcome:** governance with notice; predictable effect time.

---

## 5) Supervisor reset (recovery when approvers are unreachable)
If A‑side supervisors are unreachable (lost phones, etc.), the device can request a reset.

**Server calls:**
- Device A → `POST /pairing/start` `{side:"A"}` → `{pairing_token}`
- Device A → `POST /supervisors/reset` `{pair_id, side:"A", pairing_token}` (starts 24‑hour countdown)
- Any active A‑side supervisor can veto → `POST /supervisors/veto` `{pending_id}`

**Outcome:** if not vetoed, A‑side supervisor list is cleared at `effective_at`. The next add on A will auto‑approve (with pairing mode).

---

## 6) Day‑to‑day delivery & clean‑up
- Devices and supervisors poll `GET /inbox`, fetch `GET /messages/{id}`, then `POST /acks`.
- **Retention:**
  - **Kid spool TTL** (e.g., 48h): keeps blobs around long enough for child delivery regardless of supervisors.
  - **30‑day window** for any side that **has supervisors**. A side with **no supervisors** contributes **no** 30‑day hold.
  - After purge: only **signed header**, **SHA‑256(ciphertext)**, and **receipts** remain (fetch returns 404).
- **Ops visibility:**
  - `GET /audit?pair_id=…` → who added/removed/reset, by whom, when, how.
  - `GET /receipts?recipient_id=…` → delivered/acked history for devices/supervisors.

**Outcome:** predictable storage, clear paper trail, strong privacy (server never has plaintext).

---

## Server endpoint catalog
**Health & boot**
- `GET /health`
- `POST /activate`
- `POST /pairing/start`

**Governance**
- `POST /supervisors/add`
- `POST /supervisors/approve`
- `POST /supervisors/fast_approve`
- `POST /supervisors/remove`
- `POST /supervisors/reset`
- `POST /supervisors/veto`
- `GET  /policy`

**Messaging**
- `POST /messages`
- `GET  /inbox`
- `GET  /messages/{msg_id}`
- `POST /acks`
- `GET  /keys`

**Ops & visibility**
- `GET  /audit`
- `GET  /receipts`

**Common error signals**
- `409 POLICY_STALE` (client must `GET /policy` and retry)
- `409 PENDING_EXISTS` (one governance event per side at a time)
- `422 INVALID_RECIPIENTS` (missing required key‑wraps)
- `403 LAST_SUPERVISOR` (can’t remove the last remaining on that side)
- `401/403/404/429` as usual

---

## Client call maps
**Device (A or B)**
- Bootstrapping: `POST /activate`, `GET /policy`
- Pairing mode: `POST /pairing/start`
- Governance initiation: `POST /supervisors/add`, `POST /supervisors/reset`
- Messaging: `POST /messages`, `GET /inbox`, `GET /messages/{id}`, `POST /acks`
- Policy refresh on `409 POLICY_STALE`: `GET /policy`

**Supervisor app**
- Governance: `POST /supervisors/approve`, `POST /supervisors/fast_approve`, `POST /supervisors/remove`, `POST /supervisors/veto`, `GET /policy`
- Inbox: `GET /inbox`, `GET /messages/{id}`, `POST /acks`
- Visibility: `GET /audit`, `GET /receipts`

---

## Notes for the prototype
- Keep auth simple for week‑1: per‑device API key and supervisor bearer token; swap to mTLS + account tokens later.
- Sign headers (Ed25519) and do E2E content with per‑message ephemeral X25519 → HKDF → AEAD. The server checks header presence/versions only.
- Enforce **fetch‑time authorization** strictly so governance effects apply retroactively to unfetched items.


## Local prototype

### Prerequisites
- Go 1.22+
- Python 3.10+
- Streamlit >= 1.32 (`pip install -r apps/requirements.txt`)

### Run the stack (three terminals)
1. **Server**
   ```bash
   export PC_DB_PATH="$(pwd)/paircomm.db"
   export PC_SPOOL_TTL=172800
   export PC_SUPERVISOR_WINDOW=2592000
   export PC_PENDING_WINDOW=86400
   cd server
   go run ./cmd/server
   ```
2. **Kid app (port 8501)**
   ```bash
   cd apps
   streamlit run kid_app.py --server.port 8501
   ```
3. **Parent app (port 8502)**
   ```bash
   cd apps
   streamlit run parent_app.py --server.port 8502
   ```

Environment variables are optional; defaults are applied if unset. Set `PC_HTTP_ADDR` to change the server bind address (defaults to `:8080`). Set `PC_SERVER_URL` for the Streamlit apps when the server is not on `http://localhost:8080`.

### Smoke test
Run the automated end-to-end flow:
```bash
bash scripts/smoke.sh
```
The smoke script binds the API server to `127.0.0.1:18080` by default; override via `PC_SMOKE_PORT`.
