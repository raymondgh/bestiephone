import json
import os
from pathlib import Path
from typing import Optional

import requests
import streamlit as st

from crypto_utils import decrypt_message, encrypt_message, load_or_create_keypairs

st.set_page_config(page_title="Pair Communicator – Kid", layout="wide")

SERVER_URL = os.getenv("PC_SERVER_URL", "http://localhost:8080")
SEEDS_DIR = Path("seeds")
SEEDS_DIR.mkdir(parents=True, exist_ok=True)

if "device" not in st.session_state:
    st.session_state.device = {}
if "policy" not in st.session_state:
    st.session_state.policy = None
if "inbox" not in st.session_state:
    st.session_state.inbox = []
if "pairing_token" not in st.session_state:
    st.session_state.pairing_token = None
if "device_keys" not in st.session_state:
    st.session_state.device_keys = None
if "device_key_path" not in st.session_state:
    st.session_state.device_key_path = None


def auth_headers() -> dict:
    device = st.session_state.device
    if not device:
        return {}
    return {
        "X-Device-ID": device.get("device_id", ""),
        "X-Device-Key": device.get("api_key", ""),
    }


def request_json(method: str, path: str, **kwargs):
    url = f"{SERVER_URL}{path}"
    try:
        resp = requests.request(method, url, timeout=10, **kwargs)
    except requests.RequestException as exc:
        st.error(f"Request failed: {exc}")
        return None
    if resp.status_code >= 400:
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text
        st.error(f"{resp.status_code}: {payload}")
        return None
    if resp.content:
        try:
            return resp.json()
        except ValueError:
            return resp.text
    return None


def device_seed_path(pair_id: str, side: str) -> Path:
    safe_pair = pair_id.strip()
    safe_side = side.strip().upper()
    return SEEDS_DIR / f"{safe_pair}_{safe_side}_device.json"


def get_device_keys() -> Optional[dict]:
    if st.session_state.device_keys:
        return st.session_state.device_keys
    device = st.session_state.device
    if not device:
        return None
    pair_id = device.get("pair_id")
    side = device.get("side")
    if not pair_id or not side:
        return None
    path = device_seed_path(pair_id, side)
    if not path.exists():
        st.error("Device key seed missing. Re-activate this device to regenerate keys.")
        return None
    keys = load_or_create_keypairs("device", path)
    st.session_state.device_keys = keys
    st.session_state.device_key_path = str(path)
    return keys


def fetch_keys_data(pair_id: str):
    return request_json("GET", f"/keys?pair_id={pair_id}", headers=auth_headers())


def build_encrypted_payload(
    plaintext: str, keys_data: dict, device_keys: dict, device: dict
) -> Optional[dict]:
    sender_id = device.get("device_id")
    side = device.get("side")
    policy_version = keys_data.get("policy_version")
    if not sender_id or not side or policy_version is None:
        st.error("Incomplete sender or policy information.")
        return None

    devices_info = keys_data.get("devices", {})
    peer_side = "B" if side == "A" else "A"
    peer_info = devices_info.get(peer_side)
    if not peer_info:
        st.error("Peer device is not registered yet.")
        return None

    recipients = [
        {
            "type": "device",
            "id": peer_info.get("device_id"),
            "x25519_pub": peer_info.get("x25519_pub", ""),
            "ed25519_pub": peer_info.get("ed25519_pub", ""),
        }
    ]

    supervisors = keys_data.get("supervisors", {})
    for sup_side, sup_list in supervisors.items():
        for sup in sup_list:
            recipients.append(
                {
                    "type": "supervisor",
                    "id": sup.get("account_id"),
                    "x25519_pub": sup.get("x25519_pub", ""),
                    "ed25519_pub": sup.get("ed25519_pub", ""),
                }
            )

    if any(not r.get("id") or not r.get("x25519_pub") for r in recipients):
        st.error("Missing recipient keys. Try refreshing keys.")
        return None

    envelope = {
        "from_device_id": sender_id,
        "policy_version": policy_version,
        "recipients": recipients,
    }

    try:
        header, ciphertext = encrypt_message(
            plaintext, envelope, device_keys["ed25519"]["private"]
        )
    except Exception as exc:  # pragma: no cover - surface to UI
        st.error(f"Encryption failed: {exc}")
        return None

    payload = {
        "pair_id": device.get("pair_id"),
        "to": peer_info.get("device_id"),
        "recipients": [r["id"] for r in recipients],
        "header": header,
        "ciphertext": ciphertext,
        "policy_version": policy_version,
    }
    return payload


def send_encrypted_message(plaintext: str):
    device = st.session_state.device
    if not device:
        st.error("Activate a device first.")
        return
    device_keys = get_device_keys()
    if not device_keys:
        return

    pair_id = device.get("pair_id")
    if not pair_id:
        st.error("Pair ID missing from device state.")
        return

    def transmit(keys_data: dict):
        payload = build_encrypted_payload(plaintext, keys_data, device_keys, device)
        if not payload:
            return None
        try:
            resp = requests.post(
                f"{SERVER_URL}/messages/",
                headers={**auth_headers(), "Content-Type": "application/json"},
                json=payload,
                timeout=10,
            )
        except requests.RequestException as exc:
            st.error(f"Send failed: {exc}")
            return None
        return resp

    keys_data = fetch_keys_data(pair_id)
    if not keys_data:
        return

    response = transmit(keys_data)
    if response is None:
        return

    if response.status_code == 409:
        try:
            body = response.json()
        except ValueError:
            body = {}
        if body.get("error") == "POLICY_STALE":
            refreshed = fetch_keys_data(pair_id)
            if not refreshed:
                return
            response = transmit(refreshed)
            if response is None:
                return
    if response.status_code >= 400:
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        st.error(f"{response.status_code}: {payload}")
        return

    try:
        data = response.json()
    except ValueError:
        st.success("Message sent.")
        return
    st.success(f"Message sent: {data.get('message_id')}")


def decrypt_and_show_message(message_id: str):
    device = st.session_state.device
    if not device:
        st.error("Activate a device first.")
        return
    device_keys = get_device_keys()
    if not device_keys:
        return

    msg = request_json("GET", f"/messages/{message_id}", headers=auth_headers())
    if not msg:
        return

    header_raw = msg.get("header")
    ciphertext = msg.get("ciphertext")
    if not header_raw or not ciphertext:
        st.error("Message payload incomplete.")
        return
    try:
        header_obj = json.loads(header_raw)
    except (TypeError, json.JSONDecodeError) as exc:
        st.error(f"Invalid header JSON: {exc}")
        return
    try:
        plaintext = decrypt_message(
            header_obj,
            ciphertext,
            device_keys["x25519"]["private"],
            recipient_id=device.get("device_id"),
        )
    except Exception as exc:  # pragma: no cover - surface to UI
        st.error(f"Decrypt failed: {exc}")
        return

    st.write("#### Message contents")
    st.markdown(f"**Plaintext:** {plaintext}")
    with st.expander("Header", expanded=False):
        st.json(header_obj)

    ack_payload = {"message_id": message_id, "state": "delivered"}
    if request_json("POST", "/acks", headers=auth_headers(), json=ack_payload):
        st.success("Acknowledged")


st.title("Kid Communicator")
st.caption("Activate your device, send messages, and monitor supervisors.")

with st.expander("Server settings", expanded=False):
    st.write(f"Server URL: {SERVER_URL}")

st.header("Activation")
with st.form("activate"):
    default_pair = st.session_state.device.get("pair_id", "")
    pair_id = st.text_input("Pair ID", value=default_pair)
    side = st.selectbox(
        "Side",
        options=["A", "B"],
        index=0 if st.session_state.device.get("side", "A") == "A" else 1,
    )
    submitted = st.form_submit_button("Activate")
    if submitted:
        pair = pair_id.strip()
        if not pair:
            st.error("Pair ID is required.")
        else:
            path = device_seed_path(pair, side)
            keys = load_or_create_keypairs("device", path)
            payload = {
                "pair_id": pair,
                "side": side,
                "device_pub": {
                    "x25519_pub": keys["x25519"]["public"],
                    "ed25519_pub": keys["ed25519"]["public"],
                },
            }
            data = request_json("POST", "/activate", json=payload)
            if data:
                st.session_state.device = data
                st.session_state.device["pair_id"] = pair
                st.session_state.device["side"] = side
                st.session_state.device_keys = keys
                st.session_state.device_key_path = str(path)
                st.success("Device activated")

if st.session_state.device:
    device = st.session_state.device
    st.write("### Device credentials")
    st.code(json.dumps(device, indent=2))
    if st.session_state.device_key_path:
        st.caption(f"Key seed stored at {st.session_state.device_key_path}")

    if st.button("Refresh policy", type="primary"):
        policy = request_json("GET", "/policy", headers=auth_headers())
        if policy:
            st.session_state.policy = policy
            st.success("Policy updated")

    if st.session_state.policy is not None:
        st.subheader("Pair status")
        st.json(st.session_state.policy)
    else:
        st.info("Refresh policy to view governance state.")

    st.subheader("Pairing mode")
    with st.form("pairing"):
        submitted_pairing = st.form_submit_button("Request pairing token")
        if submitted_pairing:
            body = {"side": device.get("side")}
            token_info = request_json(
                "POST", "/pairing/start", headers=auth_headers(), json=body
            )
            if token_info:
                st.session_state.pairing_token = token_info
                st.success(f"Token: {token_info['pairing_token']}")
    if token := st.session_state.get("pairing_token"):
        st.write(token)

    st.subheader("Compose message")
    with st.form("compose"):
        plaintext = st.text_area("Message", placeholder="Write something secure...")
        submitted_send = st.form_submit_button("Send message")
        if submitted_send:
            if not plaintext.strip():
                st.error("Message body cannot be empty.")
            else:
                send_encrypted_message(plaintext.strip())

    st.subheader("Inbox")
    if st.button("Load inbox"):
        inbox = request_json("GET", "/inbox", headers=auth_headers())
        if inbox:
            st.session_state.inbox = inbox.get("items", [])
    inbox_items = st.session_state.get("inbox", [])
    if inbox_items:
        for item in inbox_items:
            cols = st.columns([3, 2, 2, 2])
            cols[0].write(item["message_id"])
            cols[1].write(item.get("created_at"))
            cols[2].write(item.get("ack_state"))
            if cols[3].button("Open", key=f"open_{item['message_id']}"):
                decrypt_and_show_message(item["message_id"])
    else:
        st.info("Inbox empty")

    st.subheader("Receipts")
    if st.button("Refresh receipts"):
        receipts = request_json("GET", "/receipts", headers=auth_headers())
        if receipts:
            st.write(receipts)

    st.subheader("Audit log")
    if st.button("View audit log"):
        audit = request_json("GET", "/audit", headers=auth_headers())
        if audit:
            st.write(audit)
else:
    st.info("Activate the device to begin.")
