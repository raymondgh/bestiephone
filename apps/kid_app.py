import json
import os
from datetime import datetime

import requests
import streamlit as st

st.set_page_config(page_title="Pair Communicator – Kid", layout="wide")

SERVER_URL = os.getenv("PC_SERVER_URL", "http://localhost:8080")

if "device" not in st.session_state:
    st.session_state.device = {}
if "policy" not in st.session_state:
    st.session_state.policy = None
if "inbox" not in st.session_state:
    st.session_state.inbox = []


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


st.title("Kid Communicator")
st.caption("Activate your device, send messages, and monitor supervisors.")

with st.expander("Server settings", expanded=False):
    st.write(f"Server URL: {SERVER_URL}")

st.header("Activation")
with st.form("activate"):
    pair_id = st.text_input("Pair ID", value=st.session_state.device.get("pair_id", ""))
    side = st.selectbox("Side", options=["A", "B"], index=0 if st.session_state.device.get("side", "A") == "A" else 1)
    submitted = st.form_submit_button("Activate")
    if submitted:
        payload = {"pair_id": pair_id.strip(), "side": side, "device_pub": {"x25519": "placeholder"}}
        data = request_json("POST", "/activate", json=payload)
        if data:
            st.session_state.device = data
            st.session_state.device["pair_id"] = pair_id.strip()
            st.session_state.device["side"] = side
            st.success("Device activated")

if st.session_state.device:
    device = st.session_state.device
    st.write("### Device credentials")
    st.code(json.dumps(device, indent=2))

    if st.button("Refresh policy", type="primary"):
        policy = request_json("GET", "/policy", headers=auth_headers())
        if policy:
            st.session_state.policy = policy
            st.success("Policy updated")

    if st.session_state.policy is None:
        st.info("Fetch policy to continue.")
    else:
        policy = st.session_state.policy
        st.subheader("Pair status")
        st.json(policy)

        st.subheader("Pairing mode")
        with st.form("pairing"):
            submitted_pairing = st.form_submit_button("Request pairing token")
            if submitted_pairing:
                body = {"side": device.get("side")}
                token_info = request_json("POST", "/pairing/start", headers=auth_headers(), json=body)
                if token_info:
                    st.session_state.pairing_token = token_info
                    st.success(f"Token: {token_info['pairing_token']}")
        if token := st.session_state.get("pairing_token"):
            st.write(token)

        st.subheader("Compose message")
        with st.form("compose"):
            plaintext = st.text_area("Message", placeholder="Write something secure...")
            header = st.text_area("Header (JSON)", value=json.dumps({"note": "demo header", "ts": datetime.utcnow().isoformat()}, indent=2))
            submitted_send = st.form_submit_button("Send message")
            if submitted_send:
                devices = policy.get("devices", {})
                side = device.get("side")
                peer_side = "B" if side == "A" else "A"
                peer_id = devices.get(peer_side)
                if not peer_id:
                    st.error("Peer device not registered")
                else:
                    required = [peer_id]
                    supervisors = policy.get("supervisors", {})
                    for s_side in (side, peer_side):
                        for sup in supervisors.get(s_side, []):
                            if sup.get("status") == "active":
                                required.append(sup.get("id"))
                    payload = {
                        "pair_id": device.get("pair_id"),
                        "to": peer_id,
                        "recipients": required,
                        "header": header,
                        "ciphertext": plaintext,
                        "policy_version": policy.get("policy_version"),
                    }
                    resp = request_json("POST", "/messages/", headers=auth_headers(), json=payload)
                    if resp:
                        st.success(f"Message sent: {resp['message_id']}")

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
                    msg = request_json("GET", f"/messages/{item['message_id']}", headers=auth_headers())
                    if msg:
                        st.write(msg)
                        ack_payload = {"message_id": item["message_id"], "state": "delivered"}
                        ack_resp = request_json("POST", "/acks", headers=auth_headers(), json=ack_payload)
                        if ack_resp:
                            st.success("Acknowledged")
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

