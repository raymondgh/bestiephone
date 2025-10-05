import json
import os
from datetime import datetime
from typing import List

import requests
import streamlit as st

st.set_page_config(page_title="Pair Communicator – Parent", layout="wide")

SERVER_URL = os.getenv("PC_SERVER_URL", "http://localhost:8080")

if "supervisor" not in st.session_state:
    st.session_state.supervisor = {}
if "policy" not in st.session_state:
    st.session_state.policy = None
if "inbox" not in st.session_state:
    st.session_state.inbox = []


def auth_headers() -> dict:
    sup = st.session_state.supervisor
    if not sup:
        return {}
    return {
        "X-Supervisor-ID": sup.get("supervisor_id", ""),
        "X-Supervisor-Key": sup.get("api_key", ""),
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


st.title("Parent Supervisor Console")
st.caption("Link to your child, review inbox, and manage governance")

with st.expander("Server settings", expanded=False):
    st.write(f"Server URL: {SERVER_URL}")

st.header("Link to communicator")
with st.form("link"):
    pair_id = st.text_input("Pair ID", value=st.session_state.supervisor.get("pair_id", ""))
    side = st.selectbox("Kid side", options=["A", "B"], index=0 if st.session_state.supervisor.get("side", "A") == "A" else 1)
    token = st.text_input("Pairing token")
    display_name = st.text_input("Display name", value=st.session_state.supervisor.get("display_name", "Guardian"))
    submitted = st.form_submit_button("Link")
    if submitted:
        payload = {
            "pair_id": pair_id.strip(),
            "side": side,
            "pairing_token": token.strip(),
            "supervisor": {"display_name": display_name},
        }
        data = request_json("POST", "/supervisors/add", json=payload)
        if data:
            st.session_state.supervisor.update(data)
            st.session_state.supervisor["pair_id"] = pair_id.strip()
            st.session_state.supervisor["side"] = side
            st.session_state.supervisor["display_name"] = display_name
            if data.get("status") == "active":
                st.success("Supervisor activated")
            else:
                st.warning("Supervisor pending approval")

if st.session_state.supervisor:
    sup = st.session_state.supervisor
    st.subheader("Supervisor credentials")
    st.code(json.dumps(sup, indent=2))

    if st.button("Refresh policy", type="primary"):
        policy = request_json("GET", "/policy", headers=auth_headers())
        if policy:
            st.session_state.policy = policy
            st.success("Policy refreshed")

    if st.session_state.policy:
        policy = st.session_state.policy
        st.subheader("Current policy")
        st.json(policy)

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
                if cols[3].button("Open", key=f"p_open_{item['message_id']}"):
                    msg = request_json("GET", f"/messages/{item['message_id']}", headers=auth_headers())
                    if msg:
                        st.write(msg)
                        ack_payload = {"message_id": item["message_id"], "state": "delivered"}
                        ack_resp = request_json("POST", "/acks", headers=auth_headers(), json=ack_payload)
                        if ack_resp:
                            st.success("Acknowledged")
        else:
            st.info("No pending messages")

        st.subheader("Governance")
        pending = policy.get("pending_events", [])
        if pending:
            st.write("Pending events:")
            for event in pending:
                cols = st.columns([3, 2, 2, 2])
                cols[0].write(event["id"])
                cols[1].write(f"{event['type']} ({event['side']})")
                cols[2].write(event.get("status"))
                cols[3].write(event.get("effective_at"))
        else:
            st.info("No pending governance events")

        with st.form("approve"):
            pending_id = st.text_input("Pending ID to approve")
            approve_side = st.radio("Approval type", options=["same_side", "fast"], index=0)
            submitted_approve = st.form_submit_button("Submit approval")
            if submitted_approve and pending_id:
                path = "/supervisors/approve" if approve_side == "same_side" else "/supervisors/fast_approve"
                payload = {"pair_id": sup.get("pair_id"), "pending_id": pending_id.strip()}
                result = request_json("POST", path, headers=auth_headers(), json=payload)
                if result:
                    st.success(result)

        with st.form("remove"):
            targets_raw = st.text_input("Supervisor IDs to remove (comma separated)")
            submitted_remove = st.form_submit_button("Schedule removal")
            if submitted_remove and targets_raw:
                targets: List[str] = [t.strip() for t in targets_raw.split(",") if t.strip()]
                payload = {"pair_id": sup.get("pair_id"), "side": sup.get("side"), "targets": targets}
                result = request_json("POST", "/supervisors/remove", headers=auth_headers(), json=payload)
                if result:
                    st.success(result)

        with st.form("reset"):
            pairing_token = st.text_input("Pairing token for reset")
            submitted_reset = st.form_submit_button("Schedule reset")
            if submitted_reset and pairing_token:
                payload = {"pair_id": sup.get("pair_id"), "side": sup.get("side"), "pairing_token": pairing_token.strip()}
                result = request_json("POST", "/supervisors/reset", headers=auth_headers(), json=payload)
                if result:
                    st.warning(result)

        with st.form("veto"):
            veto_id = st.text_input("Pending ID to veto")
            submitted_veto = st.form_submit_button("Veto reset")
            if submitted_veto and veto_id:
                payload = {"pair_id": sup.get("pair_id"), "pending_id": veto_id.strip()}
                result = request_json("POST", "/supervisors/veto", headers=auth_headers(), json=payload)
                if result:
                    st.success(result)

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
    st.info("Use a pairing token to link as a supervisor.")

