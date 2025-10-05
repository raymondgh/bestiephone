import base64
import hashlib
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

from nacl import exceptions, public, secret, signing, utils


def load_or_create_keypairs(kind: str, path: os.PathLike) -> Dict[str, Dict[str, str]]:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)

    signing_key = signing.SigningKey.generate()
    verify_key = signing_key.verify_key
    x25519_sk = public.PrivateKey.generate()

    payload = {
        "kind": kind,
        "ed25519": {
            "private": base64.b64encode(signing_key.encode()).decode("ascii"),
            "public": base64.b64encode(verify_key.encode()).decode("ascii"),
        },
        "x25519": {
            "private": base64.b64encode(x25519_sk.encode()).decode("ascii"),
            "public": base64.b64encode(x25519_sk.public_key.encode()).decode("ascii"),
        },
    }
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    os.chmod(path, 0o600)
    return payload


def encrypt_message(
    plaintext: str,
    envelope: Dict[str, object],
    sender_signing_sk_b64: str,
) -> Tuple[Dict[str, object], str]:
    recipients: List[Dict[str, str]] = envelope.get("recipients", [])  # type: ignore[arg-type]
    from_device_id = envelope.get("from_device_id")
    policy_version = envelope.get("policy_version")
    if not recipients or not from_device_id or policy_version is None:
        raise ValueError("envelope requires from_device_id, policy_version, and recipients")

    cmk = utils.random(secret.SecretBox.KEY_SIZE)
    header_recipients: List[Dict[str, str]] = []
    for recipient in recipients:
        x25519_pub_b64 = recipient.get("x25519_pub")
        recipient_type = recipient.get("type")
        recipient_id = recipient.get("id")
        if not x25519_pub_b64 or not recipient_type or not recipient_id:
            raise ValueError("recipient requires id, type, and x25519_pub")
        pub_key = public.PublicKey(base64.b64decode(x25519_pub_b64))
        sealed = public.SealedBox(pub_key).encrypt(cmk)
        header_recipients.append(
            {
                "type": recipient_type,
                "id": recipient_id,
                "wrap": base64.b64encode(sealed).decode("ascii"),
            }
        )

    created_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    header = {
        "msg_id": str(uuid.uuid4()),
        "from_device_id": from_device_id,
        "policy_version": policy_version,
        "created_at": created_at,
        "enc": {"cipher": "xsalsa20poly1305", "wrap": "sealedbox", "ver": "v1"},
        "recipients": header_recipients,
        "sig_scheme": "ed25519:v1",
    }

    signing_key = signing.SigningKey(base64.b64decode(sender_signing_sk_b64))
    payload = _signature_payload(header)
    signature = signing_key.sign(payload.encode("utf-8")).signature
    header["signature"] = base64.b64encode(signature).decode("ascii")

    box = secret.SecretBox(cmk)
    ciphertext = box.encrypt(plaintext.encode("utf-8"), utils.random(secret.SecretBox.NONCE_SIZE))
    return header, base64.b64encode(ciphertext).decode("ascii")


def decrypt_message(
    header: Dict[str, object],
    ciphertext_b64: str,
    my_x25519_sk_b64: str,
    *,
    recipient_id: Optional[str] = None,
) -> str:
    recipients: Iterable[Dict[str, str]] = header.get("recipients", [])  # type: ignore[arg-type]
    private_key = public.PrivateKey(base64.b64decode(my_x25519_sk_b64))
    ciphertext = base64.b64decode(ciphertext_b64)

    candidate_recipients = list(recipients)
    if recipient_id:
        candidate_recipients = [r for r in candidate_recipients if r.get("id") == recipient_id]
        if not candidate_recipients:
            raise ValueError("recipient wrap not found")

    cmk = None
    for recipient in candidate_recipients:
        wrap_b64 = recipient.get("wrap", "")
        if not wrap_b64:
            continue
        wrap_bytes = base64.b64decode(wrap_b64)
        try:
            cmk = public.SealedBox(private_key).decrypt(wrap_bytes)
            break
        except exceptions.CryptoError:
            continue
    if cmk is None:
        raise ValueError("unable to decrypt content key")

    plaintext = secret.SecretBox(cmk).decrypt(ciphertext)
    return plaintext.decode("utf-8")


def _signature_payload(header: Dict[str, object]) -> str:
    recipients = header.get("recipients", [])  # type: ignore[arg-type]
    sorted_recipients = sorted(
        recipients,
        key=lambda r: (r.get("type", ""), r.get("id", "")),
    )
    entries: List[str] = []
    for recipient in sorted_recipients:
        wrap_b64 = recipient.get("wrap", "")
        wrap_bytes = base64.b64decode(wrap_b64)
        digest = hashlib.sha256(wrap_bytes).hexdigest()[:16]
        entries.append(f"{recipient.get('type','')}:{recipient.get('id','')}:{digest}")
    joined = ",".join(entries)
    return (
        "pc-h1|"
        f"{header.get('msg_id')}|"
        f"{header.get('from_device_id')}|"
        f"{header.get('policy_version')}|"
        f"{header.get('created_at')}|recips={joined}"
    )
