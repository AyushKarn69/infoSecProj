"""Persistent single-node share store used by the local demonstrator.

Each instance gets a distinct SQLite file and Ed25519 identity. The class is
invoked locally by the control service; production deployment still needs the
separate HTTP/mTLS process boundary described in the architecture document.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class NodeAgent:
    def __init__(self, node_id: int, storage_path: Path, control_secret: bytes) -> None:
        self.node_id = node_id
        self.storage_path = storage_path
        self.storage_path.parent.mkdir(parents=True, exist_ok=True)
        self.control_secret = control_secret
        self.online = True
        self._db = sqlite3.connect(storage_path, check_same_thread=False)
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS shares ("
            "vault_id TEXT, epoch_id TEXT, body BLOB NOT NULL, "
            "PRIMARY KEY(vault_id, epoch_id))"
        )
        self._db.execute(
            "CREATE TABLE IF NOT EXISTS used_tokens ("
            "token_id TEXT PRIMARY KEY, used_at INTEGER NOT NULL)"
        )
        self._db.commit()
        key_path = storage_path.with_suffix(".ed25519")
        if key_path.exists():
            self._signing_key = Ed25519PrivateKey.from_private_bytes(key_path.read_bytes())
        else:
            self._signing_key = Ed25519PrivateKey.generate()
            key_path.write_bytes(
                self._signing_key.private_bytes(
                    serialization.Encoding.Raw,
                    serialization.PrivateFormat.Raw,
                    serialization.NoEncryption(),
                )
            )
        self.public_key = self._signing_key.public_key()

    def distribute(self, vault_id: str, epoch_id: str, share: dict[str, object]) -> bool:
        if not self.online or share.get("index") != self.node_id:
            return False
        body = canonical(share)
        self._db.execute(
            "INSERT OR REPLACE INTO shares(vault_id, epoch_id, body) VALUES (?, ?, ?)",
            (vault_id, epoch_id, body),
        )
        self._db.commit()
        return True

    def release(self, token: str) -> dict[str, object] | None:
        if not self.online:
            return None
        try:
            encoded, mac = token.split(".", 1)
            body = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            supplied_mac = base64.urlsafe_b64decode(mac + "=" * (-len(mac) % 4))
            expected_mac = hmac.new(self.control_secret, body, hashlib.sha256).digest()
            if not hmac.compare_digest(supplied_mac, expected_mac):
                return None
            claims = json.loads(body)
            if claims["node_id"] != self.node_id or int(claims["expires_at"]) < int(time.time()):
                return None
            token_id = str(claims["token_id"])
            cursor = self._db.execute(
                "INSERT OR IGNORE INTO used_tokens(token_id, used_at) VALUES (?, ?)",
                (token_id, int(time.time())),
            )
            if cursor.rowcount != 1:
                return None
            row = self._db.execute(
                "SELECT body FROM shares WHERE vault_id = ? AND epoch_id = ?",
                (claims["vault_id"], claims["epoch_id"]),
            ).fetchone()
            self._db.commit()
            if row is None:
                return None
            share = json.loads(row[0])
            response = {
                "node_id": self.node_id,
                "token_id": token_id,
                "vault_id": claims["vault_id"],
                "epoch_id": claims["epoch_id"],
                "share": share,
            }
            signature = self._signing_key.sign(canonical(response))
            return {**response, "signature": base64.b64encode(signature).decode("ascii")}
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            return None

    def health(self) -> dict[str, object]:
        count = self._db.execute("SELECT count(*) FROM shares").fetchone()[0]
        return {
            "node_id": self.node_id,
            "status": "online" if self.online else "offline",
            "share_generations": count,
        }

    def simulated_compromised_share(self, vault_id: str, epoch_id: str) -> dict[str, object] | None:
        """Test-lab hook: return this node's own share after simulated compromise."""
        if not self.online:
            return None
        row = self._db.execute(
            "SELECT body FROM shares WHERE vault_id = ? AND epoch_id = ?",
            (vault_id, epoch_id),
        ).fetchone()
        return json.loads(row[0]) if row else None

    def retire_generation(self, vault_id: str, epoch_id: str) -> bool:
        cursor = self._db.execute(
            "DELETE FROM shares WHERE vault_id = ? AND epoch_id = ?", (vault_id, epoch_id)
        )
        self._db.commit()
        return cursor.rowcount >= 0

    def consume_control_nonce(self, nonce: str) -> bool:
        self._db.execute("DELETE FROM used_tokens WHERE used_at < ?", (int(time.time()) - 3600,))
        cursor = self._db.execute(
            "INSERT OR IGNORE INTO used_tokens(token_id, used_at) VALUES (?, ?)",
            (f"control:{nonce}", int(time.time())),
        )
        self._db.commit()
        return cursor.rowcount == 1

    def close(self) -> None:
        self._db.close()

    def set_online(self, online: bool) -> None:
        self.online = online


def issue_release_token(
    secret: bytes, node_id: int, vault_id: str, epoch_id: str, *, ttl_seconds: int = 30
) -> str:
    claims = {
        "token_id": secrets.token_urlsafe(18),
        "node_id": node_id,
        "vault_id": vault_id,
        "epoch_id": epoch_id,
        "expires_at": int(time.time()) + ttl_seconds,
    }
    body = canonical(claims)
    signature = hmac.new(secret, body, hashlib.sha256).digest()
    encoded = base64.urlsafe_b64encode(body).decode("ascii").rstrip("=")
    mac = base64.urlsafe_b64encode(signature).decode("ascii").rstrip("=")
    return f"{encoded}.{mac}"


def verify_node_response(response: dict[str, object], public_key: Ed25519PublicKey) -> bool:
    try:
        signature = base64.b64decode(str(response["signature"]))
        body = {key: value for key, value in response.items() if key != "signature"}
        public_key.verify(signature, canonical(body))
        return True
    except Exception:
        return False
