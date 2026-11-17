"""HMAC request authentication for node control-plane calls."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

from services.node_agent.agent import canonical


def headers_for(secret: bytes, method: str, path: str, body: bytes) -> dict[str, str]:
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(18)
    message = canonical(
        {
            "method": method.upper(),
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    mac = hmac.new(secret, message, hashlib.sha256).hexdigest()
    return {
        "X-RiskShare-Timestamp": timestamp,
        "X-RiskShare-Nonce": nonce,
        "X-RiskShare-Signature": mac,
    }


def verify_headers(
    secret: bytes, method: str, path: str, body: bytes, timestamp: str, nonce: str, signature: str
) -> bool:
    try:
        if abs(int(time.time()) - int(timestamp)) > 30 or len(nonce) < 16:
            return False
    except ValueError:
        return False
    message = canonical(
        {
            "method": method.upper(),
            "path": path,
            "timestamp": timestamp,
            "nonce": nonce,
            "body_sha256": hashlib.sha256(body).hexdigest(),
        }
    )
    return hmac.compare_digest(hmac.new(secret, message, hashlib.sha256).hexdigest(), signature)
