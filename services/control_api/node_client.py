"""Mutually authenticated HTTP client for separately running node agents."""

from __future__ import annotations

import base64
import json
from typing import cast

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from services.node_agent.internal_auth import headers_for


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


class RemoteNodeClient:
    def __init__(
        self,
        node_id: int,
        base_url: str,
        control_secret: bytes,
        *,
        ca_file: str,
        client_cert: str,
        client_key: str,
        timeout: float = 5.0,
    ) -> None:
        self.node_id = node_id
        self.base_url = base_url.rstrip("/")
        self.control_secret = control_secret
        self.client = httpx.Client(
            base_url=self.base_url,
            verify=ca_file,
            cert=(client_cert, client_key),
            timeout=timeout,
        )
        identity = self.client.get("/internal/identity")
        identity.raise_for_status()
        payload = identity.json()
        if payload["node_id"] != node_id:
            raise ValueError("remote node identity does not match configured node ID")
        self.public_key = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(payload["ed25519_public_key"])
        )

    def distribute(self, vault_id: str, epoch_id: str, share: dict[str, object]) -> bool:
        body = canonical({"vault_id": vault_id, "epoch_id": epoch_id, "share": share})
        try:
            response = self.client.post(
                "/internal/shares",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    **headers_for(self.control_secret, "POST", "/internal/shares", body),
                },
            )
            return response.is_success and response.json().get("acknowledged") is True
        except httpx.HTTPError:
            return False

    def release(self, token: str) -> dict[str, object] | None:
        try:
            response = self.client.post("/internal/release", json={"token": token})
            return cast(dict[str, object], response.json()) if response.is_success else None
        except httpx.HTTPError:
            return None

    def health(self) -> dict[str, object]:
        try:
            response = self.client.get("/health")
            response.raise_for_status()
            return cast(dict[str, object], response.json())
        except httpx.HTTPError:
            return {"node_id": self.node_id, "status": "offline", "share_generations": 0}

    def retire_generation(self, vault_id: str, epoch_id: str) -> bool:
        body = canonical({"vault_id": vault_id, "epoch_id": epoch_id})
        try:
            response = self.client.post(
                "/internal/retire",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    **headers_for(self.control_secret, "POST", "/internal/retire", body),
                },
            )
            return response.is_success
        except httpx.HTTPError:
            return False

    def simulated_compromised_share(self, vault_id: str, epoch_id: str) -> dict[str, object] | None:
        body = canonical({"vault_id": vault_id, "epoch_id": epoch_id})
        try:
            response = self.client.post(
                "/internal/trace-share",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    **headers_for(self.control_secret, "POST", "/internal/trace-share", body),
                },
            )
            return response.json().get("share") if response.is_success else None
        except httpx.HTTPError:
            return None

    def set_online(self, online: bool) -> bool:
        body = canonical({"online": online})
        try:
            response = self.client.post(
                "/internal/simulation/online",
                content=body,
                headers={
                    "Content-Type": "application/json",
                    **headers_for(self.control_secret, "POST", "/internal/simulation/online", body),
                },
            )
            return response.is_success
        except httpx.HTTPError:
            return False

    def close(self) -> None:
        self.client.close()
