"""End-to-end API test using isolated local node stores and a temporary DB."""

from __future__ import annotations

import base64
import os
import tempfile
from pathlib import Path

_data_dir = Path(tempfile.mkdtemp(prefix="riskshare-api-test-"))
os.environ["RISKSHARE_DATA_DIR"] = str(_data_dir)
os.environ["RISKSHARE_DATABASE_URL"] = f"sqlite:///{(_data_dir / 'control.sqlite3').as_posix()}"
os.environ["RISKSHARE_CONTROL_SECRET"] = "test-control-secret-0123456789abcdef"
os.environ["RISKSHARE_AUTH_SECRET"] = "test-auth-secret-0123456789abcdef"

from fastapi.testclient import TestClient  # noqa: E402

from services.control_api.app import app  # noqa: E402


def test_vault_recovery_risk_rotation_and_failed_transition_fail_closed() -> None:
    with TestClient(app) as client:
        assert client.get("/control-room").status_code == 200
        admin = client.post(
            "/auth/login", json={"username": "admin", "password": "dev-admin-change-me"}
        ).json()["access_token"]
        operator = client.post(
            "/auth/login", json={"username": "operator", "password": "dev-operator-change-me"}
        ).json()["access_token"]
        admin_headers = {"Authorization": f"Bearer {admin}"}
        operator_headers = {"Authorization": f"Bearer {operator}"}

        created = client.post("/vaults", headers=operator_headers, json={"name": "research-notes"})
        assert created.status_code == 200
        vault_id = created.json()["id"]
        plaintext = b"RiskShare encrypted research artifact"
        initialized = client.post(
            f"/vaults/{vault_id}/initialize",
            headers=admin_headers,
            json={"filename": "notes.txt", "content_base64": base64.b64encode(plaintext).decode()},
        )
        assert initialized.status_code == 200
        assert initialized.json()["threshold"] == 2
        assert all(
            node["share_generations"] == 1
            for node in client.get("/nodes", headers=admin_headers).json()
        )

        second_vault = client.post(
            "/vaults", headers=operator_headers, json={"name": "second-vault"}
        ).json()["id"]
        second_init = client.post(
            f"/vaults/{second_vault}/initialize",
            headers=admin_headers,
            json={
                "filename": "second.txt",
                "content_base64": base64.b64encode(b"second object").decode(),
            },
        )
        assert second_init.status_code == 200

        request = client.post(
            "/recovery-requests", headers=operator_headers, json={"vault_id": vault_id}
        )
        assert request.status_code == 200
        recovered = client.post(
            f"/recovery-requests/{request.json()['id']}/approve", headers=admin_headers
        )
        assert recovered.status_code == 200
        assert base64.b64decode(recovered.json()["content_base64"]) == plaintext

        attack = client.post(
            "/simulator/attacks",
            headers=admin_headers,
            json={"kind": "invalid_share", "node_id": 1},
        )
        assert attack.status_code == 200
        assert attack.json()["active_threshold"] == 3
        active = client.get(f"/vaults/{vault_id}", headers=operator_headers).json()["active_epoch"]
        assert active["threshold"] == 3
        assert (
            client.get(f"/vaults/{second_vault}", headers=operator_headers).json()["active_epoch"][
                "threshold"
            ]
            == 3
        )
        trace = client.post(
            "/trace-cases",
            headers=admin_headers,
            json={"vault_id": vault_id, "leaked_node_ids": [1]},
        )
        assert trace.status_code == 200, trace.text
        assert trace.json()["identified_nodes"] == [1]
        assert trace.json()["verified"] is True
        assert (
            client.post(
                f"/trace-cases/{trace.json()['id']}/verify", headers=operator_headers
            ).json()["valid"]
            is True
        )

        failure = client.post(
            "/simulator/attacks",
            headers=admin_headers,
            json={"kind": "invalid_node_signature", "node_id": 2, "take_node_offline": True},
        )
        assert failure.status_code == 200
        assert failure.json()["active_threshold"] == 3
        assert client.get("/risk/current", headers=admin_headers).json()["recovery_frozen"] is True
        pending = client.post(
            "/recovery-requests", headers=operator_headers, json={"vault_id": vault_id}
        )
        assert pending.status_code == 423
        vault = client.get(f"/vaults/{vault_id}", headers=operator_headers).json()
        assert vault["active_epoch"]["threshold"] == 3
        assert vault["active_epoch"]["status"] == "ACTIVE"
        assert client.get("/audit/verify", headers=admin_headers).json()["valid"] is True

        assert client.post("/auth/logout", headers=admin_headers).status_code == 200
        assert client.get("/auth/me", headers=admin_headers).status_code == 401
        for _ in range(6):
            client.post("/auth/login", json={"username": "bad", "password": "bad"})
        limited = client.post("/auth/login", json={"username": "bad", "password": "bad"})
        assert limited.status_code == 429
