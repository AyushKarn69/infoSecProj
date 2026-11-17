import base64
import json
from pathlib import Path

from services.node_agent.agent import NodeAgent, issue_release_token


def test_node_store_persists_its_share_identity_and_rejects_replayed_tokens(tmp_path: Path) -> None:
    secret = b"node-agent-test-secret-0123456789"
    database = tmp_path / "node-1.sqlite3"
    node = NodeAgent(1, database, secret)
    assert node.distribute("vault", "epoch", {"index": 1, "modulus": "17", "residues": ["4", "8"]})
    public_key = node.public_key
    token = issue_release_token(secret, 1, "vault", "epoch")
    response = node.release(token)
    assert response is not None
    signature = base64.b64decode(response.pop("signature"))
    public_key.verify(
        signature, json.dumps(response, sort_keys=True, separators=(",", ":")).encode()
    )
    assert node.release(token) is None
    node.close()

    restarted = NodeAgent(1, database, secret)
    assert restarted.public_key.public_bytes_raw() == public_key.public_bytes_raw()
    assert restarted.health()["share_generations"] == 1
    restarted.close()
