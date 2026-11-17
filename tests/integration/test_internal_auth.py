from services.node_agent.internal_auth import headers_for, verify_headers


def test_internal_message_authentication_binds_method_path_and_body() -> None:
    secret = b"internal-control-secret-012345"
    body = b'{"epoch_id":"e1","vault_id":"v1"}'
    headers = headers_for(secret, "POST", "/internal/shares", body)
    assert verify_headers(
        secret,
        "POST",
        "/internal/shares",
        body,
        headers["X-RiskShare-Timestamp"],
        headers["X-RiskShare-Nonce"],
        headers["X-RiskShare-Signature"],
    )
    assert not verify_headers(
        secret,
        "POST",
        "/internal/retire",
        body,
        headers["X-RiskShare-Timestamp"],
        headers["X-RiskShare-Nonce"],
        headers["X-RiskShare-Signature"],
    )
    assert not verify_headers(
        secret,
        "POST",
        "/internal/shares",
        body + b" ",
        headers["X-RiskShare-Timestamp"],
        headers["X-RiskShare-Nonce"],
        headers["X-RiskShare-Signature"],
    )
