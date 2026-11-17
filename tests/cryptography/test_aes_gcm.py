from dataclasses import replace

import pytest

from core.crypto.encryption.aes_gcm import (
    EncryptionError,
    decrypt,
    dek_to_integer,
    encrypt,
    generate_dek,
    integer_to_dek,
)


def test_aes_gcm_round_trip_and_epoch_binding() -> None:
    key = generate_dek()
    payload = encrypt(key, b"riskshare payload", vault_id="vault-1", epoch_id="epoch-1")
    assert decrypt(key, payload) == b"riskshare payload"
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt(key, replace(payload, epoch_id="epoch-2"))
    with pytest.raises(EncryptionError, match="authentication"):
        decrypt(generate_dek(), payload)


def test_dek_integer_encoding_preserves_exact_width() -> None:
    key = bytes.fromhex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
    assert len(integer_to_dek(dek_to_integer(key))) == 32
    assert integer_to_dek(dek_to_integer(key)) == key
    with pytest.raises(EncryptionError):
        integer_to_dek(-1)
    with pytest.raises(EncryptionError):
        dek_to_integer(b"short")
