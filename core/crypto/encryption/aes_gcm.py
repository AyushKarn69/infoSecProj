"""AES-256-GCM helpers with vault/epoch-bound authenticated data."""

from __future__ import annotations

import json
import secrets
from dataclasses import dataclass

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_BYTES = 32
NONCE_BYTES = 12


class EncryptionError(ValueError):
    """Invalid key metadata or authenticated decryption failure."""


@dataclass(frozen=True)
class EncryptedObject:
    vault_id: str
    epoch_id: str
    encryption_version: int
    nonce: bytes
    ciphertext: bytes


def generate_dek() -> bytes:
    """Generate a random 256-bit data-encryption key."""
    return AESGCM.generate_key(bit_length=256)


def dek_to_integer(dek: bytes) -> int:
    if len(dek) != KEY_BYTES:
        raise EncryptionError("DEK must be exactly 32 bytes")
    return int.from_bytes(dek, "big", signed=False)


def integer_to_dek(value: int) -> bytes:
    if value < 0 or value >= 1 << (8 * KEY_BYTES):
        raise EncryptionError("integer is outside the 256-bit DEK range")
    return value.to_bytes(KEY_BYTES, "big", signed=False)


def encrypt(
    dek: bytes,
    plaintext: bytes,
    *,
    vault_id: str,
    epoch_id: str,
    encryption_version: int = 1,
) -> EncryptedObject:
    _validate_metadata(dek, vault_id, epoch_id, encryption_version)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, _aad(vault_id, epoch_id, encryption_version))
    return EncryptedObject(vault_id, epoch_id, encryption_version, nonce, ciphertext)


def decrypt(dek: bytes, encrypted: EncryptedObject) -> bytes:
    _validate_metadata(dek, encrypted.vault_id, encrypted.epoch_id, encrypted.encryption_version)
    if len(encrypted.nonce) != NONCE_BYTES:
        raise EncryptionError("AES-GCM nonce must be 12 bytes")
    try:
        return AESGCM(dek).decrypt(
            encrypted.nonce,
            encrypted.ciphertext,
            _aad(encrypted.vault_id, encrypted.epoch_id, encrypted.encryption_version),
        )
    except InvalidTag as exc:
        raise EncryptionError("ciphertext authentication failed") from exc


def _validate_metadata(dek: bytes, vault_id: str, epoch_id: str, encryption_version: int) -> None:
    if len(dek) != KEY_BYTES:
        raise EncryptionError("DEK must be exactly 32 bytes")
    if not vault_id or not epoch_id or encryption_version < 1:
        raise EncryptionError("vault, epoch, and positive encryption version are required")


def _aad(vault_id: str, epoch_id: str, encryption_version: int) -> bytes:
    return json.dumps(
        {"vault_id": vault_id, "epoch_id": epoch_id, "encryption_version": encryption_version},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
