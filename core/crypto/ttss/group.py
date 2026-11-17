"""Standard-library-backed descriptions of standardized prime-order EC groups.

Scalar multiplication is delegated to PyCA/OpenSSL. The cyclic group is
written additively here; scalar multiplication by `x` corresponds to `g^x`.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

P384_ORDER = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
    16,
)
P521_ORDER = int(
    "1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409",
    16,
)


@dataclass(frozen=True)
class PrimeOrderGroup:
    name: str
    order: int
    curve: ec.EllipticCurve

    def encode_generator_multiple(self, scalar: int) -> bytes:
        reduced = scalar % self.order
        if reduced == 0:
            return b"\x00"  # canonical encoding for the identity point
        point = ec.derive_private_key(reduced, self.curve).public_key()
        return point.public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
        )


def group_for_moduli(maximum_modulus: int) -> PrimeOrderGroup:
    """Select a standardized prime-order group whose order exceeds all mi."""
    if maximum_modulus < P384_ORDER:
        return PrimeOrderGroup("secp384r1", P384_ORDER, ec.SECP384R1())
    if maximum_modulus < P521_ORDER:
        return PrimeOrderGroup("secp521r1", P521_ORDER, ec.SECP521R1())
    raise ValueError("share modulus is too large for supported prime-order groups")
