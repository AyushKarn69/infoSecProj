"""TTSS-I tracing and verification prototype (Leslie–Dutta Algorithms 3–4).

Tracing receives only a query interface to a reconstruction box. The included
``EmbeddedShareBox`` is a test/demo oracle; it is not a hardened sandbox for
untrusted executable code.
"""

from __future__ import annotations

import secrets
from collections.abc import Sequence
from math import gcd
from typing import Protocol

from core.crypto.abss.abss_i import (
    ABSSParameterError,
    ABSSParameters,
    ABSSReconstructionError,
    ShareholderShare,
    ShareSet,
    VerificationKey,
    _crt,
    _next_prime,
)


class ReconstructionBox(Protocol):
    def query(self, additional_shares: Sequence[ShareholderShare]) -> int:
        """Return a reconstructed integer secret for supplied auxiliary shares."""


class EmbeddedShareBox:
    """Reference reconstruction box holding a fixed set of leaked shares."""

    def __init__(
        self, parameters: ABSSParameters, a1: int, fixed_shares: Sequence[ShareholderShare]
    ):
        if not (0 < len(fixed_shares) < parameters.threshold):
            raise ValueError("box must contain between one and t-1 fixed shares")
        self._threshold = parameters.threshold
        self._m0 = parameters.m0
        self._a1 = a1
        self._fixed = tuple(fixed_shares)

    def query(self, additional_shares: Sequence[ShareholderShare]) -> int:
        all_shares = (*self._fixed, *additional_shares)
        if len(all_shares) != self._threshold:
            raise ABSSReconstructionError("box query must complete the threshold")
        moduli = tuple(item.modulus for item in all_shares)
        if len(set(moduli)) != len(moduli):
            raise ABSSReconstructionError("box share moduli must be distinct")
        if any(
            left <= 1 or any(gcd(left, right) != 1 for right in moduli[i + 1 :])
            for i, left in enumerate(moduli)
        ):
            raise ABSSReconstructionError("box share moduli must be pairwise coprime")
        if any(len(item.residues) != self._threshold for item in all_shares):
            raise ABSSReconstructionError("box share has the wrong number of components")
        encoded = [
            _crt(tuple(item.residues[j] for item in all_shares), moduli)
            for j in range(self._threshold)
        ]
        components = [encoded[0] - self._a1]
        components.extend(value % self._m0 for value in encoded[1:])
        return sum(components)


def trace(
    parameters: ABSSParameters,
    share_set: ShareSet,
    box: ReconstructionBox,
    colluder_count: int,
    *,
    max_queries: int = 256,
) -> tuple[frozenset[int], int] | None:
    """Run the TTSS-I black-box trace search.

    Returns `(identified_party_indices, proof_integer)` or None when no query
    produced a candidate identifying exactly the declared number of parties.
    """
    parameters.validate()
    if share_set.parameters != parameters:
        raise ABSSParameterError("share generation does not match public parameters")
    if not (0 < colluder_count < parameters.threshold):
        raise ValueError("colluder_count must be in [1, t-1]")
    if max_queries < 1:
        raise ValueError("max_queries must be positive")

    encoded_components = share_set.tracing_key.encoded_components
    if len(encoded_components) != parameters.threshold - 1:
        raise ValueError("tracing key has the wrong component count")
    a1 = parameters.a1
    all_moduli = parameters.moduli
    random_bits = max(256, sum(m.bit_length() for m in all_moduli) + 128)

    for _ in range(max_queries):
        random_y1 = secrets.randbits(random_bits)
        auxiliary: list[ShareholderShare] = []
        used_moduli = set(all_moduli)
        for position in range(parameters.threshold - colluder_count):
            while True:
                candidate = _next_prime(
                    (1 << (max(32, max(all_moduli).bit_length() + 32) - 1))
                    | secrets.randbits(max(32, max(all_moduli).bit_length() + 32) - 1)
                    | 1
                )
                if candidate not in used_moduli and all(
                    gcd(candidate, existing) == 1 for existing in used_moduli
                ):
                    used_moduli.add(candidate)
                    break
            residues = (random_y1 % candidate,) + tuple(
                value % candidate for value in encoded_components
            )
            auxiliary.append(
                ShareholderShare(
                    index=parameters.n + position + 1, modulus=candidate, residues=residues
                )
            )

        try:
            reconstructed = box.query(auxiliary)
        except Exception:
            # A malformed/partial oracle response is not evidence and is ignored.
            continue
        later_components = tuple(value % parameters.m0 for value in encoded_components)
        candidate_y1 = reconstructed - sum(later_components) + a1
        matches = frozenset(
            index
            for index, (modulus, residue) in enumerate(
                zip(all_moduli, share_set.verification_key.first_component_residues, strict=True),
                start=1,
            )
            if candidate_y1 % modulus == residue
        )
        if len(matches) == colluder_count:
            return matches, candidate_y1
    return None


def verify(
    parameters: ABSSParameters,
    verification_key: VerificationKey,
    alleged_parties: frozenset[int] | set[int],
    proof_integer: int,
) -> bool:
    """Publicly verify the TTSS-I residue proof (Algorithm 4)."""
    parameters.validate()
    if len(verification_key.first_component_residues) != parameters.n:
        return False
    if not alleged_parties or any(index < 1 or index > parameters.n for index in alleged_parties):
        return False
    return all(
        (proof_integer % modulus == residue) == (index in alleged_parties)
        for index, (modulus, residue) in enumerate(
            zip(parameters.moduli, verification_key.first_component_residues, strict=True),
            start=1,
        )
    )
