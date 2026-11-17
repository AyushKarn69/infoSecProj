"""ABSS-II / TTSS-II prototype following Leslie–Dutta Algorithms 5–8.

The paper writes its cyclic group multiplicatively. This implementation uses
the equivalent additive notation of standardized prime-order elliptic-curve
groups and delegates point arithmetic to PyCA/OpenSSL.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from math import gcd

from core.crypto.abss.abss_i import (
    ABSSParameterError,
    ABSSParameters,
    ShareholderShare,
    ShareSet,
    _next_prime,
)
from core.crypto.abss.abss_i import (
    share as abss_i_share,
)
from core.crypto.ttss.group import PrimeOrderGroup, group_for_moduli
from core.crypto.ttss.ttss_i import ReconstructionBox


@dataclass(frozen=True)
class TracingKeyII:
    encoded_components: tuple[int, ...]
    commitments: tuple[bytes, ...]


@dataclass(frozen=True)
class VerificationKeyII:
    commitments: tuple[bytes, ...]


@dataclass(frozen=True)
class TTSSIIShareSet:
    parameters: ABSSParameters
    group: PrimeOrderGroup
    shares: tuple[ShareholderShare, ...]
    tracing_key: TracingKeyII
    verification_key: VerificationKeyII


def share_ii(secret: int, n: int, threshold: int, *, m0: int | None = None) -> TTSSIIShareSet:
    """Algorithm 5: share using ABSS-II and conceal first residues by EC points."""
    base: ShareSet = abss_i_share(secret, n, threshold, m0=m0)
    parameters = base.parameters
    group = group_for_moduli(max(parameters.moduli))
    if group.order <= max(parameters.moduli):
        raise ABSSParameterError("group order must exceed every share modulus")
    first_residues = tuple(item.residues[0] for item in base.shares)
    commitments = tuple(group.encode_generator_multiple(value) for value in first_residues)
    return TTSSIIShareSet(
        parameters=parameters,
        group=group,
        shares=base.shares,
        tracing_key=TracingKeyII(base.tracing_key.encoded_components, commitments),
        verification_key=VerificationKeyII(commitments),
    )


def trace_ii(
    generation: TTSSIIShareSet,
    box: ReconstructionBox,
    colluder_count: int,
    *,
    max_queries: int = 256,
) -> tuple[frozenset[int], int] | None:
    """Algorithm 7: identify leaked parties using only box.query()."""
    parameters = generation.parameters
    parameters.validate()
    if not (0 < colluder_count < parameters.threshold):
        raise ValueError("colluder_count must be in [1, t-1]")
    if max_queries < 1:
        raise ValueError("max_queries must be positive")
    used_source_moduli = set(parameters.moduli)
    bits = max(32, max(parameters.moduli).bit_length() + 32)
    random_bits = max(256, sum(m.bit_length() for m in parameters.moduli) + 128)
    encoded_components = generation.tracing_key.encoded_components

    for _ in range(max_queries):
        random_y1 = secrets.randbits(random_bits)
        auxiliary: list[ShareholderShare] = []
        used = set(used_source_moduli)
        for position in range(parameters.threshold - colluder_count):
            while True:
                candidate = _next_prime((1 << (bits - 1)) | secrets.randbits(bits - 1) | 1)
                if candidate not in used and all(gcd(candidate, old) == 1 for old in used):
                    used.add(candidate)
                    break
            residues = (random_y1 % candidate,) + tuple(
                value % candidate for value in encoded_components
            )
            auxiliary.append(ShareholderShare(parameters.n + position + 1, candidate, residues))
        try:
            reconstructed = box.query(auxiliary)
        except Exception:
            continue
        later_components = tuple(value % parameters.m0 for value in encoded_components)
        candidate_y1 = reconstructed - sum(later_components) + parameters.a1
        matches = frozenset(
            index
            for index, (modulus, commitment) in enumerate(
                zip(parameters.moduli, generation.verification_key.commitments, strict=True),
                start=1,
            )
            if generation.group.encode_generator_multiple(candidate_y1 % modulus) == commitment
        )
        if len(matches) == colluder_count:
            return matches, candidate_y1
    return None


def verify_ii(
    generation: TTSSIIShareSet,
    alleged_parties: frozenset[int] | set[int],
    proof_integer: int,
) -> bool:
    """Algorithm 8: publicly check the alleged subset against EC commitments."""
    parameters = generation.parameters
    try:
        parameters.validate()
    except ABSSParameterError:
        return False
    if len(generation.verification_key.commitments) != parameters.n:
        return False
    if not alleged_parties or any(index < 1 or index > parameters.n for index in alleged_parties):
        return False
    return all(
        (generation.group.encode_generator_multiple(proof_integer % modulus) == commitment)
        == (index in alleged_parties)
        for index, (modulus, commitment) in enumerate(
            zip(parameters.moduli, generation.verification_key.commitments, strict=True), start=1
        )
    )
