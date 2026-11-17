"""Finite-integer ABSS-I prototype following Leslie and Dutta, Algorithms 1–2.

This module handles nonnegative integer secrets in [0, m0). It implements the
paper's additive components and CRT reconstruction. As in the paper, shares
are not authenticated; callers must add authenticated transport/storage.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from math import gcd, prod


class ABSSParameterError(ValueError):
    """Invalid threshold or modulus parameters."""


class ABSSReconstructionError(ValueError):
    """Shares do not form a valid reconstructable ABSS-I input."""


@dataclass(frozen=True)
class ShareholderShare:
    index: int
    modulus: int
    residues: tuple[int, ...]


@dataclass(frozen=True)
class ABSSParameters:
    n: int
    threshold: int
    m0: int
    moduli: tuple[int, ...]
    a1: int

    @property
    def product_threshold_smallest(self) -> int:
        return prod(self.moduli[: self.threshold])

    def validate(self) -> None:
        if not (1 <= self.threshold <= self.n):
            raise ABSSParameterError("threshold must be between 1 and n")
        if len(self.moduli) != self.n:
            raise ABSSParameterError("there must be exactly n share moduli")
        if tuple(sorted(self.moduli)) != self.moduli:
            raise ABSSParameterError("share moduli must be strictly increasing")
        if any(m <= self.m0 for m in self.moduli):
            raise ABSSParameterError("every share modulus must exceed m0")
        all_moduli = (self.m0, *self.moduli)
        for i, left in enumerate(all_moduli):
            if left <= 1 or any(gcd(left, right) != 1 for right in all_moduli[i + 1 :]):
                raise ABSSParameterError("m0 and share moduli must be pairwise coprime")
        largest_product = prod(self.moduli[-(self.threshold - 1) :]) if self.threshold > 1 else 1
        if self.product_threshold_smallest <= self.m0 * largest_product:
            raise ABSSParameterError("Asmuth–Bloom strict modulus inequality is not satisfied")
        if not _is_probable_prime(self.m0):
            raise ABSSParameterError("m0 must be prime")
        if self.a1 < 1:
            raise ABSSParameterError("A1 must be positive")


@dataclass(frozen=True)
class ShareSet:
    parameters: ABSSParameters
    shares: tuple[ShareholderShare, ...]
    tracing_key: TracingKey
    verification_key: VerificationKey


@dataclass(frozen=True)
class TracingKey:
    """Private TTSS-I material; never return it from a public API."""

    encoded_components: tuple[int, ...]
    first_component_residues: tuple[int, ...]


@dataclass(frozen=True)
class VerificationKey:
    first_component_residues: tuple[int, ...]


def _is_probable_prime(candidate: int, rounds: int = 32) -> bool:
    if candidate < 2:
        return False
    small_primes = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)
    for prime in small_primes:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False
    d = candidate - 1
    shifts = 0
    while d % 2 == 0:
        shifts += 1
        d //= 2
    for _ in range(rounds):
        base = secrets.randbelow(candidate - 3) + 2
        value = pow(base, d, candidate)
        if value in (1, candidate - 1):
            continue
        for _ in range(shifts - 1):
            value = pow(value, 2, candidate)
            if value == candidate - 1:
                break
        else:
            return False
    return True


def _next_prime(start: int) -> int:
    candidate = max(2, start)
    if candidate > 2 and candidate % 2 == 0:
        candidate += 1
    while not _is_probable_prime(candidate):
        candidate += 1 if candidate == 2 else 2
    return candidate


def generate_parameters(
    secret: int,
    n: int,
    threshold: int,
    *,
    m0: int | None = None,
    security_slack_bits: int = 64,
) -> ABSSParameters:
    """Generate distinct prime moduli satisfying the paper's strict inequality.

    Prime generation uses a CSPRNG-backed Miller–Rabin probable-prime test.
    This is suitable for a research prototype; it is not a certified-prime API.
    """
    if secret < 0:
        raise ABSSParameterError("secret must be nonnegative")
    if not (1 <= threshold <= n):
        raise ABSSParameterError("threshold must be between 1 and n")
    if security_slack_bits < 32:
        raise ABSSParameterError("security_slack_bits must be at least 32")
    # Avoid choosing m0 immediately above the secret, which would reveal that
    # the secret is very close to a public upper bound. Size it from the secret
    # domain width with explicit headroom instead.
    m0_floor = max(secret + 1, 1 << (max(1, secret.bit_length()) + security_slack_bits), 3)
    m0 = _next_prime(m0_floor) if m0 is None else m0
    if m0 <= secret or not _is_probable_prime(m0):
        raise ABSSParameterError("m0 must be a prime strictly greater than the secret")

    # A conservative spacing makes the inequality hold even when the t-1
    # largest moduli appear on its right-hand side. Validate it after generation.
    lower = max(m0 + 1, m0 * (1 << (threshold + 1)))
    moduli: list[int] = []
    candidate = lower
    while len(moduli) < n:
        prime = _next_prime(candidate)
        if prime != m0:
            moduli.append(prime)
        candidate = prime + 1
    moduli_tuple = tuple(moduli)
    product_m = prod(moduli_tuple[:threshold])
    largest_product = prod(moduli_tuple[-(threshold - 1) :]) if threshold > 1 else 1
    while product_m <= m0 * largest_product:
        candidate = moduli_tuple[-1] + 1
        moduli.append(_next_prime(candidate))
        moduli_tuple = tuple(moduli[-n:])
        product_m = prod(moduli_tuple[:threshold])
        largest_product = prod(moduli_tuple[-(threshold - 1) :]) if threshold > 1 else 1

    # m0 is the public encoding modulus; A1 is selected when sharing so its
    # range depends on the additive component s1.
    result = ABSSParameters(n=n, threshold=threshold, m0=m0, moduli=moduli_tuple, a1=1)
    # Check static constraints and the strict threshold inequality.
    result.validate()
    return result


def share(secret: int, n: int, threshold: int, *, m0: int | None = None) -> ShareSet:
    """Algorithm 1: distribute a nonnegative integer secret using ABSS-I."""
    parameters = generate_parameters(secret, n, threshold, m0=m0)
    modulus_product = prod(parameters.moduli[:threshold])
    additive = [secrets.randbelow(parameters.m0) for _ in range(threshold - 1)]
    s1 = secret - sum(additive)

    # Select A1 so 0 < y1 < M, including when s1 is negative.
    min_a1 = max(1, 1 - s1)
    max_a1 = modulus_product - s1 - 1
    if min_a1 > max_a1:
        raise ABSSParameterError("no valid A1 exists for these parameters")
    a1 = min_a1 + secrets.randbelow(max_a1 - min_a1 + 1)

    encoded = [s1 + a1]
    for component in additive:
        max_multiplier = (modulus_product - component - 1) // parameters.m0
        if max_multiplier < 1:
            raise ABSSParameterError("no valid additive encoding multiplier exists")
        multiplier = secrets.randbelow(max_multiplier) + 1
        encoded.append(component + multiplier * parameters.m0)

    updated = ABSSParameters(
        n=parameters.n,
        threshold=parameters.threshold,
        m0=parameters.m0,
        moduli=parameters.moduli,
        a1=a1,
    )
    updated.validate()
    shares = tuple(
        ShareholderShare(
            index=index,
            modulus=modulus,
            residues=tuple(value % modulus for value in encoded),
        )
        for index, modulus in enumerate(updated.moduli, start=1)
    )
    first_residues = tuple(item.residues[0] for item in shares)
    tracing_key = TracingKey(tuple(encoded[1:]), first_residues)
    verification_key = VerificationKey(first_residues)
    return ShareSet(updated, shares, tracing_key, verification_key)


def _crt(residues: tuple[int, ...], moduli: tuple[int, ...]) -> int:
    total = prod(moduli)
    result = 0
    for residue, modulus in zip(residues, moduli, strict=True):
        partial = total // modulus
        result += residue * partial * pow(partial, -1, modulus)
    return result % total


def reconstruct(
    parameters: ABSSParameters, shares: tuple[ShareholderShare, ...] | list[ShareholderShare]
) -> int:
    """Algorithm 2: reconstruct from any t distinct shares."""
    parameters.validate()
    if len(shares) < parameters.threshold:
        raise ABSSReconstructionError("fewer than threshold shares were supplied")
    by_index: dict[int, ShareholderShare] = {}
    for item in shares:
        if item.index in by_index:
            raise ABSSReconstructionError("duplicate shareholder index")
        if not 1 <= item.index <= parameters.n:
            raise ABSSReconstructionError("share index is outside the configured range")
        expected_modulus = parameters.moduli[item.index - 1]
        if item.modulus != expected_modulus or len(item.residues) != parameters.threshold:
            raise ABSSReconstructionError("share parameters do not match this generation")
        if any(residue < 0 or residue >= item.modulus for residue in item.residues):
            raise ABSSReconstructionError("share residue is out of range")
        by_index[item.index] = item

    selected = [by_index[i] for i in sorted(by_index)[: parameters.threshold]]
    moduli = tuple(item.modulus for item in selected)
    product_m = prod(moduli)
    encoded = [
        _crt(tuple(item.residues[component] for item in selected), moduli)
        for component in range(parameters.threshold)
    ]
    if any(value >= parameters.product_threshold_smallest for value in encoded):
        raise ABSSReconstructionError("CRT value violates the encoded secret range")
    components = [encoded[0] - parameters.a1]
    components.extend(value % parameters.m0 for value in encoded[1:])
    secret = sum(components)
    # The paper assumes secrets in Z_m0. The exact range cannot be checked
    # from public parameters alone; m0 bounds the represented secret space.
    if product_m <= 0:
        raise ABSSReconstructionError("invalid CRT modulus product")
    return secret


# Paper nomenclature retained for callers familiar with Share().
Share = share
