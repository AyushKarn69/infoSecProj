from itertools import combinations

import pytest

from core.crypto.abss.abss_i import share
from core.crypto.ttss.ttss_i import EmbeddedShareBox, trace, verify


@pytest.mark.parametrize("threshold,colluders", [(2, 1), (3, 1), (3, 2), (4, 1), (4, 2), (4, 3)])
def test_trace_finds_each_controlled_colluding_subset(threshold: int, colluders: int) -> None:
    generated = share(123456, n=5, threshold=threshold)
    for fixed in combinations(generated.shares, colluders):
        box = EmbeddedShareBox(generated.parameters, generated.parameters.a1, fixed)
        result = trace(generated.parameters, generated, box, colluders, max_queries=64)
        assert result is not None
        parties, proof = result
        expected = frozenset(item.index for item in fixed)
        assert parties == expected
        assert verify(generated.parameters, generated.verification_key, parties, proof)


def test_verifier_rejects_changed_proof_or_party_set() -> None:
    generated = share(12, n=5, threshold=3)
    fixed = (generated.shares[0],)
    box = EmbeddedShareBox(generated.parameters, generated.parameters.a1, fixed)
    result = trace(generated.parameters, generated, box, 1, max_queries=64)
    assert result is not None
    parties, proof = result
    assert not verify(generated.parameters, generated.verification_key, parties, proof + 1)
    assert not verify(generated.parameters, generated.verification_key, {2}, proof)


def test_invalid_colluder_count_is_rejected() -> None:
    generated = share(5, n=5, threshold=3)
    box = EmbeddedShareBox(generated.parameters, generated.parameters.a1, generated.shares[:1])
    with pytest.raises(ValueError):
        trace(generated.parameters, generated, box, 3)
