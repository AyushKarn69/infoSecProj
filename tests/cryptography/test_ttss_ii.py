from itertools import combinations

from core.crypto.abss.abss_i import reconstruct
from core.crypto.ttss.group import P384_ORDER, P521_ORDER, group_for_moduli
from core.crypto.ttss.ttss_i import EmbeddedShareBox
from core.crypto.ttss.ttss_ii import share_ii, trace_ii, verify_ii


def test_selects_group_order_larger_than_share_moduli() -> None:
    assert group_for_moduli(10**20).order == P384_ORDER
    assert group_for_moduli(P384_ORDER).order == P521_ORDER


def test_ttss_ii_traces_and_verifies_each_single_leaker() -> None:
    generation = share_ii(123456, n=5, threshold=3)
    assert generation.group.order > max(generation.parameters.moduli)
    assert len(generation.tracing_key.encoded_components) == 2
    assert len(generation.tracing_key.commitments) == 5
    for subset in combinations(generation.shares, generation.parameters.threshold):
        assert reconstruct(generation.parameters, subset) == 123456

    for fixed in combinations(generation.shares, 1):
        box = EmbeddedShareBox(generation.parameters, generation.parameters.a1, fixed)
        result = trace_ii(generation, box, 1, max_queries=64)
        assert result is not None
        parties, proof = result
        assert parties == frozenset({fixed[0].index})
        assert verify_ii(generation, parties, proof)
        assert not verify_ii(generation, parties, proof + 1)


def test_ttss_ii_trace_uses_black_box_for_two_leakers() -> None:
    generation = share_ii(42, n=5, threshold=4)
    fixed = generation.shares[1:3]
    box = EmbeddedShareBox(generation.parameters, generation.parameters.a1, fixed)
    result = trace_ii(generation, box, 2, max_queries=64)
    assert result is not None
    parties, proof = result
    assert parties == frozenset({2, 3})
    assert verify_ii(generation, parties, proof)
