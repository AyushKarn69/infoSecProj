from itertools import combinations

from hypothesis import given, settings
from hypothesis import strategies as st

from core.crypto.abss.abss_i import reconstruct, share


@settings(max_examples=24, deadline=None)
@given(
    secret=st.integers(min_value=0, max_value=(1 << 128) - 1),
    threshold=st.integers(min_value=1, max_value=5),
)
def test_hypothesis_all_threshold_subsets_reconstruct(secret: int, threshold: int) -> None:
    generation = share(secret, n=5, threshold=threshold)
    for subset in combinations(generation.shares, threshold):
        assert reconstruct(generation.parameters, subset) == secret
