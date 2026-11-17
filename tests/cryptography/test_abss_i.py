from itertools import combinations

import pytest

from core.crypto.abss.abss_i import (
    ABSSParameterError,
    ABSSParameters,
    ABSSReconstructionError,
    generate_parameters,
    reconstruct,
    share,
)


@pytest.mark.parametrize("threshold", [1, 2, 3, 4, 5])
def test_every_threshold_sized_subset_reconstructs(threshold: int) -> None:
    secret = 123456
    generated = share(secret, n=5, threshold=threshold)
    generated.parameters.validate()
    assert generated.parameters.m0 > secret
    assert generated.parameters.m0 >= 1 << (secret.bit_length() + 64)
    for subset in combinations(generated.shares, threshold):
        assert reconstruct(generated.parameters, subset) == secret


def test_more_than_threshold_shares_reconstruct() -> None:
    generated = share(87, n=5, threshold=3)
    assert reconstruct(generated.parameters, generated.shares) == 87


def test_fewer_than_threshold_shares_fail_closed() -> None:
    generated = share(87, n=5, threshold=3)
    with pytest.raises(ABSSReconstructionError, match="fewer"):
        reconstruct(generated.parameters, generated.shares[:2])


def test_duplicate_share_index_is_rejected() -> None:
    generated = share(87, n=5, threshold=2)
    with pytest.raises(ABSSReconstructionError, match="duplicate"):
        reconstruct(generated.parameters, [generated.shares[0], generated.shares[0]])


def test_invalid_parameters_and_negative_secret_are_rejected() -> None:
    with pytest.raises(ABSSParameterError):
        generate_parameters(-1, n=5, threshold=2)
    with pytest.raises(ABSSParameterError):
        generate_parameters(7, n=5, threshold=6)
    with pytest.raises(ABSSParameterError, match="security_slack_bits"):
        generate_parameters(7, n=5, threshold=2, security_slack_bits=16)
    invalid = ABSSParameters(n=5, threshold=2, m0=7, moduli=(11, 13, 17, 19, 23), a1=1)
    with pytest.raises(ABSSParameterError, match="inequality"):
        invalid.validate()


def test_share_set_contains_paper_tracing_material() -> None:
    generated = share(42, n=5, threshold=3)
    assert len(generated.tracing_key.encoded_components) == 2
    assert (
        generated.tracing_key.first_component_residues
        == generated.verification_key.first_component_residues
    )
    assert len(generated.verification_key.first_component_residues) == 5
