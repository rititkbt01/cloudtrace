import pytest

from cloudtrace.scoring import score


def test_c01_check2_example_is_high_8():
    bd, total, band = score(["cross_identity", "first_use_in_window", "new_source", "creator_source"])
    assert total == 8 and band == "high"
    assert bd == {"cross_identity": 1, "first_use_in_window": 2, "new_source": 2,
                  "creator_source": 3}


@pytest.mark.parametrize("evidence,band", [
    (["cross_identity"], "low"),
    (["cross_identity", "first_use_in_window"], "medium"),
    (["elevated_grant"], "medium"),
    (["cross_identity", "elevated_grant"], "medium"),
    (["first_use_in_window", "new_source", "cross_identity"], "high"),
])
def test_bands(evidence, band):
    assert score(evidence)[2] == band


def test_no_evidence_is_none():
    assert score([]) == ({}, 0, "none")


def test_unknown_evidence_name_is_rejected():
    with pytest.raises(KeyError):
        score(["made_up"])
