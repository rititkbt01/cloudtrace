import pytest
from helpers import case_dirs, load_case

from cloudtrace import lineage, quality


def events_of(prefix):
    cdir = next(c for c in case_dirs() if c.name.startswith(prefix))
    _, records = load_case(cdir)
    return quality.clean(records)[0]


def test_c01_key_history_links_creation_and_first_use():
    history = lineage.build(events_of("c01"))
    assert list(history) == ["AKIAEXAMPLENEWKEY01"]
    k = history["AKIAEXAMPLENEWKEY01"]
    assert k.created_event_id == "c01-004" and k.target_user == "svc-b"
    assert k.creator_arn.endswith("user/admin-a") and k.creator_ip == "203.0.113.10"
    assert [u.event_id for u in k.uses] == ["c01-005"]
    assert k.uses[0].source_ip == "203.0.113.10"


def test_c09_gives_same_history_as_c01():
    a = lineage.build(events_of("c01"))["AKIAEXAMPLENEWKEY01"]
    b = lineage.build(events_of("c09"))["AKIAEXAMPLENEWKEY01"]
    assert (a.target_user, a.created_time, [u.time for u in a.uses]) == (
        b.target_user, b.created_time, [u.time for u in b.uses])


def test_failed_call_creates_no_key():
    assert lineage.build(events_of("c10")) == {}


def test_event_with_empty_key_id_is_not_linked():
    history = lineage.build(events_of("c11"))
    assert history["AKIAEXAMPLENEWKEY01"].uses == []


def test_key_that_is_never_used_has_no_uses():
    assert lineage.build(events_of("c08"))["AKIAEXAMPLENEWKEY01"].uses == []


@pytest.mark.parametrize("arn,name", [
    ("arn:aws:iam::123456789012:user/alice", "alice"),
    ("arn:aws:iam::123456789012:user/team/alice", "alice"),
    ("arn:aws:sts::123456789012:assumed-role/r/s", None),
    (None, None),
])
def test_name_from_arn(arn, name):
    assert lineage.name_from_arn(arn) == name


def test_user_names_ignore_case():
    assert lineage.same_user("John", "john")
    assert not lineage.same_user("john", "jon")
