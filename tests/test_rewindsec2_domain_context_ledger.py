"""Adversarial tests for :mod:`rewindsec.domain.context_ledger`.

The available-vs-observed distinction is the module's whole reason to exist
(Architecture Spec v1.1 S7), so it gets the deepest coverage here.
"""

import pytest

from rewindsec.domain.context_ledger import (ContextLedger, DuplicateFactError,
                                              FactNotAvailableError)
from rewindsec.domain.errors import IdentityMismatchError, InvalidDomainStateError


def test_introduce_fact_defaults_available_and_unobserved():
    ledger = ContextLedger("s1")
    fact = ledger.introduce_fact("f1", "org", {"a": 1}, "directory", sim_time_ms=0)
    assert fact.available is True
    assert fact.available_at_ms == 0
    assert fact.observed is False
    assert fact.observed_by_action_id is None
    assert fact.version == 1


def test_introduce_fact_can_start_unavailable():
    ledger = ContextLedger("s1")
    fact = ledger.introduce_fact("f1", "org", {"a": 1}, "directory",
                                 sim_time_ms=0, available=False)
    assert fact.available is False
    assert fact.available_at_ms is None


def test_duplicate_fact_id_rejected():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory", sim_time_ms=0)
    with pytest.raises(DuplicateFactError):
        ledger.introduce_fact("f1", "org", {"a": 2}, "directory", sim_time_ms=10)


def test_observe_before_available_rejected():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory",
                          sim_time_ms=0, available=False)
    with pytest.raises(FactNotAvailableError):
        ledger.observe("f1", action_id="act1", sim_time_ms=5)


def test_observe_unknown_fact_rejected():
    ledger = ContextLedger("s1")
    with pytest.raises(Exception):
        ledger.observe("nope", action_id="act1", sim_time_ms=5)


def test_make_available_then_observe_succeeds():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory",
                          sim_time_ms=0, available=False)
    ledger.make_available("f1", sim_time_ms=10)
    fact = ledger.observe("f1", action_id="act1", sim_time_ms=20)
    assert fact.available and fact.observed
    assert fact.observed_by_action_id == "act1"
    assert fact.observed_at_ms == 20


def test_make_available_is_idempotent_and_keeps_first_timestamp():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory",
                          sim_time_ms=0, available=False)
    ledger.make_available("f1", sim_time_ms=10)
    fact = ledger.make_available("f1", sim_time_ms=999)
    assert fact.available_at_ms == 10


def test_observe_is_idempotent_and_keeps_first_observer():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory", sim_time_ms=0)
    ledger.observe("f1", action_id="act1", sim_time_ms=5)
    fact = ledger.observe("f1", action_id="act2", sim_time_ms=999)
    assert fact.observed_by_action_id == "act1"
    assert fact.observed_at_ms == 5


def test_update_fact_bumps_version_but_preserves_observation_state():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"a": 1}, "directory", sim_time_ms=0)
    ledger.observe("f1", action_id="act1", sim_time_ms=5)
    updated = ledger.update_fact("f1", value={"a": 2}, source="corrected",
                                 sim_time_ms=30)
    assert updated.version == 2
    assert updated.value["a"] == 2
    assert updated.observed is True
    assert updated.observed_by_action_id == "act1"


def test_available_and_observed_query_helpers():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", 1, "src", sim_time_ms=0)
    ledger.introduce_fact("f2", "org", 2, "src", sim_time_ms=0, available=False)
    ledger.observe("f1", action_id="act1", sim_time_ms=1)
    assert [f.fact_id for f in ledger.available_facts()] == ["f1"]
    assert [f.fact_id for f in ledger.observed_facts()] == ["f1"]
    assert {f.fact_id for f in ledger.facts()} == {"f1", "f2"}


def test_capture_restore_roundtrip_preserves_everything():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", {"nested": [1, 2, "x"]}, "src", sim_time_ms=0)
    ledger.introduce_fact("f2", "org", None, "src", sim_time_ms=0, available=False)
    ledger.observe("f1", action_id="act1", sim_time_ms=5)
    state = ledger.capture_state()
    restored = ContextLedger.from_state(state)
    assert restored.capture_state() == state
    assert restored.get("f1").observed_by_action_id == "act1"


def test_restore_rejects_foreign_session_identity():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", 1, "src", sim_time_ms=0)
    state = ledger.capture_state()
    other = ContextLedger("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_restore_rejects_duplicate_fact_id_in_payload():
    ledger = ContextLedger("s1")
    ledger.introduce_fact("f1", "org", 1, "src", sim_time_ms=0)
    state = ledger.capture_state()
    state["facts"].append(dict(state["facts"][0]))
    with pytest.raises(InvalidDomainStateError):
        ContextLedger.from_state(state)


def test_restore_rejects_unknown_snapshot_version():
    ledger = ContextLedger("s1")
    state = ledger.capture_state()
    state["version"] = 42
    with pytest.raises(InvalidDomainStateError):
        ContextLedger.from_state(state)


def test_restore_rejects_bool_where_int_expected():
    ledger = ContextLedger("s1")
    with pytest.raises(InvalidDomainStateError):
        ledger.introduce_fact("f1", "org", 1, "src", sim_time_ms=True)


def test_value_must_be_json_safe():
    ledger = ContextLedger("s1")
    with pytest.raises(Exception):
        ledger.introduce_fact("f1", "org", {1, 2, 3}, "src", sim_time_ms=0)


def test_fact_construction_rejects_observed_without_available():
    from rewindsec.domain.context_ledger import ContextFact
    with pytest.raises(InvalidDomainStateError):
        ContextFact(fact_id="f1", category="org", value=1, source="src",
                   introduced_by_event_id=None, introduced_at_ms=0,
                   last_updated_at_ms=0, available=False, available_at_ms=None,
                   observed=True, observed_by_action_id="a1", observed_at_ms=1,
                   version=1)


def test_fact_construction_rejects_available_without_timestamp():
    from rewindsec.domain.context_ledger import ContextFact
    with pytest.raises(InvalidDomainStateError):
        ContextFact(fact_id="f1", category="org", value=1, source="src",
                   introduced_by_event_id=None, introduced_at_ms=0,
                   last_updated_at_ms=0, available=True, available_at_ms=None,
                   observed=False, observed_by_action_id=None, observed_at_ms=None,
                   version=1)
