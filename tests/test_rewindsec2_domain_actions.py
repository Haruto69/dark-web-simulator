"""Adversarial tests for :mod:`rewindsec.domain.actions`."""

import pytest

from rewindsec.domain.actions import ActionLog, LearnerAction, derive_action_id
from rewindsec.domain.enums import ActionClass
from rewindsec.domain.errors import IdentityMismatchError, InvalidDomainStateError
from rewindsec.core.events import derive_event_id


def test_action_id_is_derived_and_distinct_from_event_id():
    action_id = derive_action_id("s1", 0)
    event_id = derive_event_id("s1", 0)
    assert len(action_id) == 32
    assert action_id != event_id


def test_record_allocates_sequential_ids():
    log = ActionLog("s1")
    a0 = log.record(sim_time_ms=0, action_type="inspect.open_mail",
                    classification=ActionClass.OBSERVATIONAL)
    a1 = log.record(sim_time_ms=10, action_type="mail.submit_credentials",
                    classification=ActionClass.CONSEQUENTIAL)
    assert a0.seq == 0 and a1.seq == 1
    assert a0.action_id == derive_action_id("s1", 0)
    assert a1.action_id == derive_action_id("s1", 1)


def test_classification_helpers():
    log = ActionLog("s1")
    a = log.record(sim_time_ms=0, action_type="inspect.open_mail",
                   classification=ActionClass.OBSERVATIONAL)
    assert a.is_observational and not a.is_consequential
    b = log.record(sim_time_ms=0, action_type="mail.submit_credentials",
                   classification="consequential")
    assert b.is_consequential and not b.is_observational


def test_failed_record_does_not_consume_sequence():
    log = ActionLog("s1")
    with pytest.raises(Exception):
        log.record(sim_time_ms=0, action_type="not a valid type!!",
                  classification=ActionClass.OBSERVATIONAL)
    assert log.next_seq == 0
    a = log.record(sim_time_ms=0, action_type="inspect.open_mail",
                   classification=ActionClass.OBSERVATIONAL)
    assert a.seq == 0


def test_action_type_must_be_dotted_lowercase():
    log = ActionLog("s1")
    with pytest.raises(InvalidDomainStateError):
        log.record(sim_time_ms=0, action_type="InspectMail",
                  classification=ActionClass.OBSERVATIONAL)
    with pytest.raises(InvalidDomainStateError):
        log.record(sim_time_ms=0, action_type="singlesegment",
                  classification=ActionClass.OBSERVATIONAL)


def test_params_never_store_raw_secrets_type_but_do_accept_structured_metadata():
    log = ActionLog("s1")
    a = log.record(sim_time_ms=0, action_type="mail.click_link",
                   classification=ActionClass.CONSEQUENTIAL,
                   params={"referenced_event_id": "e" * 32, "ui_element": "button_1"})
    assert a.params["ui_element"] == "button_1"


def test_params_must_be_json_safe():
    log = ActionLog("s1")
    with pytest.raises(Exception):
        log.record(sim_time_ms=0, action_type="mail.click_link",
                  classification=ActionClass.CONSEQUENTIAL,
                  params={"bad": {1, 2, 3}})


def test_get_unknown_action_raises():
    log = ActionLog("s1")
    with pytest.raises(Exception):
        log.get("0" * 32)


def test_capture_restore_roundtrip():
    log = ActionLog("s1")
    log.record(sim_time_ms=0, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL, target="mail-1")
    log.record(sim_time_ms=5, action_type="mail.submit_credentials",
              classification=ActionClass.CONSEQUENTIAL)
    state = log.capture_state()
    restored = ActionLog.from_state(state)
    assert restored.capture_state() == state
    assert len(restored.actions()) == 2


def test_restore_rejects_foreign_session_identity():
    log = ActionLog("s1")
    log.record(sim_time_ms=0, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL)
    state = log.capture_state()
    other = ActionLog("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_restore_rejects_duplicate_seq():
    log = ActionLog("s1")
    log.record(sim_time_ms=0, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL)
    log.record(sim_time_ms=1, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL)
    state = log.capture_state()
    state["actions"][1] = dict(state["actions"][0])
    with pytest.raises(InvalidDomainStateError):
        ActionLog.from_state(state)


def test_restore_rejects_action_id_not_matching_derivation():
    log = ActionLog("s1")
    log.record(sim_time_ms=0, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL)
    state = log.capture_state()
    state["actions"][0]["action_id"] = "0" * 32
    with pytest.raises(InvalidDomainStateError):
        ActionLog.from_state(state)


def test_restore_rejects_action_belonging_to_different_session():
    log = ActionLog("s1")
    log.record(sim_time_ms=0, action_type="inspect.open_mail",
              classification=ActionClass.OBSERVATIONAL)
    state = log.capture_state()
    state["actions"][0]["session_id"] = "s2"
    state["actions"][0]["action_id"] = derive_action_id("s2", 0)
    with pytest.raises(IdentityMismatchError):
        ActionLog.from_state(state)


def test_bool_seq_rejected_in_learner_action_construction():
    with pytest.raises(Exception):
        LearnerAction(action_id=derive_action_id("s1", 0), seq=True, session_id="s1",
                     sim_time_ms=0, action_type="inspect.open_mail",
                     classification=ActionClass.OBSERVATIONAL)
