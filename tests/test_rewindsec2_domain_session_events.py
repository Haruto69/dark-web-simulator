"""Adversarial tests for :mod:`rewindsec.domain.session_events`."""

import pytest

from rewindsec.core.events import EventSpec, EventSource, EventVisibility, derive_event_id
from rewindsec.domain.errors import IdentityMismatchError, InvalidDomainStateError
from rewindsec.domain.session_events import ScheduleAuditLog, SessionEventLog


def test_record_uses_the_core_derive_event_id_scheme():
    log = SessionEventLog("s1")
    event = log.record(type="mail.delivered", sim_time_ms=0)
    assert event.event_id == derive_event_id("s1", 0)


def test_failed_record_does_not_consume_sequence():
    log = SessionEventLog("s1")
    with pytest.raises(Exception):
        log.record(type="not valid!", sim_time_ms=0)
    assert log.next_seq == 0


def test_append_fired_materialises_from_spec():
    log = SessionEventLog("s1")
    spec = EventSpec(type="mail.delivered", payload={"subject": "hi"},
                     source=EventSource.SCHEDULER)
    event = log.append_fired(spec, sim_time_ms=500)
    assert event.event_id == derive_event_id("s1", 0)
    assert event.sim_time_ms == 500
    assert event.payload["subject"] == "hi"


def test_get_and_has():
    log = SessionEventLog("s1")
    event = log.record(type="mail.delivered", sim_time_ms=0)
    assert log.has(event.event_id)
    assert log.get(event.event_id) == event
    assert not log.has("0" * 32)


def test_capture_restore_roundtrip():
    log = SessionEventLog("s1")
    log.record(type="mail.delivered", sim_time_ms=0)
    log.record(type="mail.opened", sim_time_ms=10, source=EventSource.LEARNER)
    state = log.capture_state()
    restored = SessionEventLog.from_state(state)
    assert restored.capture_state() == state
    assert len(restored.events()) == 2


def test_restore_rejects_foreign_session_identity():
    log = SessionEventLog("s1")
    log.record(type="mail.delivered", sim_time_ms=0)
    state = log.capture_state()
    other = SessionEventLog("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_restore_rejects_tampered_event_id():
    log = SessionEventLog("s1")
    log.record(type="mail.delivered", sim_time_ms=0)
    state = log.capture_state()
    state["events"][0]["event_id"] = "0" * 32
    with pytest.raises(InvalidDomainStateError):
        SessionEventLog.from_state(state)


def test_restore_rejects_duplicate_seq():
    log = SessionEventLog("s1")
    log.record(type="mail.delivered", sim_time_ms=0)
    log.record(type="mail.opened", sim_time_ms=1)
    state = log.capture_state()
    state["events"][1] = dict(state["events"][0])
    with pytest.raises(InvalidDomainStateError):
        SessionEventLog.from_state(state)


# -- schedule audit log --------------------------------------------------

def test_scheduled_then_fired_lifecycle():
    audit = ScheduleAuditLog("s1")
    entry = audit.record_scheduled("sched-1", event_type="mail.delivered",
                                   scheduled_at_ms=0, fire_at_ms=1000, priority=0)
    assert entry.is_pending
    fired = audit.record_fired("sched-1", fired_event_id="e" * 32, resolved_at_ms=1000)
    assert fired.status == "fired"
    assert fired.fired_event_id == "e" * 32
    assert audit.get("sched-1").status == "fired"


def test_scheduled_then_cancelled_lifecycle():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=1000, priority=0)
    cancelled = audit.record_cancelled("sched-1", resolved_at_ms=500, reason="isolated")
    assert cancelled.status == "cancelled"
    assert cancelled.cancellation_reason == "isolated"


def test_cannot_resolve_twice():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=1000, priority=0)
    audit.record_fired("sched-1", fired_event_id="e" * 32, resolved_at_ms=1000)
    with pytest.raises(Exception):
        audit.record_cancelled("sched-1", resolved_at_ms=1000, reason="too late")


def test_resolve_unknown_schedule_id_raises():
    audit = ScheduleAuditLog("s1")
    with pytest.raises(Exception):
        audit.record_fired("nope", fired_event_id="e" * 32, resolved_at_ms=0)


def test_pending_entries_helper():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=100, priority=0)
    audit.record_scheduled("sched-2", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=200, priority=0)
    audit.record_fired("sched-1", fired_event_id="e" * 32, resolved_at_ms=100)
    pending = audit.pending_entries()
    assert len(pending) == 1
    assert pending[0].schedule_id == "sched-2"


def test_audit_capture_restore_roundtrip():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=100, priority=0)
    audit.record_scheduled("sched-2", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=200, priority=1)
    audit.record_fired("sched-1", fired_event_id="e" * 32, resolved_at_ms=100)
    audit.record_cancelled("sched-2", resolved_at_ms=150, reason="cancelled")
    state = audit.capture_state()
    restored = ScheduleAuditLog.from_state(state)
    assert restored.capture_state() == state
    assert restored.get("sched-1").status == "fired"
    assert restored.get("sched-2").status == "cancelled"


def test_audit_restore_rejects_foreign_session_identity():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=100, priority=0)
    state = audit.capture_state()
    other = ScheduleAuditLog("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_audit_restore_rejects_duplicate_schedule_id():
    audit = ScheduleAuditLog("s1")
    audit.record_scheduled("sched-1", event_type="mail.delivered",
                           scheduled_at_ms=0, fire_at_ms=100, priority=0)
    state = audit.capture_state()
    dup = dict(state["entries"][0])
    dup["seq"] = 1
    dup["audit_id"] = "1" * 32
    state["entries"].append(dup)
    state["seq"]["next"] = 2
    with pytest.raises(InvalidDomainStateError):
        ScheduleAuditLog.from_state(state)
