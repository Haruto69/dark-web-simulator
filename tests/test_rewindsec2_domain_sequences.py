"""Adversarial tests for :mod:`rewindsec.domain.sequences`."""

import pytest

from rewindsec.domain.errors import InvalidDomainStateError, SequenceOverflowError
from rewindsec.domain.identifiers import MAX_JSON_SAFE_INT
from rewindsec.domain.sequences import SequenceCounter


def test_peek_does_not_consume():
    counter = SequenceCounter("event")
    assert counter.peek() == 0
    assert counter.peek() == 0
    assert counter.next_value == 0


def test_advance_consumes_and_increments():
    counter = SequenceCounter("event")
    assert counter.advance() == 0
    assert counter.advance() == 1
    assert counter.peek() == 2


def test_failed_operation_never_consumes_a_sequence_number():
    """The peek/advance split: a caller that never calls advance() leaves no trace."""
    counter = SequenceCounter("event")
    seq = counter.peek()
    try:
        if seq >= 0:
            raise ValueError("simulated validation failure")
    except ValueError:
        pass
    assert counter.peek() == seq == 0


def test_overflow_raises_and_does_not_advance():
    counter = SequenceCounter("event", start=MAX_JSON_SAFE_INT)
    with pytest.raises(SequenceOverflowError):
        counter.advance()
    assert counter.next_value == MAX_JSON_SAFE_INT


def test_bool_start_rejected():
    with pytest.raises(Exception):
        SequenceCounter("event", start=True)


def test_negative_start_rejected():
    with pytest.raises(Exception):
        SequenceCounter("event", start=-1)


def test_capture_restore_roundtrip():
    counter = SequenceCounter("event")
    counter.advance()
    counter.advance()
    state = counter.capture_state()
    restored = SequenceCounter.from_state(state)
    assert restored.next_value == 2
    assert restored.name == "event"


def test_restore_state_name_mismatch_rejected():
    counter = SequenceCounter("event")
    other = SequenceCounter("action")
    other.advance()
    with pytest.raises(InvalidDomainStateError):
        counter.restore_state(other.capture_state())


def test_from_state_unknown_version_rejected():
    counter = SequenceCounter("event")
    state = counter.capture_state()
    state["version"] = 999
    with pytest.raises(InvalidDomainStateError):
        SequenceCounter.from_state(state)


def test_from_state_unknown_field_rejected():
    counter = SequenceCounter("event")
    state = counter.capture_state()
    state["bogus"] = 1
    with pytest.raises(InvalidDomainStateError):
        SequenceCounter.from_state(state)


def test_from_state_missing_field_rejected():
    with pytest.raises(InvalidDomainStateError):
        SequenceCounter.from_state({"version": 1, "name": "event"})


def test_restore_leaves_counter_untouched_on_rejection():
    counter = SequenceCounter("event")
    counter.advance()
    bad_state = {"version": 1, "name": "wrong_name", "next": 5}
    with pytest.raises(InvalidDomainStateError):
        counter.restore_state(bad_state)
    assert counter.next_value == 1
