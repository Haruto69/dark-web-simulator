"""Adversarial tests for :mod:`rewindsec.domain.world`."""

import pytest

from rewindsec.domain.errors import IdentityMismatchError, InvalidDomainStateError
from rewindsec.domain.world import WorldState


def test_mutate_sets_value_and_returns_mutation_record():
    world = WorldState("s1")
    record = world.mutate("mailbox", "unread", 3, sim_time_ms=0)
    assert world.get("mailbox", "unread") == 3
    assert record.old_value is None
    assert record.new_value == 3
    assert record.seq == 0


def test_every_mutation_is_recorded_even_when_value_is_unchanged():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 3, sim_time_ms=0)
    world.mutate("mailbox", "unread", 3, sim_time_ms=10)
    assert world.revision == 2
    assert len(world.mutations()) == 2


def test_get_missing_key_returns_default():
    world = WorldState("s1")
    assert world.get("mailbox", "unread") is None
    assert world.get("mailbox", "unread", default=0) == 0


def test_has_and_namespaces():
    world = WorldState("s1")
    assert not world.has("mailbox", "unread")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    assert world.has("mailbox", "unread")
    assert world.namespaces() == ("mailbox",)


def test_get_component_returns_plain_mutable_dict():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    component = world.get_component("mailbox")
    component["unread"] = 999  # must not mutate the world
    assert world.get("mailbox", "unread") == 1


def test_mutation_cause_event_id_recorded():
    world = WorldState("s1")
    record = world.mutate("mailbox", "unread", 1, sim_time_ms=0, cause_event_id="e" * 32)
    assert record.cause_event_id == "e" * 32


def test_value_must_be_json_safe():
    world = WorldState("s1")
    with pytest.raises(Exception):
        world.mutate("mailbox", "unread", {1, 2}, sim_time_ms=0)


def test_capture_restore_roundtrip():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 3, sim_time_ms=0)
    world.mutate("files", "quarantined", ["a.exe"], sim_time_ms=10, cause_event_id="e" * 32)
    state = world.capture_state()
    restored = WorldState.from_state(state)
    assert restored.capture_state() == state
    assert restored.get("files", "quarantined") == ["a.exe"]
    assert restored.revision == 2


def test_restore_rejects_foreign_session_identity():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    state = world.capture_state()
    other = WorldState("s2")
    with pytest.raises(IdentityMismatchError):
        other.restore_state(state)


def test_restore_rejects_tampered_mutation_id():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    state = world.capture_state()
    state["mutations"][0]["mutation_id"] = "0" * 32
    with pytest.raises(InvalidDomainStateError):
        WorldState.from_state(state)


def test_restore_rejects_duplicate_mutation_seq():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    world.mutate("mailbox", "unread", 2, sim_time_ms=1)
    state = world.capture_state()
    state["mutations"][1]["seq"] = 0
    state["mutations"][1]["mutation_id"] = state["mutations"][0]["mutation_id"]
    with pytest.raises(InvalidDomainStateError):
        WorldState.from_state(state)


def test_restore_rejects_mutation_seq_at_or_above_counter():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    state = world.capture_state()
    state["mutation_seq"]["next"] = 0
    with pytest.raises(InvalidDomainStateError):
        WorldState.from_state(state)


def test_restore_rejects_unknown_field():
    world = WorldState("s1")
    state = world.capture_state()
    state["bogus"] = 1
    with pytest.raises(InvalidDomainStateError):
        WorldState.from_state(state)


def test_restore_rejects_unknown_version():
    world = WorldState("s1")
    state = world.capture_state()
    state["version"] = 7
    with pytest.raises(InvalidDomainStateError):
        WorldState.from_state(state)


def test_restore_in_place_preserves_original_on_rejection():
    world = WorldState("s1")
    world.mutate("mailbox", "unread", 1, sim_time_ms=0)
    original_state = world.capture_state()
    bad_state = dict(original_state)
    bad_state["identity"] = "someone-else"
    with pytest.raises(IdentityMismatchError):
        world.restore_state(bad_state)
    assert world.capture_state() == original_state
