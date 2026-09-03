"""The canonical simulation event model.

The event log is the authoritative history of a session: a replay re-fires
recorded events rather than regenerating them. These tests defend the two
properties that makes possible -- deterministic identity, and an event that
cannot be changed after it is recorded.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rewindsec.core.events import (EVENT_ID_LENGTH, STATE_VERSION, Event,
                                   EventSource, EventVisibility,
                                   InvalidEventFieldError,
                                   InvalidEventIdentityError,
                                   InvalidEventStateError,
                                   InvalidPayloadError, canonical_json,
                                   derive_event_id, validate_event_type)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent


def make_event(**overrides):
    """A valid event, with fields overridable per test."""
    fields = dict(session_identity="sess-0001", seq=0, type="mail.delivered",
                  sim_time_ms=1000)
    fields.update(overrides)
    return Event.create(**fields)


# -- deterministic identity --------------------------------------------------

def test_same_identity_and_seq_give_the_same_event_id():
    assert derive_event_id("sess-abc", 7) == derive_event_id("sess-abc", 7)


def test_different_seq_gives_a_different_event_id():
    assert derive_event_id("sess-abc", 7) != derive_event_id("sess-abc", 8)


def test_different_session_identity_gives_a_different_event_id():
    assert derive_event_id("sess-abc", 7) != derive_event_id("sess-abd", 7)


def test_event_id_shape_is_stable_and_log_friendly():
    event_id = derive_event_id("sess-abc", 0)
    assert len(event_id) == EVENT_ID_LENGTH == 32
    assert set(event_id) <= set("0123456789abcdef")


def test_identity_and_seq_cannot_be_confused_for_one_another():
    """Delimiters rule out concatenation collisions in the derivation material."""
    assert derive_event_id("sess-1", 23) != derive_event_id("sess-12", 3)
    assert derive_event_id("sess", 12) != derive_event_id("sess-1", 2)


def test_create_derives_the_id_the_same_way_as_the_helper():
    event = make_event(seq=3)
    assert event.event_id == derive_event_id("sess-0001", 3)


@pytest.mark.parametrize("seq", [-1, True, False, 1.0, 1.5, "3", None])
def test_invalid_seq_is_rejected(seq):
    with pytest.raises(InvalidEventIdentityError):
        derive_event_id("sess-abc", seq)


@pytest.mark.parametrize("identity", [
    "", None, 5, b"sess", "has space", "has|pipe", "unicodé", "x" * 129,
])
def test_invalid_session_identity_is_rejected(identity):
    with pytest.raises(InvalidEventIdentityError):
        derive_event_id(identity, 0)


def test_pipe_is_rejected_because_it_is_the_derivation_delimiter():
    with pytest.raises(InvalidEventIdentityError):
        derive_event_id("sess|1", 0)


# -- event type --------------------------------------------------------------

@pytest.mark.parametrize("event_type", [
    "mail.delivered", "mail.opened", "auth.credential_submitted",
    "incident.opened", "file.impacted", "browser.tab.opened",
    "a.b.c.d", "mail.thread_2.replied",
])
def test_well_formed_event_types_are_accepted(event_type):
    assert validate_event_type(event_type) == event_type


@pytest.mark.parametrize("event_type", [
    "", "delivered", "Mail.Delivered", "mail.", ".delivered", "mail..delivered",
    "mail delivered", "mail-delivered", "9mail.delivered", "_mail.delivered",
    "a.b.c.d.e", "mail.delivéred", None, 5, "x" * 97,
])
def test_malformed_event_types_are_rejected(event_type):
    with pytest.raises(InvalidEventFieldError):
        validate_event_type(event_type)


@pytest.mark.parametrize("event_type", [
    "phishing.delivered", "ransomware.started", "malware.executed",
    "bec.received", "scam.detected", "attack.began",
])
def test_learner_visible_types_may_not_name_a_threat_family(event_type):
    """The learner must discriminate; the system must not label the answer."""
    with pytest.raises(InvalidEventFieldError) as info:
        validate_event_type(event_type, EventVisibility.LEARNER_VISIBLE)
    assert "threat family" in str(info.value)

    with pytest.raises(InvalidEventFieldError):
        make_event(type=event_type, visibility=EventVisibility.LEARNER_VISIBLE)


def test_internal_events_may_name_a_threat_family():
    """An internal assessment record is exactly where a classification belongs."""
    event = make_event(type="phishing.classified",
                       visibility=EventVisibility.INTERNAL)
    assert event.type == "phishing.classified"
    assert event.is_learner_visible is False


# -- simulation time ---------------------------------------------------------

@pytest.mark.parametrize("sim_time_ms", [-1, 1.5, 1.0, True, "1000", None])
def test_invalid_sim_time_is_rejected(sim_time_ms):
    """Rejected as an event field error, not as the neighbour module's type.

    The rule itself lives in ``simtime`` so there is one definition of a valid
    instant, but a caller of the event model should only ever have to catch
    ``EventError``.
    """
    with pytest.raises(InvalidEventFieldError):
        make_event(sim_time_ms=sim_time_ms)


def test_every_event_failure_is_an_event_error():
    """One base class covers the whole surface, neighbours' rules included."""
    from rewindsec.core.events import EventError

    for build in (lambda: make_event(sim_time_ms=-1),
                  lambda: make_event(seq=-1),
                  lambda: make_event(type="bad"),
                  lambda: make_event(payload={"x": {1}}),
                  lambda: make_event(source="nobody"),
                  lambda: make_event(causes=["nope"])):
        with pytest.raises(EventError):
            build()


def test_zero_sim_time_is_valid():
    assert make_event(sim_time_ms=0).sim_time_ms == 0


def test_event_state_contains_no_wall_clock_field():
    """Deterministic event state is simulation time only."""
    state = make_event().to_state()
    for field in state:
        assert "wall" not in field
        assert field not in {"timestamp", "created_at", "recorded_at", "utc"}
    assert "sim_time_ms" in state


# -- payload -----------------------------------------------------------------

def test_payload_accepts_the_json_primitives():
    payload = {"str": "x", "int": 1, "float": 1.5, "bool": True, "null": None,
               "list": [1, "two", None], "nested": {"a": {"b": [1, 2]}}}
    event = make_event(payload=payload)
    assert event.to_state()["payload"] == payload


def test_payload_defaults_to_empty():
    assert make_event().to_state()["payload"] == {}


@pytest.mark.parametrize("payload", [
    {"bad": {1, 2}},
    {"bad": frozenset()},
    {"bad": lambda: None},
    {"bad": object()},
    {"bad": b"bytes"},
    {"bad": complex(1, 2)},
    {"bad": Event},
    {1: "int key"},
    {None: "none key"},
    {"nested": {"deeper": [{"bad": {1}}]}},
])
def test_non_json_payloads_are_rejected(payload):
    with pytest.raises(InvalidPayloadError):
        make_event(payload=payload)


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_are_rejected(value):
    with pytest.raises(InvalidPayloadError):
        make_event(payload={"x": value})
    with pytest.raises(InvalidPayloadError):
        make_event(payload={"nested": [{"x": value}]})


def test_tuple_payload_values_are_rejected():
    """A tuple returns from JSON as a list, so the event would not round-trip."""
    with pytest.raises(InvalidPayloadError) as info:
        make_event(payload={"items": (1, 2)})
    assert "list" in str(info.value)


def test_excessively_nested_payloads_are_rejected():
    deep = current = {}
    for _ in range(30):
        current["next"] = {}
        current = current["next"]
    with pytest.raises(InvalidPayloadError):
        make_event(payload=deep)


def test_mutating_the_original_payload_cannot_change_the_event():
    """A log a caller can edit after the fact is not a record of anything."""
    payload = {"to": "ops@northgate.lab", "items": [1, 2]}
    event = make_event(payload=payload)
    before = event.to_state()["payload"]

    payload["to"] = "attacker@elsewhere.lab"
    payload["items"].append(3)
    payload["new_key"] = "injected"

    assert event.to_state()["payload"] == before
    assert event.to_state()["payload"]["to"] == "ops@northgate.lab"
    assert event.to_state()["payload"]["items"] == [1, 2]
    assert "new_key" not in event.to_state()["payload"]


def test_the_exposed_payload_cannot_be_mutated_either():
    event = make_event(payload={"a": 1, "items": [1, 2], "nested": {"b": 2}})
    with pytest.raises(TypeError):
        event.payload["a"] = 99
    with pytest.raises(TypeError):
        event.payload["nested"]["b"] = 99
    with pytest.raises(AttributeError):
        event.payload["items"].append(3)


def test_mutating_a_state_copy_cannot_change_the_event():
    """to_state() hands out a copy, not a view of the event's own data."""
    event = make_event(payload={"items": [1, 2]})
    state = event.to_state()
    state["payload"]["items"].append(3)
    assert event.to_state()["payload"]["items"] == [1, 2]


# -- source and visibility ---------------------------------------------------

@pytest.mark.parametrize("source", list(EventSource))
def test_every_source_round_trips(source):
    event = make_event(source=source)
    assert event.source is source
    assert Event.from_state(event.to_state()).source is source


@pytest.mark.parametrize("visibility", list(EventVisibility))
def test_every_visibility_round_trips(visibility):
    event = make_event(type="incident.opened", visibility=visibility)
    assert event.visibility is visibility
    assert Event.from_state(event.to_state()).visibility is visibility


def test_source_and_visibility_accept_their_serialised_strings():
    event = make_event(source="learner", visibility="internal")
    assert event.source is EventSource.LEARNER
    assert event.visibility is EventVisibility.INTERNAL


@pytest.mark.parametrize("bad", ["World", "unknown", "", 5, None])
def test_unknown_source_is_rejected(bad):
    with pytest.raises(InvalidEventFieldError):
        make_event(source=bad)


@pytest.mark.parametrize("bad", ["visible", "hidden", "", 5, None])
def test_unknown_visibility_is_rejected(bad):
    with pytest.raises(InvalidEventFieldError):
        make_event(visibility=bad)


# -- causes and prerequisites ------------------------------------------------

def test_causes_preserve_order():
    parents = [derive_event_id("sess-0001", n) for n in (5, 1, 9)]
    event = make_event(seq=10, causes=parents)
    assert list(event.causes) == parents
    assert event.to_state()["causes"] == parents
    assert list(Event.from_state(event.to_state()).causes) == parents


def test_causes_ordering_is_semantically_significant():
    """Two events differing only in cause order are different events."""
    a, b = derive_event_id("s", 1), derive_event_id("s", 2)
    assert make_event(causes=[a, b]) != make_event(causes=[b, a])


def test_prerequisites_preserve_order():
    prerequisites = ["auth.credentials_exposed", "context.payroll_contact_known",
                     "incident.endpoint_not_isolated"]
    event = make_event(prerequisites=prerequisites)
    assert list(event.prerequisites) == prerequisites
    assert Event.from_state(event.to_state()).to_state()["prerequisites"] == prerequisites


def test_causes_and_prerequisites_default_to_empty():
    event = make_event()
    assert event.causes == ()
    assert event.prerequisites == ()


def test_duplicate_causes_are_rejected():
    parent = derive_event_id("sess-0001", 1)
    with pytest.raises(InvalidEventFieldError):
        make_event(causes=[parent, parent])


def test_duplicate_prerequisites_are_rejected():
    with pytest.raises(InvalidEventFieldError):
        make_event(prerequisites=["auth.exposed", "auth.exposed"])


def test_causes_must_be_event_ids():
    with pytest.raises(InvalidEventFieldError):
        make_event(causes=["not-an-event-id"])


def test_a_bare_string_is_not_a_sequence_of_causes():
    """Without this, a single id would silently become 32 one-character causes."""
    with pytest.raises(InvalidEventFieldError):
        make_event(causes=derive_event_id("sess-0001", 1))


def test_prerequisites_use_the_dotted_identifier_shape():
    with pytest.raises(InvalidEventFieldError):
        make_event(prerequisites=["not dotted"])


def test_prerequisites_may_name_a_threat_family():
    """They are internal predicates, never rendered to the learner."""
    event = make_event(prerequisites=["phishing.link_clicked"])
    assert event.prerequisites == ("phishing.link_clicked",)


# -- serialization -----------------------------------------------------------

def test_state_round_trips_through_plain_json():
    event = make_event(seq=4, type="auth.credential_submitted", sim_time_ms=90000,
                       payload={"account": "j.reyes@northgate.lab", "attempts": [1]},
                       source=EventSource.LEARNER,
                       visibility=EventVisibility.INTERNAL,
                       causes=[derive_event_id("sess-0001", 2)],
                       prerequisites=["auth.credentials_exposed"])
    revived = Event.from_state(json.loads(json.dumps(event.to_state())))
    assert revived == event
    assert revived.to_state() == event.to_state()


def test_equality_is_stable_after_a_round_trip():
    event = make_event(payload={"b": 2, "a": 1})
    assert Event.from_state(event.to_state()) == event
    assert hash(Event.from_state(event.to_state())) == hash(event)


def test_canonical_text_is_key_order_independent():
    """Two events built from differently ordered dicts are the same event."""
    first = make_event(payload={"a": 1, "b": 2})
    second = make_event(payload={"b": 2, "a": 1})
    assert first.canonical == second.canonical
    assert first == second


def test_state_contains_only_json_primitives():
    state = make_event(payload={"a": [1, {"b": None}]}).to_state()

    def check(node, path="state"):
        if isinstance(node, dict):
            for key, value in node.items():
                assert isinstance(key, str), path
                check(value, "%s.%s" % (path, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                check(value, "%s[%d]" % (path, index))
        else:
            assert node is None or isinstance(node, (str, int, float)), path

    check(state)


def test_state_declares_its_version():
    assert make_event().to_state()["version"] == STATE_VERSION


def test_events_differing_in_any_field_are_unequal():
    base = make_event()
    assert base != make_event(seq=1)
    assert base != make_event(type="mail.opened")
    assert base != make_event(sim_time_ms=2000)
    assert base != make_event(payload={"x": 1})
    assert base != make_event(source=EventSource.LEARNER)
    assert base != make_event(session_identity="sess-0002")
    assert base != "not an event"


@pytest.mark.parametrize("mutate", [
    lambda s: "not a dict",
    lambda s: None,
    lambda s: {},
    lambda s: {k: v for k, v in s.items() if k != "seq"},
    lambda s: {k: v for k, v in s.items() if k != "payload"},
    lambda s: dict(s, version=STATE_VERSION + 1),
    lambda s: dict(s, version="1"),
    lambda s: dict(s, event_id="short"),
    lambda s: dict(s, event_id="Z" * 32),
    lambda s: dict(s, seq=-1),
    lambda s: dict(s, type="Bad Type"),
    lambda s: dict(s, sim_time_ms=-1),
    lambda s: dict(s, source="nobody"),
    lambda s: dict(s, visibility="translucent"),
    lambda s: dict(s, causes=["nope"]),
    lambda s: dict(s, prerequisites=["not dotted"]),
    lambda s: dict(s, unexpected_field=1),
])
def test_malformed_state_is_rejected(mutate):
    good = json.loads(json.dumps(make_event().to_state()))
    with pytest.raises(InvalidEventStateError):
        Event.from_state(mutate(good))


def test_unknown_state_fields_are_rejected_rather_than_ignored():
    """A silently dropped field is a data-loss bug that surfaces much later."""
    good = make_event().to_state()
    with pytest.raises(InvalidEventStateError) as info:
        Event.from_state(dict(good, sim_time="oops"))
    assert "unknown" in str(info.value)


def test_canonical_json_rejects_non_finite_values():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


# -- immutability of the event itself ----------------------------------------

def test_event_attributes_cannot_be_reassigned():
    event = make_event()
    for attribute in ("event_id", "seq", "type", "sim_time_ms", "payload",
                      "source", "visibility", "causes", "prerequisites"):
        with pytest.raises(AttributeError):
            setattr(event, attribute, "tampered")


def test_event_rejects_stray_attributes():
    with pytest.raises(AttributeError):
        make_event().extra = "would never be serialised"


# -- cross-process determinism -----------------------------------------------

_SUBPROCESS_SCRIPT = """
import json, sys
sys.path.insert(0, %(root)r)
from rewindsec.core.events import Event, EventSource, EventVisibility, derive_event_id

out = {"ids": [derive_event_id("sess-cross-process", n) for n in range(6)],
       "events": []}
for seq in range(4):
    event = Event.create(
        session_identity="sess-cross-process", seq=seq,
        type="mail.delivered", sim_time_ms=seq * 1000,
        payload={"index": seq, "tags": ["a", "b"], "nested": {"k": seq / 4}},
        source=EventSource.SCHEDULER,
        visibility=EventVisibility.LEARNER_VISIBLE,
        causes=[derive_event_id("sess-cross-process", n) for n in range(seq)],
        prerequisites=["auth.credentials_exposed"])
    out["events"].append(event.canonical)
print(json.dumps(out, sort_keys=True))
"""


def _run_subprocess(hash_seed):
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = hash_seed
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_SCRIPT % {"root": str(REPO_ROOT)}],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT), timeout=120)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_event_identity_is_stable_across_processes_and_hash_seeds():
    """Catches any reliance on hash(), which CPython salts per process."""
    assert _run_subprocess("0") == _run_subprocess("12345")


def test_subprocess_events_match_the_in_process_events():
    """The other interpreter agrees with this one, not merely with itself."""
    expected = {"ids": [derive_event_id("sess-cross-process", n) for n in range(6)],
                "events": []}
    for seq in range(4):
        event = Event.create(
            session_identity="sess-cross-process", seq=seq,
            type="mail.delivered", sim_time_ms=seq * 1000,
            payload={"index": seq, "tags": ["a", "b"], "nested": {"k": seq / 4}},
            source=EventSource.SCHEDULER,
            visibility=EventVisibility.LEARNER_VISIBLE,
            causes=[derive_event_id("sess-cross-process", n) for n in range(seq)],
            prerequisites=["auth.credentials_exposed"])
        expected["events"].append(event.canonical)

    assert json.loads(_run_subprocess("7")) == expected
