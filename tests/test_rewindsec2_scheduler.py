"""The deterministic delayed-event scheduler.

The queue decides *when* consequences arrive, so any nondeterminism in it
reappears as a counterfactual replay that diverges for a reason unrelated to
the learner's decision. These tests pin the ordering contract, the insertion
counter, cancellation, and exact restore.
"""

import json
import os
import pathlib
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rewindsec.core.events import (EventError, EventSource, EventSpec,
                                   EventVisibility, derive_event_id)
from rewindsec.core.scheduler import (SCHEDULE_ID_LENGTH, STATE_VERSION,
                                      AlreadyCancelledError, EventScheduler,
                                      InvalidScheduleRequestError,
                                      InvalidSchedulerIdentityError,
                                      InvalidSchedulerStateError,
                                      ScheduledEntry, ScheduleNotFoundError,
                                      SchedulerError, derive_schedule_id,
                                      dumps_state)

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

IDENTITY = "sess-scheduler-0001"


def spec(name="mail.delivered", **overrides):
    """A valid spec, tagged so tests can tell entries apart."""
    fields = dict(type=name, payload={"tag": name})
    fields.update(overrides)
    return EventSpec(**fields)


def tags(entries):
    """The payload tags of a sequence of entries, in the order given."""
    return [entry.spec.payload["tag"] for entry in entries]


@pytest.fixture
def scheduler():
    return EventScheduler(IDENTITY)


# -- the ordering contract ---------------------------------------------------

def test_earlier_fire_time_fires_first(scheduler):
    scheduler.schedule(spec("mail.late"), 9000)
    scheduler.schedule(spec("mail.early"), 1000)
    assert tags(scheduler.due(10000)) == ["mail.early", "mail.late"]


def test_priority_breaks_a_fire_time_tie(scheduler):
    """Lower priority values fire first."""
    scheduler.schedule(spec("mail.normal"), 5000, priority=0)
    scheduler.schedule(spec("mail.urgent"), 5000, priority=-10)
    scheduler.schedule(spec("mail.lazy"), 5000, priority=10)
    assert tags(scheduler.due(5000)) == ["mail.urgent", "mail.normal", "mail.lazy"]


def test_insertion_sequence_breaks_a_time_and_priority_tie(scheduler):
    for index in range(5):
        scheduler.schedule(spec("mail.n%d" % index), 5000, priority=3)
    assert tags(scheduler.due(5000)) == ["mail.n%d" % n for n in range(5)]


def test_the_order_key_is_exactly_the_documented_triple(scheduler):
    entry = scheduler.schedule(spec(), 4200, priority=-2)
    assert entry.order_key == (4200, -2, 0)


def test_equivalent_operations_in_a_different_call_order_still_order_the_same():
    """Two schedulers fed the same (time, priority) set in different call orders.

    Insertion order is a real input -- it is the documented final tie-break --
    so the assertion is not that call order is irrelevant. It is that
    ``(fire_at_ms, priority)`` dominates it: every entry whose key differs
    orders identically regardless of when it was scheduled, and only exact
    (time, priority) duplicates fall through to insertion order.
    """
    plan = [(5000, 0, "a"), (1000, 0, "b"), (5000, -1, "c"),
            (9000, 5, "d"), (1000, -3, "e"), (5000, 0, "f")]

    forward = EventScheduler(IDENTITY)
    for fire_at, priority, tag in plan:
        forward.schedule(spec("mail.%s" % tag), fire_at, priority)

    # Same entries, scheduled in an order that keeps duplicates' relative
    # order (a before f) but moves everything else around.
    shuffled_plan = [(9000, 5, "d"), (1000, -3, "e"), (5000, 0, "a"),
                     (5000, -1, "c"), (1000, 0, "b"), (5000, 0, "f")]
    shuffled = EventScheduler(IDENTITY)
    for fire_at, priority, tag in shuffled_plan:
        shuffled.schedule(spec("mail.%s" % tag), fire_at, priority)

    assert tags(forward.due(10000)) == ["mail.e", "mail.b", "mail.c",
                                        "mail.a", "mail.f", "mail.d"]
    assert tags(shuffled.due(10000)) == ["mail.e", "mail.b", "mail.c",
                                         "mail.a", "mail.f", "mail.d"]


def test_pending_reports_exact_firing_order_without_firing(scheduler):
    scheduler.schedule(spec("mail.c"), 5000)
    scheduler.schedule(spec("mail.a"), 1000)
    scheduler.schedule(spec("mail.b"), 3000)
    assert tags(scheduler.pending()) == ["mail.a", "mail.b", "mail.c"]
    assert scheduler.pending_count == 3


# -- the insertion counter ---------------------------------------------------

def test_insertion_counter_starts_deterministically_and_increments_by_one():
    scheduler = EventScheduler(IDENTITY)
    assert scheduler.insertion_seq == 0
    for expected in range(4):
        entry = scheduler.schedule(spec(), 1000)
        assert entry.insertion_seq == expected
    assert scheduler.insertion_seq == 4


@pytest.mark.parametrize("bad_call", [
    lambda s: s.schedule(spec(), -1),
    lambda s: s.schedule(spec(), 1.5),
    lambda s: s.schedule(spec(), True),
    lambda s: s.schedule(spec(), "1000"),
    lambda s: s.schedule(spec(), 1000, priority=1.5),
    lambda s: s.schedule(spec(), 1000, priority=True),
    lambda s: s.schedule(spec(), 1000, priority="high"),
    lambda s: s.schedule("not a spec", 1000),
    lambda s: s.schedule(None, 1000),
])
def test_a_rejected_schedule_does_not_advance_the_counter(bad_call, scheduler):
    """Otherwise a validation error on one run shifts every later schedule id."""
    scheduler.schedule(spec(), 1000)
    before = scheduler.insertion_seq
    before_state = dumps_state(scheduler.capture_state())

    with pytest.raises(SchedulerError):
        bad_call(scheduler)

    assert scheduler.insertion_seq == before
    assert dumps_state(scheduler.capture_state()) == before_state


def test_cancellation_does_not_renumber_the_counter(scheduler):
    first = scheduler.schedule(spec("mail.a"), 1000)
    scheduler.schedule(spec("mail.b"), 2000)
    scheduler.cancel(first.schedule_id, "no longer relevant")

    third = scheduler.schedule(spec("mail.c"), 3000)
    assert third.insertion_seq == 2
    assert scheduler.insertion_seq == 3


def test_firing_does_not_rewind_the_counter(scheduler):
    scheduler.schedule(spec(), 1000)
    scheduler.schedule(spec(), 2000)
    scheduler.due(5000)
    assert scheduler.insertion_seq == 2
    assert scheduler.schedule(spec(), 6000).insertion_seq == 2


# -- schedule identity -------------------------------------------------------

def test_schedule_ids_are_deterministic():
    first = EventScheduler(IDENTITY)
    second = EventScheduler(IDENTITY)
    for _ in range(3):
        first.schedule(spec(), 1000)
        second.schedule(spec(), 1000)
    assert ([e.schedule_id for e in first.pending()]
            == [e.schedule_id for e in second.pending()])


def test_schedule_id_matches_the_derivation_helper(scheduler):
    entry = scheduler.schedule(spec(), 1000)
    assert entry.schedule_id == derive_schedule_id(IDENTITY, 0)
    assert len(entry.schedule_id) == SCHEDULE_ID_LENGTH == 32
    assert set(entry.schedule_id) <= set("0123456789abcdef")


def test_independent_identities_do_not_collide_at_the_same_insertion_seq():
    """Concurrent sessions must never share a schedule id."""
    ids = {derive_schedule_id("sess-%04d" % n, 0) for n in range(200)}
    assert len(ids) == 200
    assert derive_schedule_id("sess-a", 7) != derive_schedule_id("sess-b", 7)


def test_schedule_ids_and_event_ids_are_different_namespaces():
    """Distinct domain labels, so the two can never be confused in a log."""
    assert derive_schedule_id("sess-a", 3) != derive_event_id("sess-a", 3)


@pytest.mark.parametrize("identity", [
    "", None, 5, "has space", "has|pipe", "unicodé", "x" * 129,
])
def test_invalid_scheduler_identity_is_rejected(identity):
    with pytest.raises(InvalidSchedulerIdentityError):
        EventScheduler(identity)


# -- cancellation ------------------------------------------------------------

def test_a_cancelled_entry_never_fires(scheduler):
    doomed = scheduler.schedule(spec("mail.doomed"), 1000)
    scheduler.schedule(spec("mail.survivor"), 1000)
    scheduler.cancel(doomed.schedule_id, "endpoint isolated")

    fired = scheduler.due(5000)
    assert tags(fired) == ["mail.survivor"]
    assert scheduler.pending_count == 0


def test_cancellation_records_its_reason(scheduler):
    entry = scheduler.schedule(spec(), 5000)
    returned = scheduler.cancel(entry.schedule_id, "endpoint isolated at T+4m")
    assert returned is entry
    assert entry.cancelled is True
    assert entry.cancellation_reason == "endpoint isolated at T+4m"
    assert scheduler.is_cancelled(entry.schedule_id) is True


def test_cancellation_reason_may_be_omitted(scheduler):
    entry = scheduler.schedule(spec(), 5000)
    scheduler.cancel(entry.schedule_id)
    assert entry.cancelled is True
    assert entry.cancellation_reason is None


def test_cancelling_an_unknown_id_raises_clearly(scheduler):
    with pytest.raises(ScheduleNotFoundError) as info:
        scheduler.cancel(derive_schedule_id(IDENTITY, 99), "nothing there")
    assert "no pending entry" in str(info.value)


def test_cancelling_a_fired_entry_raises_because_it_is_gone(scheduler):
    entry = scheduler.schedule(spec(), 1000)
    scheduler.due(1000)
    with pytest.raises(ScheduleNotFoundError):
        scheduler.cancel(entry.schedule_id, "too late")


def test_double_cancellation_raises_and_keeps_the_first_reason(scheduler):
    """The second cancellation has no cause; overwriting would corrupt the debrief."""
    entry = scheduler.schedule(spec(), 5000)
    scheduler.cancel(entry.schedule_id, "first reason")

    with pytest.raises(AlreadyCancelledError):
        scheduler.cancel(entry.schedule_id, "second reason")
    assert entry.cancellation_reason == "first reason"


@pytest.mark.parametrize("bad_id", ["short", "Z" * 32, None, 5, ""])
def test_cancelling_a_malformed_id_is_rejected(scheduler, bad_id):
    with pytest.raises(SchedulerError):
        scheduler.cancel(bad_id)


def test_cancelled_entries_stay_inspectable_until_swept(scheduler):
    entry = scheduler.schedule(spec(), 9000)
    scheduler.cancel(entry.schedule_id, "superseded")
    assert scheduler.pending_count == 1
    assert scheduler.get(entry.schedule_id).cancellation_reason == "superseded"

    # Swept once its fire time passes: it can never fire again, and keeping it
    # would grow the checkpoint without bound.
    assert scheduler.due(9000) == ()
    assert scheduler.pending_count == 0
    with pytest.raises(ScheduleNotFoundError):
        scheduler.get(entry.schedule_id)


def test_cancellation_does_not_disturb_the_order_of_others(scheduler):
    scheduler.schedule(spec("mail.a"), 1000)
    doomed = scheduler.schedule(spec("mail.b"), 2000)
    scheduler.schedule(spec("mail.c"), 3000)
    scheduler.cancel(doomed.schedule_id, "cancelled")
    assert tags(scheduler.due(9000)) == ["mail.a", "mail.c"]


# -- firing semantics --------------------------------------------------------

def test_due_returns_only_entries_at_or_before_the_boundary(scheduler):
    scheduler.schedule(spec("mail.at"), 5000)
    scheduler.schedule(spec("mail.after"), 5001)
    assert tags(scheduler.due(5000)) == ["mail.at"]
    assert scheduler.pending_count == 1


def test_future_entries_remain_pending(scheduler):
    scheduler.schedule(spec("mail.now"), 1000)
    future = scheduler.schedule(spec("mail.later"), 8000)
    scheduler.due(1000)
    assert scheduler.pending_count == 1
    assert scheduler.get(future.schedule_id).spec.payload["tag"] == "mail.later"
    assert tags(scheduler.due(8000)) == ["mail.later"]


def test_due_removes_only_what_it_fired(scheduler):
    scheduler.schedule(spec("mail.a"), 1000)
    scheduler.schedule(spec("mail.b"), 2000)
    scheduler.schedule(spec("mail.c"), 3000)
    assert tags(scheduler.due(2000)) == ["mail.a", "mail.b"]
    assert tags(scheduler.pending()) == ["mail.c"]


def test_due_on_an_empty_queue_returns_empty(scheduler):
    assert scheduler.due(10 ** 6) == ()


def test_a_fired_entry_does_not_fire_twice(scheduler):
    scheduler.schedule(spec("mail.once"), 1000)
    assert len(scheduler.due(5000)) == 1
    assert scheduler.due(5000) == ()


@pytest.mark.parametrize("bad", [-1, 1.5, True, "5000", None])
def test_due_rejects_an_invalid_boundary(scheduler, bad):
    scheduler.schedule(spec(), 1000)
    with pytest.raises(SchedulerError):
        scheduler.due(bad)
    assert scheduler.pending_count == 1


def test_peek_next_does_not_mutate_the_scheduler(scheduler):
    scheduler.schedule(spec("mail.b"), 5000)
    scheduler.schedule(spec("mail.a"), 1000)
    before = dumps_state(scheduler.capture_state())

    for _ in range(3):
        assert scheduler.peek_next().spec.payload["tag"] == "mail.a"

    assert dumps_state(scheduler.capture_state()) == before
    assert scheduler.pending_count == 2


def test_peek_next_skips_cancelled_entries(scheduler):
    doomed = scheduler.schedule(spec("mail.doomed"), 1000)
    scheduler.schedule(spec("mail.next"), 5000)
    scheduler.cancel(doomed.schedule_id, "cancelled")
    assert scheduler.peek_next().spec.payload["tag"] == "mail.next"


def test_peek_next_is_none_when_nothing_can_fire(scheduler):
    assert scheduler.peek_next() is None
    entry = scheduler.schedule(spec(), 1000)
    scheduler.cancel(entry.schedule_id, "cancelled")
    assert scheduler.peek_next() is None


def test_peek_next_agrees_with_what_due_actually_fires(scheduler):
    scheduler.schedule(spec("mail.b"), 5000, priority=0)
    scheduler.schedule(spec("mail.a"), 5000, priority=-1)
    assert scheduler.peek_next().schedule_id == scheduler.due(5000)[0].schedule_id


# -- the spec ----------------------------------------------------------------

def test_a_spec_builds_the_event_it_describes():
    subject = spec("incident.opened", payload={"severity": "high"},
                   source=EventSource.CONSEQUENCE,
                   visibility=EventVisibility.INTERNAL,
                   prerequisites=["auth.credentials_exposed"])
    event = subject.build_event(derive_event_id("sess-x", 4), 4, 12000)

    assert event.type == "incident.opened"
    assert event.seq == 4
    assert event.sim_time_ms == 12000
    assert event.source is EventSource.CONSEQUENCE
    assert event.visibility is EventVisibility.INTERNAL
    assert event.to_state()["payload"] == {"severity": "high"}
    assert event.prerequisites == ("auth.credentials_exposed",)


def test_a_spec_holds_no_callable():
    """A stored callable cannot be serialised, checkpointed or replayed."""
    with pytest.raises(EventError):
        EventSpec("mail.delivered", payload={"on_fire": lambda: None})

    state = spec().to_state()
    for value in state.values():
        assert not callable(value)


def test_spec_payload_cannot_be_mutated_after_construction():
    payload = {"items": [1, 2]}
    subject = EventSpec("mail.delivered", payload=payload)
    payload["items"].append(3)
    assert subject.to_state()["payload"]["items"] == [1, 2]


def test_spec_rejects_a_learner_visible_threat_family_type():
    with pytest.raises(EventError):
        EventSpec("phishing.delivered",
                  visibility=EventVisibility.LEARNER_VISIBLE)


def test_the_spec_lives_with_the_event_model_it_describes():
    """It is an event minus identity and time, so it belongs to events.py.

    Re-exported from the scheduler because that is the only consumer, but the
    definition being in one place is what keeps the scheduler from reaching
    into the event model's private validators.
    """
    import rewindsec.core.events as events_module
    import rewindsec.core.scheduler as scheduler_module

    assert EventSpec.__module__ == "rewindsec.core.events"
    assert scheduler_module.EventSpec is events_module.EventSpec


# -- capture and restore -----------------------------------------------------

def test_state_round_trips_through_plain_json(scheduler):
    scheduler.schedule(spec("mail.a"), 1000)
    doomed = scheduler.schedule(spec("mail.b"), 2000, priority=-1)
    scheduler.schedule(spec("incident.opened",
                            visibility=EventVisibility.INTERNAL), 3000)
    scheduler.cancel(doomed.schedule_id, "endpoint isolated")

    captured = scheduler.capture_state()
    revived = json.loads(json.dumps(captured))
    assert revived == captured

    restored = EventScheduler.from_state(revived)
    assert dumps_state(restored.capture_state()) == dumps_state(captured)


def test_state_contains_only_json_primitives(scheduler):
    scheduler.schedule(spec("mail.a", payload={"n": [1, {"deep": None}]}), 1000)

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

    check(scheduler.capture_state())


def test_capture_is_stable_and_independent_of_scheduling_order():
    """Heap-array order is an implementation detail and must not leak into state."""
    plan = [(5000, 0), (1000, 0), (9000, -2)]
    first = EventScheduler(IDENTITY)
    for fire_at, priority in plan:
        first.schedule(spec("mail.t%d" % fire_at), fire_at, priority)

    second = EventScheduler(IDENTITY)
    for fire_at, priority in plan:
        second.schedule(spec("mail.t%d" % fire_at), fire_at, priority)

    assert dumps_state(first.capture_state()) == dumps_state(second.capture_state())
    assert dumps_state(first.capture_state()) == dumps_state(first.capture_state())


def test_pending_is_serialised_in_total_order(scheduler):
    scheduler.schedule(spec("mail.c"), 9000)
    scheduler.schedule(spec("mail.a"), 1000)
    scheduler.schedule(spec("mail.b"), 5000)
    order = [e["spec"]["payload"]["tag"]
             for e in scheduler.capture_state()["pending"]]
    assert order == ["mail.a", "mail.b", "mail.c"]


def test_cancellation_reason_survives_capture_and_restore(scheduler):
    entry = scheduler.schedule(spec(), 9000)
    scheduler.cancel(entry.schedule_id, "endpoint isolated at T+4m")

    restored = EventScheduler.from_state(
        json.loads(json.dumps(scheduler.capture_state())))
    revived = restored.get(entry.schedule_id)
    assert revived.cancelled is True
    assert revived.cancellation_reason == "endpoint isolated at T+4m"
    assert restored.due(9000) == ()


def test_restore_preserves_exact_future_firing_order(scheduler):
    for index, (fire_at, priority) in enumerate(
            [(5000, 0), (5000, -1), (5000, 0), (1000, 3), (9000, 0)]):
        scheduler.schedule(spec("mail.n%d" % index), fire_at, priority)

    captured = json.loads(json.dumps(scheduler.capture_state()))
    expected = tags(scheduler.due(10 ** 6))

    restored = EventScheduler.from_state(captured)
    assert tags(restored.due(10 ** 6)) == expected


def test_restore_preserves_the_counter_so_later_ids_continue(scheduler):
    scheduler.schedule(spec(), 1000)
    scheduler.schedule(spec(), 2000)
    captured = scheduler.capture_state()

    restored = EventScheduler.from_state(captured)
    assert restored.insertion_seq == 2
    assert restored.schedule(spec(), 3000).schedule_id == derive_schedule_id(IDENTITY, 2)


def test_restore_into_an_existing_scheduler_replaces_its_queue(scheduler):
    scheduler.schedule(spec("mail.keep"), 1000)
    captured = scheduler.capture_state()

    scheduler.schedule(spec("mail.later"), 2000)
    assert scheduler.pending_count == 2

    scheduler.restore_state(captured)
    assert tags(scheduler.pending()) == ["mail.keep"]
    assert scheduler.insertion_seq == 1


def test_restore_rejects_a_state_from_another_scheduler(scheduler):
    foreign = EventScheduler("sess-somebody-else")
    foreign.schedule(spec(), 1000)
    with pytest.raises(InvalidSchedulerStateError) as info:
        scheduler.restore_state(foreign.capture_state())
    assert "identity" in str(info.value)


def test_restore_rejects_an_entry_whose_id_is_not_re_derivable(scheduler):
    """Catches a hand-edited or foreign entry sitting in the queue."""
    scheduler.schedule(spec(), 1000)
    state = json.loads(json.dumps(scheduler.capture_state()))
    state["pending"][0]["schedule_id"] = derive_schedule_id(IDENTITY, 42)
    with pytest.raises(InvalidSchedulerStateError):
        EventScheduler(IDENTITY).restore_state(state)


def test_restore_rejects_an_entry_inserted_after_the_counter(scheduler):
    scheduler.schedule(spec(), 1000)
    state = json.loads(json.dumps(scheduler.capture_state()))
    state["insertion_seq"] = 0
    with pytest.raises(InvalidSchedulerStateError):
        EventScheduler(IDENTITY).restore_state(state)


def test_restore_rejects_duplicate_entries(scheduler):
    scheduler.schedule(spec(), 1000)
    state = json.loads(json.dumps(scheduler.capture_state()))
    state["pending"].append(dict(state["pending"][0]))
    with pytest.raises(InvalidSchedulerStateError):
        EventScheduler(IDENTITY).restore_state(state)


@pytest.mark.parametrize("mutate", [
    lambda s: "not a dict",
    lambda s: None,
    lambda s: {},
    lambda s: {k: v for k, v in s.items() if k != "pending"},
    lambda s: {k: v for k, v in s.items() if k != "insertion_seq"},
    lambda s: {k: v for k, v in s.items() if k != "identity"},
    lambda s: dict(s, version=STATE_VERSION + 1),
    lambda s: dict(s, version="1"),
    lambda s: dict(s, insertion_seq=-1),
    lambda s: dict(s, insertion_seq=1.5),
    lambda s: dict(s, identity="has space"),
    lambda s: dict(s, pending={}),
    lambda s: dict(s, pending=["not a dict"]),
    lambda s: dict(s, unexpected_field=1),
])
def test_malformed_state_is_rejected(mutate, scheduler):
    scheduler.schedule(spec(), 1000)
    good = json.loads(json.dumps(scheduler.capture_state()))
    with pytest.raises(InvalidSchedulerStateError):
        EventScheduler(IDENTITY).restore_state(mutate(good))


def test_unknown_state_version_is_rejected(scheduler):
    state = scheduler.capture_state()
    state["version"] = STATE_VERSION + 1
    with pytest.raises(InvalidSchedulerStateError) as info:
        scheduler.restore_state(state)
    assert "version" in str(info.value)


@pytest.mark.parametrize("mutate", [
    lambda s: dict(s, insertion_seq=-1),
    lambda s: dict(s, pending=["not a dict"]),
    lambda s: dict(s, version=99),
    lambda s: {k: v for k, v in s.items() if k != "pending"},
])
def test_a_failed_restore_leaves_the_scheduler_untouched(mutate, scheduler):
    """Restoration is atomic."""
    scheduler.schedule(spec("mail.a"), 1000)
    scheduler.schedule(spec("mail.b"), 2000)
    before = dumps_state(scheduler.capture_state())
    good = json.loads(json.dumps(scheduler.capture_state()))

    with pytest.raises(InvalidSchedulerStateError):
        scheduler.restore_state(mutate(good))

    assert dumps_state(scheduler.capture_state()) == before
    assert tags(scheduler.due(10 ** 6)) == ["mail.a", "mail.b"]


def test_entry_state_rejects_a_live_entry_carrying_a_cancellation_reason():
    with pytest.raises(SchedulerError):
        ScheduledEntry(derive_schedule_id(IDENTITY, 0), 1000, 0, 0, spec(),
                       cancelled=False, cancellation_reason="contradiction")


# -- no wall-clock dependency ------------------------------------------------

def test_nothing_fires_without_an_explicit_time_advance(scheduler):
    """A learner's coffee break must not change the event stream."""
    scheduler.schedule(spec("mail.later"), 60 * 60 * 1000)
    for _ in range(50):
        assert scheduler.due(0) == ()
    assert scheduler.pending_count == 1


def test_the_scheduler_module_imports_no_clock():
    """Backs up the AST guardrail with a direct reading of the module."""
    import rewindsec.core.scheduler as module

    source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
    for banned in ("import time", "import datetime", "time.time",
                   "datetime.now", "perf_counter", "sleep("):
        assert banned not in source, banned


# -- property-style determinism stress --------------------------------------

def _stress_plan():
    """A fixed, deliberately collision-heavy schedule plan.

    Generated from a small local linear congruential generator owned by this
    test, so the data is varied but the test carries no randomness of its own.
    Times and priorities repeat heavily on purpose: exact ties are where an
    ordering contract actually gets tested.
    """
    plan, state = [], 20260903
    for index in range(200):
        state = (state * 1103515245 + 12345) % (2 ** 31)
        fire_at = (state % 12) * 1000          # 12 distinct times, many ties
        priority = (state // 12) % 5 - 2       # 5 priorities, -2..2
        plan.append((fire_at, priority, "mail.item_%d" % index))
    return plan


def test_capture_fire_restore_fire_reproduces_byte_identical_results():
    """The full determinism loop, over a queue dense with exact ties."""
    plan = _stress_plan()

    def build():
        scheduler = EventScheduler(IDENTITY)
        for fire_at, priority, tag in plan:
            scheduler.schedule(spec(tag), fire_at, priority)
        return scheduler

    original = build()
    captured = json.loads(json.dumps(original.capture_state()))

    # Fire part of the queue, then the rest, recording both batches.
    first_batch = dumps_state([e.to_state() for e in original.due(5000)])
    second_batch = dumps_state([e.to_state() for e in original.due(11000)])

    restored = EventScheduler.from_state(captured)
    assert dumps_state(restored.capture_state()) == dumps_state(captured)
    assert dumps_state([e.to_state() for e in restored.due(5000)]) == first_batch
    assert dumps_state([e.to_state() for e in restored.due(11000)]) == second_batch

    # And a scheduler built from scratch agrees with both.
    rebuilt = build()
    assert dumps_state([e.to_state() for e in rebuilt.due(5000)]) == first_batch
    assert dumps_state([e.to_state() for e in rebuilt.due(11000)]) == second_batch

    assert original.pending_count == 0
    assert restored.pending_count == 0


def test_stress_plan_actually_contains_heavy_ties():
    """Guards the stress test: a plan without ties would prove nothing."""
    plan = _stress_plan()
    keys = [(fire_at, priority) for fire_at, priority, _ in plan]
    assert len(plan) == 200
    assert len(set(keys)) < 70, "the plan must repeat (time, priority) heavily"


def test_cancellation_inside_the_stress_loop_survives_restore():
    plan = _stress_plan()[:60]
    scheduler = EventScheduler(IDENTITY)
    entries = [scheduler.schedule(spec(tag), fire_at, priority)
               for fire_at, priority, tag in plan]

    for index in range(0, len(entries), 4):
        scheduler.cancel(entries[index].schedule_id, "cancelled-%d" % index)

    captured = json.loads(json.dumps(scheduler.capture_state()))
    expected = dumps_state([e.to_state() for e in scheduler.due(11000)])

    restored = EventScheduler.from_state(captured)
    assert dumps_state([e.to_state() for e in restored.due(11000)]) == expected

    fired_tags = set(json.loads(expected)[i]["spec"]["payload"]["tag"]
                     for i in range(len(json.loads(expected))))
    for index in range(0, len(entries), 4):
        assert plan[index][2] not in fired_tags


# -- cross-process determinism -----------------------------------------------

_SUBPROCESS_SCRIPT = """
import json, sys
sys.path.insert(0, %(root)r)
from rewindsec.core.scheduler import EventScheduler, EventSpec, dumps_state

plan, state = [], 20260903
for index in range(120):
    state = (state * 1103515245 + 12345) %% (2 ** 31)
    plan.append(((state %% 12) * 1000, (state // 12) %% 5 - 2, index))

scheduler = EventScheduler("sess-cross-process")
entries = []
for fire_at, priority, index in plan:
    entries.append(scheduler.schedule(
        EventSpec("mail.delivered", payload={"index": index}), fire_at, priority))
for position in range(0, len(entries), 7):
    scheduler.cancel(entries[position].schedule_id, "cancelled-%%d" %% position)

captured = scheduler.capture_state()
fired = [e.to_state() for e in scheduler.due(6000)]
print(json.dumps({"captured": dumps_state(captured),
                  "fired": dumps_state(fired),
                  "remaining": dumps_state(scheduler.capture_state())},
                 sort_keys=True))
"""


def _run_subprocess(hash_seed):
    env = dict(os.environ)
    env["PYTHONHASHSEED"] = hash_seed
    completed = subprocess.run(
        [sys.executable, "-c", _SUBPROCESS_SCRIPT % {"root": str(REPO_ROOT)}],
        capture_output=True, text=True, env=env, cwd=str(REPO_ROOT), timeout=120)
    assert completed.returncode == 0, completed.stderr
    return completed.stdout.strip()


def test_scheduler_output_is_stable_across_processes_and_hash_seeds():
    """Catches reliance on hash(), dict order or any process-global state."""
    first = _run_subprocess("0")
    second = _run_subprocess("12345")
    assert first == second

    parsed = json.loads(first)
    assert json.loads(parsed["fired"]), "the fixture must actually fire something"


def test_subprocess_scheduler_matches_the_in_process_scheduler():
    plan, state = [], 20260903
    for index in range(120):
        state = (state * 1103515245 + 12345) % (2 ** 31)
        plan.append(((state % 12) * 1000, (state // 12) % 5 - 2, index))

    scheduler = EventScheduler("sess-cross-process")
    entries = []
    for fire_at, priority, index in plan:
        entries.append(scheduler.schedule(
            EventSpec("mail.delivered", payload={"index": index}), fire_at, priority))
    for position in range(0, len(entries), 7):
        scheduler.cancel(entries[position].schedule_id, "cancelled-%d" % position)

    captured = scheduler.capture_state()
    fired = [e.to_state() for e in scheduler.due(6000)]
    expected = {"captured": dumps_state(captured),
                "fired": dumps_state(fired),
                "remaining": dumps_state(scheduler.capture_state())}

    assert json.loads(_run_subprocess("7")) == expected
