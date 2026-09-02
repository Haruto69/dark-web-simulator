"""Deterministic simulation time.

The clock has one job: make a session a pure function of its seed and its
action sequence. Every rejection tested here is a value that, if accepted,
would put an unrepeatable or unorderable number into deterministic state.
"""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rewindsec.core.simtime import (HOUR_MS, MAX_SIM_TIME_MS, MINUTE_MS,
                                    SECOND_MS, STATE_VERSION,
                                    InvalidClockStateError,
                                    InvalidDurationError, InvalidSimTimeError,
                                    SimClock, dumps_state)


# -- starting state ----------------------------------------------------------

def test_clock_starts_at_zero():
    assert SimClock().now_ms == 0


def test_clock_can_start_at_an_explicit_time():
    assert SimClock(5000).now_ms == 5000


@pytest.mark.parametrize("start", [-1, 1.5, True, "0", None, MAX_SIM_TIME_MS + 1])
def test_invalid_start_times_are_rejected(start):
    with pytest.raises(InvalidSimTimeError):
        SimClock(start)


def test_unit_constants_are_consistent():
    assert SECOND_MS == 1000
    assert MINUTE_MS == 60 * SECOND_MS
    assert HOUR_MS == 60 * MINUTE_MS


# -- advancing ---------------------------------------------------------------

def test_advance_moves_forward_and_returns_the_new_time():
    clock = SimClock()
    assert clock.advance(250) == 250
    assert clock.advance(750) == 1000
    assert clock.now_ms == 1000


def test_zero_advance_is_legal_and_is_a_no_op():
    """Several actions may legitimately occur at the same simulation instant."""
    clock = SimClock(400)
    assert clock.advance(0) == 400
    assert clock.now_ms == 400


@pytest.mark.parametrize("duration", [-1, -1000, -MAX_SIM_TIME_MS])
def test_negative_advance_is_rejected(duration):
    clock = SimClock(1000)
    with pytest.raises(InvalidDurationError):
        clock.advance(duration)
    assert clock.now_ms == 1000, "a rejected advance must not move the clock"


@pytest.mark.parametrize("duration", [1.0, 1.5, 0.0, float("nan"), float("inf")])
def test_float_advance_is_rejected(duration):
    """Floats are refused rather than rounded.

    ``advance(1.5)`` has no correct answer, and NaN/infinity are not orderable
    at all -- they would corrupt the scheduler that will sit on this clock.
    """
    with pytest.raises(InvalidDurationError):
        SimClock().advance(duration)


@pytest.mark.parametrize("duration", [True, False])
def test_bool_advance_is_rejected_despite_being_an_int(duration):
    with pytest.raises(InvalidDurationError):
        SimClock().advance(duration)


@pytest.mark.parametrize("duration", ["100", None, [100], {"ms": 1}, b"100"])
def test_non_numeric_advance_is_rejected(duration):
    with pytest.raises(InvalidDurationError):
        SimClock().advance(duration)


def test_advance_beyond_the_json_safe_bound_is_rejected():
    """Simulation time must round-trip through JSON exactly."""
    clock = SimClock(MAX_SIM_TIME_MS - 10)
    with pytest.raises(InvalidDurationError):
        clock.advance(11)
    assert clock.now_ms == MAX_SIM_TIME_MS - 10
    assert clock.advance(10) == MAX_SIM_TIME_MS


def test_clock_has_no_public_way_to_move_backwards():
    """Monotonicity during play is structural, not merely a convention."""
    clock = SimClock(1000)
    public = {name for name in dir(clock) if not name.startswith("_")}
    assert public == {"now_ms", "advance", "advance_to",
                      "capture_state", "restore_state", "from_state"}
    with pytest.raises(AttributeError):
        clock.now_ms = 0


# -- advance_to --------------------------------------------------------------

def test_advance_to_moves_to_an_absolute_time():
    clock = SimClock(100)
    assert clock.advance_to(900) == 900


def test_advance_to_the_current_time_is_a_no_op():
    clock = SimClock(100)
    assert clock.advance_to(100) == 100


def test_advance_to_the_past_is_rejected():
    clock = SimClock(1000)
    with pytest.raises(InvalidSimTimeError):
        clock.advance_to(999)
    assert clock.now_ms == 1000


@pytest.mark.parametrize("target", [-1, 1.5, True, "1000", None])
def test_invalid_advance_to_targets_are_rejected(target):
    with pytest.raises(InvalidSimTimeError):
        SimClock(0).advance_to(target)


# -- capture and restore -----------------------------------------------------

def test_capture_and_restore_round_trip():
    clock = SimClock()
    clock.advance(12345)
    captured = clock.capture_state()

    clock.advance(999)
    assert clock.now_ms == 13344

    clock.restore_state(captured, allow_rewind=True)
    assert clock.now_ms == 12345


def test_capture_does_not_move_the_clock():
    clock = SimClock(42)
    for _ in range(3):
        clock.capture_state()
    assert clock.now_ms == 42


def test_restore_refuses_to_move_backwards_by_default():
    """A stale payload must fail loudly rather than quietly rewind a live session."""
    clock = SimClock()
    early = clock.capture_state()
    clock.advance(5000)

    with pytest.raises(InvalidClockStateError) as info:
        clock.restore_state(early)
    assert "allow_rewind" in str(info.value)
    assert clock.now_ms == 5000, "a rejected restore must not move the clock"


def test_restore_moves_backwards_only_when_the_caller_says_so():
    """The one legitimate rewind path is explicit, and therefore greppable."""
    clock = SimClock()
    early = clock.capture_state()
    clock.advance(5000)
    clock.restore_state(early, allow_rewind=True)
    assert clock.now_ms == 0


def test_restore_forward_is_allowed_without_the_rewind_flag():
    clock = SimClock()
    clock.advance(9000)
    later = clock.capture_state()
    clock.restore_state(later)
    assert clock.now_ms == 9000

    fresh = SimClock()
    fresh.restore_state(later)
    assert fresh.now_ms == 9000


def test_from_state_builds_a_new_clock():
    clock = SimClock()
    clock.advance(777)
    rebuilt = SimClock.from_state(clock.capture_state())
    assert rebuilt.now_ms == 777
    assert rebuilt == clock


def test_clocks_compare_by_time():
    assert SimClock(10) == SimClock(10)
    assert SimClock(10) != SimClock(11)
    assert SimClock(10) != 10
    assert len({SimClock(10), SimClock(10), SimClock(11)}) == 2


# -- serialization -----------------------------------------------------------

def test_state_round_trips_through_plain_json():
    clock = SimClock()
    clock.advance(3 * HOUR_MS + 15 * MINUTE_MS)
    captured = clock.capture_state()
    revived = json.loads(json.dumps(captured))
    assert revived == captured
    assert SimClock.from_state(revived).now_ms == clock.now_ms


def test_captured_state_contains_only_json_primitives():
    state = SimClock(123).capture_state()
    assert set(state) == {"version", "now_ms"}
    assert isinstance(state["now_ms"], int)
    assert not isinstance(state["now_ms"], bool)
    assert state["version"] == STATE_VERSION


def test_canonical_dump_is_stable():
    clock = SimClock(500)
    assert dumps_state(clock.capture_state()) == '{"now_ms":500,"version":1}'


# -- malformed state ---------------------------------------------------------

@pytest.mark.parametrize("state", [
    "not a dict",
    None,
    [],
    {},
    {"now_ms": 100},
    {"version": 1},
    {"version": 2, "now_ms": 100},
    {"version": "1", "now_ms": 100},
    {"version": True, "now_ms": 100},
    {"version": 1, "now_ms": -1},
    {"version": 1, "now_ms": 1.5},
    {"version": 1, "now_ms": True},
    {"version": 1, "now_ms": "100"},
    {"version": 1, "now_ms": None},
    {"version": 1, "now_ms": MAX_SIM_TIME_MS + 1},
])
def test_malformed_state_is_rejected(state):
    with pytest.raises(InvalidClockStateError):
        SimClock().restore_state(state)
    with pytest.raises(InvalidClockStateError):
        SimClock.from_state(state)


def test_failed_restore_leaves_the_clock_untouched():
    clock = SimClock()
    clock.advance(2500)
    with pytest.raises(InvalidClockStateError):
        clock.restore_state({"version": 1, "now_ms": -5})
    assert clock.now_ms == 2500
