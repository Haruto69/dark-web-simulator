"""Deterministic simulation time.

Simulation time is the only clock the RewindSec 2.0 core knows about. It is an
integer count of milliseconds since the start of a session, it starts at zero,
and it moves only when something in the simulation explicitly advances it --
never because a real second passed.

Why not wall-clock time
-----------------------
A learner's coffee break must not change the simulation. If a delayed
consequence fired because 20 real minutes elapsed, two runs of the same seed
and the same action script would produce different event streams, and a
counterfactual replay could not be compared against the factual run at all.
Tying every schedule to simulation time makes the whole session a pure
function of ``(seed, action sequence)``.

Wall-clock timestamps are not banned from the project -- they are genuinely
useful for diagnostics and telemetry. They are banned from *deterministic
state*, which is what this package holds. ``tests/test_rewindsec2_core_
boundaries.py`` enforces that by refusing ``time`` and ``datetime`` imports
anywhere under ``rewindsec/core/``.

Representation
--------------
One representation, deliberately: a plain ``int`` of milliseconds. A parallel
``SimInstant`` value type was considered and rejected for now -- two
representations of the same quantity is exactly the kind of drift that makes a
checkpoint restore half-consistent, and the unit confusion it would guard
against is better handled by the named duration constants below plus strict
argument validation. Introduce one later only when a concrete caller shows it
prevents a real bug.

The scheduler is deliberately *not* here. This module owns the clock and
nothing else.
"""

import json

__all__ = [
    "SimClock",
    "SimTimeError",
    "InvalidDurationError",
    "InvalidSimTimeError",
    "InvalidClockStateError",
    "dumps_state",
    "HOUR_MS",
    "MAX_SIM_TIME_MS",
    "MINUTE_MS",
    "SECOND_MS",
    "STATE_VERSION",
]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

SECOND_MS = 1000
MINUTE_MS = 60 * SECOND_MS
HOUR_MS = 60 * MINUTE_MS

#: Simulation time must round-trip through JSON exactly, and 2**53-1 is the
#: largest integer every reasonable JSON consumer preserves. It is also about
#: 285,000 years of milliseconds, so it constrains nothing real while still
#: catching a unit-confusion bug (microseconds or nanoseconds passed by
#: mistake) before it silently becomes part of a digest.
MAX_SIM_TIME_MS = 2 ** 53 - 1


class SimTimeError(Exception):
    """Base class for every failure raised by this module."""


class InvalidDurationError(SimTimeError, ValueError):
    """A duration is not a non-negative whole number of milliseconds."""


class InvalidSimTimeError(SimTimeError, ValueError):
    """A simulation timestamp is not a valid point on the clock."""


class InvalidClockStateError(SimTimeError, ValueError):
    """A captured-state payload is malformed or unrestorable."""


def _validate_sim_time(value, what="simulation time"):
    """Return *value* if it is a valid simulation timestamp, else raise."""
    if isinstance(value, bool):
        raise InvalidSimTimeError(
            "%s must be an int, not a bool; got %r" % (what, value))
    if not isinstance(value, int):
        raise InvalidSimTimeError(
            "%s must be an int number of milliseconds, got %s"
            % (what, type(value).__name__))
    if value < 0:
        raise InvalidSimTimeError("%s must not be negative, got %d" % (what, value))
    if value > MAX_SIM_TIME_MS:
        raise InvalidSimTimeError(
            "%s exceeds the JSON-safe bound %d: %d" % (what, MAX_SIM_TIME_MS, value))
    return value


def _validate_duration(value):
    """Return *value* if it is a valid advance duration, else raise.

    Floats are rejected rather than rounded. ``advance(1.5)`` has no correct
    answer, and rounding it would put a value into simulation state that
    depends on the caller's arithmetic rather than on the simulation --
    including NaN and infinity, which are not orderable and would corrupt the
    scheduler that will sit on top of this clock.
    """
    if isinstance(value, bool):
        raise InvalidDurationError(
            "duration must be an int, not a bool; got %r" % (value,))
    if not isinstance(value, int):
        raise InvalidDurationError(
            "duration must be an int number of milliseconds, got %s"
            % type(value).__name__)
    if value < 0:
        raise InvalidDurationError(
            "duration must not be negative; simulation time never runs "
            "backwards during play. Got %d" % value)
    if value > MAX_SIM_TIME_MS:
        raise InvalidDurationError(
            "duration exceeds the JSON-safe bound %d: %d"
            % (MAX_SIM_TIME_MS, value))
    return value


class SimClock:
    """The simulation clock of one session.

    Monotonic during play: :meth:`advance` only ever moves forward, and there
    is no setter that moves it back. The single way time goes backwards is
    :meth:`restore_state` with ``allow_rewind=True``, which is what a
    checkpoint restore does -- and it has to say so explicitly, so a stray
    restore cannot silently un-advance the clock.
    """

    __slots__ = ("_now_ms",)

    def __init__(self, start_ms=0):
        self._now_ms = _validate_sim_time(start_ms, "start time")

    @property
    def now_ms(self):
        """The current simulation time, in milliseconds since session start."""
        return self._now_ms

    def __repr__(self):
        return "SimClock(now_ms=%d)" % self._now_ms

    def __eq__(self, other):
        if not isinstance(other, SimClock):
            return NotImplemented
        return self._now_ms == other._now_ms

    def __hash__(self):
        return hash((SimClock, self._now_ms))

    # -- movement ------------------------------------------------------------

    def advance(self, duration_ms):
        """Move the clock forward by *duration_ms* and return the new time.

        A zero advance is legal and is a no-op: several actions in a row may
        legitimately occur at the same simulation instant, and the scheduler
        breaks such ties on an explicit insertion sequence rather than by
        demanding that every action cost time.
        """
        duration_ms = _validate_duration(duration_ms)
        target = self._now_ms + duration_ms
        if target > MAX_SIM_TIME_MS:
            raise InvalidDurationError(
                "advancing by %d would exceed the JSON-safe bound %d"
                % (duration_ms, MAX_SIM_TIME_MS))
        self._now_ms = target
        return self._now_ms

    def advance_to(self, target_ms):
        """Move the clock forward *to* an absolute simulation time.

        Convenience for the scheduler, which thinks in absolute fire times.
        Refuses a target in the past for the same reason :meth:`advance`
        refuses a negative duration.
        """
        target_ms = _validate_sim_time(target_ms, "target time")
        if target_ms < self._now_ms:
            raise InvalidSimTimeError(
                "cannot advance to %d: the clock is already at %d"
                % (target_ms, self._now_ms))
        self._now_ms = target_ms
        return self._now_ms

    # -- state ---------------------------------------------------------------

    def capture_state(self):
        """Return a canonical, JSON-safe snapshot of the clock."""
        return {"version": STATE_VERSION, "now_ms": self._now_ms}

    def restore_state(self, state, allow_rewind=False):
        """Restore the clock from a captured state.

        By default this refuses to move the clock backwards, so an accidental
        restore of a stale payload fails loudly instead of quietly rewinding a
        live session. A checkpoint restore -- the one legitimate way simulation
        time goes backwards -- passes ``allow_rewind=True``, which makes the
        rewind path greppable and reviewable rather than implicit.

        Validation happens before assignment, so a rejected payload leaves the
        clock exactly where it was.
        """
        now_ms = self._now_ms_from_state(state)
        if not allow_rewind and now_ms < self._now_ms:
            raise InvalidClockStateError(
                "refusing to restore simulation time backwards from %d to %d; "
                "pass allow_rewind=True if this is a checkpoint restore"
                % (self._now_ms, now_ms))
        self._now_ms = now_ms

    @classmethod
    def from_state(cls, state):
        """Build a new clock from a captured state.

        Used when a session is loaded from persistence and there is no existing
        clock to restore into, so no rewind question arises.
        """
        return cls(cls._now_ms_from_state(state))

    @staticmethod
    def _now_ms_from_state(state):
        if not isinstance(state, dict):
            raise InvalidClockStateError(
                "clock state must be an object, got %s" % type(state).__name__)
        missing = {"version", "now_ms"} - set(state)
        if missing:
            raise InvalidClockStateError(
                "clock state is missing %s" % ", ".join(sorted(missing)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidClockStateError("clock state version must be an int")
        if version != STATE_VERSION:
            raise InvalidClockStateError(
                "unsupported clock state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return _validate_sim_time(state["now_ms"], "clock state now_ms")
        except InvalidSimTimeError as exc:
            raise InvalidClockStateError(str(exc)) from exc


def dumps_state(state):
    """Serialise a captured clock state to canonical JSON."""
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
