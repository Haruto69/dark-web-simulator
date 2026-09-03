"""The deterministic delayed-event scheduler.

Consequences that arrive later are the point of the product: credentials
submitted at T become an intrusion at T+20 minutes, and the learner has to
connect the two. This module owns the queue of things that have not happened
yet.

It runs entirely in simulation time. No threads, no async, no timers, no
sleeping, no wall clock. Nothing fires because a real second passed -- events
fire because the session advanced simulation time past their fire point. That
is what keeps a session a pure function of ``(seed, action sequence)``: a
learner's coffee break must not change the event stream.

The ordering contract
---------------------
Pending entries are totally ordered by::

    (fire_at_ms, priority, insertion_seq)

and by nothing else. Lower priority values fire first. ``insertion_seq`` is
unique per scheduler, so the key is a *total* order -- there is never a tie for
the comparison to fall through on. That matters more than it looks: dictionary
order, heap sift accidents, id string comparison and object identity are all
things that can order a queue *consistently within one process* while differing
across a restore. The key above cannot.

What the scheduler stores
-------------------------
Pending entries only, and no callables. A scheduled entry holds an
:class:`~rewindsec.core.events.EventSpec` -- plain validated data, defined with
the event model because that is what it describes -- because a stored callable
cannot be serialised, cannot be checkpointed and cannot be replayed. The
session materialises the actual :class:`~rewindsec.core.events.Event` at fire
time, when the sequence number and simulation time are known.

The scheduler is deliberately *not* the audit log. See :meth:`EventScheduler.cancel`.
"""

import hashlib
import heapq
import json

from rewindsec.core.events import EventSpec
from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms

__all__ = [
    "EventScheduler",
    "EventSpec",
    "ScheduledEntry",
    "SchedulerError",
    "InvalidSchedulerIdentityError",
    "InvalidScheduleRequestError",
    "InvalidSchedulerStateError",
    "ScheduleNotFoundError",
    "AlreadyCancelledError",
    "derive_schedule_id",
    "dumps_state",
    "SCHEDULE_ID_LENGTH",
    "STATE_VERSION",
]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

#: Domain-separation label for schedule-id derivation. Distinct from the event
#: label, so a schedule id and an event id built from the same numbers are
#: different strings and cannot be confused for one another in a log.
_SCHEDULE_ID_LABEL = "rewindsec2/schedule-id/v1"

SCHEDULE_ID_LENGTH = 32

_MAX_IDENTITY_LENGTH = 128
_MAX_JSON_SAFE_INT = 2 ** 53 - 1
_MAX_REASON_LENGTH = 200

#: The insertion counter starts here for every scheduler, so two schedulers
#: built from the same identity produce the same ids for the same operations.
_INITIAL_INSERTION_SEQ = 0


class SchedulerError(Exception):
    """Base class for every failure raised by this module."""


class InvalidSchedulerIdentityError(SchedulerError, ValueError):
    """A scheduler identity cannot derive stable schedule ids."""


class InvalidScheduleRequestError(SchedulerError, ValueError):
    """A schedule request is malformed and was not accepted."""


class InvalidSchedulerStateError(SchedulerError, ValueError):
    """A serialised scheduler state is malformed, foreign or of an unknown version."""


class ScheduleNotFoundError(SchedulerError, KeyError):
    """No pending entry has the given schedule id."""

    def __str__(self):
        # KeyError's __str__ reprs its argument; this reads better in a log.
        return self.args[0] if self.args else ""


class AlreadyCancelledError(SchedulerError, ValueError):
    """The entry was already cancelled, and its first reason stands."""


# -- identity ----------------------------------------------------------------

def _validate_identity(value, what="scheduler identity"):
    """Return *value* if it derives stable ids, else raise.

    Same charset rule as event identities, and for the same reason: ``|`` is
    the derivation delimiter and must not be able to appear inside a field.
    """
    if not isinstance(value, str):
        raise InvalidSchedulerIdentityError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if not value:
        raise InvalidSchedulerIdentityError("%s must not be empty" % what)
    if len(value) > _MAX_IDENTITY_LENGTH:
        raise InvalidSchedulerIdentityError(
            "%s must be at most %d characters, got %d"
            % (what, _MAX_IDENTITY_LENGTH, len(value)))
    for char in value:
        if not char.isascii():
            raise InvalidSchedulerIdentityError(
                "%s must be ASCII: %r" % (what, value))
        if not (char.isalnum() or char in "-_.:"):
            raise InvalidSchedulerIdentityError(
                "%s may contain only [A-Za-z0-9_.:-]: %r" % (what, value))
    return value


def derive_schedule_id(scheduler_identity, insertion_seq):
    """Derive a schedule id from the scheduler identity and insertion sequence.

    Pure and stable across processes and hash seeds. Two schedulers with
    different identities never produce the same id for the same insertion
    sequence, which is what keeps concurrent sessions from colliding.
    """
    scheduler_identity = _validate_identity(scheduler_identity)
    insertion_seq = _validate_counter(insertion_seq, "insertion_seq")
    material = "%s|%s|%d" % (_SCHEDULE_ID_LABEL, scheduler_identity, insertion_seq)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:SCHEDULE_ID_LENGTH]


def _validate_fire_time(value, what):
    """Validate a simulation timestamp, reporting it as a schedule-request error.

    The rule lives in ``simtime`` so the clock, events and the scheduler cannot
    drift apart about what a valid instant is; only the error type is
    translated, so everything this module raises is a :class:`SchedulerError`.
    """
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidScheduleRequestError(str(exc)) from exc


def _validate_counter(value, what):
    if isinstance(value, bool):
        raise InvalidScheduleRequestError(
            "%s must be an int, not a bool; got %r" % (what, value))
    if not isinstance(value, int):
        raise InvalidScheduleRequestError(
            "%s must be an int, got %s" % (what, type(value).__name__))
    if value < 0:
        raise InvalidScheduleRequestError(
            "%s must not be negative, got %d" % (what, value))
    if value > _MAX_JSON_SAFE_INT:
        raise InvalidScheduleRequestError(
            "%s exceeds the JSON-safe bound %d: %d"
            % (what, _MAX_JSON_SAFE_INT, value))
    return value


def _validate_priority(value):
    """Lower fires first. Negative priorities are legal and mean "sooner"."""
    if isinstance(value, bool):
        raise InvalidScheduleRequestError(
            "priority must be an int, not a bool; got %r" % (value,))
    if not isinstance(value, int):
        raise InvalidScheduleRequestError(
            "priority must be an int, got %s" % type(value).__name__)
    if not -_MAX_JSON_SAFE_INT <= value <= _MAX_JSON_SAFE_INT:
        raise InvalidScheduleRequestError(
            "priority exceeds the JSON-safe range: %d" % value)
    return value


def _validate_reason(value):
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidScheduleRequestError(
            "cancellation reason must be a str or None, got %s"
            % type(value).__name__)
    if not value:
        raise InvalidScheduleRequestError(
            "cancellation reason must not be empty; pass None if there is none")
    if len(value) > _MAX_REASON_LENGTH:
        raise InvalidScheduleRequestError(
            "cancellation reason must be at most %d characters, got %d"
            % (_MAX_REASON_LENGTH, len(value)))
    return value


def _validate_schedule_id(value, what="schedule_id"):
    if not isinstance(value, str):
        raise InvalidScheduleRequestError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if len(value) != SCHEDULE_ID_LENGTH:
        raise InvalidScheduleRequestError(
            "%s must be %d characters, got %d"
            % (what, SCHEDULE_ID_LENGTH, len(value)))
    for char in value:
        if char not in "0123456789abcdef":
            raise InvalidScheduleRequestError(
                "%s must be lowercase hex: %r" % (what, value))
    return value


# -- the scheduled entry -----------------------------------------------------

class ScheduledEntry:
    """One pending (or cancelled-but-not-yet-swept) queue entry.

    Public because :meth:`EventScheduler.due` returns these and the caller has
    to read them. Its cancellation flag is mutated only through the scheduler,
    which is why the setter is private.
    """

    __slots__ = ("_schedule_id", "_fire_at_ms", "_priority", "_insertion_seq",
                 "_spec", "_cancelled", "_cancellation_reason")

    def __init__(self, schedule_id, fire_at_ms, priority, insertion_seq, spec,
                 cancelled=False, cancellation_reason=None):
        self._schedule_id = _validate_schedule_id(schedule_id)
        self._fire_at_ms = _validate_fire_time(fire_at_ms, "fire_at_ms")
        self._priority = _validate_priority(priority)
        self._insertion_seq = _validate_counter(insertion_seq, "insertion_seq")
        if not isinstance(spec, EventSpec):
            raise InvalidScheduleRequestError(
                "spec must be an EventSpec, got %s" % type(spec).__name__)
        self._spec = spec
        if not isinstance(cancelled, bool):
            raise InvalidScheduleRequestError(
                "cancelled must be a bool, got %s" % type(cancelled).__name__)
        self._cancelled = cancelled
        self._cancellation_reason = _validate_reason(cancellation_reason)
        if not cancelled and self._cancellation_reason is not None:
            raise InvalidScheduleRequestError(
                "a live entry must not carry a cancellation reason")

    @property
    def schedule_id(self):
        return self._schedule_id

    @property
    def fire_at_ms(self):
        return self._fire_at_ms

    @property
    def priority(self):
        return self._priority

    @property
    def insertion_seq(self):
        return self._insertion_seq

    @property
    def spec(self):
        return self._spec

    @property
    def cancelled(self):
        return self._cancelled

    @property
    def cancellation_reason(self):
        return self._cancellation_reason

    @property
    def order_key(self):
        """The complete tie-break contract, and the only ordering that applies."""
        return (self._fire_at_ms, self._priority, self._insertion_seq)

    def _cancel(self, reason):
        """Mark cancelled. Called only by the owning scheduler."""
        self._cancelled = True
        self._cancellation_reason = _validate_reason(reason)

    def __repr__(self):
        return ("ScheduledEntry(schedule_id=%r, fire_at_ms=%d, priority=%d, "
                "insertion_seq=%d, type=%r, cancelled=%s)"
                % (self._schedule_id, self._fire_at_ms, self._priority,
                   self._insertion_seq, self._spec.type, self._cancelled))

    def __eq__(self, other):
        if not isinstance(other, ScheduledEntry):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash((self._schedule_id, self._insertion_seq, self._cancelled))

    def to_state(self):
        return {
            "schedule_id": self._schedule_id,
            "fire_at_ms": self._fire_at_ms,
            "priority": self._priority,
            "insertion_seq": self._insertion_seq,
            "spec": self._spec.to_state(),
            "cancelled": self._cancelled,
            "cancellation_reason": self._cancellation_reason,
        }

    _STATE_KEYS = frozenset({"schedule_id", "fire_at_ms", "priority",
                             "insertion_seq", "spec", "cancelled",
                             "cancellation_reason"})

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidSchedulerStateError(
                "scheduled entry must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidSchedulerStateError(
                "scheduled entry is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidSchedulerStateError(
                "scheduled entry has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        try:
            return cls(schedule_id=state["schedule_id"],
                       fire_at_ms=state["fire_at_ms"],
                       priority=state["priority"],
                       insertion_seq=state["insertion_seq"],
                       spec=EventSpec.from_state(state["spec"]),
                       cancelled=state["cancelled"],
                       cancellation_reason=state["cancellation_reason"])
        except InvalidSchedulerStateError:
            raise
        except Exception as exc:
            raise InvalidSchedulerStateError("scheduled entry: %s" % exc) from exc


# -- the scheduler -----------------------------------------------------------

class EventScheduler:
    """The pending-event queue of one session.

    Holds pending entries only. Fired entries leave; the event log is the
    record that they fired. Cancelled entries stay until their fire time is
    swept past, then leave too -- see :meth:`cancel` for why that is the right
    boundary.
    """

    __slots__ = ("_identity", "_insertion_seq", "_entries", "_heap")

    def __init__(self, identity):
        self._identity = _validate_identity(identity)
        self._insertion_seq = _INITIAL_INSERTION_SEQ
        #: schedule_id -> ScheduledEntry. Authoritative membership.
        self._entries = {}
        #: (fire_at_ms, priority, insertion_seq, schedule_id) heap. The first
        #: three make a total order because insertion_seq is unique among
        #: pending entries, so the schedule_id is carried for lookup and is
        #: never actually reached by a comparison.
        self._heap = []

    @property
    def identity(self):
        return self._identity

    @property
    def insertion_seq(self):
        """The next insertion sequence this scheduler will hand out."""
        return self._insertion_seq

    @property
    def pending_count(self):
        """Pending entries, cancelled-but-unswept ones included."""
        return len(self._entries)

    def __repr__(self):
        return "EventScheduler(identity=%r, pending=%d, insertion_seq=%d)" % (
            self._identity, len(self._entries), self._insertion_seq)

    # -- scheduling ----------------------------------------------------------

    def schedule(self, spec, fire_at_ms, priority=0):
        """Queue *spec* to fire at *fire_at_ms* and return the entry.

        Every argument is validated **before** the insertion counter moves, so
        a rejected request leaves the scheduler byte-identical to what it was.
        That is what makes "the counter advanced" mean "an entry exists", which
        in turn is what makes schedule ids reproducible on replay: a validation
        error on one run and not another would otherwise shift every subsequent
        id.
        """
        if not isinstance(spec, EventSpec):
            raise InvalidScheduleRequestError(
                "spec must be an EventSpec, got %s" % type(spec).__name__)
        fire_at_ms = _validate_fire_time(fire_at_ms, "fire_at_ms")
        priority = _validate_priority(priority)

        insertion_seq = self._insertion_seq
        schedule_id = derive_schedule_id(self._identity, insertion_seq)
        if schedule_id in self._entries:
            # Unreachable while the counter is monotonic; asserted rather than
            # assumed, because a silent overwrite here would lose an event.
            raise InvalidScheduleRequestError(
                "schedule id collision at insertion_seq %d" % insertion_seq)

        entry = ScheduledEntry(schedule_id, fire_at_ms, priority,
                               insertion_seq, spec)
        self._entries[schedule_id] = entry
        heapq.heappush(self._heap, entry.order_key + (schedule_id,))
        self._insertion_seq = insertion_seq + 1
        return entry

    # -- cancellation --------------------------------------------------------

    def cancel(self, schedule_id, reason=None):
        """Cancel a pending entry and return it.

        Marks rather than removes. Removing from the middle of a heap means
        re-heapifying, and a re-heapified queue is ordered by whatever the sift
        happened to do -- consistent within a process, not necessarily across a
        restore. Marking touches no ordering at all, and the entry is skipped
        when it is popped.

        The scheduler is **not** the audit log. A cancelled entry keeps its
        reason only until its fire time is swept past, because keeping every
        cancelled entry forever would grow the checkpoint without bound and
        duplicate what the event log already holds. The durable record of *why*
        something did not happen is an internal event written by the caller at
        cancellation time; this reason field is for inspecting the live queue.

        Cancelling twice raises rather than silently replacing the first
        reason: the second cancellation has no cause, and quietly overwriting
        the reason would corrupt the explanation the debrief will show.
        """
        schedule_id = _validate_schedule_id(schedule_id)
        entry = self._entries.get(schedule_id)
        if entry is None:
            raise ScheduleNotFoundError(
                "no pending entry with schedule id %s" % schedule_id)
        if entry.cancelled:
            raise AlreadyCancelledError(
                "entry %s was already cancelled (reason: %r)"
                % (schedule_id, entry.cancellation_reason))
        entry._cancel(reason)
        return entry

    def is_cancelled(self, schedule_id):
        """Whether a known pending entry is cancelled."""
        schedule_id = _validate_schedule_id(schedule_id)
        entry = self._entries.get(schedule_id)
        if entry is None:
            raise ScheduleNotFoundError(
                "no pending entry with schedule id %s" % schedule_id)
        return entry.cancelled

    # -- inspection ----------------------------------------------------------

    def get(self, schedule_id):
        """Return a pending entry by id, or raise :class:`ScheduleNotFoundError`."""
        schedule_id = _validate_schedule_id(schedule_id)
        entry = self._entries.get(schedule_id)
        if entry is None:
            raise ScheduleNotFoundError(
                "no pending entry with schedule id %s" % schedule_id)
        return entry

    def peek_next(self):
        """The next entry that would fire, or ``None``. Mutates nothing.

        Scans rather than popping. Popping to look past cancelled entries at
        the head would make an inspection method mutate the queue, and a
        "read" that changes state is exactly the kind of thing that makes two
        supposedly identical runs diverge. The scan is O(pending), which for a
        session-sized queue is not worth trading correctness for.
        """
        best = None
        for entry in self._entries.values():
            if entry.cancelled:
                continue
            if best is None or entry.order_key < best.order_key:
                best = entry
        return best

    def pending(self):
        """Every pending entry in exact firing order, cancelled ones included."""
        return tuple(sorted(self._entries.values(), key=lambda e: e.order_key))

    # -- firing --------------------------------------------------------------

    def due(self, up_to_ms):
        """Remove and return every live entry with ``fire_at_ms <= up_to_ms``.

        Returned in exact total order. Cancelled entries in the swept window
        are removed and *not* returned -- they can never fire again, so keeping
        them would only grow the state. Entries after the window stay pending,
        untouched.
        """
        up_to_ms = _validate_fire_time(up_to_ms, "up_to_ms")
        fired = []
        while self._heap and self._heap[0][0] <= up_to_ms:
            fire_at_ms, priority, insertion_seq, schedule_id = heapq.heappop(self._heap)
            entry = self._entries.pop(schedule_id, None)
            if entry is None:
                # Unreachable: heap and entry table are updated together.
                raise InvalidSchedulerStateError(
                    "scheduler heap and entry table disagree about %s" % schedule_id)
            if entry.cancelled:
                continue
            fired.append(entry)
        return tuple(fired)

    # -- state ---------------------------------------------------------------

    def capture_state(self):
        """Return a canonical, JSON-safe snapshot of the whole queue.

        Pending entries are written in total order rather than in heap-array
        order. The heap's internal arrangement is an implementation detail that
        two semantically identical schedulers need not share, so serialising it
        raw would make equal queues produce unequal JSON -- and every digest
        built on top of it meaningless.
        """
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "insertion_seq": self._insertion_seq,
            "pending": [entry.to_state() for entry in self.pending()],
        }

    _STATE_KEYS = frozenset({"version", "identity", "insertion_seq", "pending"})

    def restore_state(self, state):
        """Restore this scheduler from a captured state.

        Atomic: everything is parsed and every invariant checked before a
        single attribute is assigned, so a rejected payload leaves the
        scheduler exactly as it was.

        The payload's identity must match this scheduler's. A mismatch means a
        session is restoring another session's queue, which would produce
        entries whose schedule ids cannot be re-derived -- a divergence with no
        visible cause.
        """
        identity, insertion_seq, entries, heap = self._parse_state(
            state, expected_identity=self._identity)
        self._identity = identity
        self._insertion_seq = insertion_seq
        self._entries = entries
        self._heap = heap

    @classmethod
    def from_state(cls, state):
        """Build a new scheduler from a captured state, identity included."""
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        _, insertion_seq, entries, heap = cls._parse_state(
            state, expected_identity=identity)
        instance._insertion_seq = insertion_seq
        instance._entries = entries
        instance._heap = heap
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidSchedulerStateError(
                "scheduler state must be an object, got %s" % type(state).__name__)
        missing = EventScheduler._STATE_KEYS - set(state)
        if missing:
            raise InvalidSchedulerStateError(
                "scheduler state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - EventScheduler._STATE_KEYS
        if unknown:
            raise InvalidSchedulerStateError(
                "scheduler state has unknown field(s) %s"
                % ", ".join(sorted(unknown)))

        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidSchedulerStateError("scheduler state version must be an int")
        if version != STATE_VERSION:
            raise InvalidSchedulerStateError(
                "unsupported scheduler state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return _validate_identity(state["identity"])
        except InvalidSchedulerIdentityError as exc:
            raise InvalidSchedulerStateError(
                "scheduler state identity: %s" % exc) from exc

    @staticmethod
    def _parse_state(state, expected_identity):
        identity = EventScheduler._identity_from_state(state)
        if identity != expected_identity:
            raise InvalidSchedulerStateError(
                "scheduler state belongs to identity %r, not %r"
                % (identity, expected_identity))

        try:
            insertion_seq = _validate_counter(state["insertion_seq"], "insertion_seq")
        except InvalidScheduleRequestError as exc:
            raise InvalidSchedulerStateError(
                "scheduler state insertion_seq: %s" % exc) from exc

        raw_pending = state["pending"]
        if not isinstance(raw_pending, list):
            raise InvalidSchedulerStateError(
                "scheduler state pending must be a list, got %s"
                % type(raw_pending).__name__)

        entries, heap, seen_insertions = {}, [], set()
        for raw in raw_pending:
            entry = ScheduledEntry.from_state(raw)

            # Every id must be re-derivable from the identity and the insertion
            # sequence. This catches a tampered, hand-edited or foreign entry
            # that would otherwise sit in the queue looking legitimate.
            expected_id = derive_schedule_id(identity, entry.insertion_seq)
            if entry.schedule_id != expected_id:
                raise InvalidSchedulerStateError(
                    "entry %s does not match its derived id %s for "
                    "insertion_seq %d" % (entry.schedule_id, expected_id,
                                          entry.insertion_seq))
            if entry.insertion_seq >= insertion_seq:
                raise InvalidSchedulerStateError(
                    "entry insertion_seq %d is not below the counter %d; an "
                    "entry cannot have been inserted after the counter reached "
                    "its current value"
                    % (entry.insertion_seq, insertion_seq))
            if entry.insertion_seq in seen_insertions:
                raise InvalidSchedulerStateError(
                    "duplicate insertion_seq %d; the ordering key would not be "
                    "a total order" % entry.insertion_seq)
            if entry.schedule_id in entries:
                raise InvalidSchedulerStateError(
                    "duplicate schedule id %s" % entry.schedule_id)

            seen_insertions.add(entry.insertion_seq)
            entries[entry.schedule_id] = entry
            heap.append(entry.order_key + (entry.schedule_id,))

        heapq.heapify(heap)
        return identity, insertion_seq, entries, heap


def dumps_state(state):
    """Serialise a captured scheduler state to canonical JSON."""
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
