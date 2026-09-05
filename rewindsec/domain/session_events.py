"""The authoritative session event log, and the scheduling audit trail.

Two distinct records live here, and Architecture Spec v1.1 S9 is explicit that
they must not collapse into one:

``SessionEventLog``
    The append-only record of events that actually happened -- fired,
    immediate, or system events. It reuses :func:`rewindsec.core.events
    .derive_event_id` directly, because the spec is explicit that event ids
    must continue to use the existing derivation and a second scheme must not
    be invented. This log owns the "event" sequence counter.

``ScheduleAuditLog``
    :class:`~rewindsec.core.scheduler.EventScheduler` sweeps cancelled entries
    out of its pending heap once their fire time passes, and never records
    fired entries at all -- it is a queue, not history. So restoring a session
    from the scheduler's own state alone cannot answer "what was scheduled,
    what fired, what was cancelled and why". This module is the durable answer
    to that question, independent of what the live scheduler still happens to
    be holding.
"""

from rewindsec.core.events import (Event, EventSource, EventVisibility,
                                   derive_event_id, validate_event_type)
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError, UnknownReferenceError)
from rewindsec.domain.identifiers import (derive_id, validate_bounded_str,
                                          validate_identity, validate_nonneg_int)
from rewindsec.domain.sequences import SequenceCounter

__all__ = [
    "SessionEventLog",
    "ScheduleAuditEntry",
    "ScheduleAuditLog",
    "derive_audit_id",
]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

#: Distinct from every other id label: an audit entry id built from the same
#: (identity, seq) pair as an event, action or world mutation must never
#: collide with any of them.
_AUDIT_ID_LABEL = "rewindsec2/schedule-audit-id/v1"

_MAX_REASON_LENGTH = 200

_AUDIT_STATUSES = frozenset({"pending", "fired", "cancelled"})


def derive_audit_id(session_identity, seq):
    return derive_id(_AUDIT_ID_LABEL, session_identity, seq)


# -- the event log -------------------------------------------------------------

class SessionEventLog:
    """The append-only, session-owned log of :class:`~rewindsec.core.events.Event`.

    Owns the event sequence counter. Every event appended here must have been
    built with ``seq`` equal to what this log's counter is about to hand out --
    enforced in :meth:`append` -- so the log and the counter can never disagree
    about how many events have happened.
    """

    __slots__ = ("_identity", "_seq", "_events")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "session event log identity")
        self._seq = SequenceCounter("event")
        self._events = []

    @property
    def identity(self):
        return self._identity

    @property
    def next_seq(self):
        return self._seq.peek()

    def __repr__(self):
        return "SessionEventLog(identity=%r, events=%d)" % (
            self._identity, len(self._events))

    def record(self, type, sim_time_ms, payload=None, source=EventSource.WORLD,
              visibility=EventVisibility.LEARNER_VISIBLE, causes=(),
              prerequisites=()):
        """Validate, allocate a sequence number, and append one event.

        Mirrors :meth:`~rewindsec.domain.actions.ActionLog.record`: the
        candidate event is built and fully validated against the *peeked*
        sequence number before the counter is advanced, so a rejected event
        (bad type, bad payload, unresolvable ``causes``) leaves the counter --
        and therefore every future event id -- untouched.
        """
        seq = self._seq.peek()
        event = Event.create(
            session_identity=self._identity, seq=seq, type=type,
            sim_time_ms=sim_time_ms, payload=payload, source=source,
            visibility=visibility, causes=causes, prerequisites=prerequisites)
        self._seq.advance()
        self._events.append(event)
        return event

    def append_fired(self, spec, sim_time_ms):
        """Materialise and append the event a scheduler entry's spec describes.

        Used when a :class:`~rewindsec.core.scheduler.EventScheduler` entry
        comes due: ``spec`` is that entry's own
        :class:`~rewindsec.core.events.EventSpec`, and this method allocates
        the next event sequence and id from this log's own counter and
        materialises the event via ``spec.build_event`` -- the mechanism the
        core already provides for exactly this, rather than re-freezing an
        already-frozen payload by hand. Kept distinct from :meth:`record`
        because a fired event's shape came from the scheduler's queued spec,
        not from a fresh call site.
        """
        seq = self._seq.peek()
        event_id = derive_event_id(self._identity, seq)
        event = spec.build_event(event_id=event_id, seq=seq, sim_time_ms=sim_time_ms)
        self._seq.advance()
        self._events.append(event)
        return event

    def get(self, event_id):
        for event in self._events:
            if event.event_id == event_id:
                return event
        raise UnknownReferenceError("no session event with id %r" % event_id)

    def has(self, event_id):
        try:
            self.get(event_id)
        except UnknownReferenceError:
            return False
        return True

    def events(self):
        """Every recorded event, in the order it was recorded."""
        return tuple(self._events)

    # -- state -------------------------------------------------------------

    def capture_state(self):
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "seq": self._seq.capture_state(),
            "events": [e.to_state() for e in self._events],
        }

    _STATE_KEYS = frozenset({"version", "identity", "seq", "events"})

    def restore_state(self, state):
        identity, seq, events = self._parse_state(state, expected_identity=self._identity)
        self._identity = identity
        self._seq = seq
        self._events = events

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        _, seq, events = cls._parse_state(state, expected_identity=identity)
        instance._seq = seq
        instance._events = events
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "session event log state must be an object, got %s"
                % type(state).__name__)
        missing = SessionEventLog._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "session event log state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - SessionEventLog._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "session event log state has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("session event log state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported session event log state version %r (this build "
                "writes %d)" % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "session event log identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "session event log state belongs to identity %r, not %r"
                % (identity, expected_identity))

        seq = SequenceCounter.from_state(state["seq"])

        raw_events = state["events"]
        if not isinstance(raw_events, list):
            raise InvalidDomainStateError(
                "session event log state events must be a list, got %s"
                % type(raw_events).__name__)

        events, seen_seq = [], set()
        for raw in raw_events:
            try:
                event = Event.from_state(raw)
            except Exception as exc:
                raise InvalidDomainStateError(
                    "session event log: %s" % exc) from exc
            expected_id = derive_event_id(identity, event.seq)
            if event.event_id != expected_id:
                raise InvalidDomainStateError(
                    "event %s does not match its derived id %s for seq %d"
                    % (event.event_id, expected_id, event.seq))
            if event.seq in seen_seq:
                raise InvalidDomainStateError("duplicate event seq %d" % event.seq)
            if event.seq >= seq.next_value:
                raise InvalidDomainStateError(
                    "event seq %d is not below the counter %d"
                    % (event.seq, seq.next_value))
            seen_seq.add(event.seq)
            events.append(event)
        events.sort(key=lambda e: e.seq)

        return identity, seq, events


# -- the scheduling audit trail -------------------------------------------------

class ScheduleAuditEntry:
    """One durable record of a scheduling decision and its eventual outcome.

    Independent of :class:`~rewindsec.core.scheduler.ScheduledEntry`: this
    object's ``status`` moves from ``"pending"`` to exactly one of ``"fired"``
    or ``"cancelled"`` and then never changes again, so it survives the
    scheduler sweeping the live entry out of its own heap.
    """

    __slots__ = ("_audit_id", "_seq", "_schedule_id", "_event_type",
                 "_scheduled_at_ms", "_fire_at_ms", "_priority",
                 "_scheduling_cause_event_id", "_status", "_fired_event_id",
                 "_resolved_at_ms", "_cancellation_reason")

    def __init__(self, audit_id, seq, schedule_id, event_type, scheduled_at_ms,
                 fire_at_ms, priority, scheduling_cause_event_id, status,
                 fired_event_id=None, resolved_at_ms=None,
                 cancellation_reason=None):
        self._audit_id = _validate_hex_id(audit_id, "audit_id")
        self._seq = validate_nonneg_int(seq, "seq")
        self._schedule_id = validate_bounded_str(schedule_id, "schedule_id", 64)
        self._event_type = validate_event_type(event_type)
        self._scheduled_at_ms = validate_nonneg_int(scheduled_at_ms, "scheduled_at_ms")
        self._fire_at_ms = validate_nonneg_int(fire_at_ms, "fire_at_ms")
        self._priority = self._validate_priority(priority)
        self._scheduling_cause_event_id = (
            None if scheduling_cause_event_id is None
            else validate_identity(scheduling_cause_event_id, "scheduling_cause_event_id"))

        if status not in _AUDIT_STATUSES:
            raise InvalidDomainStateError(
                "schedule audit status must be one of %s, got %r"
                % (sorted(_AUDIT_STATUSES), status))
        self._status = status

        self._fired_event_id = (
            None if fired_event_id is None
            else validate_identity(fired_event_id, "fired_event_id"))
        self._resolved_at_ms = (
            None if resolved_at_ms is None
            else validate_nonneg_int(resolved_at_ms, "resolved_at_ms"))
        self._cancellation_reason = (
            None if cancellation_reason is None
            else validate_bounded_str(cancellation_reason, "cancellation_reason",
                                      _MAX_REASON_LENGTH))

        if status == "pending":
            if self._fired_event_id is not None or self._resolved_at_ms is not None \
                    or self._cancellation_reason is not None:
                raise InvalidDomainStateError(
                    "a pending schedule audit entry must not carry resolution fields")
        elif status == "fired":
            if self._fired_event_id is None or self._resolved_at_ms is None:
                raise InvalidDomainStateError(
                    "a fired schedule audit entry must record fired_event_id "
                    "and resolved_at_ms")
            if self._cancellation_reason is not None:
                raise InvalidDomainStateError(
                    "a fired schedule audit entry must not carry a cancellation reason")
        else:  # cancelled
            if self._resolved_at_ms is None:
                raise InvalidDomainStateError(
                    "a cancelled schedule audit entry must record resolved_at_ms")
            if self._fired_event_id is not None:
                raise InvalidDomainStateError(
                    "a cancelled schedule audit entry must not record fired_event_id")

    @staticmethod
    def _validate_priority(value):
        if isinstance(value, bool) or not isinstance(value, int):
            raise InvalidDomainStateError("priority must be an int")
        return value

    # -- fields --------------------------------------------------------------

    @property
    def audit_id(self):
        return self._audit_id

    @property
    def seq(self):
        return self._seq

    @property
    def schedule_id(self):
        return self._schedule_id

    @property
    def event_type(self):
        return self._event_type

    @property
    def scheduled_at_ms(self):
        return self._scheduled_at_ms

    @property
    def fire_at_ms(self):
        return self._fire_at_ms

    @property
    def priority(self):
        return self._priority

    @property
    def scheduling_cause_event_id(self):
        return self._scheduling_cause_event_id

    @property
    def status(self):
        return self._status

    @property
    def is_pending(self):
        return self._status == "pending"

    @property
    def fired_event_id(self):
        return self._fired_event_id

    @property
    def resolved_at_ms(self):
        return self._resolved_at_ms

    @property
    def cancellation_reason(self):
        return self._cancellation_reason

    def _as_fired(self, fired_event_id, resolved_at_ms):
        return ScheduleAuditEntry(
            audit_id=self._audit_id, seq=self._seq, schedule_id=self._schedule_id,
            event_type=self._event_type, scheduled_at_ms=self._scheduled_at_ms,
            fire_at_ms=self._fire_at_ms, priority=self._priority,
            scheduling_cause_event_id=self._scheduling_cause_event_id,
            status="fired", fired_event_id=fired_event_id,
            resolved_at_ms=resolved_at_ms)

    def _as_cancelled(self, resolved_at_ms, reason):
        return ScheduleAuditEntry(
            audit_id=self._audit_id, seq=self._seq, schedule_id=self._schedule_id,
            event_type=self._event_type, scheduled_at_ms=self._scheduled_at_ms,
            fire_at_ms=self._fire_at_ms, priority=self._priority,
            scheduling_cause_event_id=self._scheduling_cause_event_id,
            status="cancelled", resolved_at_ms=resolved_at_ms,
            cancellation_reason=reason)

    def __repr__(self):
        return "ScheduleAuditEntry(audit_id=%r, schedule_id=%r, status=%r)" % (
            self._audit_id, self._schedule_id, self._status)

    def __eq__(self, other):
        if not isinstance(other, ScheduleAuditEntry):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash((self._audit_id, self._status))

    # -- state -------------------------------------------------------------

    def to_state(self):
        return {
            "audit_id": self._audit_id,
            "seq": self._seq,
            "schedule_id": self._schedule_id,
            "event_type": self._event_type,
            "scheduled_at_ms": self._scheduled_at_ms,
            "fire_at_ms": self._fire_at_ms,
            "priority": self._priority,
            "scheduling_cause_event_id": self._scheduling_cause_event_id,
            "status": self._status,
            "fired_event_id": self._fired_event_id,
            "resolved_at_ms": self._resolved_at_ms,
            "cancellation_reason": self._cancellation_reason,
        }

    _STATE_KEYS = frozenset({
        "audit_id", "seq", "schedule_id", "event_type", "scheduled_at_ms",
        "fire_at_ms", "priority", "scheduling_cause_event_id", "status",
        "fired_event_id", "resolved_at_ms", "cancellation_reason",
    })

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "schedule audit entry must be an object, got %s"
                % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "schedule audit entry is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "schedule audit entry has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        try:
            return cls(
                audit_id=state["audit_id"], seq=state["seq"],
                schedule_id=state["schedule_id"], event_type=state["event_type"],
                scheduled_at_ms=state["scheduled_at_ms"],
                fire_at_ms=state["fire_at_ms"], priority=state["priority"],
                scheduling_cause_event_id=state["scheduling_cause_event_id"],
                status=state["status"], fired_event_id=state["fired_event_id"],
                resolved_at_ms=state["resolved_at_ms"],
                cancellation_reason=state["cancellation_reason"])
        except InvalidDomainStateError:
            raise
        except DomainError as exc:
            raise InvalidDomainStateError("schedule audit entry: %s" % exc) from exc


def _validate_hex_id(value, what):
    if not isinstance(value, str):
        raise InvalidDomainStateError("%s must be a str, got %s" % (what, type(value).__name__))
    if len(value) != 32:
        raise InvalidDomainStateError("%s must be 32 characters, got %d" % (what, len(value)))
    for char in value:
        if char not in "0123456789abcdef":
            raise InvalidDomainStateError("%s must be lowercase hex: %r" % (what, value))
    return value


class ScheduleAuditLog:
    """The append-only, session-owned log of scheduling decisions.

    Owns its own sequence counter, independent of the event and action
    counters -- a scheduling decision is neither an event nor a learner
    action, and mixing its numbering with either would make "the Nth thing of
    this kind" ambiguous.
    """

    __slots__ = ("_identity", "_seq", "_entries")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "schedule audit log identity")
        self._seq = SequenceCounter("schedule_audit")
        self._entries = {}

    @property
    def identity(self):
        return self._identity

    def __repr__(self):
        return "ScheduleAuditLog(identity=%r, entries=%d)" % (
            self._identity, len(self._entries))

    def record_scheduled(self, schedule_id, event_type, scheduled_at_ms, fire_at_ms,
                         priority, scheduling_cause_event_id=None):
        """Record that ``schedule_id`` was newly queued. Returns the new entry."""
        seq = self._seq.peek()
        audit_id = derive_audit_id(self._identity, seq)
        entry = ScheduleAuditEntry(
            audit_id=audit_id, seq=seq, schedule_id=schedule_id,
            event_type=event_type, scheduled_at_ms=scheduled_at_ms,
            fire_at_ms=fire_at_ms, priority=priority,
            scheduling_cause_event_id=scheduling_cause_event_id, status="pending")
        self._seq.advance()
        self._entries[schedule_id] = entry
        return entry

    def record_fired(self, schedule_id, fired_event_id, resolved_at_ms):
        entry = self._get_pending(schedule_id)
        updated = entry._as_fired(fired_event_id, resolved_at_ms)
        self._entries[schedule_id] = updated
        return updated

    def record_cancelled(self, schedule_id, resolved_at_ms, reason=None):
        entry = self._get_pending(schedule_id)
        updated = entry._as_cancelled(resolved_at_ms, reason)
        self._entries[schedule_id] = updated
        return updated

    def _get_pending(self, schedule_id):
        entry = self._entries.get(schedule_id)
        if entry is None:
            raise UnknownReferenceError(
                "no schedule audit entry for schedule id %r" % schedule_id)
        if not entry.is_pending:
            raise InvalidDomainStateError(
                "schedule audit entry %r is already resolved as %r"
                % (schedule_id, entry.status))
        return entry

    def get(self, schedule_id):
        entry = self._entries.get(schedule_id)
        if entry is None:
            raise UnknownReferenceError(
                "no schedule audit entry for schedule id %r" % schedule_id)
        return entry

    def has(self, schedule_id):
        return schedule_id in self._entries

    def entries(self):
        """Every entry, ordered by ``seq`` (i.e. the order each was scheduled)."""
        return tuple(sorted(self._entries.values(), key=lambda e: e.seq))

    def pending_entries(self):
        return tuple(e for e in self.entries() if e.is_pending)

    # -- state -------------------------------------------------------------

    def capture_state(self):
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "seq": self._seq.capture_state(),
            "entries": [e.to_state() for e in self.entries()],
        }

    _STATE_KEYS = frozenset({"version", "identity", "seq", "entries"})

    def restore_state(self, state):
        identity, seq, entries = self._parse_state(state, expected_identity=self._identity)
        self._identity = identity
        self._seq = seq
        self._entries = entries

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        _, seq, entries = cls._parse_state(state, expected_identity=identity)
        instance._seq = seq
        instance._entries = entries
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "schedule audit log state must be an object, got %s"
                % type(state).__name__)
        missing = ScheduleAuditLog._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "schedule audit log state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - ScheduleAuditLog._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "schedule audit log state has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError(
                "schedule audit log state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported schedule audit log state version %r (this build "
                "writes %d)" % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "schedule audit log identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "schedule audit log state belongs to identity %r, not %r"
                % (identity, expected_identity))

        seq = SequenceCounter.from_state(state["seq"])

        raw_entries = state["entries"]
        if not isinstance(raw_entries, list):
            raise InvalidDomainStateError(
                "schedule audit log state entries must be a list, got %s"
                % type(raw_entries).__name__)

        entries, seen_seq, seen_schedule = {}, set(), set()
        for raw in raw_entries:
            entry = ScheduleAuditEntry.from_state(raw)
            expected_id = derive_audit_id(identity, entry.seq)
            if entry.audit_id != expected_id:
                raise InvalidDomainStateError(
                    "schedule audit entry %s does not match its derived id %s "
                    "for seq %d" % (entry.audit_id, expected_id, entry.seq))
            if entry.seq in seen_seq:
                raise InvalidDomainStateError(
                    "duplicate schedule audit seq %d" % entry.seq)
            if entry.schedule_id in seen_schedule:
                raise InvalidDomainStateError(
                    "duplicate schedule audit entry for schedule id %r"
                    % entry.schedule_id)
            if entry.seq >= seq.next_value:
                raise InvalidDomainStateError(
                    "schedule audit seq %d is not below the counter %d"
                    % (entry.seq, seq.next_value))
            seen_seq.add(entry.seq)
            seen_schedule.add(entry.schedule_id)
            entries[entry.schedule_id] = entry

        return identity, seq, entries
