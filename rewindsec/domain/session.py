"""``SimulationSession``: the storage-independent simulation aggregate root.

Everything else in :mod:`rewindsec.domain` is a part; this is the whole. It
composes the existing deterministic core (:class:`~rewindsec.core.rng
.SeededRandom`, :class:`~rewindsec.core.simtime.SimClock`,
:class:`~rewindsec.core.scheduler.EventScheduler`) with the domain objects
built for Batch 1 (:class:`~rewindsec.domain.world.WorldState`,
:class:`~rewindsec.domain.context_ledger.ContextLedger`,
:class:`~rewindsec.domain.session_events.SessionEventLog`,
:class:`~rewindsec.domain.session_events.ScheduleAuditLog`,
:class:`~rewindsec.domain.actions.ActionLog`,
:class:`~rewindsec.domain.incidents.IncidentGraph`), and is the only object
with visibility into all of them -- so it is also the only object responsible
for validating references *between* them (a consequence's ``cause_event_id``
really exists in the event log, an observation's ``action_id`` really exists
in the action log, and so on). Each sub-object still validates its own
self-contained invariants; this aggregate adds the cross-object ones.

No application content lives here. Which mail messages exist, what a
"suspicious link" looks like, how MFA prompts behave -- none of that is
Batch 1. This module provides the mechanism a later batch's engines will
call: advance time, schedule and fire events, record actions, mutate world
state, and record consequences, all through one deterministic, persistable
aggregate.
"""

from rewindsec.core.events import EventSource, EventVisibility
from rewindsec.core.rng import SeededRandom
from rewindsec.core.scheduler import EventScheduler, EventSpec
from rewindsec.core.simtime import SimClock
from rewindsec.domain.actions import ActionLog
from rewindsec.domain.context_ledger import ContextLedger
from rewindsec.domain.enums import Focus, Mode, SessionStatus, coerce_enum
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError, SessionNotActiveError,
                                     UnknownReferenceError)
from rewindsec.domain.identifiers import validate_identity, validate_nonneg_int
from rewindsec.domain.incidents import IncidentGraph
from rewindsec.domain.session_events import ScheduleAuditLog, SessionEventLog
from rewindsec.domain.world import WorldState

__all__ = ["SimulationSession"]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

_MAX_LEARNER_REF_LENGTH = 128


def _require_active(method):
    def wrapper(self, *args, **kwargs):
        if self._status is not SessionStatus.ACTIVE:
            raise SessionNotActiveError(
                "session %r is %s, not active" % (self._session_id, self._status.value))
        return method(self, *args, **kwargs)
    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    return wrapper


class SimulationSession:
    """The aggregate root of one deterministic simulation session.

    Construct with :meth:`create` for a brand-new session (allocates a fresh
    root seed's owner and every sub-object from scratch), or restore an
    existing one with :meth:`from_state`. Every mutating operation on an
    aggregate loaded from persistence behaves identically to one that had run
    continuously in memory, provided it is given the same root seed and the
    same sequence of calls -- that equivalence is what Batch 1's resume tests
    exist to demonstrate.
    """

    __slots__ = ("_session_id", "_learner_ref", "_focus", "_mode", "_status",
                 "_revision", "_rng", "_clock", "_scheduler", "_world",
                 "_ledger", "_event_log", "_schedule_audit", "_action_log",
                 "_incidents")

    def __init__(self, session_id, learner_ref, focus, mode, status, revision,
                 rng, clock, scheduler, world, ledger, event_log,
                 schedule_audit, action_log, incidents):
        self._session_id = validate_identity(session_id, "session_id")
        self._learner_ref = validate_identity(learner_ref, "learner_ref")
        self._focus = coerce_enum(focus, Focus, "focus")
        self._mode = coerce_enum(mode, Mode, "mode")
        self._status = coerce_enum(status, SessionStatus, "status")
        self._revision = validate_nonneg_int(revision, "revision")

        for name, obj in (("rng", rng), ("clock", clock), ("scheduler", scheduler),
                          ("world", world), ("ledger", ledger),
                          ("event_log", event_log),
                          ("schedule_audit", schedule_audit),
                          ("action_log", action_log), ("incidents", incidents)):
            identity = getattr(obj, "identity", None)
            if identity is not None and identity != self._session_id:
                raise IdentityMismatchError(
                    "%s belongs to identity %r, not session %r"
                    % (name, identity, self._session_id))

        self._rng = rng
        self._clock = clock
        self._scheduler = scheduler
        self._world = world
        self._ledger = ledger
        self._event_log = event_log
        self._schedule_audit = schedule_audit
        self._action_log = action_log
        self._incidents = incidents

    @classmethod
    def create(cls, session_id, learner_ref, focus, mode, root_seed):
        """Build a brand-new, empty, active session."""
        return cls(
            session_id=session_id, learner_ref=learner_ref, focus=focus, mode=mode,
            status=SessionStatus.ACTIVE, revision=0,
            rng=SeededRandom(root_seed), clock=SimClock(),
            scheduler=EventScheduler(session_id), world=WorldState(session_id),
            ledger=ContextLedger(session_id), event_log=SessionEventLog(session_id),
            schedule_audit=ScheduleAuditLog(session_id),
            action_log=ActionLog(session_id), incidents=IncidentGraph(session_id))

    # -- identity and lifecycle fields -----------------------------------

    @property
    def session_id(self):
        return self._session_id

    @property
    def learner_ref(self):
        return self._learner_ref

    @property
    def focus(self):
        return self._focus

    @property
    def mode(self):
        return self._mode

    @property
    def status(self):
        return self._status

    @property
    def is_active(self):
        return self._status is SessionStatus.ACTIVE

    @property
    def revision(self):
        """Bumped on every accepted mutation. Used for optimistic concurrency."""
        return self._revision

    @property
    def root_seed(self):
        return self._rng.root_seed

    @property
    def now_ms(self):
        return self._clock.now_ms

    def __repr__(self):
        return ("SimulationSession(session_id=%r, focus=%s, mode=%s, status=%s, "
                "now_ms=%d, revision=%d)" % (
                    self._session_id, self._focus.value, self._mode.value,
                    self._status.value, self._clock.now_ms, self._revision))

    # -- sub-object access (read-only) ------------------------------------

    @property
    def rng(self):
        return self._rng

    @property
    def clock(self):
        return self._clock

    @property
    def scheduler(self):
        return self._scheduler

    @property
    def world(self):
        return self._world

    @property
    def ledger(self):
        return self._ledger

    @property
    def event_log(self):
        return self._event_log

    @property
    def schedule_audit(self):
        return self._schedule_audit

    @property
    def action_log(self):
        return self._action_log

    @property
    def incidents(self):
        return self._incidents

    def _bump_revision(self):
        self._revision = validate_nonneg_int(self._revision + 1, "revision")

    # -- time --------------------------------------------------------------

    @_require_active
    def advance_time(self, duration_ms):
        """Advance the clock, then fire every scheduler entry now due."""
        self._clock.advance(duration_ms)
        return self._fire_due()

    def _fire_due(self):
        fired_events = []
        for entry in self._scheduler.due(self._clock.now_ms):
            event = self._event_log.append_fired(entry.spec, self._clock.now_ms)
            self._schedule_audit.record_fired(
                entry.schedule_id, fired_event_id=event.event_id,
                resolved_at_ms=self._clock.now_ms)
            fired_events.append(event)
        if fired_events:
            self._bump_revision()
        return tuple(fired_events)

    # -- events --------------------------------------------------------------

    @_require_active
    def record_immediate_event(self, type, payload=None, source=EventSource.WORLD,
                               visibility=EventVisibility.LEARNER_VISIBLE,
                               causes=(), prerequisites=()):
        """Record an event that happens right now, with no scheduling delay."""
        self._validate_causes_exist(causes)
        event = self._event_log.record(
            type=type, sim_time_ms=self._clock.now_ms, payload=payload,
            source=source, visibility=visibility, causes=causes,
            prerequisites=prerequisites)
        self._bump_revision()
        return event

    @_require_active
    def schedule_event(self, type, delay_ms, payload=None, priority=0,
                       source=EventSource.SCHEDULER,
                       visibility=EventVisibility.LEARNER_VISIBLE, causes=(),
                       prerequisites=(), scheduling_cause_event_id=None):
        """Queue an event to fire ``delay_ms`` of simulation time from now."""
        self._validate_causes_exist(causes)
        if scheduling_cause_event_id is not None:
            self._require_known_event(scheduling_cause_event_id)
        spec = EventSpec(type=type, payload=payload, source=source,
                         visibility=visibility, causes=causes,
                         prerequisites=prerequisites)
        fire_at_ms = self._clock.now_ms + _validate_delay(delay_ms)
        entry = self._scheduler.schedule(spec, fire_at_ms, priority=priority)
        self._schedule_audit.record_scheduled(
            entry.schedule_id, event_type=type, scheduled_at_ms=self._clock.now_ms,
            fire_at_ms=fire_at_ms, priority=priority,
            scheduling_cause_event_id=scheduling_cause_event_id)
        self._bump_revision()
        return entry

    @_require_active
    def cancel_scheduled(self, schedule_id, reason=None):
        entry = self._scheduler.cancel(schedule_id, reason=reason)
        self._schedule_audit.record_cancelled(
            schedule_id, resolved_at_ms=self._clock.now_ms, reason=reason)
        self._bump_revision()
        return entry

    def _require_known_event(self, event_id):
        if not self._event_log.has(event_id):
            raise UnknownReferenceError(
                "no session event with id %r" % event_id)

    def _validate_causes_exist(self, causes):
        for event_id in causes:
            self._require_known_event(event_id)

    # -- learner actions -----------------------------------------------------

    @_require_active
    def record_action(self, action_type, classification, target=None, params=None):
        action = self._action_log.record(
            sim_time_ms=self._clock.now_ms, action_type=action_type,
            classification=classification, target=target, params=params)
        self._bump_revision()
        return action

    # -- context ledger --------------------------------------------------

    @_require_active
    def introduce_fact(self, fact_id, category, value, source,
                       introduced_by_event_id=None, available=True):
        if introduced_by_event_id is not None:
            self._require_known_event(introduced_by_event_id)
        fact = self._ledger.introduce_fact(
            fact_id=fact_id, category=category, value=value, source=source,
            sim_time_ms=self._clock.now_ms,
            introduced_by_event_id=introduced_by_event_id, available=available)
        self._bump_revision()
        return fact

    @_require_active
    def make_fact_available(self, fact_id):
        fact = self._ledger.make_available(fact_id, sim_time_ms=self._clock.now_ms)
        self._bump_revision()
        return fact

    @_require_active
    def observe_fact(self, fact_id, action_id):
        if not self._action_log.has(action_id):
            raise UnknownReferenceError("no learner action with id %r" % action_id)
        fact = self._ledger.observe(fact_id, action_id=action_id,
                                    sim_time_ms=self._clock.now_ms)
        self._bump_revision()
        return fact

    # -- world state -----------------------------------------------------

    @_require_active
    def mutate_world(self, namespace, key, value, cause_event_id=None):
        if cause_event_id is not None:
            self._require_known_event(cause_event_id)
        mutation = self._world.mutate(
            namespace=namespace, key=key, value=value,
            sim_time_ms=self._clock.now_ms, cause_event_id=cause_event_id)
        self._bump_revision()
        return mutation

    # -- causal consequence graph -------------------------------------------

    @_require_active
    def open_incident(self, title, opening_event_id=None):
        if opening_event_id is not None:
            self._require_known_event(opening_event_id)
        incident = self._incidents.open_incident(
            title=title, opened_at_ms=self._clock.now_ms,
            opening_event_id=opening_event_id)
        self._bump_revision()
        return incident

    @_require_active
    def record_consequence(self, incident_id, parent_consequence_ids=(),
                           cause_event_id=None, triggering_action_id=None,
                           scheduled_delay_ms=None, affected_namespace=None,
                           affected_key=None, mutation_ref=None, description=None):
        if cause_event_id is not None:
            self._require_known_event(cause_event_id)
        if triggering_action_id is not None and not self._action_log.has(triggering_action_id):
            raise UnknownReferenceError(
                "no learner action with id %r" % triggering_action_id)
        if mutation_ref is not None:
            if not any(m.mutation_id == mutation_ref for m in self._world.mutations()):
                raise UnknownReferenceError(
                    "no world mutation with id %r" % mutation_ref)
        consequence = self._incidents.record_consequence(
            incident_id=incident_id, sim_time_ms=self._clock.now_ms,
            parent_consequence_ids=parent_consequence_ids,
            cause_event_id=cause_event_id, triggering_action_id=triggering_action_id,
            scheduled_delay_ms=scheduled_delay_ms,
            affected_namespace=affected_namespace, affected_key=affected_key,
            mutation_ref=mutation_ref, description=description)
        self._bump_revision()
        return consequence

    # -- lifecycle ---------------------------------------------------------

    @_require_active
    def complete(self):
        self._status = SessionStatus.COMPLETED
        self._bump_revision()

    @_require_active
    def abandon(self):
        self._status = SessionStatus.ABANDONED
        self._bump_revision()

    # -- state ---------------------------------------------------------------

    def capture_state(self):
        """Return a canonical, JSON-safe snapshot of the entire aggregate."""
        return {
            "version": STATE_VERSION,
            "session_id": self._session_id,
            "learner_ref": self._learner_ref,
            "focus": self._focus.value,
            "mode": self._mode.value,
            "status": self._status.value,
            "revision": self._revision,
            "rng": self._rng.capture_state(),
            "clock": self._clock.capture_state(),
            "scheduler": self._scheduler.capture_state(),
            "world": self._world.capture_state(),
            "ledger": self._ledger.capture_state(),
            "event_log": self._event_log.capture_state(),
            "schedule_audit": self._schedule_audit.capture_state(),
            "action_log": self._action_log.capture_state(),
            "incidents": self._incidents.capture_state(),
        }

    _STATE_KEYS = frozenset({
        "version", "session_id", "learner_ref", "focus", "mode", "status",
        "revision", "rng", "clock", "scheduler", "world", "ledger",
        "event_log", "schedule_audit", "action_log", "incidents",
    })

    def restore_state(self, state):
        """Restore this instance in place from a previously captured state.

        Fully parsed and validated before any attribute is assigned, matching
        the atomic restore contract every sub-object in this package follows:
        a rejected payload leaves the session exactly as it was.
        """
        fields = self._parse_state(state, expected_session_id=self._session_id)
        (self._session_id, self._learner_ref, self._focus, self._mode,
         self._status, self._revision, self._rng, self._clock, self._scheduler,
         self._world, self._ledger, self._event_log, self._schedule_audit,
         self._action_log, self._incidents) = fields

    @classmethod
    def from_state(cls, state):
        """Build a fresh instance from a captured state, identity included."""
        session_id = cls._session_id_from_state(state)
        fields = cls._parse_state(state, expected_session_id=session_id)
        return cls(*fields)

    @staticmethod
    def _session_id_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "session state must be an object, got %s" % type(state).__name__)
        missing = SimulationSession._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "session state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - SimulationSession._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "session state has unknown field(s) %s" % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("session state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported session state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return validate_identity(state["session_id"], "session state session_id")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_session_id):
        session_id = cls._session_id_from_state(state)
        if session_id != expected_session_id:
            raise IdentityMismatchError(
                "session state belongs to identity %r, not %r"
                % (session_id, expected_session_id))

        try:
            learner_ref = validate_identity(state["learner_ref"], "learner_ref")
            focus = coerce_enum(state["focus"], Focus, "focus")
            mode = coerce_enum(state["mode"], Mode, "mode")
            status = coerce_enum(state["status"], SessionStatus, "status")
            revision = validate_nonneg_int(state["revision"], "revision")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

        try:
            rng = SeededRandom.from_state(state["rng"])
            clock = SimClock.from_state(state["clock"])
            scheduler = EventScheduler.from_state(state["scheduler"])
        except Exception as exc:
            raise InvalidDomainStateError(
                "session state core sub-object: %s" % exc) from exc
        if scheduler.identity != session_id:
            raise IdentityMismatchError(
                "scheduler state belongs to identity %r, not %r"
                % (scheduler.identity, session_id))

        world = WorldState.from_state(state["world"])
        ledger = ContextLedger.from_state(state["ledger"])
        event_log = SessionEventLog.from_state(state["event_log"])
        schedule_audit = ScheduleAuditLog.from_state(state["schedule_audit"])
        action_log = ActionLog.from_state(state["action_log"])
        incidents = IncidentGraph.from_state(state["incidents"])

        # -- cross-object referential integrity --------------------------
        # Each sub-object above has already validated its own shape. What
        # remains is checking that references crossing an object boundary
        # actually resolve, which is this aggregate's responsibility alone.

        known_event_ids = {e.event_id for e in event_log.events()}
        known_action_ids = {a.action_id for a in action_log.actions()}
        known_mutation_ids = {m.mutation_id for m in world.mutations()}

        for fact in ledger.facts():
            if fact.introduced_by_event_id is not None \
                    and fact.introduced_by_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "fact %r references unknown event %r"
                    % (fact.fact_id, fact.introduced_by_event_id))
            if fact.observed_by_action_id is not None \
                    and fact.observed_by_action_id not in known_action_ids:
                raise InvalidDomainStateError(
                    "fact %r references unknown action %r"
                    % (fact.fact_id, fact.observed_by_action_id))

        for mutation in world.mutations():
            if mutation.cause_event_id is not None \
                    and mutation.cause_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "world mutation %r references unknown event %r"
                    % (mutation.mutation_id, mutation.cause_event_id))

        for entry in schedule_audit.entries():
            if entry.scheduling_cause_event_id is not None \
                    and entry.scheduling_cause_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "schedule audit entry %r references unknown event %r"
                    % (entry.audit_id, entry.scheduling_cause_event_id))
            if entry.fired_event_id is not None \
                    and entry.fired_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "schedule audit entry %r references unknown fired event %r"
                    % (entry.audit_id, entry.fired_event_id))

        for incident in incidents.incidents():
            if incident.opening_event_id is not None \
                    and incident.opening_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "incident %r references unknown event %r"
                    % (incident.incident_id, incident.opening_event_id))

        for consequence in incidents.consequences():
            if consequence.cause_event_id is not None \
                    and consequence.cause_event_id not in known_event_ids:
                raise InvalidDomainStateError(
                    "consequence %r references unknown event %r"
                    % (consequence.consequence_id, consequence.cause_event_id))
            if consequence.triggering_action_id is not None \
                    and consequence.triggering_action_id not in known_action_ids:
                raise InvalidDomainStateError(
                    "consequence %r references unknown action %r"
                    % (consequence.consequence_id, consequence.triggering_action_id))
            if consequence.mutation_ref is not None \
                    and consequence.mutation_ref not in known_mutation_ids:
                raise InvalidDomainStateError(
                    "consequence %r references unknown world mutation %r"
                    % (consequence.consequence_id, consequence.mutation_ref))

        return (session_id, learner_ref, focus, mode, status, revision, rng,
               clock, scheduler, world, ledger, event_log, schedule_audit,
               action_log, incidents)


def _validate_delay(value):
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidDomainStateError(
            "delay_ms must be an int, got %s" % type(value).__name__)
    if value < 0:
        raise InvalidDomainStateError("delay_ms must not be negative, got %d" % value)
    return value
