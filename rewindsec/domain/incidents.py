"""The generic, threat-agnostic causal consequence graph.

Architecture Spec v1.1 S12-13: a consequence is a fact that something later
happened *because of* something earlier -- credentials submitted at T become
an account compromise recorded at T+20 minutes. This module gives that
causal link a durable, queryable identity, independent of which threat family
produced it. No phishing, ransomware, MFA or BEC engine lives here: those are
later batches that will *call* this graph, not extend it.

Two kinds of node
------------------
``Incident``
    The umbrella: one incident groups every consequence that traces back to
    the same originating cause. Opened once, referenced by every consequence
    under it.

``Consequence``
    One caused effect: it names its incident, the event(s) it is a parent of
    (``parent_consequence_ids``, for multi-step chains), the ``cause_event_id``
    and/or ``triggering_action_id`` that produced it, an optional scheduled
    delay, the world component it affected, and a reference to the
    :class:`~rewindsec.domain.world.WorldMutation` it produced, if any.

This module validates only its own internal shape and its own graph
invariants (no cycles, no duplicate parent, parent must already exist). It
does **not** check that ``cause_event_id`` is a real event or that
``mutation_ref`` names a real mutation -- those references live in other
logs this module has no visibility into. That cross-object check is the
:class:`~rewindsec.domain.session.SimulationSession` aggregate's job, the same
division of responsibility used throughout this package.
"""

from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError, UnknownReferenceError)
from rewindsec.domain.identifiers import (derive_id, validate_bounded_str,
                                          validate_identity, validate_nonneg_int)
from rewindsec.domain.json_safe import freeze, thaw
from rewindsec.domain.sequences import SequenceCounter

__all__ = ["Incident", "Consequence", "IncidentGraph", "CycleError"]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

_INCIDENT_ID_LABEL = "rewindsec2/incident-id/v1"
_CONSEQUENCE_ID_LABEL = "rewindsec2/consequence-id/v1"

_MAX_TITLE_LENGTH = 128
_MAX_NAMESPACE_LENGTH = 64
_MAX_KEY_LENGTH = 128


class CycleError(DomainError, ValueError):
    """A consequence's parents would create a cycle in the causal graph."""


def _validate_sim_time(value, what):
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidDomainStateError(str(exc)) from exc


def _derive_incident_id(identity, seq):
    return derive_id(_INCIDENT_ID_LABEL, identity, seq)


def _derive_consequence_id(identity, seq):
    return derive_id(_CONSEQUENCE_ID_LABEL, identity, seq)


class Incident:
    """The umbrella grouping every consequence traced to one originating cause."""

    __slots__ = ("_incident_id", "_seq", "_title", "_opened_at_ms",
                 "_opening_event_id")

    def __init__(self, incident_id, seq, title, opened_at_ms, opening_event_id):
        self._incident_id = _validate_id(incident_id, "incident_id")
        self._seq = validate_nonneg_int(seq, "seq")
        self._title = validate_bounded_str(title, "title", _MAX_TITLE_LENGTH)
        self._opened_at_ms = _validate_sim_time(opened_at_ms, "opened_at_ms")
        self._opening_event_id = (
            None if opening_event_id is None
            else validate_identity(opening_event_id, "opening_event_id"))

    @property
    def incident_id(self):
        return self._incident_id

    @property
    def seq(self):
        return self._seq

    @property
    def title(self):
        return self._title

    @property
    def opened_at_ms(self):
        return self._opened_at_ms

    @property
    def opening_event_id(self):
        return self._opening_event_id

    def __repr__(self):
        return "Incident(incident_id=%r, title=%r)" % (self._incident_id, self._title)

    def __eq__(self, other):
        if not isinstance(other, Incident):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash(self._incident_id)

    def to_state(self):
        return {
            "incident_id": self._incident_id,
            "seq": self._seq,
            "title": self._title,
            "opened_at_ms": self._opened_at_ms,
            "opening_event_id": self._opening_event_id,
        }

    _STATE_KEYS = frozenset({"incident_id", "seq", "title", "opened_at_ms",
                             "opening_event_id"})

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "incident must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "incident is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "incident has unknown field(s) %s" % ", ".join(sorted(unknown)))
        try:
            return cls(incident_id=state["incident_id"], seq=state["seq"],
                       title=state["title"], opened_at_ms=state["opened_at_ms"],
                       opening_event_id=state["opening_event_id"])
        except DomainError as exc:
            raise InvalidDomainStateError("incident: %s" % exc) from exc


class Consequence:
    """One caused effect within an incident's causal chain."""

    __slots__ = ("_consequence_id", "_seq", "_incident_id",
                 "_parent_consequence_ids", "_cause_event_id",
                 "_triggering_action_id", "_scheduled_delay_ms",
                 "_affected_namespace", "_affected_key", "_mutation_ref",
                 "_sim_time_ms", "_description")

    def __init__(self, consequence_id, seq, incident_id, parent_consequence_ids,
                 cause_event_id, triggering_action_id, scheduled_delay_ms,
                 affected_namespace, affected_key, mutation_ref, sim_time_ms,
                 description):
        self._consequence_id = _validate_id(consequence_id, "consequence_id")
        self._seq = validate_nonneg_int(seq, "seq")
        self._incident_id = _validate_id(incident_id, "incident_id")

        parents = tuple(parent_consequence_ids)
        seen = set()
        for parent_id in parents:
            _validate_id(parent_id, "parent_consequence_id")
            if parent_id == self._consequence_id:
                raise InvalidDomainStateError(
                    "consequence %r cannot be its own parent" % consequence_id)
            if parent_id in seen:
                raise InvalidDomainStateError(
                    "consequence %r lists parent %r more than once"
                    % (consequence_id, parent_id))
            seen.add(parent_id)
        self._parent_consequence_ids = parents

        self._cause_event_id = (
            None if cause_event_id is None
            else validate_identity(cause_event_id, "cause_event_id"))
        self._triggering_action_id = (
            None if triggering_action_id is None
            else validate_identity(triggering_action_id, "triggering_action_id"))
        if self._cause_event_id is None and self._triggering_action_id is None \
                and not self._parent_consequence_ids:
            raise InvalidDomainStateError(
                "consequence %r has no cause: it must have a cause_event_id, "
                "a triggering_action_id, or at least one parent consequence"
                % consequence_id)

        self._scheduled_delay_ms = (
            None if scheduled_delay_ms is None
            else validate_nonneg_int(scheduled_delay_ms, "scheduled_delay_ms"))
        self._affected_namespace = (
            None if affected_namespace is None
            else validate_bounded_str(affected_namespace, "affected_namespace",
                                      _MAX_NAMESPACE_LENGTH))
        self._affected_key = (
            None if affected_key is None
            else validate_bounded_str(affected_key, "affected_key", _MAX_KEY_LENGTH))
        if (self._affected_namespace is None) != (self._affected_key is None):
            raise InvalidDomainStateError(
                "consequence %r: affected_namespace and affected_key must be "
                "both present or both absent" % consequence_id)
        self._mutation_ref = (
            None if mutation_ref is None
            else validate_identity(mutation_ref, "mutation_ref"))
        self._sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        self._description = freeze(description, path="description")

    # -- fields ----------------------------------------------------------

    @property
    def consequence_id(self):
        return self._consequence_id

    @property
    def seq(self):
        return self._seq

    @property
    def incident_id(self):
        return self._incident_id

    @property
    def parent_consequence_ids(self):
        return self._parent_consequence_ids

    @property
    def cause_event_id(self):
        return self._cause_event_id

    @property
    def triggering_action_id(self):
        return self._triggering_action_id

    @property
    def scheduled_delay_ms(self):
        return self._scheduled_delay_ms

    @property
    def affected_namespace(self):
        return self._affected_namespace

    @property
    def affected_key(self):
        return self._affected_key

    @property
    def mutation_ref(self):
        return self._mutation_ref

    @property
    def sim_time_ms(self):
        return self._sim_time_ms

    @property
    def description(self):
        return self._description

    def __repr__(self):
        return "Consequence(consequence_id=%r, incident_id=%r)" % (
            self._consequence_id, self._incident_id)

    def __eq__(self, other):
        if not isinstance(other, Consequence):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash(self._consequence_id)

    def to_state(self):
        return {
            "consequence_id": self._consequence_id,
            "seq": self._seq,
            "incident_id": self._incident_id,
            "parent_consequence_ids": list(self._parent_consequence_ids),
            "cause_event_id": self._cause_event_id,
            "triggering_action_id": self._triggering_action_id,
            "scheduled_delay_ms": self._scheduled_delay_ms,
            "affected_namespace": self._affected_namespace,
            "affected_key": self._affected_key,
            "mutation_ref": self._mutation_ref,
            "sim_time_ms": self._sim_time_ms,
            "description": thaw(self._description),
        }

    _STATE_KEYS = frozenset({
        "consequence_id", "seq", "incident_id", "parent_consequence_ids",
        "cause_event_id", "triggering_action_id", "scheduled_delay_ms",
        "affected_namespace", "affected_key", "mutation_ref", "sim_time_ms",
        "description",
    })

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "consequence must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "consequence is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "consequence has unknown field(s) %s" % ", ".join(sorted(unknown)))
        raw_parents = state["parent_consequence_ids"]
        if not isinstance(raw_parents, list):
            raise InvalidDomainStateError(
                "consequence parent_consequence_ids must be a list, got %s"
                % type(raw_parents).__name__)
        try:
            return cls(
                consequence_id=state["consequence_id"], seq=state["seq"],
                incident_id=state["incident_id"],
                parent_consequence_ids=raw_parents,
                cause_event_id=state["cause_event_id"],
                triggering_action_id=state["triggering_action_id"],
                scheduled_delay_ms=state["scheduled_delay_ms"],
                affected_namespace=state["affected_namespace"],
                affected_key=state["affected_key"],
                mutation_ref=state["mutation_ref"],
                sim_time_ms=state["sim_time_ms"], description=state["description"])
        except InvalidDomainStateError:
            raise
        except DomainError as exc:
            raise InvalidDomainStateError("consequence: %s" % exc) from exc


def _validate_id(value, what):
    if not isinstance(value, str):
        raise InvalidDomainStateError("%s must be a str, got %s" % (what, type(value).__name__))
    if len(value) != 32:
        raise InvalidDomainStateError("%s must be 32 characters, got %d" % (what, len(value)))
    for char in value:
        if char not in "0123456789abcdef":
            raise InvalidDomainStateError("%s must be lowercase hex: %r" % (what, value))
    return value


class IncidentGraph:
    """The identity-scoped causal graph of one session.

    Owns two independent sequence counters, ``incident`` and ``consequence``,
    because the two kinds of node are numbered separately.
    """

    __slots__ = ("_identity", "_incident_seq", "_consequence_seq",
                 "_incidents", "_consequences")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "incident graph identity")
        self._incident_seq = SequenceCounter("incident")
        self._consequence_seq = SequenceCounter("consequence")
        self._incidents = {}
        self._consequences = {}

    @property
    def identity(self):
        return self._identity

    def __repr__(self):
        return "IncidentGraph(identity=%r, incidents=%d, consequences=%d)" % (
            self._identity, len(self._incidents), len(self._consequences))

    # -- mutation ------------------------------------------------------------

    def open_incident(self, title, opened_at_ms, opening_event_id=None):
        seq = self._incident_seq.peek()
        incident_id = _derive_incident_id(self._identity, seq)
        incident = Incident(incident_id=incident_id, seq=seq, title=title,
                            opened_at_ms=opened_at_ms,
                            opening_event_id=opening_event_id)
        self._incident_seq.advance()
        self._incidents[incident_id] = incident
        return incident

    def record_consequence(self, incident_id, sim_time_ms, parent_consequence_ids=(),
                           cause_event_id=None, triggering_action_id=None,
                           scheduled_delay_ms=None, affected_namespace=None,
                           affected_key=None, mutation_ref=None, description=None):
        """Record one caused effect under an existing incident.

        Raises :class:`~rewindsec.domain.errors.UnknownReferenceError` if
        ``incident_id`` or any parent consequence id is unknown, and
        :class:`CycleError` if any parent (transitively) has this
        not-yet-created consequence as one of *its* ancestors -- unreachable
        in practice since a parent must already exist and ids are never
        reused, but checked explicitly so the invariant is asserted rather
        than assumed.
        """
        if incident_id not in self._incidents:
            raise UnknownReferenceError("no incident with id %r" % incident_id)
        parent_ids = tuple(parent_consequence_ids)
        for parent_id in parent_ids:
            if parent_id not in self._consequences:
                raise UnknownReferenceError(
                    "no consequence with id %r" % parent_id)

        seq = self._consequence_seq.peek()
        consequence_id = _derive_consequence_id(self._identity, seq)

        for parent_id in parent_ids:
            if self._has_ancestor(parent_id, consequence_id):
                raise CycleError(
                    "recording consequence %r under parent %r would create a "
                    "cycle" % (consequence_id, parent_id))

        consequence = Consequence(
            consequence_id=consequence_id, seq=seq, incident_id=incident_id,
            parent_consequence_ids=parent_ids, cause_event_id=cause_event_id,
            triggering_action_id=triggering_action_id,
            scheduled_delay_ms=scheduled_delay_ms,
            affected_namespace=affected_namespace, affected_key=affected_key,
            mutation_ref=mutation_ref, sim_time_ms=sim_time_ms,
            description=description)
        self._consequence_seq.advance()
        self._consequences[consequence_id] = consequence
        return consequence

    def _has_ancestor(self, consequence_id, candidate_ancestor_id):
        """Whether ``candidate_ancestor_id`` is ``consequence_id`` or reachable
        by walking its parents. Since only already-existing consequences may
        be named as parents, this can only be true for a to-be-reused id."""
        if consequence_id == candidate_ancestor_id:
            return True
        consequence = self._consequences.get(consequence_id)
        if consequence is None:
            return False
        return any(self._has_ancestor(parent_id, candidate_ancestor_id)
                   for parent_id in consequence.parent_consequence_ids)

    # -- queries ---------------------------------------------------------

    def get_incident(self, incident_id):
        incident = self._incidents.get(incident_id)
        if incident is None:
            raise UnknownReferenceError("no incident with id %r" % incident_id)
        return incident

    def has_incident(self, incident_id):
        return incident_id in self._incidents

    def incidents(self):
        return tuple(sorted(self._incidents.values(), key=lambda i: i.seq))

    def get_consequence(self, consequence_id):
        consequence = self._consequences.get(consequence_id)
        if consequence is None:
            raise UnknownReferenceError("no consequence with id %r" % consequence_id)
        return consequence

    def has_consequence(self, consequence_id):
        return consequence_id in self._consequences

    def consequences(self):
        return tuple(sorted(self._consequences.values(), key=lambda c: c.seq))

    def consequences_for_incident(self, incident_id):
        return tuple(c for c in self.consequences() if c.incident_id == incident_id)

    # -- state -------------------------------------------------------------

    def capture_state(self):
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "incident_seq": self._incident_seq.capture_state(),
            "consequence_seq": self._consequence_seq.capture_state(),
            "incidents": [i.to_state() for i in self.incidents()],
            "consequences": [c.to_state() for c in self.consequences()],
        }

    _STATE_KEYS = frozenset({"version", "identity", "incident_seq",
                             "consequence_seq", "incidents", "consequences"})

    def restore_state(self, state):
        (identity, incident_seq, consequence_seq, incidents,
         consequences) = self._parse_state(state, expected_identity=self._identity)
        self._identity = identity
        self._incident_seq = incident_seq
        self._consequence_seq = consequence_seq
        self._incidents = incidents
        self._consequences = consequences

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        (_, incident_seq, consequence_seq, incidents,
         consequences) = cls._parse_state(state, expected_identity=identity)
        instance._incident_seq = incident_seq
        instance._consequence_seq = consequence_seq
        instance._incidents = incidents
        instance._consequences = consequences
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "incident graph state must be an object, got %s"
                % type(state).__name__)
        missing = IncidentGraph._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "incident graph state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - IncidentGraph._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "incident graph state has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("incident graph state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported incident graph state version %r (this build "
                "writes %d)" % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "incident graph identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "incident graph state belongs to identity %r, not %r"
                % (identity, expected_identity))

        incident_seq = SequenceCounter.from_state(state["incident_seq"])
        consequence_seq = SequenceCounter.from_state(state["consequence_seq"])

        raw_incidents = state["incidents"]
        if not isinstance(raw_incidents, list):
            raise InvalidDomainStateError(
                "incident graph state incidents must be a list, got %s"
                % type(raw_incidents).__name__)
        incidents, seen_incident_seq = {}, set()
        for raw in raw_incidents:
            incident = Incident.from_state(raw)
            expected_id = _derive_incident_id(identity, incident.seq)
            if incident.incident_id != expected_id:
                raise InvalidDomainStateError(
                    "incident %s does not match its derived id %s for seq %d"
                    % (incident.incident_id, expected_id, incident.seq))
            if incident.seq in seen_incident_seq:
                raise InvalidDomainStateError("duplicate incident seq %d" % incident.seq)
            if incident.seq >= incident_seq.next_value:
                raise InvalidDomainStateError(
                    "incident seq %d is not below the counter %d"
                    % (incident.seq, incident_seq.next_value))
            seen_incident_seq.add(incident.seq)
            incidents[incident.incident_id] = incident

        raw_consequences = state["consequences"]
        if not isinstance(raw_consequences, list):
            raise InvalidDomainStateError(
                "incident graph state consequences must be a list, got %s"
                % type(raw_consequences).__name__)
        consequences, seen_consequence_seq = {}, set()
        for raw in raw_consequences:
            consequence = Consequence.from_state(raw)
            expected_id = _derive_consequence_id(identity, consequence.seq)
            if consequence.consequence_id != expected_id:
                raise InvalidDomainStateError(
                    "consequence %s does not match its derived id %s for seq %d"
                    % (consequence.consequence_id, expected_id, consequence.seq))
            if consequence.seq in seen_consequence_seq:
                raise InvalidDomainStateError(
                    "duplicate consequence seq %d" % consequence.seq)
            if consequence.seq >= consequence_seq.next_value:
                raise InvalidDomainStateError(
                    "consequence seq %d is not below the counter %d"
                    % (consequence.seq, consequence_seq.next_value))
            if consequence.incident_id not in incidents:
                raise InvalidDomainStateError(
                    "consequence %s references unknown incident %s"
                    % (consequence.consequence_id, consequence.incident_id))
            for parent_id in consequence.parent_consequence_ids:
                if parent_id not in consequences:
                    raise InvalidDomainStateError(
                        "consequence %s references unknown parent %s"
                        % (consequence.consequence_id, parent_id))
            seen_consequence_seq.add(consequence.seq)
            consequences[consequence.consequence_id] = consequence

        return identity, incident_seq, consequence_seq, incidents, consequences
