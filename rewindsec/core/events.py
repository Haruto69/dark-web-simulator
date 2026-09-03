"""The canonical simulation event model.

An :class:`Event` is one recorded fact about a simulation: a message arrived,
a learner opened it, credentials were submitted, an incident opened. The event
log is append-only and is the authoritative history of a session -- a replay
re-fires recorded events rather than regenerating them, so anything that is not
in an event did not happen.

Two properties make that work, and both are enforced here rather than left to
convention.

Deterministic identity
----------------------
``event_id`` is derived from ``(session_identity, seq)`` by SHA-256, not by
``uuid4``. A random identifier would give two replays of one seed different
event ids, and no digest comparison could survive that: the factual and
counterfactual runs would differ in every event before the divergence point,
for a reason that has nothing to do with the learner's decision.

Behavioural type names, never threat families
---------------------------------------------
Event types are namespaced behaviour: ``mail.delivered``, not
``phishing.delivered``. The learner is meant to discriminate benign from
adversarial themselves, so the system must not label the answer in a field the
UI renders. Threat classification is an internal assessment consumed at
debrief, never a learner-visible event type; :func:`validate_event_type`
enforces that for learner-visible events.

The event does not allocate its own ``seq``. A future ``SimulationSession``
owns that counter, because sequence numbers must be unique and gapless across
the whole session and no single event can know that. :class:`EventSpec` is the
same description *without* the identity and time fields, for an event that has
not happened yet -- it is what the scheduler queues.
"""

import hashlib
import json
from enum import Enum
from types import MappingProxyType

from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms

__all__ = [
    "Event",
    "EventSpec",
    "EventSource",
    "EventVisibility",
    "EventError",
    "InvalidEventIdentityError",
    "InvalidEventFieldError",
    "InvalidPayloadError",
    "InvalidEventStateError",
    "derive_event_id",
    "validate_event_type",
    "canonical_json",
    "EVENT_ID_LENGTH",
    "STATE_VERSION",
]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

#: Domain-separation label for event-id derivation. Versioned deliberately:
#: changing it changes every event id for every session, so stored sessions
#: would stop matching their recorded history.
_EVENT_ID_LABEL = "rewindsec2/event-id/v1"

#: 32 hex characters = 128 bits. Long enough that a collision is not a
#: practical concern across every session this system will ever run, short
#: enough to read in a log line and quote in a bug report.
EVENT_ID_LENGTH = 32

_MAX_IDENTITY_LENGTH = 128
_MAX_TYPE_LENGTH = 96
_MAX_SEQ = 2 ** 53 - 1

#: JSON nesting deeper than this is a bug rather than a payload. The limit
#: turns a RecursionError deep inside validation into a clear message.
_MAX_PAYLOAD_DEPTH = 16

#: Threat-family words that may not head a *learner-visible* event type. The
#: product rule is that benign and adversarial events are indistinguishable in
#: the UI; an event type is rendered, so a type like ``phishing.delivered``
#: hands the learner the answer. Internal events are free to use these words --
#: an internal assessment record is exactly where a classification belongs.
_THREAT_FAMILY_NAMESPACES = frozenset({
    "phishing", "spearphishing", "smishing", "vishing", "quishing",
    "ransomware", "malware", "trojan", "worm", "spyware",
    "bec", "scam", "fraud", "attack", "exploit", "threat", "adversary",
    "compromise", "breach", "malicious",
})


class EventSource(Enum):
    """What produced an event.

    A closed vocabulary, because "where did this come from?" is asked during
    every debrief and a free-text answer would drift into inconsistency.
    """

    #: Authored world behaviour: the simulated organisation doing its business.
    WORLD = "world"
    #: A previously scheduled delayed event reaching its fire time.
    SCHEDULER = "scheduler"
    #: A direct result of something the learner did.
    LEARNER = "learner"
    #: A consequence rule firing off an earlier event or action.
    CONSEQUENCE = "consequence"
    #: The simulation machinery itself: session start, end, checkpoint markers.
    SYSTEM = "system"


class EventVisibility(Enum):
    """Whether the learner can see an event.

    One log, two projections -- deliberately not two logs. A separate internal
    log would immediately raise the question of which one is authoritative,
    and the answer has to be "there is only one".
    """

    LEARNER_VISIBLE = "learner_visible"
    INTERNAL = "internal"


class EventError(Exception):
    """Base class for every failure raised by this module."""


class InvalidEventIdentityError(EventError, ValueError):
    """A session identity or sequence number cannot derive a stable event id."""


class InvalidEventFieldError(EventError, ValueError):
    """An event field is missing, of the wrong type, or malformed."""


class InvalidPayloadError(EventError, ValueError):
    """A payload is not JSON-safe, canonicalisable and deterministic."""


class InvalidEventStateError(EventError, ValueError):
    """A serialised event is malformed, foreign or of an unknown version."""


# -- identity ----------------------------------------------------------------

def _validate_identity(value, what="session identity"):
    """Return *value* if it derives a stable identifier, else raise.

    The charset excludes ``|``, which is the delimiter used in the derivation
    material. A separator that can also appear inside a field is how hash
    derivations acquire silent collisions, and this is the one place to rule
    that out rather than reason about it later.
    """
    if not isinstance(value, str):
        raise InvalidEventIdentityError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if not value:
        raise InvalidEventIdentityError("%s must not be empty" % what)
    if len(value) > _MAX_IDENTITY_LENGTH:
        raise InvalidEventIdentityError(
            "%s must be at most %d characters, got %d"
            % (what, _MAX_IDENTITY_LENGTH, len(value)))
    for char in value:
        if not char.isascii():
            raise InvalidEventIdentityError("%s must be ASCII: %r" % (what, value))
        if not (char.isalnum() or char in "-_.:"):
            raise InvalidEventIdentityError(
                "%s may contain only [A-Za-z0-9_.:-]: %r" % (what, value))
    return value


def _validate_seq(value, what="seq"):
    """Return *value* if it is a valid sequence position, else raise."""
    if isinstance(value, bool):
        raise InvalidEventIdentityError(
            "%s must be an int, not a bool; got %r" % (what, value))
    if not isinstance(value, int):
        raise InvalidEventIdentityError(
            "%s must be an int, got %s" % (what, type(value).__name__))
    if value < 0:
        raise InvalidEventIdentityError("%s must not be negative, got %d" % (what, value))
    if value > _MAX_SEQ:
        raise InvalidEventIdentityError(
            "%s exceeds the JSON-safe bound %d: %d" % (what, _MAX_SEQ, value))
    return value


def derive_event_id(session_identity, seq):
    """Derive an event id from the session identity and sequence position.

    Pure, total and stable: the same pair always yields the same id, in any
    process, under any ``PYTHONHASHSEED``. SHA-256 rather than ``hash()``,
    which CPython salts per process.
    """
    session_identity = _validate_identity(session_identity)
    seq = _validate_seq(seq)
    material = "%s|%s|%d" % (_EVENT_ID_LABEL, session_identity, seq)
    digest = hashlib.sha256(material.encode("utf-8")).hexdigest()
    return digest[:EVENT_ID_LENGTH]


def _validate_event_sim_time(value, what="sim_time_ms"):
    """Validate a simulation timestamp, reporting it as an event field error.

    The rule itself lives in ``simtime`` so events, the clock and the scheduler
    cannot drift apart about what a valid instant is. Only the error type is
    translated, so that everything this module raises is an :class:`EventError`
    and a caller never has to know which neighbour did the checking.
    """
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidEventFieldError(str(exc)) from exc


def _validate_event_id(value, what="event_id"):
    if not isinstance(value, str):
        raise InvalidEventFieldError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if len(value) != EVENT_ID_LENGTH:
        raise InvalidEventFieldError(
            "%s must be %d characters, got %d" % (what, EVENT_ID_LENGTH, len(value)))
    for char in value:
        if char not in "0123456789abcdef":
            raise InvalidEventFieldError(
                "%s must be lowercase hex: %r" % (what, value))
    return value


# -- event type --------------------------------------------------------------

def validate_event_type(value, visibility=None):
    """Return *value* if it is a well-formed event type, else raise.

    The format is ``namespace.name`` with two to four dot-separated segments,
    each matching ``[a-z][a-z0-9_]*``. A controlled string rather than an enum:
    the vocabulary will grow with every authored scenario, and a central enum
    would turn "add one content event" into "edit the core".

    When *visibility* is ``LEARNER_VISIBLE`` the leading segment may not be a
    threat family -- see ``_THREAT_FAMILY_NAMESPACES``.
    """
    if not isinstance(value, str):
        raise InvalidEventFieldError(
            "event type must be a str, got %s" % type(value).__name__)
    if not value:
        raise InvalidEventFieldError("event type must not be empty")
    if len(value) > _MAX_TYPE_LENGTH:
        raise InvalidEventFieldError(
            "event type must be at most %d characters, got %d"
            % (_MAX_TYPE_LENGTH, len(value)))

    segments = value.split(".")
    if not 2 <= len(segments) <= 4:
        raise InvalidEventFieldError(
            "event type must have 2 to 4 dot-separated segments "
            "(namespace.name): %r" % (value,))
    for segment in segments:
        if not segment:
            raise InvalidEventFieldError(
                "event type has an empty segment: %r" % (value,))
        for index, char in enumerate(segment):
            if not char.isascii():
                raise InvalidEventFieldError("event type must be ASCII: %r" % (value,))
            if char == "_" and index > 0:
                continue
            if char.isdigit() and index > 0:
                continue
            if not (char.isalpha() and char.islower()):
                raise InvalidEventFieldError(
                    "event type segments must match [a-z][a-z0-9_]*: %r" % (value,))

    if visibility is EventVisibility.LEARNER_VISIBLE:
        if segments[0] in _THREAT_FAMILY_NAMESPACES:
            raise InvalidEventFieldError(
                "learner-visible event type %r names a threat family. The "
                "learner has to discriminate benign from adversarial "
                "themselves, so the type must describe behaviour "
                "(mail.delivered), not classification (phishing.delivered). "
                "Classification belongs on an internal event." % (value,))
    return value


def _validate_prerequisite(value):
    """Prerequisite identifiers share the event-type shape, minus the threat rule.

    They are internal metadata only -- nothing in this task evaluates them --
    and an internal predicate named ``auth.credentials_exposed`` is exactly
    what it should be called.
    """
    try:
        return validate_event_type(value, visibility=None)
    except InvalidEventFieldError as exc:
        raise InvalidEventFieldError("prerequisite: %s" % exc) from exc


def _validate_ordered_unique(values, what, validator):
    """Return a validated tuple, preserving order and rejecting duplicates.

    A tuple rather than a set because ordering is part of the recorded history:
    two events whose causes differ only in order are different events, and a
    set would silently make them equal. Duplicates are rejected because a
    repeated parent is a construction bug, not a meaningful statement.
    """
    if isinstance(values, (str, bytes)):
        raise InvalidEventFieldError(
            "%s must be a sequence of strings, not a single string" % what)
    try:
        items = list(values)
    except TypeError as exc:
        raise InvalidEventFieldError(
            "%s must be an iterable of strings, got %s"
            % (what, type(values).__name__)) from exc

    seen, validated = set(), []
    for item in items:
        checked = validator(item)
        if checked in seen:
            raise InvalidEventFieldError(
                "%s contains a duplicate: %r" % (what, checked))
        seen.add(checked)
        validated.append(checked)
    return tuple(validated)


# -- payload -----------------------------------------------------------------

def _freeze_payload(value, depth=0, path="payload"):
    """Validate a payload recursively and return an immutable equivalent.

    Dicts become :class:`~types.MappingProxyType`, lists become tuples. Both
    are stdlib immutables -- no custom persistent-map implementation is worth
    the maintenance here.

    Immutability is not tidiness. The payload of a recorded event is history:
    if a caller can mutate the dict it passed in and thereby change what the
    log says happened, the log is not a record of anything.
    """
    if depth > _MAX_PAYLOAD_DEPTH:
        raise InvalidPayloadError(
            "%s nests deeper than %d levels" % (path, _MAX_PAYLOAD_DEPTH))

    # bool before int: bool is a subclass, and JSON keeps them distinct.
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if not -_MAX_SEQ <= value <= _MAX_SEQ:
            raise InvalidPayloadError(
                "%s: int %d is outside the JSON-safe range" % (path, value))
        return value
    if isinstance(value, float):
        # Rejected rather than allowed through: allow_nan=False would fail at
        # serialisation time instead, which is far from the offending caller.
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidPayloadError(
                "%s: NaN and infinity are not JSON values" % path)
        return value
    if isinstance(value, dict):
        frozen = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidPayloadError(
                    "%s: keys must be strings, got %s"
                    % (path, type(key).__name__))
            frozen[key] = _freeze_payload(item, depth + 1, "%s.%s" % (path, key))
        return MappingProxyType(frozen)
    if isinstance(value, list):
        return tuple(_freeze_payload(item, depth + 1, "%s[%d]" % (path, index))
                     for index, item in enumerate(value))
    if isinstance(value, tuple):
        # Deliberate: a tuple survives json.dumps but comes back as a list, so
        # an event built from a tuple would not equal itself after a
        # round-trip. Reject it at the door rather than debug it later.
        raise InvalidPayloadError(
            "%s: use a list, not a tuple. A tuple serialises to a JSON array "
            "and returns as a list, so the event would not survive a "
            "round-trip unchanged." % path)

    raise InvalidPayloadError(
        "%s: %s is not a JSON value. Payloads must be built from dict, list, "
        "str, int, float, bool and None only -- no sets, no callables, no "
        "class instances, no bytes." % (path, type(value).__name__))


def _thaw_payload(value):
    """Return a plain, mutable, JSON-serialisable copy of a frozen payload."""
    if isinstance(value, MappingProxyType):
        return {key: _thaw_payload(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [_thaw_payload(item) for item in value]
    return value


def canonical_json(state):
    """Serialise event state canonically.

    Sorted keys and tight separators so that equal states produce equal text.
    ``allow_nan=False`` is belt-and-braces: the payload validator already
    refused NaN and infinity, and this makes it impossible for a later change
    to that validator to silently emit invalid JSON.
    """
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


# -- the event ---------------------------------------------------------------

class Event:
    """One immutable recorded fact about a simulation.

    Construct with :meth:`create` when the id should be derived from the
    session identity, or directly when the id is already known (restoring from
    a state payload, for instance).
    """

    __slots__ = ("_event_id", "_seq", "_type", "_sim_time_ms", "_payload",
                 "_source", "_visibility", "_causes", "_prerequisites",
                 "_canonical")

    def __init__(self, event_id, seq, type, sim_time_ms, payload=None,
                 source=EventSource.WORLD,
                 visibility=EventVisibility.LEARNER_VISIBLE,
                 causes=(), prerequisites=()):
        self._event_id = _validate_event_id(event_id)
        self._seq = _validate_seq(seq)
        self._source = _coerce_enum(source, EventSource, "source")
        self._visibility = _coerce_enum(visibility, EventVisibility, "visibility")
        # Type validation needs the visibility, so it comes after it.
        self._type = validate_event_type(type, self._visibility)
        self._sim_time_ms = _validate_event_sim_time(sim_time_ms)
        self._payload = _freeze_payload({} if payload is None else payload)
        self._causes = _validate_ordered_unique(causes, "causes", _validate_event_id)
        self._prerequisites = _validate_ordered_unique(
            prerequisites, "prerequisites", _validate_prerequisite)
        # Computed once. It is the equality key, and it is the natural digest
        # input for the checkpoint work that comes later.
        self._canonical = canonical_json(self.to_state())

    @classmethod
    def create(cls, session_identity, seq, type, sim_time_ms, payload=None,
               source=EventSource.WORLD,
               visibility=EventVisibility.LEARNER_VISIBLE,
               causes=(), prerequisites=()):
        """Build an event, deriving ``event_id`` from the session identity."""
        return cls(derive_event_id(session_identity, seq), seq, type,
                   sim_time_ms, payload=payload, source=source,
                   visibility=visibility, causes=causes,
                   prerequisites=prerequisites)

    # -- fields --------------------------------------------------------------

    @property
    def event_id(self):
        return self._event_id

    @property
    def seq(self):
        return self._seq

    @property
    def type(self):
        return self._type

    @property
    def sim_time_ms(self):
        return self._sim_time_ms

    @property
    def payload(self):
        """The payload as a read-only view.

        Dicts are ``MappingProxyType`` and lists are tuples, so nothing reached
        through here can be mutated. Use :meth:`to_state` for a plain,
        JSON-serialisable copy.
        """
        return self._payload

    @property
    def source(self):
        return self._source

    @property
    def visibility(self):
        return self._visibility

    @property
    def is_learner_visible(self):
        return self._visibility is EventVisibility.LEARNER_VISIBLE

    @property
    def causes(self):
        """Parent event ids, in order. Ordering is part of the record."""
        return self._causes

    @property
    def prerequisites(self):
        """Prerequisite identifiers, in order. Metadata only for now."""
        return self._prerequisites

    # -- value semantics -----------------------------------------------------

    def __repr__(self):
        return ("Event(event_id=%r, seq=%d, type=%r, sim_time_ms=%d, source=%s, "
                "visibility=%s)" % (self._event_id, self._seq, self._type,
                                    self._sim_time_ms, self._source.value,
                                    self._visibility.value))

    def __eq__(self, other):
        if not isinstance(other, Event):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self):
        # Python's salted string hash is fine here: this value is used only for
        # in-memory dict and set membership within one process. It is never
        # serialised, digested or written into simulation state -- the
        # canonical JSON is what does that job.
        return hash(self._canonical)

    @property
    def canonical(self):
        """The canonical JSON text of this event. Equal events, equal text."""
        return self._canonical

    # -- state ---------------------------------------------------------------

    def to_state(self):
        """Return a canonical, JSON-safe mapping of this event.

        Contains no wall-clock value of any kind. Deterministic event state is
        simulation time only; diagnostic timestamps belong to the telemetry
        layer, outside this package.
        """
        return {
            "version": STATE_VERSION,
            "event_id": self._event_id,
            "seq": self._seq,
            "type": self._type,
            "sim_time_ms": self._sim_time_ms,
            "payload": _thaw_payload(self._payload),
            "source": self._source.value,
            "visibility": self._visibility.value,
            "causes": list(self._causes),
            "prerequisites": list(self._prerequisites),
        }

    _STATE_KEYS = frozenset({
        "version", "event_id", "seq", "type", "sim_time_ms", "payload",
        "source", "visibility", "causes", "prerequisites",
    })

    @classmethod
    def from_state(cls, state):
        """Rebuild an event from :meth:`to_state` output.

        Unknown keys are rejected rather than ignored: a misspelled field that
        is silently dropped is a data-loss bug that surfaces much later, as an
        unexplained digest mismatch.
        """
        if not isinstance(state, dict):
            raise InvalidEventStateError(
                "event state must be an object, got %s" % type(state).__name__)

        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidEventStateError(
                "event state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidEventStateError(
                "event state has unknown field(s) %s" % ", ".join(sorted(unknown)))

        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidEventStateError("event state version must be an int")
        if version != STATE_VERSION:
            raise InvalidEventStateError(
                "unsupported event state version %r (this build writes %d)"
                % (version, STATE_VERSION))

        try:
            return cls(
                event_id=state["event_id"],
                seq=state["seq"],
                type=state["type"],
                sim_time_ms=state["sim_time_ms"],
                payload=state["payload"],
                source=_coerce_enum(state["source"], EventSource, "source"),
                visibility=_coerce_enum(state["visibility"], EventVisibility,
                                        "visibility"),
                causes=state["causes"],
                prerequisites=state["prerequisites"],
            )
        except EventError as exc:
            raise InvalidEventStateError("event state: %s" % exc) from exc


# -- the event specification -------------------------------------------------

class EventSpec:
    """Everything needed to build a future event, minus what only time knows.

    An :class:`~rewindsec.core.events.Event` needs an ``event_id``, a ``seq``
    and a ``sim_time_ms``. A scheduled event has none of them yet: the sequence
    number is allocated by the session at fire time, and the id derives from it.
    A spec carries the rest -- type, payload, source, visibility, causes,
    prerequisites -- as validated, immutable, JSON-safe data.

    Deliberately not a callable, and deliberately not a partially built Event.
    A callable cannot be serialised or replayed, and an Event with placeholder
    identity fields would be a lie sitting in the queue waiting to be believed.
    """

    __slots__ = ("_type", "_payload", "_source", "_visibility", "_causes",
                 "_prerequisites", "_canonical")

    def __init__(self, type, payload=None, source=EventSource.SCHEDULER,
                 visibility=EventVisibility.LEARNER_VISIBLE,
                 causes=(), prerequisites=()):
        self._source = _coerce_enum(source, EventSource, "source")
        self._visibility = _coerce_enum(visibility, EventVisibility, "visibility")
        self._type = validate_event_type(type, self._visibility)
        self._payload = _freeze_payload({} if payload is None else payload)
        self._causes = _validate_ordered_unique(causes, "causes", _validate_event_id)
        self._prerequisites = _validate_ordered_unique(
            prerequisites, "prerequisites", _validate_prerequisite)
        self._canonical = canonical_json(self.to_state())

    @property
    def type(self):
        return self._type

    @property
    def payload(self):
        """Read-only view; see :attr:`rewindsec.core.events.Event.payload`."""
        return self._payload

    @property
    def source(self):
        return self._source

    @property
    def visibility(self):
        return self._visibility

    @property
    def causes(self):
        return self._causes

    @property
    def prerequisites(self):
        return self._prerequisites

    def build_event(self, event_id, seq, sim_time_ms):
        """Materialise the event this spec describes.

        The caller supplies the identity and the time, because the session owns
        the sequence counter and the clock. This method allocates nothing.
        """
        return Event(event_id=event_id, seq=seq, type=self._type,
                     sim_time_ms=sim_time_ms,
                     payload=_thaw_payload(self._payload),
                     source=self._source, visibility=self._visibility,
                     causes=self._causes, prerequisites=self._prerequisites)

    def __repr__(self):
        return "EventSpec(type=%r, source=%s, visibility=%s)" % (
            self._type, self._source.value, self._visibility.value)

    def __eq__(self, other):
        if not isinstance(other, EventSpec):
            return NotImplemented
        return self._canonical == other._canonical

    def __hash__(self):
        # In-memory use only; never serialised. See Event.__hash__.
        return hash(self._canonical)

    def to_state(self):
        return {
            "type": self._type,
            "payload": _thaw_payload(self._payload),
            "source": self._source.value,
            "visibility": self._visibility.value,
            "causes": list(self._causes),
            "prerequisites": list(self._prerequisites),
        }

    _STATE_KEYS = frozenset({"type", "payload", "source", "visibility",
                             "causes", "prerequisites"})

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidEventStateError(
                "event spec must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidEventStateError(
                "event spec is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidEventStateError(
                "event spec has unknown field(s) %s" % ", ".join(sorted(unknown)))
        try:
            return cls(type=state["type"], payload=state["payload"],
                       source=state["source"], visibility=state["visibility"],
                       causes=state["causes"],
                       prerequisites=state["prerequisites"])
        except EventError as exc:
            raise InvalidEventStateError("event spec: %s" % exc) from exc


def _coerce_enum(value, enum_cls, what):
    """Accept either the enum member or its serialised string value."""
    if isinstance(value, enum_cls):
        return value
    if isinstance(value, str):
        try:
            return enum_cls(value)
        except ValueError:
            pass
    raise InvalidEventFieldError(
        "%s must be one of %s, got %r"
        % (what, ", ".join(member.value for member in enum_cls), value))

