"""LearnerAction: the record of something the learner did, distinct from
SessionEvent (something the world did or something that happened to the
learner). Architecture Spec v1.1 S8 and S23 draw this distinction; this module
implements it.

Observational actions (open, inspect, search, read) usually reveal
information and drive :meth:`ContextLedger.observe`. Consequential actions
(submit credentials, approve MFA, isolate the workstation) can change world or
incident state. Batch 1 defines the record and its classification; it does
not implement any application-specific action behaviour -- which concrete
action types exist, and what each one does to the world, is Batch 2 and 3.

Deterministic identity mirrors ``rewindsec.core.events.derive_event_id``
exactly, with a distinct domain-separation label so an action id and an event
id built from the same ``(session_id, seq)`` pair are always different
strings.
"""

import hashlib

from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms
from rewindsec.domain.enums import ActionClass, coerce_enum
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError)
from rewindsec.domain.identifiers import (MAX_IDENTITY_LENGTH, validate_bounded_str,
                                          validate_identity, validate_nonneg_int)
from rewindsec.domain.json_safe import freeze, thaw
from rewindsec.domain.sequences import SequenceCounter

__all__ = ["LearnerAction", "ActionLog", "derive_action_id", "ACTION_ID_LENGTH"]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

#: Distinct from every other id label in this codebase, so an action id can
#: never collide with an event id, a world-mutation id or a consequence id
#: derived from the same ``(identity, seq)`` pair.
_ACTION_ID_LABEL = "rewindsec2/action-id/v1"

ACTION_ID_LENGTH = 32

_MAX_ACTION_TYPE_LENGTH = 96


def derive_action_id(session_identity, seq):
    """Derive a stable action id from the session identity and sequence."""
    session_identity = validate_identity(session_identity, "session identity")
    seq = validate_nonneg_int(seq, "seq")
    material = "%s|%s|%d" % (_ACTION_ID_LABEL, session_identity, seq)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:ACTION_ID_LENGTH]


def _validate_action_id(value, what="action_id"):
    if not isinstance(value, str):
        raise InvalidDomainStateError(
            "%s must be a str, got %s" % (what, type(value).__name__))
    if len(value) != ACTION_ID_LENGTH:
        raise InvalidDomainStateError(
            "%s must be %d characters, got %d" % (what, ACTION_ID_LENGTH, len(value)))
    for char in value:
        if char not in "0123456789abcdef":
            raise InvalidDomainStateError("%s must be lowercase hex: %r" % (what, value))
    return value


def _validate_action_type(value):
    """A namespaced dotted string, ``namespace.name``, 2-4 segments.

    Mirrors ``rewindsec.core.events.validate_event_type`` in shape (so the
    same authoring convention applies to both) but does not enforce the
    threat-family exclusion: an action is something the *learner* did, driven
    by the learner's own interpretation, not a system label the UI renders as
    a category.
    """
    if not isinstance(value, str):
        raise InvalidDomainStateError(
            "action_type must be a str, got %s" % type(value).__name__)
    if not value:
        raise InvalidDomainStateError("action_type must not be empty")
    if len(value) > _MAX_ACTION_TYPE_LENGTH:
        raise InvalidDomainStateError(
            "action_type must be at most %d characters, got %d"
            % (_MAX_ACTION_TYPE_LENGTH, len(value)))
    segments = value.split(".")
    if not 2 <= len(segments) <= 4:
        raise InvalidDomainStateError(
            "action_type must have 2 to 4 dot-separated segments "
            "(namespace.name): %r" % (value,))
    for segment in segments:
        if not segment:
            raise InvalidDomainStateError(
                "action_type has an empty segment: %r" % (value,))
        for index, char in enumerate(segment):
            if not char.isascii():
                raise InvalidDomainStateError("action_type must be ASCII: %r" % (value,))
            if char == "_" and index > 0:
                continue
            if char.isdigit() and index > 0:
                continue
            if not (char.isalpha() and char.islower()):
                raise InvalidDomainStateError(
                    "action_type segments must match [a-z][a-z0-9_]*: %r" % (value,))
    return value


def _validate_sim_time(value, what):
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidDomainStateError(str(exc)) from exc


class LearnerAction:
    """One immutable recorded fact about what the learner did.

    No credentials, clipboard contents, or free-text sensitive payloads are
    ever appropriate here -- ``params`` is JSON-safe structured metadata only
    (an event id being referenced, a UI element name), never secrets.
    """

    __slots__ = ("_action_id", "_seq", "_session_id", "_sim_time_ms",
                 "_action_type", "_classification", "_target", "_params")

    def __init__(self, action_id, seq, session_id, sim_time_ms, action_type,
                 classification, target=None, params=None):
        self._action_id = _validate_action_id(action_id)
        self._seq = validate_nonneg_int(seq, "seq")
        self._session_id = validate_identity(session_id, "session_id")
        self._sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        self._action_type = _validate_action_type(action_type)
        self._classification = coerce_enum(classification, ActionClass, "classification")
        self._target = (None if target is None
                        else validate_bounded_str(target, "target", MAX_IDENTITY_LENGTH))
        self._params = freeze({} if params is None else params, path="params")

    @classmethod
    def create(cls, session_id, seq, sim_time_ms, action_type, classification,
              target=None, params=None):
        """Build an action, deriving ``action_id`` from the session identity."""
        action_id = derive_action_id(session_id, seq)
        return cls(action_id=action_id, seq=seq, session_id=session_id,
                   sim_time_ms=sim_time_ms, action_type=action_type,
                   classification=classification, target=target, params=params)

    # -- fields --------------------------------------------------------------

    @property
    def action_id(self):
        return self._action_id

    @property
    def seq(self):
        return self._seq

    @property
    def session_id(self):
        return self._session_id

    @property
    def sim_time_ms(self):
        return self._sim_time_ms

    @property
    def action_type(self):
        return self._action_type

    @property
    def classification(self):
        return self._classification

    @property
    def is_observational(self):
        return self._classification is ActionClass.OBSERVATIONAL

    @property
    def is_consequential(self):
        return self._classification is ActionClass.CONSEQUENTIAL

    @property
    def target(self):
        return self._target

    @property
    def params(self):
        return self._params

    def __repr__(self):
        return ("LearnerAction(action_id=%r, seq=%d, action_type=%r, "
                "classification=%s)" % (self._action_id, self._seq,
                                        self._action_type, self._classification.value))

    def __eq__(self, other):
        if not isinstance(other, LearnerAction):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash((self._action_id, self._seq))

    # -- state ---------------------------------------------------------------

    def to_state(self):
        return {
            "version": STATE_VERSION,
            "action_id": self._action_id,
            "seq": self._seq,
            "session_id": self._session_id,
            "sim_time_ms": self._sim_time_ms,
            "action_type": self._action_type,
            "classification": self._classification.value,
            "target": self._target,
            "params": thaw(self._params),
        }

    _STATE_KEYS = frozenset({"version", "action_id", "seq", "session_id",
                             "sim_time_ms", "action_type", "classification",
                             "target", "params"})

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "learner action must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "learner action is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "learner action has unknown field(s) %s" % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("learner action version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported learner action version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return cls(action_id=state["action_id"], seq=state["seq"],
                       session_id=state["session_id"],
                       sim_time_ms=state["sim_time_ms"],
                       action_type=state["action_type"],
                       classification=state["classification"],
                       target=state["target"], params=state["params"])
        except DomainError as exc:
            raise InvalidDomainStateError("learner action: %s" % exc) from exc


class ActionLog:
    """The append-only, session-owned log of learner actions.

    Owns the action sequence counter. ``identity`` must equal every recorded
    action's ``session_id`` -- enforced on every append and re-checked on
    restore -- so an action log can never be silently populated with actions
    derived under a different session.
    """

    __slots__ = ("_identity", "_seq", "_actions")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "action log identity")
        self._seq = SequenceCounter("action")
        self._actions = []

    @property
    def identity(self):
        return self._identity

    @property
    def next_seq(self):
        return self._seq.peek()

    def __repr__(self):
        return "ActionLog(identity=%r, actions=%d)" % (
            self._identity, len(self._actions))

    def record(self, sim_time_ms, action_type, classification, target=None,
              params=None):
        """Validate, allocate a sequence number, and append one action.

        Validation happens on a candidate built from the peeked (not yet
        consumed) sequence number, so a rejected action leaves the sequence
        counter untouched.
        """
        seq = self._seq.peek()
        action = LearnerAction.create(
            session_id=self._identity, seq=seq, sim_time_ms=sim_time_ms,
            action_type=action_type, classification=classification,
            target=target, params=params)
        self._seq.advance()
        self._actions.append(action)
        return action

    def get(self, action_id):
        from rewindsec.domain.errors import UnknownReferenceError
        action_id = _validate_action_id(action_id)
        for action in self._actions:
            if action.action_id == action_id:
                return action
        raise UnknownReferenceError("no learner action with id %r" % action_id)

    def has(self, action_id):
        try:
            self.get(action_id)
        except Exception:
            return False
        return True

    def actions(self):
        """Every recorded action, in the order it was recorded."""
        return tuple(self._actions)

    # -- state -----------------------------------------------------------

    def capture_state(self):
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "seq": self._seq.capture_state(),
            "actions": [a.to_state() for a in self._actions],
        }

    _STATE_KEYS = frozenset({"version", "identity", "seq", "actions"})

    def restore_state(self, state):
        identity, seq, actions = self._parse_state(state, expected_identity=self._identity)
        self._identity = identity
        self._seq = seq
        self._actions = actions

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        _, seq, actions = cls._parse_state(state, expected_identity=identity)
        instance._seq = seq
        instance._actions = actions
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "action log state must be an object, got %s" % type(state).__name__)
        missing = ActionLog._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "action log state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - ActionLog._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "action log state has unknown field(s) %s" % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("action log state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported action log state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "action log state identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "action log state belongs to identity %r, not %r"
                % (identity, expected_identity))

        seq = SequenceCounter.from_state(state["seq"])

        raw_actions = state["actions"]
        if not isinstance(raw_actions, list):
            raise InvalidDomainStateError(
                "action log state actions must be a list, got %s"
                % type(raw_actions).__name__)

        actions, seen_seq = [], set()
        for raw in raw_actions:
            action = LearnerAction.from_state(raw)
            if action.session_id != identity:
                raise IdentityMismatchError(
                    "action %s belongs to session %r, not %r"
                    % (action.action_id, action.session_id, identity))
            expected_id = derive_action_id(identity, action.seq)
            if action.action_id != expected_id:
                raise InvalidDomainStateError(
                    "action %s does not match its derived id %s for seq %d"
                    % (action.action_id, expected_id, action.seq))
            if action.seq in seen_seq:
                raise InvalidDomainStateError(
                    "duplicate action seq %d" % action.seq)
            if action.seq >= seq.next_value:
                raise InvalidDomainStateError(
                    "action seq %d is not below the counter %d"
                    % (action.seq, seq.next_value))
            seen_seq.add(action.seq)
            actions.append(action)
        actions.sort(key=lambda a: a.seq)

        return identity, seq, actions
