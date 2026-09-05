"""A monotonic, persisted, session-owned sequence counter.

``rewindsec.core.events`` deliberately does not allocate its own ``seq``:
sequence numbers must be unique and gapless across a whole session, and no
single ``Event`` can know that. :class:`SequenceCounter` is that owner. A
:class:`~rewindsec.domain.session.SimulationSession` holds two independent
instances -- one for the event log, one for the learner-action log -- because
mixing them would make "the Nth thing that happened" ambiguous between two
kinds of thing.

The peek/advance split is what gives "failed operations do not silently
consume sequence numbers" a real mechanism instead of a comment: a caller
peeks the next value, builds and validates whatever that value identifies
(an ``Event``, a ``LearnerAction``), and only calls :meth:`advance` once that
construction has actually succeeded. If validation raises, the counter is
untouched.
"""

from rewindsec.domain.errors import InvalidDomainStateError, SequenceOverflowError
from rewindsec.domain.identifiers import (MAX_JSON_SAFE_INT, validate_identity,
                                          validate_nonneg_int)

__all__ = ["SequenceCounter"]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1


class SequenceCounter:
    """A monotonic counter of sequence numbers, starting at zero.

    ``name`` identifies which sequence this is (``"event"``, ``"action"``)
    purely for error messages and for identity-mismatch checks on restore; it
    plays no role in the numbers produced.
    """

    __slots__ = ("_name", "_next")

    def __init__(self, name, start=0):
        self._name = validate_identity(name, "sequence name")
        self._next = validate_nonneg_int(start, "sequence start", MAX_JSON_SAFE_INT)

    @property
    def name(self):
        return self._name

    @property
    def next_value(self):
        """The value :meth:`advance` will hand out next. Read-only; a peek."""
        return self._next

    def __repr__(self):
        return "SequenceCounter(name=%r, next=%d)" % (self._name, self._next)

    def peek(self):
        """Return the next value without consuming it.

        Callers build and fully validate whatever this value identifies
        *before* calling :meth:`advance`, so a rejected construction leaves
        the counter exactly where it was.
        """
        return self._next

    def advance(self):
        """Consume and return the value that :meth:`peek` last reported.

        Raises :class:`SequenceOverflowError` rather than wrapping, so a
        session that has genuinely run out of sequence numbers fails loudly
        instead of silently reusing one.
        """
        value = self._next
        if value >= MAX_JSON_SAFE_INT:
            raise SequenceOverflowError(
                "sequence %r is exhausted at the JSON-safe bound %d"
                % (self._name, MAX_JSON_SAFE_INT))
        self._next = value + 1
        return value

    # -- state ---------------------------------------------------------------

    def capture_state(self):
        return {"version": STATE_VERSION, "name": self._name, "next": self._next}

    def restore_state(self, state):
        """Restore this counter from a captured state.

        The payload's name must match this counter's -- a mismatch means a
        session is restoring the wrong sequence into the wrong owner, which
        would silently make event and action numbering swap meanings.
        """
        name, next_value = self._parse_state(state, expected_name=self._name)
        self._name = name
        self._next = next_value

    @classmethod
    def from_state(cls, state):
        name, next_value = cls._parse_state(state, expected_name=None)
        instance = cls(name, start=next_value)
        return instance

    @classmethod
    def _parse_state(cls, state, expected_name):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "sequence state must be an object, got %s" % type(state).__name__)
        required = {"version", "name", "next"}
        missing = required - set(state)
        if missing:
            raise InvalidDomainStateError(
                "sequence state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - required
        if unknown:
            raise InvalidDomainStateError(
                "sequence state has unknown field(s) %s" % ", ".join(sorted(unknown)))

        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("sequence state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported sequence state version %r (this build writes %d)"
                % (version, STATE_VERSION))

        try:
            name = validate_identity(state["name"], "sequence state name")
        except Exception as exc:
            raise InvalidDomainStateError("sequence state name: %s" % exc) from exc
        if expected_name is not None and name != expected_name:
            raise InvalidDomainStateError(
                "sequence state belongs to %r, not %r" % (name, expected_name))

        try:
            next_value = validate_nonneg_int(state["next"], "sequence state next")
        except Exception as exc:
            raise InvalidDomainStateError("sequence state next: %s" % exc) from exc

        return name, next_value
