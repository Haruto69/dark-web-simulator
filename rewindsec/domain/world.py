"""Storage-independent, versioned authoritative workplace state.

Batch 1 builds the generic foundation only: named components/namespaces
holding validated JSON-safe values, an explicit mutation operation, and an
auditable mutation log. It intentionally does not know about Mail, Files,
Browser or any other workstation application -- Batch 2 specialises this
foundation for each of those. Building their fields in now would be exactly
the kind of premature detail Architecture Spec v1.1 S11 warns against.
"""

from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError, UnknownReferenceError)
from rewindsec.domain.identifiers import (derive_id, validate_bounded_str,
                                          validate_identity)
from rewindsec.domain.json_safe import freeze, thaw
from rewindsec.domain.sequences import SequenceCounter

__all__ = ["WorldMutation", "WorldState"]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

#: Domain-separation label for world-mutation id derivation.
_MUTATION_ID_LABEL = "rewindsec2/world-mutation-id/v1"

_MAX_NAMESPACE_LENGTH = 64
_MAX_KEY_LENGTH = 128


def _validate_sim_time(value, what):
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidDomainStateError(str(exc)) from exc


class WorldMutation:
    """One recorded, auditable change to the world.

    Immutable once constructed, the same way :class:`~rewindsec.core.events.Event`
    is: a mutation record is history, and history does not change after the
    fact.
    """

    __slots__ = ("_mutation_id", "_seq", "_namespace", "_key", "_old_value",
                 "_new_value", "_cause_event_id", "_sim_time_ms")

    def __init__(self, mutation_id, seq, namespace, key, old_value, new_value,
                 cause_event_id, sim_time_ms):
        self._mutation_id = validate_identity(mutation_id, "mutation_id")
        self._seq = seq
        self._namespace = namespace
        self._key = key
        self._old_value = freeze(old_value, path="old_value")
        self._new_value = freeze(new_value, path="new_value")
        self._cause_event_id = (
            None if cause_event_id is None
            else validate_identity(cause_event_id, "cause_event_id"))
        self._sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")

    @property
    def mutation_id(self):
        return self._mutation_id

    @property
    def seq(self):
        return self._seq

    @property
    def namespace(self):
        return self._namespace

    @property
    def key(self):
        return self._key

    @property
    def old_value(self):
        return self._old_value

    @property
    def new_value(self):
        return self._new_value

    @property
    def cause_event_id(self):
        return self._cause_event_id

    @property
    def sim_time_ms(self):
        return self._sim_time_ms

    def __repr__(self):
        return ("WorldMutation(mutation_id=%r, seq=%d, namespace=%r, key=%r)"
                % (self._mutation_id, self._seq, self._namespace, self._key))

    def to_state(self):
        return {
            "mutation_id": self._mutation_id,
            "seq": self._seq,
            "namespace": self._namespace,
            "key": self._key,
            "old_value": thaw(self._old_value),
            "new_value": thaw(self._new_value),
            "cause_event_id": self._cause_event_id,
            "sim_time_ms": self._sim_time_ms,
        }

    _STATE_KEYS = frozenset({"mutation_id", "seq", "namespace", "key", "old_value",
                             "new_value", "cause_event_id", "sim_time_ms"})

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "world mutation must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "world mutation is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "world mutation has unknown field(s) %s" % ", ".join(sorted(unknown)))
        try:
            return cls(mutation_id=state["mutation_id"], seq=state["seq"],
                       namespace=state["namespace"], key=state["key"],
                       old_value=state["old_value"], new_value=state["new_value"],
                       cause_event_id=state["cause_event_id"],
                       sim_time_ms=state["sim_time_ms"])
        except DomainError as exc:
            raise InvalidDomainStateError("world mutation: %s" % exc) from exc


class WorldState:
    """The authoritative synthetic workplace state of one session."""

    __slots__ = ("_identity", "_components", "_mutation_seq", "_mutations")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "world identity")
        #: namespace -> {key: frozen value}
        self._components = {}
        self._mutation_seq = SequenceCounter("world_mutation")
        self._mutations = []

    @property
    def identity(self):
        return self._identity

    @property
    def revision(self):
        """How many mutations have been applied. Monotonic, never decreases."""
        return len(self._mutations)

    def __repr__(self):
        return "WorldState(identity=%r, namespaces=%d, revision=%d)" % (
            self._identity, len(self._components), self.revision)

    # -- reads -----------------------------------------------------------

    def namespaces(self):
        return tuple(sorted(self._components))

    def get_component(self, namespace):
        """Every key/value pair in *namespace*, or an empty mapping."""
        namespace = validate_bounded_str(namespace, "namespace", _MAX_NAMESPACE_LENGTH)
        component = self._components.get(namespace, {})
        return {key: thaw(value) for key, value in sorted(component.items())}

    def get(self, namespace, key, default=None):
        namespace = validate_bounded_str(namespace, "namespace", _MAX_NAMESPACE_LENGTH)
        key = validate_bounded_str(key, "key", _MAX_KEY_LENGTH)
        component = self._components.get(namespace)
        if component is None or key not in component:
            return default
        return thaw(component[key])

    def has(self, namespace, key):
        namespace = validate_bounded_str(namespace, "namespace", _MAX_NAMESPACE_LENGTH)
        key = validate_bounded_str(key, "key", _MAX_KEY_LENGTH)
        component = self._components.get(namespace)
        return component is not None and key in component

    # -- mutation ----------------------------------------------------------

    def mutate(self, namespace, key, value, sim_time_ms, cause_event_id=None):
        """Set ``(namespace, key)`` to *value* and record an auditable mutation.

        Every mutation is recorded, including one that sets a key to the same
        value it already held: a consequence that "re-confirms" state is still
        a consequence that happened, and the causal graph may need to point at
        it.
        """
        namespace = validate_bounded_str(namespace, "namespace", _MAX_NAMESPACE_LENGTH)
        key = validate_bounded_str(key, "key", _MAX_KEY_LENGTH)
        frozen_value = freeze(value, path="value")
        sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")

        component = self._components.get(namespace)
        old_value = None if component is None else component.get(key)

        seq = self._mutation_seq.peek()
        mutation_id = _derive_mutation_id(self._identity, seq)
        record = WorldMutation(
            mutation_id=mutation_id, seq=seq, namespace=namespace, key=key,
            old_value=thaw(old_value), new_value=thaw(frozen_value),
            cause_event_id=cause_event_id, sim_time_ms=sim_time_ms)
        self._mutation_seq.advance()

        if component is None:
            component = {}
            self._components[namespace] = component
        component[key] = frozen_value
        self._mutations.append(record)
        return record

    def mutations(self):
        """Every mutation, in the order it was applied."""
        return tuple(self._mutations)

    # -- state -------------------------------------------------------------

    def capture_state(self):
        components = {}
        for namespace in sorted(self._components):
            component = self._components[namespace]
            components[namespace] = {key: thaw(component[key])
                                     for key in sorted(component)}
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "mutation_seq": self._mutation_seq.capture_state(),
            "components": components,
            "mutations": [m.to_state() for m in self._mutations],
        }

    _STATE_KEYS = frozenset({"version", "identity", "mutation_seq", "components",
                             "mutations"})

    def restore_state(self, state):
        (identity, mutation_seq, components, mutations) = self._parse_state(
            state, expected_identity=self._identity)
        self._identity = identity
        self._mutation_seq = mutation_seq
        self._components = components
        self._mutations = mutations

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        (_, mutation_seq, components, mutations) = cls._parse_state(
            state, expected_identity=identity)
        instance._mutation_seq = mutation_seq
        instance._components = components
        instance._mutations = mutations
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "world state must be an object, got %s" % type(state).__name__)
        missing = WorldState._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "world state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - WorldState._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "world state has unknown field(s) %s" % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("world state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported world state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "world state identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "world state belongs to identity %r, not %r"
                % (identity, expected_identity))

        mutation_seq = SequenceCounter.from_state(state["mutation_seq"])

        raw_components = state["components"]
        if not isinstance(raw_components, dict):
            raise InvalidDomainStateError(
                "world state components must be an object, got %s"
                % type(raw_components).__name__)
        components = {}
        for namespace, raw_component in raw_components.items():
            namespace = validate_bounded_str(
                namespace, "world state namespace", _MAX_NAMESPACE_LENGTH)
            if not isinstance(raw_component, dict):
                raise InvalidDomainStateError(
                    "world state component %r must be an object" % namespace)
            component = {}
            for key, value in raw_component.items():
                key = validate_bounded_str(key, "world state key", _MAX_KEY_LENGTH)
                component[key] = freeze(value, path="%s.%s" % (namespace, key))
            components[namespace] = component

        raw_mutations = state["mutations"]
        if not isinstance(raw_mutations, list):
            raise InvalidDomainStateError(
                "world state mutations must be a list, got %s"
                % type(raw_mutations).__name__)
        mutations, seen_seq = [], set()
        for raw in raw_mutations:
            mutation = WorldMutation.from_state(raw)
            expected_id = _derive_mutation_id(identity, mutation.seq)
            if mutation.mutation_id != expected_id:
                raise InvalidDomainStateError(
                    "world mutation %s does not match its derived id %s for "
                    "seq %d" % (mutation.mutation_id, expected_id, mutation.seq))
            if mutation.seq in seen_seq:
                raise InvalidDomainStateError(
                    "duplicate world mutation seq %d" % mutation.seq)
            if mutation.seq >= mutation_seq.next_value:
                raise InvalidDomainStateError(
                    "world mutation seq %d is not below the counter %d"
                    % (mutation.seq, mutation_seq.next_value))
            seen_seq.add(mutation.seq)
            mutations.append(mutation)
        mutations.sort(key=lambda m: m.seq)

        return identity, mutation_seq, components, mutations


def _derive_mutation_id(identity, seq):
    return derive_id(_MUTATION_ID_LABEL, identity, seq)
