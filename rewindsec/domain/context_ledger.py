"""The Context Ledger: available context vs. observed context.

Architecture Spec v1.1 S7 makes this a first-class domain object rather than a
loose collection of booleans, and draws one load-bearing distinction:

    AVAILABLE CONTEXT  !=  OBSERVED CONTEXT

A fact can exist and be legitimately reachable by the learner (a domain name
mentioned in a legitimate email, say) without the learner ever having opened
that email and read it. Later threat eligibility and evidence-based scoring
both read from this distinction, so it has to be real state, not something
inferred after the fact from the event log.

This module implements the ledger and its facts. It does not implement
eligibility, hazard/pressure, or scoring -- those are later batches and they
consume this ledger's queries, they do not live inside it.
"""

from types import MappingProxyType

from rewindsec.core.simtime import SimTimeError, validate_sim_time_ms
from rewindsec.domain.errors import (DomainError, IdentityMismatchError,
                                     InvalidDomainStateError, UnknownReferenceError)
from rewindsec.domain.identifiers import (MAX_IDENTITY_LENGTH, validate_bounded_str,
                                          validate_identity, validate_nonneg_int)
from rewindsec.domain.json_safe import freeze, thaw

__all__ = [
    "ContextFact",
    "ContextLedger",
    "DuplicateFactError",
    "FactNotAvailableError",
]

#: Bumped only when the serialised shape changes incompatibly.
STATE_VERSION = 1

_MAX_CATEGORY_LENGTH = 64
_MAX_SOURCE_LENGTH = 128


class DuplicateFactError(DomainError, ValueError):
    """A fact with this id already exists; use :meth:`ContextLedger.update_fact`."""


class FactNotAvailableError(DomainError, ValueError):
    """The learner cannot observe a fact the workplace has not made available."""


def _validate_sim_time(value, what):
    try:
        return validate_sim_time_ms(value, what)
    except SimTimeError as exc:
        raise InvalidDomainStateError(str(exc)) from exc


class ContextFact:
    """One organisational fact tracked by the ledger.

    Instances are handed out by :class:`ContextLedger` and are conceptually
    read-only from the outside; the ledger is the only thing that flips
    ``available``/``observed`` or bumps ``version``, exactly the way
    :class:`~rewindsec.core.scheduler.ScheduledEntry` restricts cancellation to
    its owning scheduler.
    """

    __slots__ = ("_fact_id", "_category", "_value", "_source",
                 "_introduced_by_event_id", "_introduced_at_ms",
                 "_last_updated_at_ms", "_available", "_available_at_ms",
                 "_observed", "_observed_by_action_id", "_observed_at_ms",
                 "_version")

    def __init__(self, fact_id, category, value, source, introduced_by_event_id,
                 introduced_at_ms, last_updated_at_ms, available, available_at_ms,
                 observed, observed_by_action_id, observed_at_ms, version):
        self._fact_id = validate_identity(fact_id, "fact_id")
        self._category = validate_bounded_str(category, "category", _MAX_CATEGORY_LENGTH)
        self._value = freeze(value, path="fact value")
        self._source = validate_bounded_str(source, "source", _MAX_SOURCE_LENGTH)
        self._introduced_by_event_id = (
            None if introduced_by_event_id is None
            else validate_identity(introduced_by_event_id, "introduced_by_event_id"))
        self._introduced_at_ms = _validate_sim_time(introduced_at_ms, "introduced_at_ms")
        self._last_updated_at_ms = _validate_sim_time(
            last_updated_at_ms, "last_updated_at_ms")

        if not isinstance(available, bool):
            raise InvalidDomainStateError(
                "fact %r: available must be a bool" % fact_id)
        self._available = available
        self._available_at_ms = (
            None if available_at_ms is None
            else _validate_sim_time(available_at_ms, "available_at_ms"))
        if available and self._available_at_ms is None:
            raise InvalidDomainStateError(
                "fact %r: available facts must record available_at_ms" % fact_id)
        if not available and self._available_at_ms is not None:
            raise InvalidDomainStateError(
                "fact %r: unavailable facts must not record available_at_ms" % fact_id)

        if not isinstance(observed, bool):
            raise InvalidDomainStateError(
                "fact %r: observed must be a bool" % fact_id)
        self._observed = observed
        self._observed_by_action_id = (
            None if observed_by_action_id is None
            else validate_identity(observed_by_action_id, "observed_by_action_id"))
        self._observed_at_ms = (
            None if observed_at_ms is None
            else _validate_sim_time(observed_at_ms, "observed_at_ms"))
        if observed and (self._observed_by_action_id is None
                         or self._observed_at_ms is None):
            raise InvalidDomainStateError(
                "fact %r: observed facts must record observed_by_action_id "
                "and observed_at_ms" % fact_id)
        if not observed and (self._observed_by_action_id is not None
                             or self._observed_at_ms is not None):
            raise InvalidDomainStateError(
                "fact %r: unobserved facts must not record observation fields"
                % fact_id)
        if observed and not available:
            raise InvalidDomainStateError(
                "fact %r: cannot be observed without being available" % fact_id)

        self._version = validate_nonneg_int(version, "version")
        if self._version < 1:
            raise InvalidDomainStateError("fact %r: version must be at least 1" % fact_id)

    # -- fields ----------------------------------------------------------

    @property
    def fact_id(self):
        return self._fact_id

    @property
    def category(self):
        return self._category

    @property
    def value(self):
        return self._value

    @property
    def source(self):
        return self._source

    @property
    def introduced_by_event_id(self):
        return self._introduced_by_event_id

    @property
    def introduced_at_ms(self):
        return self._introduced_at_ms

    @property
    def last_updated_at_ms(self):
        return self._last_updated_at_ms

    @property
    def available(self):
        return self._available

    @property
    def available_at_ms(self):
        return self._available_at_ms

    @property
    def observed(self):
        return self._observed

    @property
    def observed_by_action_id(self):
        return self._observed_by_action_id

    @property
    def observed_at_ms(self):
        return self._observed_at_ms

    @property
    def version(self):
        return self._version

    def __repr__(self):
        return ("ContextFact(fact_id=%r, category=%r, available=%s, observed=%s, "
                "version=%d)" % (self._fact_id, self._category, self._available,
                                 self._observed, self._version))

    def __eq__(self, other):
        if not isinstance(other, ContextFact):
            return NotImplemented
        return self.to_state() == other.to_state()

    def __hash__(self):
        return hash((self._fact_id, self._version))

    # -- state -------------------------------------------------------------

    def to_state(self):
        return {
            "fact_id": self._fact_id,
            "category": self._category,
            "value": thaw(self._value),
            "source": self._source,
            "introduced_by_event_id": self._introduced_by_event_id,
            "introduced_at_ms": self._introduced_at_ms,
            "last_updated_at_ms": self._last_updated_at_ms,
            "available": self._available,
            "available_at_ms": self._available_at_ms,
            "observed": self._observed,
            "observed_by_action_id": self._observed_by_action_id,
            "observed_at_ms": self._observed_at_ms,
            "version": self._version,
        }

    _STATE_KEYS = frozenset({
        "fact_id", "category", "value", "source", "introduced_by_event_id",
        "introduced_at_ms", "last_updated_at_ms", "available", "available_at_ms",
        "observed", "observed_by_action_id", "observed_at_ms", "version",
    })

    @classmethod
    def from_state(cls, state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "context fact must be an object, got %s" % type(state).__name__)
        missing = cls._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "context fact is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - cls._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "context fact has unknown field(s) %s" % ", ".join(sorted(unknown)))
        try:
            return cls(
                fact_id=state["fact_id"], category=state["category"],
                value=state["value"], source=state["source"],
                introduced_by_event_id=state["introduced_by_event_id"],
                introduced_at_ms=state["introduced_at_ms"],
                last_updated_at_ms=state["last_updated_at_ms"],
                available=state["available"], available_at_ms=state["available_at_ms"],
                observed=state["observed"],
                observed_by_action_id=state["observed_by_action_id"],
                observed_at_ms=state["observed_at_ms"], version=state["version"])
        except InvalidDomainStateError:
            raise
        except DomainError as exc:
            raise InvalidDomainStateError("context fact: %s" % exc) from exc


class ContextLedger:
    """The Context Ledger of one session.

    ``identity`` is the owning session id. It plays no role in fact-id
    derivation (fact ids are content-authored, e.g. ``"company_domain"``, not
    derived) but it is recorded in captured state and checked on restore, so a
    ledger can never be silently restored into the wrong session.
    """

    __slots__ = ("_identity", "_facts")

    def __init__(self, identity):
        self._identity = validate_identity(identity, "ledger identity")
        self._facts = {}

    @property
    def identity(self):
        return self._identity

    def __repr__(self):
        return "ContextLedger(identity=%r, facts=%d)" % (
            self._identity, len(self._facts))

    # -- mutation ------------------------------------------------------------

    def introduce_fact(self, fact_id, category, value, source, sim_time_ms,
                       introduced_by_event_id=None, available=True):
        """Introduce a new fact into the ledger and return it.

        Raises :class:`DuplicateFactError` if ``fact_id`` already exists --
        re-introduction is :meth:`update_fact`, a distinct operation, so a
        caller cannot accidentally reset a fact's observation history by
        calling the wrong one.
        """
        fact_id = validate_identity(fact_id, "fact_id")
        if fact_id in self._facts:
            raise DuplicateFactError("fact %r already exists" % fact_id)
        sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        fact = ContextFact(
            fact_id=fact_id, category=category, value=value, source=source,
            introduced_by_event_id=introduced_by_event_id,
            introduced_at_ms=sim_time_ms, last_updated_at_ms=sim_time_ms,
            available=bool(available) if not isinstance(available, bool) else available,
            available_at_ms=sim_time_ms if available else None,
            observed=False, observed_by_action_id=None, observed_at_ms=None,
            version=1)
        self._facts[fact_id] = fact
        return fact

    def update_fact(self, fact_id, value, source, sim_time_ms,
                    introduced_by_event_id=None):
        """Update an existing fact's value/source and bump its version.

        Availability and observation state are untouched: updating what a
        fact *means* (a corrected payroll domain, say) must not retroactively
        make an unobserved fact look observed or vice versa.
        """
        existing = self.get(fact_id)
        sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        updated = ContextFact(
            fact_id=existing.fact_id, category=existing.category, value=value,
            source=source, introduced_by_event_id=introduced_by_event_id,
            introduced_at_ms=existing.introduced_at_ms,
            last_updated_at_ms=sim_time_ms,
            available=existing.available, available_at_ms=existing.available_at_ms,
            observed=existing.observed,
            observed_by_action_id=existing.observed_by_action_id,
            observed_at_ms=existing.observed_at_ms, version=existing.version + 1)
        self._facts[fact_id] = updated
        return updated

    def make_available(self, fact_id, sim_time_ms):
        """Mark a fact available to the learner. Idempotent.

        A repeat call once a fact is already available is a no-op that keeps
        the original ``available_at_ms`` -- the first moment it genuinely
        became available is the one that matters for fairness.
        """
        existing = self.get(fact_id)
        if existing.available:
            return existing
        sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        updated = ContextFact(
            fact_id=existing.fact_id, category=existing.category,
            value=thaw(existing.value), source=existing.source,
            introduced_by_event_id=existing.introduced_by_event_id,
            introduced_at_ms=existing.introduced_at_ms,
            last_updated_at_ms=existing.last_updated_at_ms,
            available=True, available_at_ms=sim_time_ms,
            observed=False, observed_by_action_id=None, observed_at_ms=None,
            version=existing.version)
        self._facts[fact_id] = updated
        return updated

    def observe(self, fact_id, action_id, sim_time_ms):
        """Record that ``action_id`` observed ``fact_id``. Idempotent.

        Raises :class:`FactNotAvailableError` if the fact has not yet been
        made available -- a learner cannot inspect information the simulated
        workplace has not legitimately surfaced. A repeat observation is a
        no-op that keeps the *first* observing action and timestamp, because
        that is the moment scoring and eligibility care about.
        """
        existing = self.get(fact_id)
        if not existing.available:
            raise FactNotAvailableError(
                "fact %r is not available to the learner yet" % fact_id)
        if existing.observed:
            return existing
        action_id = validate_identity(action_id, "action_id")
        sim_time_ms = _validate_sim_time(sim_time_ms, "sim_time_ms")
        updated = ContextFact(
            fact_id=existing.fact_id, category=existing.category,
            value=thaw(existing.value), source=existing.source,
            introduced_by_event_id=existing.introduced_by_event_id,
            introduced_at_ms=existing.introduced_at_ms,
            last_updated_at_ms=existing.last_updated_at_ms,
            available=True, available_at_ms=existing.available_at_ms,
            observed=True, observed_by_action_id=action_id,
            observed_at_ms=sim_time_ms, version=existing.version)
        self._facts[fact_id] = updated
        return updated

    # -- queries ---------------------------------------------------------

    def get(self, fact_id):
        fact_id = validate_identity(fact_id, "fact_id")
        fact = self._facts.get(fact_id)
        if fact is None:
            raise UnknownReferenceError("no fact with id %r" % fact_id)
        return fact

    def has(self, fact_id):
        return validate_identity(fact_id, "fact_id") in self._facts

    def facts(self):
        """Every fact, sorted by ``fact_id`` for deterministic ordering."""
        return tuple(self._facts[key] for key in sorted(self._facts))

    def available_facts(self):
        return tuple(fact for fact in self.facts() if fact.available)

    def observed_facts(self):
        return tuple(fact for fact in self.facts() if fact.observed)

    # -- state -------------------------------------------------------------

    def capture_state(self):
        return {
            "version": STATE_VERSION,
            "identity": self._identity,
            "facts": [fact.to_state() for fact in self.facts()],
        }

    _STATE_KEYS = frozenset({"version", "identity", "facts"})

    def restore_state(self, state):
        identity, facts = self._parse_state(state, expected_identity=self._identity)
        self._identity = identity
        self._facts = facts

    @classmethod
    def from_state(cls, state):
        identity = cls._identity_from_state(state)
        instance = cls(identity)
        _, facts = cls._parse_state(state, expected_identity=identity)
        instance._facts = facts
        return instance

    @staticmethod
    def _identity_from_state(state):
        if not isinstance(state, dict):
            raise InvalidDomainStateError(
                "context ledger state must be an object, got %s"
                % type(state).__name__)
        missing = ContextLedger._STATE_KEYS - set(state)
        if missing:
            raise InvalidDomainStateError(
                "context ledger state is missing %s" % ", ".join(sorted(missing)))
        unknown = set(state) - ContextLedger._STATE_KEYS
        if unknown:
            raise InvalidDomainStateError(
                "context ledger state has unknown field(s) %s"
                % ", ".join(sorted(unknown)))
        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise InvalidDomainStateError("context ledger state version must be an int")
        if version != STATE_VERSION:
            raise InvalidDomainStateError(
                "unsupported context ledger state version %r (this build writes %d)"
                % (version, STATE_VERSION))
        try:
            return validate_identity(state["identity"], "context ledger state identity")
        except DomainError as exc:
            raise InvalidDomainStateError(str(exc)) from exc

    @classmethod
    def _parse_state(cls, state, expected_identity):
        identity = cls._identity_from_state(state)
        if identity != expected_identity:
            raise IdentityMismatchError(
                "context ledger state belongs to identity %r, not %r"
                % (identity, expected_identity))

        raw_facts = state["facts"]
        if not isinstance(raw_facts, list):
            raise InvalidDomainStateError(
                "context ledger state facts must be a list, got %s"
                % type(raw_facts).__name__)

        facts = {}
        for raw in raw_facts:
            fact = ContextFact.from_state(raw)
            if fact.fact_id in facts:
                raise InvalidDomainStateError(
                    "duplicate fact id %r" % fact.fact_id)
            facts[fact.fact_id] = fact
        return identity, facts
