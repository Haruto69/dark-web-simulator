"""A deterministic in-memory consequence adapter.

This exists so the runtime's semantics can be proven without Flask, without
Docker and without touching a filesystem. It is also the reference for what a
real adapter must do: resolve a symbolic action key through a fixed table, and
restore an exact baseline on rewind.

An action is a pure function ``state -> state`` registered under a symbolic
key. Because the table is supplied by trusted setup code rather than by a
scenario definition, a scenario can only ever *name* an action, never define
one.
"""

import copy
from typing import Any, Callable, Dict, Mapping, MutableMapping

from ..errors import AdapterProtocolError
from .base import ConsequenceAdapter

StateMutator = Callable[[MutableMapping[str, Any]], None]


class InMemoryConsequenceAdapter(ConsequenceAdapter):
    """Holds a plain dict as the environment; actions mutate a copy of it."""

    environment_kind = "in_memory"

    def __init__(self, baseline: Mapping[str, Any],
                 actions: Mapping[str, StateMutator]):
        if not isinstance(baseline, Mapping):
            raise AdapterProtocolError("baseline must be a mapping")
        for key, action in actions.items():
            if not callable(action):
                raise AdapterProtocolError(
                    "action {0!r} is not callable".format(key))
        self._baseline: Dict[str, Any] = copy.deepcopy(dict(baseline))
        self._actions: Dict[str, StateMutator] = dict(actions)
        self._state: Dict[str, Any] = copy.deepcopy(self._baseline)
        self.supported_actions = frozenset(self._actions)
        # Call counters, so tests can assert an action was never reached.
        self.applied: list = []
        self.rewind_count = 0
        self.prepare_count = 0

    # -- adapter protocol --------------------------------------------------
    def prepare(self) -> None:
        self.prepare_count += 1
        self._state = copy.deepcopy(self._baseline)

    def capture_state(self) -> Mapping[str, Any]:
        # A deep copy: the caller must not be able to mutate the environment
        # by holding on to a captured mapping.
        return copy.deepcopy(self._state)

    def apply(self, action_key: str) -> None:
        self.require_supported(action_key)
        self.applied.append(action_key)
        self._actions[action_key](self._state)

    def rewind(self) -> None:
        self.rewind_count += 1
        self._state = copy.deepcopy(self._baseline)


class DriftingRewindAdapter(InMemoryConsequenceAdapter):
    """A deliberately broken adapter whose rewind does not restore baseline.

    Used to prove the runtime fails closed rather than trusting the adapter.
    Never used outside tests and documentation examples.
    """

    environment_kind = "in_memory_faulty"

    def __init__(self, baseline, actions, drift_key="drift_marker"):
        super().__init__(baseline, actions)
        self._drift_key = drift_key
        self._drift = 0

    def rewind(self) -> None:
        super().rewind()
        self._drift += 1
        self._state[self._drift_key] = self._drift
