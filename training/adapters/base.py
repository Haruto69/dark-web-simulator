"""The consequence-adapter contract.

An adapter is the only component that knows what an ``action_key`` actually
does. The runtime drives it through a deliberately narrow protocol:

    prepare()          bring the environment to its verified starting state
    capture_state()    return a JSON-safe mapping describing the environment
    apply(action_key)  enact one named consequence
    rewind()           restore the starting state

That is the whole surface. The runtime never reaches into a backend, never
holds a container handle and never issues a command, so the same runtime drives
an in-memory fake, a synthetic account ledger, or (in a later milestone) a
sandbox adapter that delegates through ``SandboxManager``.

Adapters are trusted code shipped with the application. Scenario definitions
are not: an adapter must expose a fixed ``supported_actions`` vocabulary, and
the runtime refuses to run any scenario naming an action outside it.
"""

import abc
from typing import Any, FrozenSet, Mapping

from ..errors import AdapterProtocolError, UnknownActionError


class ConsequenceAdapter(abc.ABC):
    """Base class for every consequence environment."""

    #: Symbolic actions this adapter can enact. Subclasses must override.
    supported_actions: FrozenSet[str] = frozenset()

    #: Human-readable description of the environment, for result provenance.
    environment_kind: str = "unspecified"

    @abc.abstractmethod
    def prepare(self) -> None:
        """Bring the environment to the state a run should begin from.

        Called once, before the baseline is captured. Must be idempotent
        enough that calling it on a fresh adapter yields the same logical
        state every time.
        """

    @abc.abstractmethod
    def capture_state(self) -> Mapping[str, Any]:
        """Return the current environment state as a JSON-safe mapping.

        Must be a pure observation: capturing state must never change it, or
        baseline verification becomes meaningless. Must not include secrets.
        """

    @abc.abstractmethod
    def apply(self, action_key: str) -> None:
        """Enact the consequence named by ``action_key``."""

    @abc.abstractmethod
    def rewind(self) -> None:
        """Restore the environment to the state ``prepare`` established.

        The runtime independently verifies the result by fingerprint and fails
        closed if it does not match; an adapter is never trusted to self-report
        a successful rewind.
        """

    # -- shared helpers ----------------------------------------------------
    def require_supported(self, action_key: str) -> str:
        """Raise :class:`UnknownActionError` unless the action is declared."""
        if action_key not in self.supported_actions:
            raise UnknownActionError(
                "adapter {0} does not support action {1!r}; supported: {2}"
                .format(type(self).__name__, action_key,
                        ", ".join(sorted(self.supported_actions)) or "(none)"))
        return action_key

    def describe(self) -> Mapping[str, Any]:
        """Provenance recorded alongside a result."""
        return {
            "adapter": type(self).__name__,
            "environment_kind": self.environment_kind,
            "supported_actions": sorted(self.supported_actions),
        }

    def check_protocol(self) -> None:
        """Validate the adapter is usable before a run starts."""
        if not self.supported_actions:
            raise AdapterProtocolError(
                "adapter {0} declares no supported actions".format(
                    type(self).__name__))
        if not isinstance(self.supported_actions, (set, frozenset)):
            raise AdapterProtocolError(
                "adapter {0}.supported_actions must be a set".format(
                    type(self).__name__))
