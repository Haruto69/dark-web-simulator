"""Consequence adapters -- the trusted bridge between a symbolic action key and
a real environment.

``base`` defines the contract. ``memory`` provides the deterministic in-memory
adapter used to prove the runtime's semantics without Flask or Docker. A
sandbox adapter delegating through ``SandboxManager`` is a later milestone; the
runtime is designed so that adding one requires no change to the runtime.
"""

from .base import ConsequenceAdapter
from .memory import DriftingRewindAdapter, InMemoryConsequenceAdapter

__all__ = ["ConsequenceAdapter", "InMemoryConsequenceAdapter",
           "DriftingRewindAdapter"]
