"""Conference sandbox subsystem for the Dark Web Risk Simulator.

Educational simulation only. Nothing in this package encrypts data, propagates,
persists, escalates privilege, evades detection or contacts external systems.
"""

from .errors import (BackendUnavailableError, SandboxCommandError, SandboxError,
                     SandboxNotFoundError, SandboxNotReadyError, UnsafePathError)
from .events import EventCollector, EventType, make_event
from .manager import SandboxManager
from .scenarios.file_impact import FileImpactScenario

__all__ = [
    "SandboxManager", "FileImpactScenario", "EventType", "EventCollector",
    "make_event", "SandboxError", "SandboxNotFoundError", "SandboxNotReadyError",
    "UnsafePathError", "BackendUnavailableError", "SandboxCommandError",
]
