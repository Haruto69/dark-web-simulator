"""Conference sandbox subsystem for RewindSec.

Educational simulation only. Nothing in this package encrypts data, propagates,
persists, escalates privilege, evades detection or contacts external systems.
"""

from .errors import (BackendUnavailableError, BaselineMismatchError,
                     SandboxCommandError, SandboxError, SandboxNotFoundError,
                     SandboxNotReadyError, ScenarioStateError, UnsafePathError)
from .events import EventCollector, EventType, make_event
from .identity import LAB_DOMAIN, SyntheticIdentityStore
from .manager import SandboxManager
from .scenarios.file_impact import FileImpactScenario
from .scenarios.phishing import (STAGES, SYNTHETIC_RESOURCES, PhishingScenario,
                                 new_scenario_id, stage_index)
from .session_scope import is_session_sandbox, sandbox_id_for_session

__all__ = [
    "SandboxManager", "FileImpactScenario", "PhishingScenario", "EventType",
    "EventCollector", "make_event", "SandboxError", "SandboxNotFoundError",
    "SandboxNotReadyError", "UnsafePathError", "BackendUnavailableError",
    "SandboxCommandError", "ScenarioStateError", "BaselineMismatchError",
    "SyntheticIdentityStore",
    "LAB_DOMAIN", "STAGES", "SYNTHETIC_RESOURCES", "new_scenario_id",
    "stage_index", "sandbox_id_for_session", "is_session_sandbox",
]
