"""SandboxManager -- lifecycle owner for the disposable sandbox.

Responsibilities: create, inspect, reset and destroy a sandbox, and emit
lifecycle telemetry. It knows nothing about what a scenario does; scenarios
live in ``sandbox/scenarios`` and are handed a manager.

Flask routes call this class. Docker/subprocess details stay in the backends.
"""

from .backends.base import validate_sandbox_id
from .backends.docker import DockerBackend
from .backends.local import LocalBackend
from .errors import SandboxNotReadyError
from .events import EventCollector, EventType, make_event

DEFAULT_SANDBOX_ID = "primary"


class SandboxManager:
    def __init__(self, backend, recorder=None, default_sandbox_id=DEFAULT_SANDBOX_ID):
        self.backend = backend
        self.recorder = recorder or EventCollector()
        self.default_sandbox_id = validate_sandbox_id(default_sandbox_id)

    # -- construction ------------------------------------------------------
    @classmethod
    def autodetect(cls, local_root, recorder=None, prefer_docker=True, image=None):
        """Pick DockerBackend when Docker is usable, else LocalBackend.

        The chosen backend's ``isolation_summary`` is reported to the operator
        so a reduced-isolation run is never mistaken for a contained one.
        """
        if prefer_docker:
            docker = DockerBackend(image=image) if image else DockerBackend()
            if docker.is_available():
                return cls(docker, recorder=recorder)
        return cls(LocalBackend(local_root), recorder=recorder)

    # -- telemetry ---------------------------------------------------------
    def _emit(self, event_type, session_id=None, scenario_id=None,
              target=None, details=None):
        return self.recorder(make_event(
            event_type, scenario_id=scenario_id, session_id=session_id,
            source="sandbox:%s" % self.backend.name, target=target,
            details=details))

    # -- lifecycle ---------------------------------------------------------
    def create(self, sandbox_id=None, session_id=None):
        sandbox_id = validate_sandbox_id(sandbox_id or self.default_sandbox_id)
        info = self.backend.create(sandbox_id)
        self._emit(EventType.SANDBOX_CREATED, session_id=session_id,
                   target=sandbox_id,
                   details="backend=%s; %s" % (self.backend.name,
                                               self.backend.isolation_summary))
        return info

    def status(self, sandbox_id=None):
        sandbox_id = validate_sandbox_id(sandbox_id or self.default_sandbox_id)
        info = dict(self.backend.status(sandbox_id))
        info["isolation"] = self.backend.isolation_summary
        info["ready"] = info.get("state") == "running"
        return info

    def is_ready(self, sandbox_id=None):
        return self.status(sandbox_id)["ready"]

    def require_ready(self, sandbox_id=None):
        info = self.status(sandbox_id)
        if not info["ready"]:
            raise SandboxNotReadyError(
                "sandbox %r is not running (state=%s); create it first"
                % (info["sandbox_id"], info.get("state")))
        return info

    def reset(self, sandbox_id=None, session_id=None):
        sandbox_id = validate_sandbox_id(sandbox_id or self.default_sandbox_id)
        info = self.backend.reset(sandbox_id)
        self._emit(EventType.SANDBOX_RESET, session_id=session_id,
                   target=sandbox_id,
                   details="workspace restored to synthetic baseline")
        return info

    def destroy(self, sandbox_id=None, session_id=None):
        sandbox_id = validate_sandbox_id(sandbox_id or self.default_sandbox_id)
        info = self.backend.destroy(sandbox_id)
        self._emit(EventType.SANDBOX_DESTROYED, session_id=session_id,
                   target=sandbox_id, details="sandbox removed")
        return info

    # -- inspection --------------------------------------------------------
    def workspace_state(self, sandbox_id=None):
        sandbox_id = validate_sandbox_id(sandbox_id or self.default_sandbox_id)
        self.require_ready(sandbox_id)
        return self.backend.workspace_state(sandbox_id)
