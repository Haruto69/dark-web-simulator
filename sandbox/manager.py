"""SandboxManager -- lifecycle owner for the disposable sandbox.

Responsibilities: create, inspect, reset and destroy a sandbox, and emit
lifecycle telemetry. It knows nothing about what a scenario does; scenarios
live in ``sandbox/scenarios`` and are handed a manager.

Flask routes call this class. Docker/subprocess details stay in the backends.
"""

import time

from .backends.base import validate_sandbox_id
from .backends.docker import DockerBackend
from .backends.local import LocalBackend
from .errors import SandboxError, SandboxNotReadyError
from .events import EventCollector, EventType, make_event

DEFAULT_SANDBOX_ID = "primary"


class SandboxManager:
    """Lifecycle owner. One manager per process, many sandboxes.

    ``default_sandbox_id`` exists for library/CLI use. The Flask layer
    constructs the manager with ``default_sandbox_id=None`` so that a route
    which forgets to pass a session-scoped id fails loudly instead of silently
    sharing one workspace between learners.
    """

    def __init__(self, backend, recorder=None, default_sandbox_id=DEFAULT_SANDBOX_ID):
        self.backend = backend
        self.recorder = recorder or EventCollector()
        self.default_sandbox_id = (validate_sandbox_id(default_sandbox_id)
                                   if default_sandbox_id is not None else None)

    # -- construction ------------------------------------------------------
    @classmethod
    def autodetect(cls, local_root, recorder=None, prefer_docker=True, image=None,
                   default_sandbox_id=DEFAULT_SANDBOX_ID):
        """Pick DockerBackend when Docker is usable, else LocalBackend.

        The chosen backend's ``isolation_summary`` is reported to the operator
        so a reduced-isolation run is never mistaken for a contained one.
        """
        if prefer_docker:
            docker = DockerBackend(image=image) if image else DockerBackend()
            if docker.is_available():
                return cls(docker, recorder=recorder,
                           default_sandbox_id=default_sandbox_id)
        return cls(LocalBackend(local_root), recorder=recorder,
                   default_sandbox_id=default_sandbox_id)

    # -- id resolution -----------------------------------------------------
    def resolve_id(self, sandbox_id=None):
        """Validate an explicit id, or fall back to the configured default."""
        if sandbox_id is None:
            if self.default_sandbox_id is None:
                raise SandboxError(
                    "a sandbox id is required (this manager has no default; "
                    "pass the session-scoped id)")
            sandbox_id = self.default_sandbox_id
        return validate_sandbox_id(sandbox_id)

    # -- telemetry ---------------------------------------------------------
    def _emit(self, event_type, session_id=None, scenario_id=None,
              target=None, details=None):
        return self.recorder(make_event(
            event_type, scenario_id=scenario_id, session_id=session_id,
            source="sandbox:%s" % self.backend.name, target=target,
            details=details))

    # -- lifecycle ---------------------------------------------------------
    def create(self, sandbox_id=None, session_id=None):
        sandbox_id = self.resolve_id(sandbox_id)
        info = self.backend.create(sandbox_id)
        self._emit(EventType.SANDBOX_CREATED, session_id=session_id,
                   target=sandbox_id,
                   details="backend=%s; %s" % (self.backend.name,
                                               self.backend.isolation_summary))
        return info

    def status(self, sandbox_id=None):
        sandbox_id = self.resolve_id(sandbox_id)
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
        sandbox_id = self.resolve_id(sandbox_id)
        info = self.backend.reset(sandbox_id)
        self._emit(EventType.SANDBOX_RESET, session_id=session_id,
                   target=sandbox_id,
                   details="workspace restored to synthetic baseline")
        return info

    def destroy(self, sandbox_id=None, session_id=None):
        sandbox_id = self.resolve_id(sandbox_id)
        info = self.backend.destroy(sandbox_id)
        self._emit(EventType.SANDBOX_DESTROYED, session_id=session_id,
                   target=sandbox_id, details="sandbox removed")
        return info

    # -- inspection --------------------------------------------------------
    def workspace_state(self, sandbox_id=None):
        sandbox_id = self.resolve_id(sandbox_id)
        self.require_ready(sandbox_id)
        return self.backend.workspace_state(sandbox_id)

    def list_sandboxes(self):
        """Instructor aggregation: every sandbox id the backend owns."""
        try:
            return self.backend.list_sandboxes()
        except SandboxError:
            return []

    def sandbox_metadata(self):
        """Ownership-checked inventory with creation timestamps."""
        try:
            return self.backend.sandbox_metadata()
        except SandboxError:
            return []

    # -- lifecycle hygiene -------------------------------------------------
    def stale_sandboxes(self, max_age_seconds, now=None):
        """Ids of owned sandboxes older than ``max_age_seconds``.

        Pure and side-effect free, so the selection rule can be unit-tested
        independently of any destruction. Deterministic: the result is sorted,
        and depends only on (inventory, max_age, now).

        A sandbox whose ``created_at`` is unknown is **never** selected.
        """
        if not isinstance(max_age_seconds, (int, float)) or max_age_seconds < 0:
            raise SandboxError("max_age_seconds must be a non-negative number")
        now = time.time() if now is None else now
        stale = []
        for row in self.sandbox_metadata():
            created = row.get("created_at")
            if created is None:
                continue
            age = now - created
            if age >= max_age_seconds:
                stale.append((row["sandbox_id"], age))
        return sorted(stale)

    def reap_stale(self, max_age_seconds, now=None, session_id=None, dry_run=False):
        """Destroy owned sandboxes older than ``max_age_seconds``.

        Safety properties, in order of importance:

        1. Candidates come only from :meth:`sandbox_metadata`, which is
           ownership-checked by the backend (Docker label / marker file). An
           unrelated container or directory is never even enumerated.
        2. Every id is re-validated against ``SANDBOX_ID_RE`` before use.
        3. Unknown creation time is skipped, never reaped.
        4. ``dry_run=True`` reports the selection without destroying anything.

        Emits one ``SANDBOX_REAP_SCAN`` event per invocation and one
        ``SANDBOX_REAPED`` event per sandbox actually destroyed.
        """
        candidates = self.stale_sandboxes(max_age_seconds, now=now)
        self._emit(EventType.SANDBOX_REAP_SCAN, session_id=session_id,
                   details="max_age=%.1fs; candidates=%d; dry_run=%s"
                           % (float(max_age_seconds), len(candidates), dry_run))
        reaped = []
        for sandbox_id, age in candidates:
            sandbox_id = validate_sandbox_id(sandbox_id)
            if dry_run:
                reaped.append({"sandbox_id": sandbox_id, "age_seconds": age,
                               "destroyed": False})
                continue
            try:
                self.backend.destroy(sandbox_id)
            except SandboxError as exc:
                self._emit(EventType.SANDBOX_REAP_SCAN, session_id=session_id,
                           target=sandbox_id,
                           details="reap failed: %s" % str(exc)[:200])
                continue
            self._emit(EventType.SANDBOX_REAPED, session_id=session_id,
                       target=sandbox_id,
                       details="stale sandbox destroyed after %.1fs (max_age=%.1fs)"
                               % (age, float(max_age_seconds)))
            reaped.append({"sandbox_id": sandbox_id, "age_seconds": age,
                           "destroyed": True})
        return reaped

    def ensure_ready(self, sandbox_id=None, session_id=None):
        """Create the sandbox only if it is not already running.

        Idempotent, so a learner re-entering a scenario keeps their workspace
        instead of silently resetting it.
        """
        sandbox_id = self.resolve_id(sandbox_id)
        info = self.status(sandbox_id)
        if info["ready"]:
            return info
        self.create(sandbox_id, session_id=session_id)
        return self.status(sandbox_id)
