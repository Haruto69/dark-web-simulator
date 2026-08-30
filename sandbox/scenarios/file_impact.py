"""FileImpactScenario -- the safe ransomware-style file-impact simulation.

The scenario validates the sandbox, asks the backend to apply the constrained
demo impact to allow-listed synthetic files, and emits structured telemetry for
every step. It contains no filesystem logic of its own; see
``sandbox/impact_core.py`` for what the "impact" actually is (a reversible
rename) and ``sandbox/paths.py`` for the target policy.
"""

import uuid

from ..dataset import BASELINE_FILENAMES
from ..errors import SandboxError, SandboxNotReadyError
from ..events import EventType, make_event
from ..paths import sandbox_path
from ..sanitize import error_reference, telemetry_detail

SCENARIO_NAME = "file_impact"


class FileImpactScenario:
    name = SCENARIO_NAME
    description = (
        "Ransomware-style file impact, emulated by reversibly renaming "
        "allow-listed synthetic files inside a disposable sandbox. "
        "No encryption, no propagation, no persistence."
    )

    def __init__(self, manager):
        self.manager = manager

    def _emit(self, event_type, scenario_id, session_id, target=None, details=None):
        return self.manager.recorder(make_event(
            event_type, scenario_id=scenario_id, session_id=session_id,
            source="scenario:%s" % self.name, target=target, details=details))

    def run(self, sandbox_id=None, session_id=None, targets=None, scenario_id=None):
        """Execute the scenario. Returns a result dict.

        Raises :class:`SandboxNotReadyError` if no sandbox is running -- the
        failure is recorded as SCENARIO_FAILED telemetry before re-raising.
        """
        scenario_id = scenario_id or uuid.uuid4().hex[:12]
        sandbox_id = self.manager.resolve_id(sandbox_id)
        selected = list(targets) if targets else list(BASELINE_FILENAMES)

        self._emit(EventType.SCENARIO_STARTED, scenario_id, session_id,
                   target=sandbox_id,
                   details="scenario=%s; targets=%d" % (self.name, len(selected)))

        try:
            self.manager.require_ready(sandbox_id)
        except SandboxNotReadyError as exc:
            # Never persist the exception *message*: a backend failure can
            # carry host paths, argv or container stderr, and SCENARIO_FAILED
            # rows are exported by instructors. The class name plus a
            # correlation reference is all telemetry keeps.
            self._emit(EventType.SCENARIO_FAILED, scenario_id, session_id,
                       details=telemetry_detail(exc, error_reference()))
            raise

        self._emit(EventType.FILE_IMPACT_STARTED, scenario_id, session_id,
                   details="applying demo impact to %d synthetic file(s)" % len(selected))

        try:
            results = self.manager.backend.run_impact(sandbox_id, selected)
        except SandboxError as exc:
            self._emit(EventType.SCENARIO_FAILED, scenario_id, session_id,
                       details=telemetry_detail(exc, error_reference()))
            raise

        impacted = 0
        for result in results:
            if result["status"] == "rejected":
                self._emit(EventType.FILE_IMPACT_REJECTED, scenario_id, session_id,
                           target=str(result["target"])[:200], details=result["detail"])
                continue
            if result["status"] == "impacted":
                impacted += 1
            self._emit(EventType.FILE_IMPACT, scenario_id, session_id,
                       target=sandbox_path(result["target"]),
                       details=result["detail"])

        self._emit(EventType.FILE_IMPACT_COMPLETED, scenario_id, session_id,
                   details="%d file(s) impacted, %d result(s) total"
                           % (impacted, len(results)))
        self._emit(EventType.SCENARIO_COMPLETED, scenario_id, session_id,
                   details="scenario=%s completed" % self.name)

        return {
            "scenario_id": scenario_id,
            "scenario": self.name,
            "impacted": impacted,
            "results": results,
        }
