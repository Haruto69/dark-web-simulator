"""Local (no-Docker) sandbox backend.

This backend runs the simulation against a *project-controlled scratch
directory* instead of a container. It exists so the simulator can be developed,
tested and demonstrated on machines without Docker, and so the automated tests
never require a container runtime.

ISOLATION CAVEAT: this backend provides workspace confinement (fixed dataset,
allow-listed filenames, no directory walking) but NOT process, user or network
isolation. ``DockerBackend`` is the isolation-bearing backend and is what the
paper's threat boundary describes. ``isolation_summary`` is surfaced in the
dashboard so the operator always knows which one is active.
"""

import os
import shutil

from .. import impact_core
from ..dataset import WORKSPACE_DIRNAME, seed_workspace
from ..errors import SandboxNotFoundError
from .base import SandboxBackend, validate_sandbox_id


class LocalBackend(SandboxBackend):
    name = "local"
    isolation_summary = (
        "Workspace confinement only (fixed synthetic dataset, allow-listed "
        "filenames). No container, process or network isolation."
    )

    def __init__(self, root):
        # ``root`` is chosen by the application, never by request data.
        self.root = os.path.abspath(root)

    # -- helpers ---------------------------------------------------------
    def _sandbox_dir(self, sandbox_id):
        return os.path.join(self.root, validate_sandbox_id(sandbox_id))

    def _workspace(self, sandbox_id):
        return os.path.join(self._sandbox_dir(sandbox_id), WORKSPACE_DIRNAME)

    def _require(self, sandbox_id):
        workspace = self._workspace(sandbox_id)
        if not os.path.isdir(workspace):
            raise SandboxNotFoundError("no local sandbox %r" % sandbox_id)
        return workspace

    # -- backend interface -----------------------------------------------
    def is_available(self):
        return True

    def create(self, sandbox_id):
        workspace = self._workspace(sandbox_id)
        if os.path.isdir(self._sandbox_dir(sandbox_id)):
            shutil.rmtree(self._sandbox_dir(sandbox_id))
        seed_workspace(workspace)
        return {
            "sandbox_id": sandbox_id,
            "backend": self.name,
            "state": "running",
            "workspace": workspace,
        }

    def status(self, sandbox_id):
        try:
            workspace = self._require(sandbox_id)
        except SandboxNotFoundError:
            return {"sandbox_id": sandbox_id, "backend": self.name,
                    "state": "absent", "workspace": None}
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": "running", "workspace": workspace}

    def reset(self, sandbox_id):
        """Destroy and re-seed -- the same disposable semantics as Docker."""
        return self.create(sandbox_id)

    def destroy(self, sandbox_id):
        directory = self._sandbox_dir(sandbox_id)
        if os.path.isdir(directory):
            shutil.rmtree(directory)
        return {"sandbox_id": sandbox_id, "state": "absent"}

    def run_impact(self, sandbox_id, targets):
        return impact_core.run_file_impact(self._require(sandbox_id), targets)

    def workspace_state(self, sandbox_id):
        return impact_core.workspace_state(self._require(sandbox_id))

    def list_sandboxes(self):
        if not os.path.isdir(self.root):
            return []
        found = []
        for entry in sorted(os.listdir(self.root)):
            if os.path.isdir(os.path.join(self.root, entry, WORKSPACE_DIRNAME)):
                found.append(entry)
        return found
