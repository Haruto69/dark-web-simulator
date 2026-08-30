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

import json
import os
import shutil
import time

from .. import impact_core
from ..dataset import WORKSPACE_DIRNAME, seed_workspace
from ..errors import SandboxError, SandboxNotFoundError
from .base import SandboxBackend, validate_sandbox_id

#: Ownership marker written into every sandbox directory this backend creates.
#: A directory under the root without a readable marker is never reaped -- the
#: reaper only removes what it can prove it made.
MARKER_FILENAME = ".dws-sandbox.json"
MARKER_MAGIC = "dark-web-sandbox"


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

    def _marker_path(self, sandbox_id):
        return os.path.join(self._sandbox_dir(sandbox_id), MARKER_FILENAME)

    def _write_marker(self, sandbox_id):
        marker = {"magic": MARKER_MAGIC, "sandbox_id": sandbox_id,
                  "created_at": time.time()}
        with open(self._marker_path(sandbox_id), "w", encoding="utf-8") as handle:
            json.dump(marker, handle)
        return marker

    def _read_marker(self, sandbox_id):
        """Return the ownership marker, or None if absent/unreadable/foreign."""
        try:
            with open(self._marker_path(sandbox_id), encoding="utf-8") as handle:
                marker = json.load(handle)
        except (OSError, ValueError):
            return None
        if not isinstance(marker, dict) or marker.get("magic") != MARKER_MAGIC:
            return None
        if marker.get("sandbox_id") != sandbox_id:
            return None
        return marker

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
        marker = self._write_marker(sandbox_id)
        return {
            "sandbox_id": sandbox_id,
            "backend": self.name,
            "state": "running",
            "workspace": workspace,
            "created_at": marker["created_at"],
        }

    def status(self, sandbox_id):
        try:
            workspace = self._require(sandbox_id)
        except SandboxNotFoundError:
            return {"sandbox_id": sandbox_id, "backend": self.name,
                    "state": "absent", "workspace": None, "created_at": None}
        marker = self._read_marker(sandbox_id)
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": "running", "workspace": workspace,
                "created_at": (marker or {}).get("created_at"),
                "owned": marker is not None}

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
        return [row["sandbox_id"] for row in self.sandbox_metadata()]

    def sandbox_metadata(self):
        """``[{"sandbox_id", "created_at", "state"}]`` for owned workspaces.

        Three conditions must hold: the directory name is a valid sandbox id,
        it contains a seeded workspace, and it carries this backend's ownership
        marker. A stray directory a user dropped into the scratch root is
        therefore invisible here and can never be reaped.
        """
        if not os.path.isdir(self.root):
            return []
        rows = []
        for entry in sorted(os.listdir(self.root)):
            try:
                sandbox_id = validate_sandbox_id(entry)
            except SandboxError:
                continue
            if not os.path.isdir(os.path.join(self.root, entry, WORKSPACE_DIRNAME)):
                continue
            marker = self._read_marker(sandbox_id)
            if marker is None:
                continue
            rows.append({"sandbox_id": sandbox_id,
                         "created_at": marker.get("created_at"),
                         "state": "running"})
        return rows
