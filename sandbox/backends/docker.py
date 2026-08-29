"""Docker-based disposable sandbox backend.

Isolation properties enforced on every container we create:

  * ``--network none``   -- no outbound Internet, no access to host services,
                            no reachable ports at all. Strictly stronger than an
                            internal bridge network, and simpler.
  * ``--cap-drop ALL`` and ``--security-opt no-new-privileges``
  * non-root user, memory and PID limits
  * no bind mounts, no named volumes, no Docker socket, no host networking,
    not privileged. The workspace lives only in the container's own writable
    layer, so destroying the container destroys all simulation state.

Reset is implemented as destroy + recreate rather than in-place repair, which
makes the baseline reproducible by construction.

Docker is driven through ``subprocess`` with argument *lists* -- never
``shell=True`` -- and every invocation has a timeout.
"""

import json
import shutil
import subprocess

from ..dataset import BASELINE_FILENAMES
from ..errors import (BackendUnavailableError, SandboxCommandError,
                      SandboxNotFoundError, UnsafePathError)
from ..paths import normalise_target
from .base import SandboxBackend, validate_sandbox_id

DEFAULT_IMAGE = "dark-web-sandbox-target:latest"
CONTAINER_PREFIX = "dws-sandbox-"
DEFAULT_TIMEOUT = 60


class DockerBackend(SandboxBackend):
    name = "docker"
    isolation_summary = (
        "Disposable container: --network none, all capabilities dropped, "
        "no-new-privileges, non-root, no bind mounts, no Docker socket."
    )

    def __init__(self, image=DEFAULT_IMAGE, timeout=DEFAULT_TIMEOUT,
                 docker_binary="docker"):
        self.image = image
        self.timeout = timeout
        self.docker_binary = docker_binary

    # -- plumbing ---------------------------------------------------------
    def _container(self, sandbox_id):
        return CONTAINER_PREFIX + validate_sandbox_id(sandbox_id)

    def _run(self, args, check=True):
        try:
            completed = subprocess.run(
                [self.docker_binary] + args,
                capture_output=True, text=True,
                timeout=self.timeout, shell=False, check=False,
            )
        except FileNotFoundError as exc:
            raise BackendUnavailableError("docker CLI not found") from exc
        except subprocess.TimeoutExpired as exc:
            raise SandboxCommandError(
                "docker command timed out after %ss: %s" % (self.timeout, args[0])
            ) from exc
        if check and completed.returncode != 0:
            raise SandboxCommandError(
                "docker %s failed (exit %d): %s"
                % (args[0], completed.returncode, completed.stderr.strip()[:400])
            )
        return completed

    # -- backend interface -------------------------------------------------
    def is_available(self):
        if shutil.which(self.docker_binary) is None:
            return False
        try:
            return self._run(["info", "--format", "{{.ServerVersion}}"],
                             check=False).returncode == 0
        except (BackendUnavailableError, SandboxCommandError):
            return False

    def create(self, sandbox_id):
        name = self._container(sandbox_id)
        self.destroy(sandbox_id)
        self._run([
            "run", "--detach",
            "--name", name,
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--user", "10001:10001",
            "--memory", "256m",
            "--pids-limit", "128",
            "--label", "dws-sandbox=1",
            self.image,
        ])
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": "running", "container": name,
                "workspace": "/workspace"}

    def status(self, sandbox_id):
        name = self._container(sandbox_id)
        completed = self._run(
            ["inspect", "--format", "{{.State.Status}}", "--", name], check=False)
        if completed.returncode != 0:
            return {"sandbox_id": sandbox_id, "backend": self.name,
                    "state": "absent", "container": name, "workspace": None}
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": completed.stdout.strip() or "unknown",
                "container": name, "workspace": "/workspace"}

    def reset(self, sandbox_id):
        self.destroy(sandbox_id)
        return self.create(sandbox_id)

    def destroy(self, sandbox_id):
        name = self._container(sandbox_id)
        self._run(["rm", "--force", "--volumes", "--", name], check=False)
        return {"sandbox_id": sandbox_id, "state": "absent", "container": name}

    def _require_running(self, sandbox_id):
        state = self.status(sandbox_id)
        if state["state"] != "running":
            raise SandboxNotFoundError(
                "sandbox %r is not running (state=%s)" % (sandbox_id, state["state"]))
        return state

    def _exec_tool(self, sandbox_id, tool_args):
        self._require_running(sandbox_id)
        completed = self._run(
            ["exec", "--", self._container(sandbox_id),
             "python", "-m", "sandbox.tools.impact_tool"] + tool_args)
        try:
            return json.loads(completed.stdout)
        except ValueError as exc:
            raise SandboxCommandError(
                "sandbox tool returned non-JSON output") from exc

    def run_impact(self, sandbox_id, targets):
        selected = list(targets) if targets else list(BASELINE_FILENAMES)
        safe, results = [], []
        # Validate host-side first: unsafe targets never reach the container.
        for target in selected:
            try:
                safe.append(normalise_target(target))
            except UnsafePathError as exc:
                results.append({"target": str(target)[:120],
                                "status": "rejected", "detail": str(exc)})
        if safe:
            results.extend(self._exec_tool(sandbox_id, ["impact", "--"] + safe))
        return results

    def workspace_state(self, sandbox_id):
        return self._exec_tool(sandbox_id, ["state"])

    def list_sandboxes(self):
        completed = self._run(
            ["ps", "--all", "--filter", "label=dws-sandbox=1",
             "--format", "{{.Names}}"], check=False)
        if completed.returncode != 0:
            return []
        names = [line.strip() for line in completed.stdout.splitlines() if line.strip()]
        return sorted(n[len(CONTAINER_PREFIX):] for n in names
                      if n.startswith(CONTAINER_PREFIX))
