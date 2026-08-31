"""Docker-based disposable sandbox backend.

Isolation properties enforced on every container we create:

  * ``--network none``   -- no outbound Internet, no access to host services,
                            no reachable ports at all. Strictly stronger than an
                            internal bridge network, and simpler.
  * ``--cap-drop ALL`` and ``--security-opt no-new-privileges``
  * ``--read-only``      -- immutable root filesystem. The single writable path
                            is ``/workspace``, supplied as a **tmpfs** (RAM, not
                            a host directory), so the scenario can rename its
                            synthetic files while everything else -- binaries,
                            libraries, ``/etc`` -- is unwritable.
  * non-root user, memory and PID limits
  * no bind mounts, no named volumes, no Docker socket, no host networking,
    not privileged. The workspace lives only in the container's own tmpfs, so
    destroying the container destroys all simulation state and nothing is
    written to the host at any point.

Every container carries the ``dws-sandbox=1`` label. That label is the *only*
way this code identifies containers it owns; see :meth:`list_sandboxes` and
:meth:`sandbox_metadata`, which are what the reaper relies on to guarantee it
never touches an unrelated container.

Reset is implemented as destroy + recreate rather than in-place repair, which
makes the baseline reproducible by construction.

Lifecycle readiness is *synchronous and content-verified*: :meth:`create` seeds
the workspace itself with a blocking ``docker exec`` and confirms the seeded
digests against the host-side baseline before returning, so neither create nor
reset can hand back a container whose workspace is still being written.

Docker is driven through ``subprocess`` with argument *lists* -- never
``shell=True`` -- and every invocation has a timeout.
"""

import datetime
import json
import re
import shutil
import subprocess

from ..dataset import BASELINE_DIGESTS, BASELINE_FILENAMES
from ..errors import (BackendUnavailableError, SandboxCommandError,
                      SandboxError, SandboxNotFoundError, UnsafePathError)
from ..paths import normalise_target
from .base import SandboxBackend, validate_sandbox_id

DEFAULT_IMAGE = "dark-web-sandbox-target:latest"
CONTAINER_PREFIX = "dws-sandbox-"
DEFAULT_TIMEOUT = 60

#: Ownership label. Both the key and the value must match before this backend
#: will report -- let alone remove -- a container.
OWNER_LABEL_KEY = "dws-sandbox"
OWNER_LABEL_VALUE = "1"
OWNER_LABEL = "%s=%s" % (OWNER_LABEL_KEY, OWNER_LABEL_VALUE)

#: Size of the tmpfs mounted at /workspace. The synthetic dataset is a few KB;
#: this is a bound, not a target.
WORKSPACE_TMPFS_SIZE = "16m"


def parse_docker_time(value):
    """Parse a Docker timestamp into a POSIX float, or return None.

    Handles both the RFC3339 form from ``docker inspect`` and the
    ``2026-08-30 12:00:00 +0000 UTC`` form from ``docker ps``. Returns None
    rather than raising: a sandbox with an unreadable creation time is simply
    never considered stale, which fails safe.
    """
    if not value:
        return None
    text = value.strip()
    # docker ps: "2026-08-30 12:00:00 +0530 IST"
    match = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) ([+-]\d{4})", text)
    if match:
        try:
            stamp = datetime.datetime.strptime(
                "%s %s" % (match.group(1), match.group(2)), "%Y-%m-%d %H:%M:%S %z")
            return stamp.timestamp()
        except ValueError:
            return None
    # docker inspect: RFC3339, with nanosecond precision Python cannot parse.
    text = text.replace("Z", "+00:00")
    text = re.sub(r"\.(\d{6})\d+", r".\1", text)
    try:
        return datetime.datetime.fromisoformat(text).timestamp()
    except ValueError:
        return None


class DockerBackend(SandboxBackend):
    name = "docker"
    isolation_summary = (
        "Disposable container: --network none, all capabilities dropped, "
        "no-new-privileges, read-only root filesystem, tmpfs workspace, "
        "non-root, no bind mounts, no Docker socket."
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

    def image_available(self):
        """True when the configured target image is present locally.

        A read-only ``docker image inspect``. The learner-facing R4 scenario
        needs to distinguish "Docker is not running" from "the contained target
        image was never built", and must refuse to run in either case rather
        than degrade to a non-contained backend.
        """
        try:
            return self._run(["image", "inspect", "--", self.image],
                             check=False).returncode == 0
        except (BackendUnavailableError, SandboxCommandError):
            return False

    def _seed(self, sandbox_id):
        """Seed the workspace synchronously and prove it matches the baseline.

        ``docker exec`` blocks until the seed process exits, and the seed tool
        verifies its own writes by read-back, so this method returns only once
        the workspace holds the complete baseline. The digests it reports are
        then re-checked here against :data:`BASELINE_DIGESTS`, computed
        independently on the host: the readiness decision never depends on
        timing, only on content.
        """
        completed = self._run(
            ["exec", "--", self._container(sandbox_id),
             "python", "-m", "sandbox.tools.seed"], check=False)
        if completed.returncode != 0:
            raise SandboxCommandError(
                "workspace seeding failed (exit %d): %s"
                % (completed.returncode, completed.stderr.strip()[:400]))
        try:
            payload = json.loads(completed.stdout)
        except ValueError as exc:
            raise SandboxCommandError(
                "workspace seeding returned non-JSON output") from exc
        digests = payload.get("digests") if isinstance(payload, dict) else None
        if digests != dict(BASELINE_DIGESTS):
            raise SandboxCommandError(
                "workspace baseline verification failed: the seeded workspace "
                "is not byte-identical to the synthetic baseline")
        return payload

    def create(self, sandbox_id):
        """Create a container and return only once it is fully ready.

        Readiness means: the container is running *and* its workspace holds the
        complete, byte-identical synthetic baseline. Seeding happens here, via
        a blocking ``docker exec``, rather than in the image ``CMD`` -- ``docker
        run --detach`` reports "running" the instant the process starts, which
        would otherwise let a caller read a baseline file that exists but is
        still empty. No sleeping or polling is involved; the guarantee is a
        content check, not a timing one.

        If seeding or verification fails the half-built container is destroyed
        and :class:`SandboxCommandError` is raised. A partially seeded sandbox
        is never returned.
        """
        name = self._container(sandbox_id)
        self.destroy(sandbox_id)
        self._run([
            "run", "--detach",
            "--name", name,
            "--network", "none",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--read-only",
            # The one writable path, in RAM. Not a host directory: a tmpfs is
            # not a bind mount and exposes nothing of the host filesystem.
            "--tmpfs", "/workspace:rw,noexec,nosuid,uid=10001,gid=10001,size=%s"
                       % WORKSPACE_TMPFS_SIZE,
            "--user", "10001:10001",
            "--memory", "256m",
            "--pids-limit", "128",
            "--label", OWNER_LABEL,
            self.image,
        ])
        try:
            self._seed(sandbox_id)
        except BaseException:
            # Never hand back a sandbox whose contents we cannot vouch for.
            self.destroy(sandbox_id)
            raise
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": "running", "container": name,
                "workspace": "/workspace",
                "created_at": self._created_at(sandbox_id)}

    def _created_at(self, sandbox_id):
        """Container creation time as a POSIX timestamp, or None.

        Read from Docker itself rather than tracked in this process, so it
        survives a Flask restart and cannot drift.
        """
        completed = self._run(
            ["inspect", "--format", "{{.Created}}", "--",
             self._container(sandbox_id)], check=False)
        if completed.returncode != 0:
            return None
        return parse_docker_time(completed.stdout.strip())

    def status(self, sandbox_id):
        name = self._container(sandbox_id)
        completed = self._run(
            ["inspect", "--format", "{{.State.Status}}\t{{.Created}}\t{{index .Config.Labels \"dws-sandbox\"}}",
             "--", name], check=False)
        if completed.returncode != 0:
            return {"sandbox_id": sandbox_id, "backend": self.name,
                    "state": "absent", "container": name, "workspace": None,
                    "created_at": None}
        parts = completed.stdout.strip().split("\t")
        state = parts[0] if parts else "unknown"
        created = parse_docker_time(parts[1]) if len(parts) > 1 else None
        label = parts[2] if len(parts) > 2 else ""
        if label != OWNER_LABEL_VALUE:
            # A container occupying our name that we did not create. Report it
            # as absent rather than ever acting on it.
            return {"sandbox_id": sandbox_id, "backend": self.name,
                    "state": "absent", "container": name, "workspace": None,
                    "created_at": None, "owned": False}
        return {"sandbox_id": sandbox_id, "backend": self.name,
                "state": state or "unknown",
                "container": name, "workspace": "/workspace",
                "created_at": created, "owned": True}

    def reset(self, sandbox_id):
        """Destroy and recreate, returning only once the baseline is restored.

        Inherits :meth:`create`'s readiness guarantee: an immediate read after
        reset() returns always observes the complete baseline content.
        """
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
        """Ids of containers this application owns.

        Two independent conditions must both hold before a container is
        reported: the ``dws-sandbox=1`` label (applied only by :meth:`create`)
        *and* the ``dws-sandbox-`` name prefix with a valid sandbox id after it.
        Anything else on the host is invisible to this method, which is what
        makes reaping safe.
        """
        return [row["sandbox_id"] for row in self.sandbox_metadata()]

    def sandbox_metadata(self):
        """``[{"sandbox_id", "created_at", "state"}]`` for owned containers."""
        completed = self._run(
            ["ps", "--all", "--filter", "label=" + OWNER_LABEL,
             "--format", "{{.Names}}\t{{.CreatedAt}}\t{{.State}}"], check=False)
        if completed.returncode != 0:
            return []
        rows = []
        for line in completed.stdout.splitlines():
            parts = line.strip().split("\t")
            if not parts or not parts[0]:
                continue
            name = parts[0]
            if not name.startswith(CONTAINER_PREFIX):
                continue
            candidate = name[len(CONTAINER_PREFIX):]
            try:
                sandbox_id = validate_sandbox_id(candidate)
            except SandboxError:
                # A labelled container whose name we cannot parse is left
                # strictly alone.
                continue
            rows.append({
                "sandbox_id": sandbox_id,
                "created_at": parse_docker_time(parts[1]) if len(parts) > 1 else None,
                "state": parts[2] if len(parts) > 2 else "unknown",
            })
        return sorted(rows, key=lambda r: r["sandbox_id"])
