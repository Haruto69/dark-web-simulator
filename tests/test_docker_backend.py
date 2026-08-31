"""Docker backend tests.

Split in two:
  * unit tests that assert the *hardening flags* of the docker command line
    without needing Docker (they capture subprocess arguments);
  * integration tests that are skipped unless Docker and the sandbox image are
    actually available.

Build the image first for the integration tests:
    docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
"""

import hashlib
import json
import pathlib
import subprocess
import time

import pytest

from sandbox.backends.docker import DEFAULT_IMAGE, DockerBackend
from sandbox.dataset import (BASELINE_DIGESTS, BASELINE_FILENAMES,
                             SYNTHETIC_FILES, seed_workspace,
                             verify_workspace, workspace_digests)
from sandbox.errors import SandboxCommandError, SandboxError
from sandbox.manager import SandboxManager
from sandbox.scenarios.file_impact import FileImpactScenario


SEED_STDOUT = json.dumps({"workspace": "/workspace",
                          "files": list(BASELINE_FILENAMES),
                          "digests": dict(BASELINE_DIGESTS)})


class _Recorder:
    """Captures argv instead of executing Docker.

    ``create()`` seeds synchronously via ``docker exec``, so the fake answers a
    seed exec with the payload a real container would produce; every other
    command gets ``stdout``.
    """

    def __init__(self, returncode=0, stdout="", seed_stdout=SEED_STDOUT,
                 seed_returncode=0):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout
        self.seed_stdout = seed_stdout
        self.seed_returncode = seed_returncode

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if "sandbox.tools.seed" in args:
            return subprocess.CompletedProcess(
                args, self.seed_returncode, self.seed_stdout, "")
        return subprocess.CompletedProcess(args, self.returncode, self.stdout, "")


def test_create_uses_hardened_flags(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    DockerBackend().create("primary")

    run_argv = [a for a, _ in recorder.calls if "run" in a][0]
    assert run_argv[:2] == ["docker", "run"]
    for flag, value in [("--network", "none"), ("--cap-drop", "ALL"),
                        ("--security-opt", "no-new-privileges"),
                        ("--user", "10001:10001")]:
        assert value == run_argv[run_argv.index(flag) + 1]

    forbidden = ["--privileged", "--network=host", "-v", "--volume", "--mount",
                 "/var/run/docker.sock", "--pid=host", "--cap-add"]
    for token in forbidden:
        assert token not in run_argv, "%s must never be used" % token
    assert DEFAULT_IMAGE in run_argv


def test_subprocess_is_never_invoked_through_a_shell(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    DockerBackend().create("primary")
    for args, kwargs in recorder.calls:
        assert kwargs.get("shell") is False
        assert isinstance(args, list)
        assert kwargs.get("timeout")


@pytest.mark.parametrize("bad", ["../evil", "a b", "Primary; rm -rf /", "", "x" * 40])
def test_invalid_sandbox_ids_are_refused(bad):
    with pytest.raises(SandboxError):
        DockerBackend().create(bad)


def test_timeout_is_reported_as_a_sandbox_error(monkeypatch):
    def timeout(args, **kwargs):
        raise subprocess.TimeoutExpired(args, 1)
    monkeypatch.setattr(subprocess, "run", timeout)
    with pytest.raises(SandboxCommandError):
        DockerBackend().status("primary")


def test_unsafe_targets_never_reach_the_container(monkeypatch):
    backend = DockerBackend()
    monkeypatch.setattr(backend, "_exec_tool",
                        lambda *a, **k: pytest.fail("unsafe target reached container"))
    results = backend.run_impact("primary", ["../../etc/passwd"])
    assert results[0]["status"] == "rejected"


# -- readiness: create() must not return before the workspace is seeded -------
#
# Regression cover for the race in which `docker run --detach` returned while
# the image CMD was still seeding, so a caller could read a baseline file that
# existed but was still zero bytes.

def _commands(recorder):
    return [argv for argv, _ in recorder.calls]


def _seed_index(commands):
    return next(i for i, argv in enumerate(commands)
                if "sandbox.tools.seed" in argv)


def test_create_seeds_the_workspace_synchronously_before_returning(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    DockerBackend().create("primary")

    commands = _commands(recorder)
    run_index = next(i for i, argv in enumerate(commands) if argv[1] == "run")
    seed_index = _seed_index(commands)
    assert run_index < seed_index, "the container must exist before it is seeded"

    seed_argv = commands[seed_index]
    assert seed_argv[:4] == ["docker", "exec", "--", "dws-sandbox-primary"]
    assert seed_argv[-3:] == ["python", "-m", "sandbox.tools.seed"]
    # Exactly one seed per create, and nothing weakens the container to do it.
    assert sum("sandbox.tools.seed" in argv for argv in commands) == 1


def test_create_does_not_wait_on_a_timer(monkeypatch):
    """Readiness is a content check; no sleeping, polling or retry loop."""
    recorder = _Recorder()
    slept = []
    monkeypatch.setattr(subprocess, "run", recorder)
    monkeypatch.setattr(time, "sleep", lambda seconds: slept.append(seconds))
    DockerBackend().create("primary")
    assert slept == []
    for argv in _commands(recorder):
        assert "sleep" not in argv
        assert "wait" not in argv


def test_the_image_does_not_seed_asynchronously_at_start():
    root = pathlib.Path(__file__).resolve().parents[1]
    dockerfile = root / "docker" / "sandbox-target" / "Dockerfile"
    cmd_lines = [line for line in dockerfile.read_text(encoding="utf-8").splitlines()
                 if line.startswith("CMD")]
    assert cmd_lines, "the image must declare a CMD"
    assert all("sandbox.tools.seed" not in line for line in cmd_lines), (
        "seeding from CMD runs after `docker run --detach` returns and "
        "reintroduces the partially seeded workspace race")


def test_failed_seeding_destroys_the_container_and_raises(monkeypatch):
    recorder = _Recorder(seed_returncode=1, seed_stdout="")
    monkeypatch.setattr(subprocess, "run", recorder)
    with pytest.raises(SandboxCommandError):
        DockerBackend().create("primary")

    commands = _commands(recorder)
    seed_index = _seed_index(commands)
    removals = [i for i, argv in enumerate(commands) if argv[1] == "rm"]
    assert any(i > seed_index for i in removals), (
        "a sandbox that failed to seed must be destroyed, never returned")


def test_a_partially_seeded_workspace_is_never_reported_ready(monkeypatch):
    """An empty baseline file is exactly the symptom the race produced."""
    wrong = dict(BASELINE_DIGESTS)
    wrong[BASELINE_FILENAMES[0]] = hashlib.sha256(b"").hexdigest()
    recorder = _Recorder(seed_stdout=json.dumps(
        {"workspace": "/workspace", "files": list(BASELINE_FILENAMES),
         "digests": wrong}))
    monkeypatch.setattr(subprocess, "run", recorder)

    with pytest.raises(SandboxCommandError):
        DockerBackend().create("primary")
    commands = _commands(recorder)
    assert any(argv[1] == "rm" for argv in commands[_seed_index(commands):])


def test_seeding_introduces_no_containment_weakening_arguments(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    DockerBackend().create("primary")
    forbidden = ["--privileged", "--network=host", "-v", "--volume", "--mount",
                 "/var/run/docker.sock", "--pid=host", "--cap-add", "--user=root",
                 "--read-only=false"]
    for argv in _commands(recorder):
        for token in forbidden:
            assert token not in argv, "%s must never be used" % token


def test_reset_recreates_and_reseeds(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(subprocess, "run", recorder)
    DockerBackend().reset("primary")
    commands = _commands(recorder)
    assert any(argv[1] == "run" for argv in commands)
    assert _seed_index(commands) > next(
        i for i, argv in enumerate(commands) if argv[1] == "run")


# -- the seeding primitive itself --------------------------------------------

def test_seed_workspace_verifies_its_own_writes(tmp_path):
    written = seed_workspace(str(tmp_path))
    assert written == list(BASELINE_FILENAMES)
    assert workspace_digests(str(tmp_path)) == dict(BASELINE_DIGESTS)
    for name in BASELINE_FILENAMES:
        assert (tmp_path / name).read_bytes() == SYNTHETIC_FILES[name].encode("utf-8")


def test_verify_workspace_rejects_an_empty_baseline_file(tmp_path):
    seed_workspace(str(tmp_path))
    (tmp_path / BASELINE_FILENAMES[0]).write_bytes(b"")
    with pytest.raises(SandboxError):
        verify_workspace(str(tmp_path))


def test_verify_workspace_rejects_a_missing_baseline_file(tmp_path):
    seed_workspace(str(tmp_path))
    (tmp_path / BASELINE_FILENAMES[1]).unlink()
    with pytest.raises(SandboxError):
        verify_workspace(str(tmp_path))


# -- integration -------------------------------------------------------------

def _docker_image_ready():
    backend = DockerBackend()
    if not backend.is_available():
        return False
    try:
        return backend._run(["image", "inspect", "--", DEFAULT_IMAGE],
                            check=False).returncode == 0
    except SandboxError:
        return False


docker_required = pytest.mark.skipif(
    not _docker_image_ready(),
    reason="Docker or the dark-web-sandbox-target image is unavailable")


@docker_required
def test_docker_end_to_end():
    backend = DockerBackend()
    manager = SandboxManager(backend, default_sandbox_id="pytest")
    try:
        manager.create()
        assert manager.status()["ready"] is True
        assert all(f["status"] == "baseline" for f in manager.workspace_state())

        result = FileImpactScenario(manager).run()
        assert result["impacted"] == len(BASELINE_FILENAMES)
        assert all(f["status"] == "impacted" for f in manager.workspace_state())

        manager.reset()
        assert all(f["status"] == "baseline" for f in manager.workspace_state())
    finally:
        manager.destroy()


@docker_required
def test_container_has_no_network_access():
    backend = DockerBackend()
    manager = SandboxManager(backend, default_sandbox_id="pytest-net")
    try:
        manager.create()
        probe = backend._run([
            "exec", "--", backend._container("pytest-net"), "python", "-c",
            "import socket;socket.create_connection(('1.1.1.1',53),3)"
        ], check=False)
        assert probe.returncode != 0, "sandbox container must have no network"
    finally:
        manager.destroy()
