"""Docker backend tests.

Split in two:
  * unit tests that assert the *hardening flags* of the docker command line
    without needing Docker (they capture subprocess arguments);
  * integration tests that are skipped unless Docker and the sandbox image are
    actually available.

Build the image first for the integration tests:
    docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
"""

import subprocess

import pytest

from sandbox.backends.docker import DEFAULT_IMAGE, DockerBackend
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.errors import SandboxCommandError, SandboxError
from sandbox.manager import SandboxManager
from sandbox.scenarios.file_impact import FileImpactScenario


class _Recorder:
    """Captures argv instead of executing Docker."""

    def __init__(self, returncode=0, stdout=""):
        self.calls = []
        self.returncode = returncode
        self.stdout = stdout

    def __call__(self, args, **kwargs):
        self.calls.append((args, kwargs))
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
