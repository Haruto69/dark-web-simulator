"""Milestone 3, section 2: measured containment of the real Docker sandbox.

These are *controlled containment tests*, not exploit attempts. Every probe is
either a read of container configuration or a benign operation that is expected
to fail; none of them attempts to escape, escalate, or attack anything. The
container has no network, so a network probe cannot reach a third party even in
principle.

Skipped automatically when Docker or the target image is unavailable. Build it
with::

    docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
"""

import json
import uuid

import pytest

from sandbox.backends.docker import (DEFAULT_IMAGE, OWNER_LABEL_KEY,
                                     OWNER_LABEL_VALUE, DockerBackend)
from sandbox.dataset import BASELINE_FILENAMES, SYNTHETIC_FILES
from sandbox.errors import SandboxError
from sandbox.impact_core import demo_state_text
from sandbox.manager import SandboxManager
from sandbox.scenarios.file_impact import FileImpactScenario


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

pytestmark = docker_required


@pytest.fixture
def backend():
    return DockerBackend()


@pytest.fixture
def sandbox(backend):
    """One disposable container, always removed afterwards."""
    sandbox_id = "pytest-%s" % uuid.uuid4().hex[:8]
    backend.create(sandbox_id)
    try:
        yield sandbox_id
    finally:
        backend.destroy(sandbox_id)


def inspect(backend, sandbox_id):
    raw = backend._run(["inspect", "--", backend._container(sandbox_id)]).stdout
    return json.loads(raw)[0]


def run_in(backend, sandbox_id, *argv):
    return backend._run(["exec", "--", backend._container(sandbox_id)] + list(argv),
                        check=False)


# -- declared isolation properties -------------------------------------------

def test_network_mode_is_none(backend, sandbox):
    config = inspect(backend, sandbox)
    assert config["HostConfig"]["NetworkMode"] == "none"
    assert list(config["NetworkSettings"]["Networks"]) == ["none"]
    # No address at all: on this Docker version the key is absent entirely
    # for --network none, which is stronger than an empty string.
    assert not config["NetworkSettings"].get("IPAddress")
    assert not config["NetworkSettings"].get("Ports")


def test_root_filesystem_is_read_only(backend, sandbox):
    assert inspect(backend, sandbox)["HostConfig"]["ReadonlyRootfs"] is True


def test_container_runs_as_a_non_root_user(backend, sandbox):
    assert inspect(backend, sandbox)["Config"]["User"] == "10001:10001"
    probe = run_in(backend, sandbox, "python", "-c", "import os;print(os.getuid())")
    assert probe.stdout.strip() == "10001"


def test_all_capabilities_are_dropped(backend, sandbox):
    host = inspect(backend, sandbox)["HostConfig"]
    assert host["CapDrop"] == ["ALL"]
    assert not host["CapAdd"]


def test_no_new_privileges_is_enabled(backend, sandbox):
    assert "no-new-privileges" in inspect(backend, sandbox)["HostConfig"]["SecurityOpt"]


def test_container_is_not_privileged(backend, sandbox):
    assert inspect(backend, sandbox)["HostConfig"]["Privileged"] is False


def test_host_namespaces_are_not_shared(backend, sandbox):
    host = inspect(backend, sandbox)["HostConfig"]
    assert host["NetworkMode"] != "host"
    assert (host.get("PidMode") or "") != "host"
    assert (host.get("IpcMode") or "") != "host"
    assert (host.get("UTSMode") or "") != "host"


def test_no_bind_mounts_or_volumes(backend, sandbox):
    config = inspect(backend, sandbox)
    assert not config["HostConfig"]["Binds"]
    assert not config["HostConfig"]["VolumesFrom"]
    # The only mount is the workspace tmpfs, which is RAM, not a host path.
    for mount in config.get("Mounts") or []:
        assert mount.get("Type") != "bind", "no host directory may be mounted"


def test_the_workspace_is_a_tmpfs_not_a_host_directory(backend, sandbox):
    tmpfs = inspect(backend, sandbox)["HostConfig"].get("Tmpfs") or {}
    assert "/workspace" in tmpfs
    mounts = run_in(backend, sandbox, "cat", "/proc/mounts").stdout
    workspace_line = [line for line in mounts.splitlines()
                      if " /workspace " in line]
    assert workspace_line and workspace_line[0].startswith("tmpfs ")


def test_no_docker_socket_is_exposed(backend, sandbox):
    config = inspect(backend, sandbox)
    serialised = json.dumps(config)
    assert "docker.sock" not in serialised
    probe = run_in(backend, sandbox, "python", "-c",
                   "import os;print(os.path.exists('/var/run/docker.sock'))")
    assert probe.stdout.strip() == "False"


def test_memory_and_pid_limits_are_applied(backend, sandbox):
    host = inspect(backend, sandbox)["HostConfig"]
    assert host["Memory"] == 256 * 1024 * 1024
    assert host["PidsLimit"] == 128


def test_container_carries_the_ownership_label(backend, sandbox):
    labels = inspect(backend, sandbox)["Config"]["Labels"]
    assert labels.get(OWNER_LABEL_KEY) == OWNER_LABEL_VALUE


# -- negative containment probes ---------------------------------------------

def test_outbound_tcp_is_unreachable(backend, sandbox):
    probe = run_in(backend, sandbox, "python", "-c",
                   "import socket;socket.create_connection(('1.1.1.1',53),3)")
    assert probe.returncode != 0
    assert "unreachable" in (probe.stderr or "").lower()


def test_dns_resolution_fails(backend, sandbox):
    probe = run_in(backend, sandbox, "python", "-c",
                   "import socket;socket.gethostbyname('example.com')")
    assert probe.returncode != 0


def test_the_host_gateway_is_unreachable(backend, sandbox):
    probe = run_in(backend, sandbox, "python", "-c",
                   "import socket;socket.create_connection(('172.17.0.1',80),3)")
    assert probe.returncode != 0


def test_writing_outside_the_workspace_fails(backend, sandbox):
    for path in ("/etc/probe", "/opt/simulator/probe", "/probe"):
        probe = run_in(backend, sandbox, "python", "-c",
                       "open(%r,'w').write('x')" % path)
        assert probe.returncode != 0, "%s must not be writable" % path


def test_the_workspace_itself_is_writable(backend, sandbox):
    probe = run_in(backend, sandbox, "python", "-c",
                   "open('/workspace/.probe','w').write('x')")
    assert probe.returncode == 0, "the scenario needs a writable workspace"


def test_a_dropped_capability_cannot_be_used(backend, sandbox):
    raw_socket = run_in(backend, sandbox, "python", "-c",
                        "import socket;socket.socket(socket.AF_INET,socket.SOCK_RAW,1)")
    assert raw_socket.returncode != 0
    chown = run_in(backend, sandbox, "python", "-c",
                   "import os;os.chown('/etc/hostname',10001,10001)")
    assert chown.returncode != 0


def test_no_host_filesystem_is_visible(backend, sandbox):
    probe = run_in(backend, sandbox, "python", "-c",
                   "import os;print([p for p in ('/host','/mnt/c','/c')"
                   " if os.path.exists(p)])")
    assert probe.stdout.strip() == "[]"


def test_the_scenario_tool_rejects_targets_outside_the_workspace(backend, sandbox):
    for hostile in ("../../etc/passwd", "/etc/passwd", "nested/dir/file.txt"):
        probe = run_in(backend, sandbox, "python", "-m",
                       "sandbox.tools.impact_tool", "impact", "--", hostile)
        results = json.loads(probe.stdout)
        assert results[0]["status"] == "rejected", hostile


def test_an_unknown_filename_is_rejected_even_inside_the_workspace(backend, sandbox):
    run_in(backend, sandbox, "python", "-c",
           "open('/workspace/not_in_dataset.txt','w').write('x')")
    probe = run_in(backend, sandbox, "python", "-m",
                   "sandbox.tools.impact_tool", "impact", "--",
                   "not_in_dataset.txt")
    assert json.loads(probe.stdout)[0]["status"] == "rejected"


def test_one_sandbox_cannot_see_another_sandboxes_workspace(backend):
    first = "pytest-iso-a-%s" % uuid.uuid4().hex[:6]
    second = "pytest-iso-b-%s" % uuid.uuid4().hex[:6]
    backend.create(first)
    backend.create(second)
    try:
        marker = "marker-%s" % uuid.uuid4().hex[:8]
        run_in(backend, first, "python", "-c",
               "open('/workspace/%s','w').write('x')" % marker)

        listing = run_in(backend, second, "python", "-c",
                         "import os,json;print(json.dumps(sorted(os.listdir('/workspace'))))")
        assert marker not in json.loads(listing.stdout)

        # Impacting one workspace leaves the other at baseline.
        backend.run_impact(first, list(BASELINE_FILENAMES))
        assert all(f["status"] == "impacted"
                   for f in backend.workspace_state(first))
        assert all(f["status"] == "baseline"
                   for f in backend.workspace_state(second))

        # Content-level non-interference: the untouched sandbox still holds the
        # exact synthetic plaintext, and none of the demo state leaked into it.
        for name in BASELINE_FILENAMES:
            probe = run_in(backend, second, "python", "-c",
                           "import sys;sys.stdout.write("
                           "open('/workspace/%s').read())" % name)
            assert probe.stdout == SYNTHETIC_FILES[name], name
            assert "DWS-DEMO-STATE" not in probe.stdout
    finally:
        backend.destroy(first)
        backend.destroy(second)


# -- lifecycle correctness ---------------------------------------------------

def test_reset_restores_byte_identical_baseline_content(backend, sandbox):
    manager = SandboxManager(backend, default_sandbox_id=None)
    FileImpactScenario(manager).run(sandbox_id=sandbox)
    manager.reset(sandbox)

    for name in BASELINE_FILENAMES:
        probe = run_in(backend, sandbox, "python", "-c",
                       "import sys;sys.stdout.write(open('/workspace/%s').read())" % name)
        assert probe.stdout == SYNTHETIC_FILES[name], name


def test_impact_replaces_content_inside_the_container(backend, sandbox):
    """The synthetic plaintext is gone; the fixed demo state is in its place."""
    backend.run_impact(sandbox, ["finance_report.txt"])
    probe = run_in(backend, sandbox, "python", "-c",
                   "import sys;sys.stdout.write("
                   "open('/workspace/finance_report.txt.demo_locked').read())")
    assert probe.stdout == demo_state_text("finance_report.txt")
    assert probe.stdout != SYNTHETIC_FILES["finance_report.txt"]

    # The original name is gone, and the plaintext is nowhere in the workspace.
    listing = run_in(backend, sandbox, "python", "-c",
                     "import os,json;print(json.dumps(sorted(os.listdir('/workspace'))))")
    entries = json.loads(listing.stdout)
    assert "finance_report.txt" not in entries
    assert "finance_report.txt.demo_locked" in entries
    assert not any(e.endswith(".demo_staging") for e in entries)

    blob = run_in(backend, sandbox, "python", "-c",
                  "import os,sys;d='/workspace';"
                  "sys.stdout.write(''.join("
                  "open(os.path.join(d,n),encoding='utf-8',errors='replace').read()"
                  " for n in sorted(os.listdir(d))"
                  " if os.path.isfile(os.path.join(d,n))))").stdout
    assert "1,240,000" not in blob
    assert "QUARTERLY FINANCE REPORT" not in blob


def test_every_baseline_file_is_content_impacted_in_the_container(backend, sandbox):
    backend.run_impact(sandbox, list(BASELINE_FILENAMES))
    for name in BASELINE_FILENAMES:
        probe = run_in(backend, sandbox, "python", "-c",
                       "import sys;sys.stdout.write("
                       "open('/workspace/%s.demo_locked').read())" % name)
        assert probe.stdout == demo_state_text(name), name
        assert probe.stdout != SYNTHETIC_FILES[name], name
        assert probe.stdout.strip(), name


def test_the_digest_gate_refuses_a_modified_file_in_the_container(backend, sandbox):
    """An allow-listed name holding non-baseline bytes is refused untouched."""
    run_in(backend, sandbox, "python", "-c",
           "open('/workspace/project_notes.txt','w').write('locally modified\\n')")
    probe = run_in(backend, sandbox, "python", "-m",
                   "sandbox.tools.impact_tool", "impact", "--",
                   "project_notes.txt")
    assert json.loads(probe.stdout)[0]["status"] == "rejected"

    still = run_in(backend, sandbox, "python", "-c",
                   "import sys;sys.stdout.write(open('/workspace/project_notes.txt').read())")
    assert still.stdout == "locally modified\n"
    exists = run_in(backend, sandbox, "python", "-c",
                    "import os;print(os.path.exists("
                    "'/workspace/project_notes.txt.demo_locked'))")
    assert exists.stdout.strip() == "False"


def test_a_symlink_under_a_baseline_name_is_not_followed_in_the_container(
        backend, sandbox):
    run_in(backend, sandbox, "python", "-c",
           "import os;os.remove('/workspace/client_database.csv');"
           "os.symlink('/etc/hostname','/workspace/client_database.csv')")
    probe = run_in(backend, sandbox, "python", "-m",
                   "sandbox.tools.impact_tool", "impact", "--",
                   "client_database.csv")
    assert json.loads(probe.stdout)[0]["status"] == "rejected"
    # /etc is read-only anyway; assert the link target is intact regardless.
    target = run_in(backend, sandbox, "python", "-c",
                    "import sys;sys.stdout.write(open('/etc/hostname').read())")
    assert "DWS-DEMO-STATE" not in target.stdout


def test_destroying_a_sandbox_discards_its_state(backend):
    sandbox_id = "pytest-gone-%s" % uuid.uuid4().hex[:6]
    backend.create(sandbox_id)
    backend.destroy(sandbox_id)
    assert backend.status(sandbox_id)["state"] == "absent"
    assert sandbox_id not in backend.list_sandboxes()


# -- readiness under rapid lifecycle churn -----------------------------------
#
# Regression cover for a real race seen on a slower Windows/Docker Desktop
# host: the image CMD used to seed the workspace *after* `docker run --detach`
# had already reported the container running, so an immediate read could catch
# a baseline file that existed but was still zero bytes. create() now seeds
# synchronously, so every read below must see the exact baseline.

RAPID_ITERATIONS = 5
STRESS_ITERATIONS = 8


def read_workspace(backend, sandbox_id):
    """Contents of every baseline filename, read in one exec (None if absent)."""
    script = (
        "import json,os,sys;"
        "d='/workspace';"
        "names=%r;"
        "sys.stdout.write(json.dumps({n: (open(os.path.join(d,n),encoding='utf-8')"
        ".read() if os.path.isfile(os.path.join(d,n)) else None) for n in names}))"
        % (list(BASELINE_FILENAMES),))
    probe = run_in(backend, sandbox_id, "python", "-c", script)
    assert probe.returncode == 0, probe.stderr
    return json.loads(probe.stdout)


def assert_exact_baseline(contents, context):
    for name in BASELINE_FILENAMES:
        assert contents[name] is not None, "%s: %s is missing" % (context, name)
        assert contents[name] != "", "%s: %s is empty (partial seed)" % (context, name)
        assert contents[name] == SYNTHETIC_FILES[name], (
            "%s: %s does not match the baseline" % (context, name))


def test_create_returns_only_after_the_full_baseline_is_present(backend, sandbox):
    assert_exact_baseline(read_workspace(backend, sandbox), "after create")
    assert all(f["status"] == "baseline" for f in backend.workspace_state(sandbox))


def test_rapid_create_then_read_never_sees_a_partial_baseline(backend):
    for attempt in range(RAPID_ITERATIONS):
        sandbox_id = "pytest-rapid-%s" % uuid.uuid4().hex[:8]
        backend.create(sandbox_id)
        try:
            assert_exact_baseline(read_workspace(backend, sandbox_id),
                                  "rapid create #%d" % attempt)
        finally:
            backend.destroy(sandbox_id)


def test_reset_returns_only_after_exact_baseline_restoration(backend, sandbox):
    manager = SandboxManager(backend, default_sandbox_id=None)
    FileImpactScenario(manager).run(sandbox_id=sandbox)
    manager.reset(sandbox)
    assert_exact_baseline(read_workspace(backend, sandbox), "after reset")


def test_rapid_impact_reset_read_never_sees_a_partial_baseline(backend, sandbox):
    manager = SandboxManager(backend, default_sandbox_id=None)
    for attempt in range(RAPID_ITERATIONS):
        FileImpactScenario(manager).run(sandbox_id=sandbox)
        manager.reset(sandbox)
        assert_exact_baseline(read_workspace(backend, sandbox),
                              "impact/reset cycle #%d" % attempt)


def test_repeated_lifecycle_stress_does_not_reproduce_the_race(backend):
    """Full create -> impact -> reset -> read cycles, back to back."""
    manager = SandboxManager(backend, default_sandbox_id=None)
    for attempt in range(STRESS_ITERATIONS):
        sandbox_id = "pytest-stress-%s" % uuid.uuid4().hex[:8]
        manager.create(sandbox_id)
        try:
            assert_exact_baseline(read_workspace(backend, sandbox_id),
                                  "stress create #%d" % attempt)
            FileImpactScenario(manager).run(sandbox_id=sandbox_id)
            manager.reset(sandbox_id)
            assert_exact_baseline(read_workspace(backend, sandbox_id),
                                  "stress reset #%d" % attempt)
        finally:
            manager.destroy(sandbox_id)


def test_a_ready_sandbox_reports_baseline_state_immediately(backend):
    """workspace_state() straight after create() must never report 'missing'."""
    for _ in range(RAPID_ITERATIONS):
        sandbox_id = "pytest-state-%s" % uuid.uuid4().hex[:8]
        backend.create(sandbox_id)
        try:
            state = backend.workspace_state(sandbox_id)
            assert {row["status"] for row in state} == {"baseline"}
        finally:
            backend.destroy(sandbox_id)


def test_the_container_seeds_nothing_on_its_own(backend):
    """The image must idle: an unseeded container has an empty workspace.

    Proves the readiness guarantee comes from create()'s synchronous seed and
    not from a lucky race with a background CMD.
    """
    name = "dws-sandbox-pytest-idle-%s" % uuid.uuid4().hex[:6]
    backend._run(["run", "--detach", "--name", name, "--network", "none",
                  "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                  "--read-only", "--tmpfs",
                  "/workspace:rw,noexec,nosuid,uid=10001,gid=10001,size=16m",
                  "--user", "10001:10001", DEFAULT_IMAGE], check=False)
    try:
        for _ in range(3):
            listing = backend._run(
                ["exec", "--", name, "python", "-c",
                 "import os,json;print(json.dumps(sorted(os.listdir('/workspace'))))"],
                check=False)
            assert json.loads(listing.stdout) == []
    finally:
        backend._run(["rm", "--force", "--", name], check=False)


# -- ownership and reaping ---------------------------------------------------

def test_only_labelled_containers_are_enumerated(backend, sandbox):
    metadata = {row["sandbox_id"]: row for row in backend.sandbox_metadata()}
    assert sandbox in metadata
    assert metadata[sandbox]["created_at"] is not None

    # An unlabelled container on the same host must be invisible here.
    foreign = "dws-not-ours-%s" % uuid.uuid4().hex[:6]
    backend._run(["run", "--detach", "--name", foreign, "--network", "none",
                  "--entrypoint", "sleep", DEFAULT_IMAGE, "infinity"], check=False)
    try:
        assert foreign not in backend.list_sandboxes()
        assert all(not row["sandbox_id"].startswith("dws-not-ours")
                   for row in backend.sandbox_metadata())
    finally:
        backend._run(["rm", "--force", "--", foreign], check=False)


def test_reap_stale_destroys_only_old_owned_containers(backend):
    manager = SandboxManager(backend, default_sandbox_id=None)
    old = "pytest-reap-%s" % uuid.uuid4().hex[:6]
    fresh = "pytest-keep-%s" % uuid.uuid4().hex[:6]
    manager.create(old)
    manager.create(fresh)
    try:
        created = manager.status(old)["created_at"]
        assert created is not None

        # Nothing is stale against a long max_age.
        assert manager.reap_stale(86400) == []
        assert manager.status(old)["ready"] is True

        # Reap anything at least 0 seconds old, evaluated far in the future.
        reaped = {row["sandbox_id"]
                  for row in manager.reap_stale(0, now=created + 10_000)}
        assert old in reaped and fresh in reaped
        assert manager.status(old)["state"] == "absent"
    finally:
        backend.destroy(old)
        backend.destroy(fresh)
