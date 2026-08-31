"""Milestone R4, section 30: the ransomware scenario against real containers.

Focused container coverage for the R4 consequence adapter only -- the existing
formal A-F evaluation suite is not duplicated here. Every assertion is either a
read of container configuration or an observation of the synthetic workspace;
nothing attempts to escape, escalate or reach a network.

Skipped automatically when Docker or the target image is unavailable. Build it
with::

    docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
"""

import json
import uuid

import pytest

from sandbox.backends.docker import DEFAULT_IMAGE, DockerBackend
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.errors import SandboxError
from sandbox.manager import SandboxManager
from scenario_adapters.ransomware import (ACTION_ISOLATED_AND_REPORTED,
                                          ACTION_REPORTED_ONLY,
                                          ACTION_RESTARTED,
                                          ACTION_WORK_CONTINUED,
                                          IMPACT_PROGRESSION, INITIAL_IMPACT,
                                          RANSOMWARE_DECISION_ID,
                                          RANSOMWARE_SCENARIO,
                                          RansomwareConsequenceAdapter)
from training.runtime import CounterfactualRuntime
from training.snapshots import StateSnapshot


def _docker_image_ready():
    backend = DockerBackend()
    if not backend.is_available():
        return False
    try:
        return backend.image_available()
    except SandboxError:
        return False


docker_required = pytest.mark.skipif(
    not _docker_image_ready(),
    reason="Docker or the dark-web-sandbox-target image is unavailable")

pytestmark = docker_required


@pytest.fixture
def contained_manager():
    """A manager on the real Docker backend, cleaning up its own container."""
    manager = SandboxManager(DockerBackend(), default_sandbox_id=None)
    created = []

    def make(sandbox_id):
        created.append(sandbox_id)
        return sandbox_id

    manager.make_id = make
    yield manager
    for sandbox_id in created:
        try:
            manager.destroy(sandbox_id)
        except SandboxError:
            pass


@pytest.fixture
def adapter(contained_manager):
    sandbox_id = contained_manager.make_id("r4-dkr-" + uuid.uuid4().hex[:8])
    return RansomwareConsequenceAdapter(contained_manager, sandbox_id)


def counts(state):
    return state["files"]["impacted_count"], state["files"]["available_count"]


def test_initial_state_is_exactly_one_impacted_and_four_pristine(adapter):
    adapter.prepare()
    state = adapter.capture_state()
    assert counts(state) == (1, 4)
    assert state["files"]["impacted"] == [INITIAL_IMPACT]
    assert state["files"]["available"] == list(IMPACT_PROGRESSION[1:])


@pytest.mark.parametrize("action,expected", [
    (ACTION_ISOLATED_AND_REPORTED, 1),
    (ACTION_REPORTED_ONLY, 2),
    (ACTION_RESTARTED, 3),
    (ACTION_WORK_CONTINUED, 5),
])
def test_each_action_reaches_its_authored_count_in_a_container(adapter, action,
                                                               expected):
    adapter.prepare()
    adapter.apply(action)
    assert counts(adapter.capture_state()) == (expected, 5 - expected)


def test_rewind_restores_the_one_impact_baseline_exactly(adapter):
    adapter.prepare()
    baseline = StateSnapshot.capture(adapter.capture_state())
    adapter.apply(ACTION_WORK_CONTINUED)
    assert counts(adapter.capture_state()) == (5, 0)
    adapter.rewind()
    rewound = StateSnapshot.capture(adapter.capture_state())
    assert rewound.digest == baseline.digest
    assert counts(rewound.state) == (1, 4)


def test_full_pair_runs_from_one_verified_baseline_in_containers(adapter):
    pair = CounterfactualRuntime(RANSOMWARE_SCENARIO, adapter).run_decision_pair(
        RANSOMWARE_DECISION_ID,
        factual_choice_id="continue_working",
        counterfactual_choice_id="isolate_and_report")
    assert pair.baseline_digest == pair.rewound_snapshot.digest
    assert counts(pair.baseline_snapshot.state) == (1, 4)
    assert counts(pair.factual.resulting_snapshot.state) == (5, 0)
    assert counts(pair.counterfactual.resulting_snapshot.state) == (1, 4)
    assert pair.factual.choice_id == "continue_working"


def test_the_scenario_container_keeps_the_existing_containment(adapter):
    """No host mount, no network, read-only root -- unchanged by R4."""
    adapter.prepare()
    backend = adapter.manager.backend
    raw = backend._run(["inspect", "--", backend._container(adapter.sandbox_id)])
    config = json.loads(raw.stdout)[0]

    assert config["HostConfig"]["NetworkMode"] == "none"
    assert config["HostConfig"]["ReadonlyRootfs"] is True
    assert config["HostConfig"]["Privileged"] is False
    assert not config["HostConfig"].get("Binds")
    assert config["Mounts"] == []
    assert "/workspace" in config["HostConfig"]["Tmpfs"]
    assert config["HostConfig"]["CapDrop"] == ["ALL"]
    assert "no-new-privileges" in " ".join(
        config["HostConfig"]["SecurityOpt"] or [])
    # The workspace is the only writable path and it is RAM, not the host.
    for mount in config["HostConfig"].get("Mounts") or []:
        assert mount.get("Type") != "bind"


def test_only_synthetic_dataset_entries_exist_in_the_container_workspace(
        adapter):
    adapter.prepare()
    adapter.apply(ACTION_WORK_CONTINUED)
    rows = adapter.manager.workspace_state(adapter.sandbox_id)
    assert sorted(row["name"] for row in rows) == sorted(BASELINE_FILENAMES)
    assert {row["status"] for row in rows} == {"impacted"}


def test_the_target_image_is_the_expected_one(adapter):
    assert adapter.manager.backend.image == DEFAULT_IMAGE
