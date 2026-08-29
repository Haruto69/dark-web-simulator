"""B. File-impact correctness, C. reset correctness, E. failure behaviour."""

import os

import pytest

from sandbox import FileImpactScenario, SandboxNotReadyError
from sandbox.dataset import BASELINE_FILENAMES, SYNTHETIC_FILES
from sandbox.paths import IMPACT_SUFFIX


def workspace(manager):
    return manager.backend._workspace(manager.default_sandbox_id)


def test_create_seeds_the_full_synthetic_dataset(manager):
    manager.create()
    root = workspace(manager)
    for name in BASELINE_FILENAMES:
        assert os.path.isfile(os.path.join(root, name))
    assert all(f["status"] == "baseline" for f in manager.workspace_state())


def test_file_impact_renames_every_synthetic_file(manager):
    manager.create()
    result = FileImpactScenario(manager).run()

    assert result["impacted"] == len(BASELINE_FILENAMES)
    root = workspace(manager)
    for name in BASELINE_FILENAMES:
        assert not os.path.exists(os.path.join(root, name))
        assert os.path.isfile(os.path.join(root, name + IMPACT_SUFFIX))
    assert all(f["status"] == "impacted" for f in manager.workspace_state())


def test_impact_does_not_alter_file_contents(manager):
    """The emulator renames only -- it must never transform bytes."""
    manager.create()
    FileImpactScenario(manager).run()
    root = workspace(manager)
    for name, expected in SYNTHETIC_FILES.items():
        with open(os.path.join(root, name + IMPACT_SUFFIX), encoding="utf-8") as fh:
            assert fh.read() == expected


def test_impact_can_target_a_single_file(manager):
    manager.create()
    result = FileImpactScenario(manager).run(targets=["finance_report.txt"])
    assert result["impacted"] == 1
    states = {f["name"]: f["status"] for f in manager.workspace_state()}
    assert states["finance_report.txt"] == "impacted"
    assert states["thesis_draft.txt"] == "baseline"


def test_unsafe_targets_are_rejected_not_executed(manager):
    manager.create()
    result = FileImpactScenario(manager).run(
        targets=["../../../etc/passwd", "finance_report.txt"])

    statuses = {r["target"]: r["status"] for r in result["results"]}
    assert statuses["../../../etc/passwd"] == "rejected"
    assert statuses["finance_report.txt"] == "impacted"
    assert result["impacted"] == 1


def test_reset_restores_the_exact_baseline(manager):
    manager.create()
    FileImpactScenario(manager).run()
    manager.reset()

    root = workspace(manager)
    for name, expected in SYNTHETIC_FILES.items():
        assert not os.path.exists(os.path.join(root, name + IMPACT_SUFFIX))
        with open(os.path.join(root, name), encoding="utf-8") as fh:
            assert fh.read() == expected
    assert all(f["status"] == "baseline" for f in manager.workspace_state())


def test_runs_are_deterministic_across_reset(manager):
    manager.create()
    first = FileImpactScenario(manager).run()["results"]
    manager.reset()
    second = FileImpactScenario(manager).run()["results"]

    strip = lambda rs: [(r["target"], r["status"], r.get("new_name")) for r in rs]
    assert strip(first) == strip(second)
    # Content digests must match too -- same baseline bytes every time.
    assert [r["content_sha256_16"] for r in first] == \
           [r["content_sha256_16"] for r in second]


def test_scenario_without_a_sandbox_fails_cleanly(manager):
    with pytest.raises(SandboxNotReadyError):
        FileImpactScenario(manager).run()
    # Guard rail: no workspace was created as a side effect.
    assert manager.status()["state"] == "absent"


def test_destroy_removes_the_workspace(manager):
    manager.create()
    manager.destroy()
    assert manager.status()["state"] == "absent"
    assert not os.path.exists(workspace(manager))
