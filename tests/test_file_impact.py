"""B. File-impact correctness, C. reset correctness, E. failure behaviour."""

import os

import pytest

from sandbox import FileImpactScenario, SandboxNotReadyError
from sandbox import impact_core
from sandbox.dataset import (BASELINE_DIGESTS, BASELINE_FILENAMES,
                             SYNTHETIC_FILES)
from sandbox.errors import BaselineMismatchError, SandboxError, UnsafePathError
from sandbox.paths import IMPACT_SUFFIX


def workspace(manager):
    return manager.backend._workspace(manager.default_sandbox_id)


def test_create_seeds_the_full_synthetic_dataset(manager):
    manager.create()
    root = workspace(manager)
    for name in BASELINE_FILENAMES:
        assert os.path.isfile(os.path.join(root, name))
    assert all(f["status"] == "baseline" for f in manager.workspace_state())


def test_file_impact_transforms_every_synthetic_file(manager):
    manager.create()
    result = FileImpactScenario(manager).run()

    assert result["impacted"] == len(BASELINE_FILENAMES)
    root = workspace(manager)
    for name in BASELINE_FILENAMES:
        assert not os.path.exists(os.path.join(root, name))
        assert os.path.isfile(os.path.join(root, name + IMPACT_SUFFIX))
    assert all(f["status"] == "impacted" for f in manager.workspace_state())


def test_impact_replaces_contents_with_the_fixed_demo_state(manager):
    """The emulator no longer renames only: the synthetic plaintext is gone."""
    manager.create()
    FileImpactScenario(manager).run()
    root = workspace(manager)
    for name in BASELINE_FILENAMES:
        with open(os.path.join(root, name + IMPACT_SUFFIX), "rb") as fh:
            data = fh.read()
        assert data == impact_core.demo_state_bytes(name)
        assert impact_core.is_demo_state(data)
        assert data != SYNTHETIC_FILES[name].encode("utf-8")


def test_impacted_files_no_longer_contain_the_synthetic_plaintext(manager):
    """Plaintext markers from the baseline must not survive anywhere."""
    manager.create()
    FileImpactScenario(manager).run()
    root = workspace(manager)
    markers = ["Synthetic Person A", "Example Client One", "1,240,000",
               "Milestone 1: sandbox foundation", "Abstract (placeholder)"]
    blob = b""
    for entry in sorted(os.listdir(root)):
        path = os.path.join(root, entry)
        if os.path.isfile(path):
            with open(path, "rb") as fh:
                blob += fh.read()
    for marker in markers:
        assert marker.encode("utf-8") not in blob, marker


def test_the_demo_state_carries_no_original_content(manager):
    """The placeholder is a constant of the filename, not of the file."""
    for name in BASELINE_FILENAMES:
        text = impact_core.demo_state_text(name)
        assert text.startswith(impact_core.DEMO_STATE_MAGIC + "\n")
        assert "original_filename=%s" % name in text
        assert "simulation_only=true" in text
        # Every non-trivial line of the baseline is absent from the placeholder.
        for line in SYNTHETIC_FILES[name].splitlines():
            if len(line.strip()) > 12:
                assert line not in text


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


# -- the two safety gates ----------------------------------------------------
#
# Gate one is the filename allow-list; gate two is the baseline digest. Both
# must hold before a single byte is written. These tests are the boundary: they
# assert what the emulator refuses, which is the property that keeps it
# non-generalisable.

@pytest.mark.parametrize("hostile", [
    "not_in_dataset.txt",           # unknown filename
    "../../etc/passwd",             # traversal
    "../finance_report.txt",        # traversal to a known name
    "nested/dir/finance_report.txt",  # nested path
    "/etc/passwd",                  # absolute, outside the workspace
    "/workspace/../etc/passwd",     # absolute with traversal
    "finance_report.*",             # glob-ish
    "*.txt",                        # glob-ish
    "",                             # empty
    "finance_report.txt\x00.png",   # NUL byte
])
def test_targets_outside_the_fixed_dataset_are_rejected(manager, hostile):
    manager.create()
    root = workspace(manager)
    with pytest.raises(UnsafePathError):
        impact_core.impact_one(root, hostile)
    # Nothing was touched: the whole baseline is still intact.
    assert all(f["status"] == "baseline" for f in manager.workspace_state())


def test_a_known_filename_with_modified_content_is_rejected(manager):
    """Gate two. The name is allow-listed; the bytes are not the baseline."""
    manager.create()
    root = workspace(manager)
    target = os.path.join(root, "finance_report.txt")
    with open(target, "wb") as fh:
        fh.write(b"pretend this is somebody's real document\n")

    with pytest.raises(BaselineMismatchError):
        impact_core.impact_one(root, "finance_report.txt")

    # Refused *untouched*: the emulator never discards bytes it did not write.
    with open(target, "rb") as fh:
        assert fh.read() == b"pretend this is somebody's real document\n"
    assert not os.path.exists(target + IMPACT_SUFFIX)


def test_a_single_appended_byte_is_enough_to_be_refused(manager):
    manager.create()
    root = workspace(manager)
    target = os.path.join(root, "client_database.csv")
    with open(target, "ab") as fh:
        fh.write(b"x")
    with pytest.raises(BaselineMismatchError):
        impact_core.impact_one(root, "client_database.csv")


def test_the_digest_gate_is_reported_as_a_rejection_not_a_failure(manager):
    manager.create()
    root = workspace(manager)
    with open(os.path.join(root, "project_notes.txt"), "wb") as fh:
        fh.write(b"modified\n")

    result = FileImpactScenario(manager).run()
    statuses = {r["target"]: r["status"] for r in result["results"]}
    assert statuses["project_notes.txt"] == "rejected"
    assert result["impacted"] == len(BASELINE_FILENAMES) - 1
    # The refusal reason describes policy, never the file's content.
    detail = [r["detail"] for r in result["results"]
              if r["target"] == "project_notes.txt"][0]
    assert impact_core.REJECT_NOT_BASELINE_CONTENT in detail
    assert "modified" not in detail


def test_an_already_impacted_file_is_not_transformed_twice(manager):
    manager.create()
    root = workspace(manager)
    impact_core.impact_one(root, "thesis_draft.txt")
    again = impact_core.impact_one(root, "thesis_draft.txt")
    assert again["status"] == "already_impacted"
    with open(os.path.join(root, "thesis_draft.txt" + IMPACT_SUFFIX), "rb") as fh:
        assert fh.read() == impact_core.demo_state_bytes("thesis_draft.txt")


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="no symlink support")
def test_a_symlink_under_a_baseline_name_is_never_followed(manager, tmp_path):
    """A link occupying an allow-listed name must not redirect the write."""
    manager.create()
    root = workspace(manager)
    outsider = tmp_path / "outside.txt"
    outsider.write_text("content that lives outside the workspace\n",
                        encoding="utf-8")

    target = os.path.join(root, "employee_records.csv")
    os.remove(target)
    try:
        os.symlink(str(outsider), target)
    except (OSError, NotImplementedError, AttributeError):
        pytest.skip("this platform does not permit creating symlinks")

    with pytest.raises(SandboxError):
        impact_core.impact_one(root, "employee_records.csv")

    # The link target outside the workspace is untouched, and nothing was
    # written through it.
    assert outsider.read_text(encoding="utf-8") == \
        "content that lives outside the workspace\n"
    assert not os.path.exists(os.path.join(root, "employee_records.csv"
                                           + IMPACT_SUFFIX))


def test_only_the_five_synthetic_files_are_ever_touched(manager):
    """No file outside the fixed dataset appears, changes, or disappears."""
    manager.create()
    root = workspace(manager)
    bystander = os.path.join(root, "unrelated_bystander.txt")
    with open(bystander, "wb") as fh:
        fh.write(b"not part of the dataset\n")

    FileImpactScenario(manager).run()

    with open(bystander, "rb") as fh:
        assert fh.read() == b"not part of the dataset\n"
    expected = {n + IMPACT_SUFFIX for n in BASELINE_FILENAMES}
    expected.add("unrelated_bystander.txt")
    assert set(os.listdir(root)) == expected


# -- transactional safety ----------------------------------------------------

def test_a_write_failure_leaves_no_partial_or_corrupt_output(manager,
                                                             monkeypatch):
    manager.create()
    root = workspace(manager)
    original = os.path.join(root, "finance_report.txt")

    def boom(src, dst):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(SandboxError):
        impact_core.impact_one(root, "finance_report.txt")

    # The original is intact, the destination does not exist, and no staging
    # file was left behind.
    with open(original, "rb") as fh:
        assert fh.read() == SYNTHETIC_FILES["finance_report.txt"].encode("utf-8")
    assert not os.path.exists(original + IMPACT_SUFFIX)
    assert not any(e.endswith(impact_core.STAGING_SUFFIX)
                   for e in os.listdir(root))


def test_a_failed_impact_is_surfaced_not_reported_as_success(manager,
                                                             monkeypatch):
    manager.create()

    def boom(src, dst):
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(os, "replace", boom)

    with pytest.raises(SandboxError):
        FileImpactScenario(manager).run()


def test_no_staging_file_survives_a_successful_run(manager):
    manager.create()
    FileImpactScenario(manager).run()
    assert not any(e.endswith(impact_core.STAGING_SUFFIX)
                   for e in os.listdir(workspace(manager)))


# -- reset is the only restoration path --------------------------------------

def test_there_is_no_reverse_operation(manager):
    """No unlock/decrypt/restore path exists in the emulator or its CLI."""
    from sandbox.tools import impact_tool

    assert not hasattr(impact_core, "restore_one")
    with pytest.raises(SystemExit):
        impact_tool.main(["restore", "--", "finance_report.txt"])


def test_reset_restores_byte_identical_content_after_a_content_impact(manager):
    import hashlib

    manager.create()
    FileImpactScenario(manager).run()
    manager.reset()

    root = workspace(manager)
    assert set(os.listdir(root)) == set(BASELINE_FILENAMES)
    for name in BASELINE_FILENAMES:
        with open(os.path.join(root, name), "rb") as fh:
            data = fh.read()
        assert hashlib.sha256(data).hexdigest() == BASELINE_DIGESTS[name]
        assert data == SYNTHETIC_FILES[name].encode("utf-8")
