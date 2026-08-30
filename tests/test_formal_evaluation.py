"""Milestone 4, sections 3-4 and 11-12: the formal-run scaffolding itself.

The experiment bodies drive Docker and are exercised by the formal run; what is
tested here is everything that decides *whether a result is admissible*: the
backend guard, the reproducibility profile, the warm-up bookkeeping, the
containment summariser and the result-file layout. A bug in any of those would
silently corrupt every number in the paper.
"""

import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation import containment, environment, formal_run
from evaluation.environment import FormalRunError
from evaluation.specifications import SPECIFICATION_VERSION
from sandbox.backends.base import validate_sandbox_id
from sandbox.backends.docker import DEFAULT_IMAGE
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.paths import IMPACT_SUFFIX


# -- the Docker-only rule ----------------------------------------------------

def test_a_formal_run_refuses_the_local_backend():
    with pytest.raises(FormalRunError) as caught:
        environment.require_docker_backend("local", DEFAULT_IMAGE)
    assert "docker" in str(caught.value)


@pytest.mark.parametrize("backend", ["local", "auto", "", "Docker", None])
def test_only_the_exact_docker_backend_name_is_accepted(backend):
    with pytest.raises(FormalRunError):
        environment.require_docker_backend(backend, DEFAULT_IMAGE)


def test_a_missing_target_image_aborts_the_run(monkeypatch):
    monkeypatch.setattr(environment, "docker_engine_version", lambda: "99.9")
    monkeypatch.setattr(environment, "image_identity", lambda image: (None, None))
    with pytest.raises(FormalRunError) as caught:
        environment.require_docker_backend("docker", "no-such-image:latest")
    assert "docker build" in str(caught.value)


def test_an_unreachable_engine_aborts_rather_than_degrading(monkeypatch):
    monkeypatch.setattr(environment, "docker_engine_version", lambda: None)
    with pytest.raises(FormalRunError) as caught:
        environment.require_docker_backend("docker", DEFAULT_IMAGE)
    assert "local backend" in str(caught.value)


# -- the reproducibility profile ---------------------------------------------

REQUIRED_PROFILE_FIELDS = (
    "os", "docker_desktop_client_version", "docker_engine_version",
    "python_version", "cpu_count", "backend", "target_image",
    "target_image_id", "experiment_timestamp_utc", "git_commit", "clock",
)


def test_the_profile_records_every_required_field():
    profile = environment.experiment_profile("docker", image=DEFAULT_IMAGE)
    for name in REQUIRED_PROFILE_FIELDS:
        assert name in profile, name


def test_the_profile_records_some_memory_figure():
    profile = environment.experiment_profile("docker")
    assert (profile["host_memory_bytes"] is not None
            or profile["docker_vm_memory_bytes"] is not None), \
        "at least one memory figure must be recorded for the paper"


def test_the_profile_records_the_backend_verbatim():
    # No normalisation, no inference: whatever ran is what is written down.
    assert environment.experiment_profile("local")["backend"] == "local"


def test_the_profile_is_json_serialisable():
    json.loads(json.dumps(environment.experiment_profile("docker"), default=str))


def test_a_profile_field_the_machine_cannot_report_is_none_not_a_guess(monkeypatch):
    monkeypatch.setattr(environment, "_run", lambda *a, **k: None)
    profile = environment.experiment_profile("docker", image=DEFAULT_IMAGE)
    assert profile["docker_engine_version"] is None
    assert profile["target_image_id"] is None


def test_extra_profile_fields_are_merged():
    profile = environment.experiment_profile("docker",
                                             extra={"specification_version": "x"})
    assert profile["specification_version"] == "x"


# -- experiment plumbing -----------------------------------------------------

def test_formal_sandbox_ids_are_valid_prefixed_and_unique():
    ids = {formal_run.formal_sandbox_id("repro") for _ in range(200)}
    assert len(ids) == 200
    for sandbox_id in ids:
        assert sandbox_id.startswith(formal_run.FORMAL_PREFIX)
        validate_sandbox_id(sandbox_id)


def test_expected_digests_describe_the_declared_dataset():
    baseline = formal_run.baseline_digests()
    assert sorted(baseline) == sorted(BASELINE_FILENAMES)
    impacted = formal_run.impacted_digests()
    assert sorted(impacted) == sorted(n + IMPACT_SUFFIX for n in BASELINE_FILENAMES)
    # Rename-only: every impacted file keeps its baseline digest.
    for name, digest in baseline.items():
        assert impacted[name + IMPACT_SUFFIX] == digest


def test_the_declared_default_sizes_meet_the_protocol_minimums():
    assert formal_run.DEFAULT_REPRODUCIBILITY_RUNS >= 30
    assert formal_run.DEFAULT_ISOLATION_TRIALS >= 30
    assert formal_run.DEFAULT_ISOLATION_SANDBOXES >= 3
    assert formal_run.DEFAULT_TELEMETRY_RUNS >= 30
    assert formal_run.DEFAULT_PERFORMANCE_RUNS >= 50
    assert formal_run.DEFAULT_SCALES == (10, 25, 50, 100)
    assert formal_run.DEFAULT_CONCURRENCY_LEVELS == (1, 2, 4, 8)
    assert formal_run.DEFAULT_WARMUP >= 1


def test_warm_up_observations_are_returned_for_disclosure_not_discarded_silently():
    class FakeBackend:
        name = "fake"

        def create(self, sandbox_id):
            return {"sandbox_id": sandbox_id, "state": "running"}

        def status(self, sandbox_id):
            return {"sandbox_id": sandbox_id, "state": "running"}

        def reset(self, sandbox_id):
            return self.create(sandbox_id)

        def destroy(self, sandbox_id):
            return {"sandbox_id": sandbox_id, "state": "absent"}

        def run_impact(self, sandbox_id, targets):
            return [{"target": name, "status": "impacted",
                     "detail": "renamed"} for name in BASELINE_FILENAMES]

        isolation_summary = "fake"

    discarded = formal_run.warm_up(FakeBackend(), 2)
    assert len(discarded) == 2
    for row in discarded:
        assert row["error"] == ""
        assert row["create_seconds"] >= 0.0
        assert row["scenario_seconds"] >= 0.0


def test_a_telemetry_row_for_a_failed_run_scores_zero_not_full_marks():
    row = formal_run._telemetry_row(0, "file_impact", [], None, "s", error="boom")
    assert row["completeness"] == 0.0
    assert row["complete"] is False
    assert row["sequence_exact"] is False
    assert row["error"] == "boom"


def test_a_telemetry_row_scores_a_good_sequence():
    import datetime
    base = datetime.datetime(2026, 8, 30, 12, 0, 0)
    events = [{"event_type": t, "scenario_id": "s1", "session_id": "u1",
               "timestamp": base + datetime.timedelta(seconds=i)}
              for i, t in enumerate(
                  ["SCENARIO_STARTED", "FILE_IMPACT_STARTED", "FILE_IMPACT",
                   "FILE_IMPACT_COMPLETED", "SCENARIO_COMPLETED"])]
    row = formal_run._telemetry_row(0, "file_impact", events, "s1", "u1")
    assert row["completeness"] == 1.0 and row["sequence_exact"]
    assert row["precision"] == 1.0
    assert row["observed_sequence"].startswith("SCENARIO_STARTED,")


# -- containment declarations ------------------------------------------------

REQUIRED_CONTAINMENT_CHECKS = (
    "network_none", "read_only_rootfs", "tmpfs_workspace",
    "workspace_noexec_nosuid", "non_root_uid", "capabilities_dropped",
    "no_new_privileges", "not_privileged", "no_host_mounts",
    "no_docker_socket", "memory_limit", "pid_limit",
    "blocked_network_probe", "blocked_rootfs_write", "blocked_invalid_target",
    "cross_sandbox_isolation",
)


@pytest.mark.parametrize("check", REQUIRED_CONTAINMENT_CHECKS)
def test_every_required_containment_property_is_declared(check):
    assert check in containment.CHECK_DESCRIPTIONS


def test_the_containment_summary_reports_failures_rather_than_hiding_them():
    results = [
        {"check": "network_none", "passed": True},
        {"check": "read_only_rootfs", "passed": False},
    ]
    summary = containment.summarise_containment(results)
    assert summary["failed"] == 1
    assert summary["failed_checks"] == ["read_only_rootfs"]
    assert summary["all_passed"] is False


def test_a_check_that_never_ran_is_not_counted_as_a_pass():
    summary = containment.summarise_containment(
        [{"check": "network_none", "passed": True}])
    assert summary["all_passed"] is False
    assert "read_only_rootfs" in summary["not_run"]


def test_a_fully_passing_run_is_reported_as_such():
    results = [{"check": check, "passed": True}
               for check in containment.CHECK_DESCRIPTIONS]
    summary = containment.summarise_containment(results)
    assert summary["all_passed"] is True and summary["failed"] == 0


# -- result files ------------------------------------------------------------

def test_result_files_are_written_in_the_declared_layout(tmp_path):
    rows = [{"run": 0, "ok": True, "extra_field_ignored": 1},
            {"run": 1, "ok": False}]
    csv_path = tmp_path / "reproducibility.csv"
    formal_run.write_csv(str(csv_path), rows, ["run", "ok"])
    with open(csv_path, encoding="utf-8", newline="") as handle:
        read_back = list(csv.DictReader(handle))
    assert [r["run"] for r in read_back] == ["0", "1"]
    assert "extra_field_ignored" not in read_back[0]

    json_path = tmp_path / "summary.json"
    formal_run.write_json(str(json_path), {"profile": {"backend": "docker"},
                                           "rows": rows})
    payload = json.load(open(json_path, encoding="utf-8"))
    assert payload["profile"]["backend"] == "docker"


def test_the_specification_version_is_recorded_with_every_formal_run():
    profile = environment.experiment_profile(
        "docker", extra={"specification_version": SPECIFICATION_VERSION})
    assert profile["specification_version"] == SPECIFICATION_VERSION


def test_leftover_enumeration_separates_formal_sandboxes_from_others():
    class FakeBackend:
        def sandbox_metadata(self):
            return [{"sandbox_id": "fml-perf-aaaaaaaa"},
                    {"sandbox_id": "sess-1234567890abcdef"}]

    leftover = formal_run.leftover_sandboxes(FakeBackend())
    assert leftover["formal"] == ["fml-perf-aaaaaaaa"]
    assert leftover["other"] == ["sess-1234567890abcdef"]


def test_an_unenumerable_backend_is_reported_not_assumed_clean():
    class BrokenBackend:
        def sandbox_metadata(self):
            raise RuntimeError("docker went away")

    leftover = formal_run.leftover_sandboxes(BrokenBackend())
    assert leftover["formal"] == [] and "error" in leftover
