"""Milestone 3, sections 6-7: evaluation metrics and harness behaviour.

The statistics reported in the paper are computed by these functions, so they
are tested against hand-checked values rather than against themselves.
"""

import json
import os
import statistics
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation import metrics
from evaluation.run_experiments import (baseline_signature, eval_sandbox_id,
                                        experiment_a, experiment_b,
                                        experiment_c, experiment_d,
                                        impacted_signature, make_manager,
                                        write_results)
from sandbox.backends.base import validate_sandbox_id
from sandbox.dataset import BASELINE_FILENAMES


# -- percentile --------------------------------------------------------------

def test_percentile_uses_nearest_rank():
    values = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    assert metrics.percentile(values, 0.95) == 10
    assert metrics.percentile(values, 0.5) == 5
    assert metrics.percentile(values, 0.0) == 1
    assert metrics.percentile(values, 1.0) == 10


def test_percentile_is_order_independent():
    assert metrics.percentile([5, 1, 3], 0.5) == metrics.percentile([1, 3, 5], 0.5)


def test_percentile_of_nothing_is_none():
    assert metrics.percentile([], 0.95) is None


@pytest.mark.parametrize("fraction", [-0.1, 1.1])
def test_percentile_rejects_an_out_of_range_fraction(fraction):
    with pytest.raises(ValueError):
        metrics.percentile([1, 2, 3], fraction)


# -- summarise ---------------------------------------------------------------

def test_summarise_matches_hand_computed_statistics():
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    summary = metrics.summarise(values)
    assert summary["n"] == 8
    assert summary["mean"] == pytest.approx(5.0)
    assert summary["median"] == pytest.approx(4.5)
    assert summary["stdev"] == pytest.approx(statistics.stdev(values))
    assert summary["min"] == 2.0
    assert summary["max"] == 9.0
    assert summary["p95"] == 9.0


def test_summarise_reports_none_stdev_for_a_single_sample():
    summary = metrics.summarise([1.5])
    assert summary["n"] == 1
    assert summary["stdev"] is None
    assert summary["mean"] == summary["median"] == 1.5


def test_summarise_of_nothing_is_explicitly_empty():
    summary = metrics.summarise([])
    assert summary["n"] == 0
    assert summary["mean"] is None and summary["p95"] is None


def test_summarise_records_its_unit():
    assert metrics.summarise([1], unit="bytes")["unit"] == "bytes"


# -- rates -------------------------------------------------------------------

def test_rate_is_a_proportion():
    assert metrics.rate(3, 4) == 0.75
    assert metrics.rate(0, 4) == 0.0


def test_rate_of_nothing_is_none_not_zero():
    """'No runs' must stay distinguishable from 'every run failed'."""
    assert metrics.rate(0, 0) is None


def test_aggregate_flags_counts_true_values():
    records = [{"ok": True}, {"ok": False}, {"ok": True}, {}]
    assert metrics.aggregate_flags(records, "ok") == {
        "true": 2, "total": 4, "rate": 0.5}


def test_mean_ratio_ignores_missing_values():
    records = [{"r": 1.0}, {"r": 0.5}, {"r": None}, {}]
    assert metrics.mean_ratio(records, "r") == pytest.approx(0.75)
    assert metrics.mean_ratio([], "r") is None


# -- timing ------------------------------------------------------------------

def test_stopwatch_measures_a_positive_interval():
    with metrics.Stopwatch() as watch:
        sum(range(10000))
    assert watch.elapsed is not None and watch.elapsed >= 0


def test_time_call_returns_the_result_and_an_elapsed_time():
    result, elapsed = metrics.time_call(sum, [1, 2, 3])
    assert result == 6
    assert elapsed >= 0


# -- metadata ----------------------------------------------------------------

def test_run_metadata_records_reproducibility_fields():
    metadata = metrics.run_metadata("local", scenario="file_impact", runs=7)
    assert metadata["backend"] == "local"
    assert metadata["runs"] == 7
    assert metadata["scenario"] == "file_impact"
    assert metadata["python_version"] == sys.version.split()[0]
    assert metadata["timestamp_utc"].endswith("+00:00")
    assert "platform" in metadata
    assert "docker_version" in metadata  # None is a valid, recorded value


def test_run_metadata_never_infers_the_backend():
    """The backend is whatever the caller declared, verbatim."""
    assert metrics.run_metadata("local")["backend"] == "local"
    assert metrics.run_metadata("docker")["backend"] == "docker"


def test_extra_metadata_is_merged():
    metadata = metrics.run_metadata("local", extra={"scales": [1, 2]})
    assert metadata["scales"] == [1, 2]


# -- harness plumbing --------------------------------------------------------

def test_eval_sandbox_ids_are_valid_and_unique():
    ids = {eval_sandbox_id("repro") for _ in range(50)}
    assert len(ids) == 50
    for sandbox_id in ids:
        assert validate_sandbox_id(sandbox_id) == sandbox_id
        assert sandbox_id.startswith("eval-")


def test_signatures_describe_the_declared_dataset():
    baseline = baseline_signature()
    impacted = impacted_signature()
    assert len(baseline) == len(BASELINE_FILENAMES)
    assert {status for _, status, _ in baseline} == {"baseline"}
    assert {status for _, status, _ in impacted} == {"impacted"}
    assert all(present.endswith(".demo_locked") for _, _, present in impacted)


def test_docker_backend_is_never_silently_substituted(tmp_path, monkeypatch):
    """Requesting docker when it is unavailable must abort, not fall back."""
    from sandbox.backends.docker import DockerBackend
    monkeypatch.setattr(DockerBackend, "is_available", lambda self: False)
    with pytest.raises(SystemExit):
        make_manager("docker", str(tmp_path))


def test_unknown_backend_is_refused(tmp_path):
    with pytest.raises(SystemExit):
        make_manager("magic", str(tmp_path))


def test_write_results_emits_json_and_csv_with_metadata(tmp_path, monkeypatch):
    import evaluation.run_experiments as harness
    monkeypatch.setattr(harness, "RESULTS_DIR", str(tmp_path))

    metadata = metrics.run_metadata("local", runs=2)
    rows = [{"run": 0, "value": 1.5}, {"run": 1, "value": 2.5}]
    paths = harness.write_results("unit_test", metadata, {"mean": 2.0},
                                  rows, ["run", "value"])

    with open(paths["json"], encoding="utf-8") as handle:
        payload = json.load(handle)
    assert payload["experiment"] == "unit_test"
    assert payload["metadata"]["backend"] == "local"
    assert payload["observations"] == rows

    with open(paths["csv"], encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    assert lines[0] == "run,value"
    assert len(lines) == 3
    assert os.path.basename(paths["json"]).startswith("unit_test_local_")


# -- experiments run end to end on the local backend -------------------------

@pytest.fixture
def local_manager(tmp_path):
    return make_manager("local", str(tmp_path / "eval-roots"))


def test_experiment_a_reports_full_correctness_on_a_healthy_backend(local_manager):
    name, metadata, summary, rows, fields = experiment_a(local_manager, "local", 2)
    assert name == "experiment_a_reproducibility"
    assert metadata["backend"] == "local"
    assert len(rows) == 2
    assert summary["success_rate"]["rate"] == 1.0
    assert summary["reset_correctness_rate"]["rate"] == 1.0
    assert summary["mean_telemetry_completeness"] == 1.0
    assert set(fields) <= set(rows[0]) | {"telemetry_missing", "error"}


def test_experiment_b_detects_isolation(local_manager):
    _, _, summary, rows, _ = experiment_b(local_manager, "local", 1)
    assert summary["filesystem_isolation_rate"]["rate"] == 1.0
    assert summary["identity_isolation_rate"]["rate"] == 1.0
    assert summary["event_isolation_rate"]["rate"] == 1.0
    assert rows[0]["derived_ids_distinct"] is True


def test_experiment_c_measures_completeness_against_the_declared_sequence(local_manager):
    _, _, summary, rows, _ = experiment_c(local_manager, "local", 2)
    assert summary["mean_completeness_ratio"] == 1.0
    assert summary["full_completeness_rate"] == 1.0
    assert rows[0]["missing_events"] == ""
    assert rows[0]["captured_expected_events"] == rows[0]["expected_events"]


def test_experiment_d_produces_latency_summaries(local_manager):
    _, metadata, summary, rows, _ = experiment_d(local_manager, "local", 3)
    assert metadata["clock"] == "time.perf_counter"
    assert summary["completed_runs"] == 3
    assert summary["failed_runs"] == 0
    for phase in ("create_seconds", "scenario_seconds", "reset_seconds",
                  "destroy_seconds"):
        assert summary[phase]["n"] == 3
        assert summary[phase]["mean"] > 0
        assert summary[phase]["p95"] >= summary[phase]["median"]


def test_experiment_failures_are_recorded_not_swallowed(local_manager, monkeypatch):
    """A broken backend must show up as a failed run, never as a silent pass."""
    def boom(*args, **kwargs):
        raise RuntimeError("simulated backend failure")
    monkeypatch.setattr(local_manager.backend, "create", boom)

    _, _, summary, rows, _ = experiment_a(local_manager, "local", 2)
    assert summary["success_rate"]["rate"] == 0.0
    assert all("simulated backend failure" in row["error"] for row in rows)


# -- backend selection is explicit, never a silent downgrade -----------------

def test_flask_backend_choice_is_explicit(tmp_path, monkeypatch):
    """SANDBOX_BACKEND=docker must fail loudly rather than degrade silently."""
    from types import SimpleNamespace

    import sandbox_routes
    from sandbox.backends.docker import DockerBackend
    from sandbox.errors import SandboxError

    monkeypatch.setattr(DockerBackend, "is_available", lambda self: False)
    monkeypatch.setenv("SANDBOX_BACKEND", "docker")
    fake_app = SimpleNamespace(_sandbox_manager=None)
    with pytest.raises(SandboxError):
        sandbox_routes.ensure_manager(fake_app, None, None, str(tmp_path))


def test_flask_local_backend_can_be_pinned(tmp_path, monkeypatch):
    from types import SimpleNamespace

    import sandbox_routes

    monkeypatch.setenv("SANDBOX_BACKEND", "local")
    fake_app = SimpleNamespace(_sandbox_manager=None)
    manager = sandbox_routes.ensure_manager(fake_app, None, None, str(tmp_path))
    assert manager.backend.name == "local"
    assert manager.default_sandbox_id is None
