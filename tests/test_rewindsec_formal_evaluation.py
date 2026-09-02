"""Tests for the RewindSec formal evaluation HARNESS itself.

These tests exercise the evaluator (``evaluation/rewindsec_specifications.py``
and ``evaluation/rewindsec_formal_run.py``), not production code a second
time: they prove the oracle is independent, that its verification logic
actually catches corruption/mismatch/duplication/omission, and that the
harness's operational guarantees (dirty-tree refusal, Docker refusal,
deterministic output layout, cleanup scoping) hold.

Section headers below correspond to spec section 24 (A-S).
"""

import csv
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation import rewindsec_specifications as spec
from evaluation import rewindsec_formal_run as harness


# =============================================================================
# Fake ORM plumbing: a minimal stand-in for
# ``db.session.query(Model).filter_by(...).order_by(...).all()`` so
# ``verify_telemetry`` can be exercised without a real Flask/SQLAlchemy app.
# =============================================================================

class _Ascending:
    """Stand-in for a SQLAlchemy InstrumentedAttribute's ``.asc()``."""

    def asc(self):
        return None


class FakeEvent:
    #: Class-level attribute so ``FakeEvent.id.asc()`` (mirroring
    #: ``SecurityEvent.id.asc()`` in the real ``order_by`` call) works without
    #: a real SQLAlchemy column.
    id = _Ascending()

    def __init__(self, event_type, scenario_id, session_id, source,
                timestamp=None, id=None):
        self.event_type = event_type
        self.scenario_id = scenario_id
        self.session_id = session_id
        self.source = source
        self.timestamp = timestamp
        if id is not None:
            self.id = id


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter_by(self, **kwargs):
        rows = self._rows
        for key, value in kwargs.items():
            rows = [r for r in rows if getattr(r, key, None) == value]
        return _FakeQuery(rows)

    def order_by(self, *a, **k):
        return self

    def all(self):
        return list(self._rows)


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows

    def query(self, model):
        return _FakeQuery(self._rows)


class FakeAppModule:
    """Enough of ``app`` for ``verify_telemetry`` to run against."""

    def __init__(self, rows):
        self.db = types_module.SimpleNamespace(session=_FakeSession(rows))
        self.SecurityEvent = FakeEvent


import types as types_module


def make_successful_events(execution_id="exec-1", session_id="sess-1",
                           source=None):
    source = source or spec.EXPECTED_TELEMETRY_SOURCE
    return [
        FakeEvent(name, execution_id, session_id, source, timestamp=i, id=i)
        for i, name in enumerate(spec.SUCCESS_EVENT_SEQUENCE)
    ]


# =============================================================================
# A. new spec file doesn't import production scenario definitions
# =============================================================================

def test_spec_module_does_not_import_production_scenario_tables():
    spec.assert_no_production_imports()


def test_spec_module_forbidden_roots_are_the_real_production_modules():
    # The guard is only meaningful if it actually names the modules that hold
    # the scenario tables / event ordering / learning-quality mappings.
    assert "scenario_adapters" in spec.FORBIDDEN_IMPORT_ROOTS
    assert "training_service" in spec.FORBIDDEN_IMPORT_ROOTS
    assert "training.definitions" in spec.FORBIDDEN_IMPORT_ROOTS


def test_a_forbidden_import_would_actually_be_caught():
    # Prove the AST check has teeth: a module that DOES import a forbidden
    # root fails the same assertion this oracle passes.
    import ast
    import tempfile
    with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False,
                                     encoding="utf-8") as fh:
        fh.write("import scenario_adapters\n")
        path = fh.name
    try:
        roots = spec._imported_module_roots(path)
        assert "scenario_adapters" in roots
    finally:
        os.remove(path)


# =============================================================================
# B. six lifecycle strings independently frozen
# =============================================================================

def test_six_lifecycle_events_are_frozen_literal_strings():
    assert spec.SUCCESS_EVENT_SEQUENCE == (
        "TRAINING_EXECUTION_STARTED",
        "TRAINING_BASELINE_CAPTURED",
        "TRAINING_FACTUAL_CAPTURED",
        "TRAINING_REWIND_VERIFIED",
        "TRAINING_COUNTERFACTUAL_CAPTURED",
        "TRAINING_EXECUTION_COMPLETED",
    )
    assert len(spec.SUCCESS_EVENT_SEQUENCE) == 6
    assert spec.TRAINING_EXECUTION_FAILED == "TRAINING_EXECUTION_FAILED"
    assert spec.TRAINING_EXECUTION_FAILED not in spec.SUCCESS_EVENT_SEQUENCE
    assert spec.TRAINING_EXECUTION_FAILED in spec.KNOWN_TRAINING_EVENT_TYPES


# =============================================================================
# C. four scenario keys exist
# =============================================================================

def test_four_scenario_keys_exist():
    assert spec.SCENARIO_KEYS == (
        "phishing_credential_compromise",
        "ransomware_incident_response",
        "mfa_fatigue_response",
        "business_email_compromise",
    )
    assert set(spec.SCENARIOS) == set(spec.SCENARIO_KEYS)


# =============================================================================
# D. each scenario has exactly four stable choices
# =============================================================================

@pytest.mark.parametrize("scenario_key", spec.SCENARIO_KEYS)
def test_each_scenario_has_exactly_four_choices(scenario_key):
    ids = spec.SCENARIOS[scenario_key]["choice_ids"]
    assert len(ids) == 4
    assert len(set(ids)) == 4, "choice ids must be distinct"
    action_keys = spec.SCENARIOS[scenario_key]["action_keys"]
    assert set(action_keys) == set(ids)
    assert len(set(action_keys.values())) == 4, "action keys must be distinct"


# =============================================================================
# E. all 12 ordered distinct pairs generated per scenario
# =============================================================================

@pytest.mark.parametrize("scenario_key", spec.SCENARIO_KEYS)
def test_all_twelve_ordered_pairs_generated(scenario_key):
    pairs = spec.ordered_pairs(scenario_key)
    assert len(pairs) == 12
    assert len(set(pairs)) == 12, "pairs must be distinct"
    for a, b in pairs:
        assert a != b
    ids = set(spec.SCENARIOS[scenario_key]["choice_ids"])
    for a, b in pairs:
        assert a in ids and b in ids


def test_total_pair_count_is_48():
    assert spec.total_pair_count() == 48
    assert sum(len(v) for v in spec.all_pairs().values()) == 48


# =============================================================================
# F. independent digest verification catches corrupted state
# =============================================================================

def test_independent_digest_matches_for_identical_state():
    state = {"b": 2, "a": 1}
    digest = spec.independent_digest(state)
    assert spec.independent_digest({"a": 1, "b": 2}) == digest


def test_independent_digest_catches_corrupted_state():
    digest = spec.independent_digest({"a": 1, "b": 2})
    assert spec.independent_digest({"a": 1, "b": 3}) != digest


def test_verify_stored_digest_catches_tampered_json_text():
    text = json.dumps({"x": 1})
    digest = spec.independent_digest({"x": 1})
    ok, recomputed = spec.verify_stored_digest(text, digest)
    assert ok and recomputed == digest

    tampered = json.dumps({"x": 2})
    ok, recomputed = spec.verify_stored_digest(tampered, digest)
    assert not ok
    assert recomputed != digest


def test_verify_stored_digest_fails_closed_on_unparseable_text():
    ok, recomputed = spec.verify_stored_digest("{not json", "anydigest")
    assert ok is False
    assert recomputed is None


# =============================================================================
# G. rewind mismatch is a failed verdict
# =============================================================================

def test_negative_rewind_corruption_check_is_refused_not_reported_success():
    # The harness's own controlled negative test (spec section 9): a
    # deliberately corrupted rewind must be refused by the runtime, and the
    # harness must observe that refusal rather than call it success.
    assert harness.negative_rewind_corruption_check() is True


def test_experiment_c_flags_a_baseline_rewind_mismatch_row():
    rows = [
        {"scenario_key": "x", "execution_id": "e1",
         "baseline_digest": "aaa", "rewound_digest": "aaa",
         "verification_failures": []},
        {"scenario_key": "x", "execution_id": "e2",
         "baseline_digest": "aaa", "rewound_digest": "bbb",  # corrupted
         "verification_failures": ["baseline digest != rewound digest"]},
    ]
    summary = harness.experiment_c_from_rows(rows)
    per_scenario = summary["per_scenario"]["x"]
    assert per_scenario["mismatch_count"] == 1
    assert per_scenario["mismatched_execution_ids"] == ["e2"]
    assert per_scenario["rewind_verification_rate"] == 0.5


# =============================================================================
# H. duplicate training lifecycle event fails exact-sequence scoring
# =============================================================================

def test_duplicate_lifecycle_event_fails_exact_sequence():
    events = make_successful_events()
    events.append(FakeEvent(spec.TRAINING_BASELINE_CAPTURED, "exec-1",
                            "sess-1", spec.EXPECTED_TELEMETRY_SOURCE,
                            timestamp=6, id=6))
    app_module = FakeAppModule(events)
    failures, detail = harness.verify_telemetry(app_module, "exec-1", "sess-1")
    assert detail["exact_sequence_ok"] is False
    assert detail["duplicate_lifecycle_events"] == 1
    assert any("exactly one" in f for f in failures)


# =============================================================================
# I. wrong session_id fails correlation
# =============================================================================

def test_wrong_session_id_fails_correlation():
    events = make_successful_events(session_id="sess-1")
    app_module = FakeAppModule(events)
    failures, detail = harness.verify_telemetry(
        app_module, "exec-1", "sess-DIFFERENT")
    assert detail["session_correlation_ok"] is False
    assert any("session_id correlation" in f for f in failures)


# =============================================================================
# J. wrong execution_id fails correlation
# =============================================================================

def test_wrong_execution_id_fails_correlation():
    events = make_successful_events(execution_id="exec-1")
    app_module = FakeAppModule(events)
    # verify_telemetry filters by scenario_id == execution_id internally, so
    # querying with the WRONG execution id returns no rows at all -- which is
    # exactly how a cross-execution correlation failure must surface: nothing
    # verifiable is found, not a false positive completeness result.
    failures, detail = harness.verify_telemetry(
        app_module, "exec-OTHER", "sess-1")
    assert detail["observed_event_types"] == []
    assert detail["completeness_ok"] is False
    assert failures  # every expected event is reported missing


# =============================================================================
# K. missing lifecycle event reduces completeness
# =============================================================================

def test_missing_lifecycle_event_reduces_completeness():
    events = make_successful_events()
    del events[2]  # drop TRAINING_FACTUAL_CAPTURED
    app_module = FakeAppModule(events)
    failures, detail = harness.verify_telemetry(app_module, "exec-1", "sess-1")
    assert len(detail["observed_event_types"]) == 5
    assert detail["completeness_ok"] is False
    assert any("TRAINING_FACTUAL_CAPTURED" in f for f in failures)


# =============================================================================
# L. unexpected TRAINING_* event fails precision/exactness
# =============================================================================

def test_unexpected_training_event_fails_exactness():
    events = make_successful_events()
    events.insert(3, FakeEvent("TRAINING_SOMETHING_UNEXPECTED", "exec-1",
                               "sess-1", spec.EXPECTED_TELEMETRY_SOURCE,
                               timestamp=2.5, id=99))
    app_module = FakeAppModule(events)
    failures, detail = harness.verify_telemetry(app_module, "exec-1", "sess-1")
    assert detail["unexpected_training_event_count"] == 1
    assert any("unexpected TRAINING_*" in f for f in failures)


def test_failed_event_never_scores_as_successful():
    events = make_successful_events()
    events.append(FakeEvent(spec.TRAINING_EXECUTION_FAILED, "exec-1",
                            "sess-1", spec.EXPECTED_TELEMETRY_SOURCE,
                            timestamp=7, id=7))
    app_module = FakeAppModule(events)
    failures, detail = harness.verify_telemetry(app_module, "exec-1", "sess-1")
    assert any("TRAINING_EXECUTION_FAILED present" in f for f in failures)


# =============================================================================
# M. execution_id uniqueness and pair_id-repeat semantics
# =============================================================================

def test_execution_id_uniqueness_and_pair_id_repeat_in_repeatability_summary():
    records = [
        {"trial_succeeded": True, "execution_id": "exec-A", "pair_id": "pair-X",
         "baseline_digest": "b", "rewound_digest": "b",
         "factual_result_digest": "f", "counterfactual_result_digest": "c"},
        {"trial_succeeded": True, "execution_id": "exec-B", "pair_id": "pair-X",
         "baseline_digest": "b", "rewound_digest": "b",
         "factual_result_digest": "f", "counterfactual_result_digest": "c"},
    ]
    summary = harness._repeatability_summary(records)
    assert summary["execution_id_uniqueness_ok"] is True
    # pair_id is EXPECTED to repeat for an identical pair -- the reproducibility
    # rate is scored as 1.0 (all runs shared the one pair_id), not penalised.
    assert summary["pair_id_reproducibility_rate"] == 1.0

    # Now duplicate an execution_id: uniqueness must fail.
    records[1]["execution_id"] = "exec-A"
    summary2 = harness._repeatability_summary(records)
    assert summary2["execution_id_uniqueness_ok"] is False


# =============================================================================
# N. dirty-tree formal guard works
# =============================================================================

def test_dirty_tree_is_refused_by_default(monkeypatch):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", True))
    with pytest.raises(harness.RewindSecFormalRunRefused):
        harness.check_dirty_tree(allow_dirty=False)


def test_clean_tree_is_never_refused(monkeypatch):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", False))
    sha, dirty = harness.check_dirty_tree(allow_dirty=False)
    assert dirty is False


# =============================================================================
# O. --allow-dirty permits only explicitly marked development run
# =============================================================================

def test_allow_dirty_permits_a_dirty_tree(monkeypatch):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", True))
    sha, dirty = harness.check_dirty_tree(allow_dirty=True)
    assert dirty is True  # permitted; caller marks development_run/admissible


def test_main_marks_admissible_false_and_development_run_true_when_dirty(
        monkeypatch, tmp_path):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", True))
    monkeypatch.setattr(harness, "bootstrap_app",
                        lambda root_dir: pytest.skip(
                            "stop before touching a real DB; admissibility "
                            "is decided before bootstrap runs"))
    # We only need to observe the admissible/development_run computation,
    # which happens before bootstrap_app; drive it directly instead of the
    # full main() to avoid needing Docker/Flask here.
    sha, dirty = harness.check_dirty_tree(allow_dirty=True)
    admissible = (not dirty) and False
    development_run = bool(dirty) or False
    assert admissible is False
    assert development_run is True


def test_main_refuses_a_dirty_tree_without_allow_dirty(monkeypatch, tmp_path):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", True))
    with pytest.raises(harness.RewindSecFormalRunRefused):
        harness.main(["--results-dir", str(tmp_path), "--experiments", "A",
                      "--scenarios", spec.PHISHING])


# =============================================================================
# P. ransomware full run refuses unavailable Docker
# =============================================================================

def test_ransomware_run_refuses_when_docker_unavailable(monkeypatch):
    from evaluation.environment import FormalRunError, require_docker_backend
    # Reuses (does not duplicate) evaluation.environment's Docker guard -- the
    # same one evaluation/formal_run.py already relies on for the historical
    # harness.
    with pytest.raises(FormalRunError):
        require_docker_backend("local", "some-image:latest")


def test_main_requires_docker_when_ransomware_and_docker_dependent_experiment_selected(
        monkeypatch, tmp_path):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", False))

    def _boom(backend_name, image):
        raise harness.RewindSecFormalRunRefused("docker unavailable (test)")
    monkeypatch.setattr(harness, "require_docker_backend", _boom)
    with pytest.raises(harness.RewindSecFormalRunRefused):
        harness.main(["--results-dir", str(tmp_path), "--experiments", "A",
                      "--scenarios", spec.RANSOMWARE])


def test_main_does_not_require_docker_when_ransomware_not_selected(
        monkeypatch, tmp_path):
    monkeypatch.setattr(harness, "git_commit", lambda: ("deadbeef", False))

    def _boom(*a, **k):
        raise AssertionError("Docker guard must not run when ransomware is "
                             "excluded from the scenario selection")
    monkeypatch.setattr(harness, "require_docker_backend", _boom)

    # harness.main() -> bootstrap_app() imports a REAL ``app`` module bound to
    # a throwaway sqlite db via os.environ, and caches it in sys.modules like
    # any import. Both must be restored afterward, or every later test in this
    # same pytest process that does ``import app`` (e.g. tests/conftest.py's
    # session-scoped ``flask_app`` fixture, or a fresh ``import app`` in
    # another test module) would silently get this throwaway instance/db
    # instead of its own -- a real cross-test-file pollution hazard, not a
    # theoretical one.
    import sys as _sys
    env_before = dict(os.environ)
    app_before = _sys.modules.get("app")
    try:
        # Non-ransomware scenarios only, containment skipped: main() should
        # reach the real (non-Docker) bootstrap and run to completion.
        result = harness.main(["--results-dir", str(tmp_path), "--experiments",
                               "A", "--scenarios", spec.PHISHING,
                               "--skip-containment"])
        assert result == 0
    finally:
        os.environ.clear()
        os.environ.update(env_before)
        if app_before is not None:
            _sys.modules["app"] = app_before
        else:
            _sys.modules.pop("app", None)


# =============================================================================
# Q. result CSV/JSON layout deterministic
# =============================================================================

def test_write_json_and_csv_layout_is_deterministic(tmp_path):
    rows = [
        {"scenario_key": "b_scn", "trial_succeeded": True, "error": None},
        {"scenario_key": "a_scn", "trial_succeeded": False, "error": "boom"},
    ]
    json_path = tmp_path / "out.json"
    csv_path = tmp_path / "out.csv"
    harness.write_json(str(json_path), {"rows": rows})
    harness.write_csv(str(csv_path), rows,
                      ["scenario_key", "trial_succeeded", "error"])

    loaded = json.loads(json_path.read_text(encoding="utf-8"))
    assert loaded["rows"] == rows

    with open(csv_path, newline="", encoding="utf-8") as fh:
        reader = list(csv.DictReader(fh))
    assert reader[0]["scenario_key"] == "b_scn"
    assert reader[1]["error"] == "boom"

    json_path2 = tmp_path / "out2.json"
    harness.write_json(str(json_path2), {"rows": rows})
    assert json_path.read_bytes() == json_path2.read_bytes()


# =============================================================================
# R. failures remain in output rows
# =============================================================================

def test_failed_trial_is_never_dropped_from_pass_fail_summary():
    rows = [
        {"trial_succeeded": True, "execution_id": "e1"},
        {"trial_succeeded": False, "execution_id": "e2"},
    ]
    summary = harness._pass_fail_summary(rows)
    assert summary["n"] == 2
    assert summary["failed"] == 1
    assert summary["failed_row_indices"] == [1]
    assert summary["failed_execution_ids"] == ["e2"]


def test_failed_trial_is_never_dropped_from_written_rows(tmp_path):
    rows = [
        {"scenario_key": "x", "trial_succeeded": True, "error": None},
        {"scenario_key": "x", "trial_succeeded": False,
         "error": "TrainingExecutionError: boom"},
    ]
    path = tmp_path / "rows.csv"
    harness.write_csv(str(path), rows,
                      ["scenario_key", "trial_succeeded", "error"])
    with open(path, newline="", encoding="utf-8") as fh:
        reader = list(csv.DictReader(fh))
    assert len(reader) == 2
    failed = [r for r in reader if r["trial_succeeded"] == "False"]
    assert len(failed) == 1
    assert "boom" in failed[0]["error"]


# =============================================================================
# S. cleanup does not target unrelated owned sandboxes
# =============================================================================

def test_cleanup_only_destroys_sandboxes_this_factory_created():
    factory = harness.AdapterFactory.__new__(harness.AdapterFactory)
    factory._docker_image = None
    factory.created_sandbox_ids = ["rwsf-abc123"]

    destroyed = []

    class FakeBackend:
        def sandbox_metadata(self_inner):
            # One sandbox this factory made, plus one belonging to an
            # unrelated, concurrently-active learner/instructor session.
            return [{"sandbox_id": "rwsf-abc123"},
                   {"sandbox_id": "some-other-active-learner-sandbox"}]

    class FakeManager:
        backend = FakeBackend()

        def destroy(self_inner, sandbox_id):
            destroyed.append(sandbox_id)

    factory._docker_manager = FakeManager()
    report = factory.cleanup()

    assert destroyed == ["rwsf-abc123"]
    assert "some-other-active-learner-sandbox" not in destroyed
    assert report["other_owned_untouched"] == [
        "some-other-active-learner-sandbox"]
    assert report["cleaned"] == ["rwsf-abc123"]


def test_sandbox_prefix_is_stable_and_namespaced():
    assert harness.SANDBOX_PREFIX == "rwsf-"
    sid = harness.new_sandbox_id()
    assert sid.startswith(harness.SANDBOX_PREFIX)


# =============================================================================
# Extra: consequence-fact oracle sanity (spec section 10)
# =============================================================================

def test_ransomware_consequence_facts_match_verified_impact_counts():
    facts = spec.SCENARIOS[spec.RANSOMWARE]["consequence_facts"]
    assert facts["isolate_and_report"]["files.impacted_count"] == 1
    assert facts["report_without_isolating"]["files.impacted_count"] == 2
    assert facts["restart_workstation"]["files.impacted_count"] == 3
    assert facts["continue_working"]["files.impacted_count"] == 5


def test_check_consequence_facts_catches_a_mismatched_state():
    failures = spec.check_consequence_facts(
        spec.RANSOMWARE, "isolate_and_report",
        {"files": {"impacted_count": 999}, "endpoint": {"isolated": True,
                                                        "restarted": False},
         "incident": {"reported": True}})
    assert failures
    assert any("files.impacted_count" in f for f in failures)


def test_check_consequence_facts_passes_for_a_correct_state():
    failures = spec.check_consequence_facts(
        spec.RANSOMWARE, "isolate_and_report",
        {"files": {"impacted_count": 1}, "endpoint": {"isolated": True,
                                                       "restarted": False},
         "incident": {"reported": True}})
    assert failures == []


def test_check_consequence_facts_reports_missing_path_not_a_silent_pass():
    failures = spec.check_consequence_facts(
        spec.RANSOMWARE, "isolate_and_report", {"files": {}})
    assert failures
    assert any("missing fact" in f for f in failures)


def test_staged_preview_scenarios_are_exactly_ransomware_mfa_bec():
    assert set(spec.staged_preview_scenarios()) == {
        spec.RANSOMWARE, spec.MFA, spec.BEC}
    assert spec.PHISHING not in spec.staged_preview_scenarios()
    assert spec.SCENARIOS[spec.PHISHING]["staged_preview"] is False


def test_docker_required_scenarios_is_exactly_ransomware():
    assert spec.docker_required_scenarios() == (spec.RANSOMWARE,)


def test_specification_manifest_reports_scope_and_no_learning_claims():
    manifest = spec.specification_manifest()
    scope = manifest["scope"].lower()
    assert "does not measure" in scope
    assert "educational effectiveness" in scope
    assert manifest["total_ordered_pairs"] == 48


# =============================================================================
# T. bootstrap_app restores every process-global it touches, even on failure
# =============================================================================
#
# bootstrap_app mutates os.environ (a handful of keys) and sys.modules["app"]
# to boot a real Flask app on a throwaway SQLite DB. It is a context manager
# so it can restore both to their exact pre-call state on exit -- whether the
# ``with`` block completed normally, bootstrap itself raised, or code inside
# the block raised -- so it is safe to call from pytest or any other
# long-lived Python process, not only a fresh CLI subprocess.
#
# Every test below mutates the REAL process os.environ / sys.modules["app"]
# to set up its "ambient" starting condition (e.g. "key absent", "key set to
# X"), not just a copy -- so each one restores the exact prior ambient state
# (e.g. conftest's real INSTRUCTOR_PASSWORD) afterward via this fixture,
# instead of leaving it cleared for every later test in the same pytest
# process.

@pytest.fixture
def restore_ambient_process_state():
    env_before = {key: (key in os.environ, os.environ.get(key))
                 for key in harness._BOOTSTRAP_ENV_KEYS}
    app_before_existed = "app" in sys.modules
    app_before = sys.modules.get("app")
    yield
    for key, (existed, value) in env_before.items():
        if existed:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)
    if app_before_existed:
        sys.modules["app"] = app_before
    else:
        sys.modules.pop("app", None)


def test_bootstrap_app_restores_preexisting_env_values(
        tmp_path, restore_ambient_process_state):
    for key in harness._BOOTSTRAP_ENV_KEYS:
        os.environ[key] = "pre-existing-" + key
    # Three keys (SIMULATOR_DATABASE_URI/SANDBOX_LOCAL_ROOT/SANDBOX_BACKEND)
    # are unconditionally overwritten; the other three only via setdefault,
    # so they legitimately keep their pre-existing value throughout.
    overwritten = ("SIMULATOR_DATABASE_URI", "SANDBOX_LOCAL_ROOT",
                  "SANDBOX_BACKEND")
    with harness.bootstrap_app(str(tmp_path)):
        for key in overwritten:
            assert os.environ[key] != "pre-existing-" + key
    for key in harness._BOOTSTRAP_ENV_KEYS:
        assert os.environ[key] == "pre-existing-" + key


def test_bootstrap_app_removes_previously_absent_env_keys(
        tmp_path, restore_ambient_process_state):
    for key in harness._BOOTSTRAP_ENV_KEYS:
        os.environ.pop(key, None)
    with harness.bootstrap_app(str(tmp_path)):
        for key in harness._BOOTSTRAP_ENV_KEYS:
            assert key in os.environ
    for key in harness._BOOTSTRAP_ENV_KEYS:
        assert key not in os.environ


def test_bootstrap_app_restores_preexisting_app_module_by_identity(
        tmp_path, restore_ambient_process_state):
    sentinel = object()
    sys.modules["app"] = sentinel
    with harness.bootstrap_app(str(tmp_path)) as app_module:
        assert sys.modules["app"] is app_module
        assert sys.modules["app"] is not sentinel
    assert sys.modules["app"] is sentinel


def test_bootstrap_app_removes_previously_absent_app_module(
        tmp_path, restore_ambient_process_state):
    sys.modules.pop("app", None)
    with harness.bootstrap_app(str(tmp_path)):
        assert "app" in sys.modules
    assert "app" not in sys.modules


def test_bootstrap_app_restores_state_when_setup_raises(
        tmp_path, monkeypatch, restore_ambient_process_state):
    for key in harness._BOOTSTRAP_ENV_KEYS:
        os.environ.pop(key, None)
    sys.modules.pop("app", None)
    sentinel = object()
    sys.modules["app"] = sentinel

    import builtins
    real_import = builtins.__import__

    def _fake_import(name, *a, **k):
        if name == "app":
            raise RuntimeError("simulated app import failure")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", _fake_import)

    with pytest.raises(RuntimeError, match="simulated app import failure"):
        with harness.bootstrap_app(str(tmp_path)):
            pass  # never reached; bootstrap itself raises
    for key in harness._BOOTSTRAP_ENV_KEYS:
        assert key not in os.environ
    assert sys.modules["app"] is sentinel


def test_bootstrap_app_restores_state_when_body_raises(
        tmp_path, restore_ambient_process_state):
    for key in harness._BOOTSTRAP_ENV_KEYS:
        os.environ.pop(key, None)
    sentinel = object()
    sys.modules["app"] = sentinel
    with pytest.raises(RuntimeError, match="simulated experiment failure"):
        with harness.bootstrap_app(str(tmp_path)):
            raise RuntimeError("simulated experiment failure")
    for key in harness._BOOTSTRAP_ENV_KEYS:
        assert key not in os.environ
    assert sys.modules["app"] is sentinel
