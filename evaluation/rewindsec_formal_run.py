"""Formal SYSTEMS evaluation harness for the CURRENT RewindSec architecture.

    python -m evaluation.rewindsec_formal_run --smoke --allow-dirty
    python -m evaluation.rewindsec_formal_run --experiments A,B,F --allow-dirty

DISTINCT FROM ``evaluation/formal_run.py``
------------------------------------------------
That module measures the historical Milestone-4 conference-simulator
architecture (single-branch scenarios: ``credential_reuse_phishing``,
``ransomware_awareness``, ``file_impact``). It is untouched by this work -- see
the doc-comment added at its top.

This module measures the CURRENT paired-counterfactual architecture: human
decision -> technical consequence -> exact rewind -> counterfactual consequence
-> state comparison, across the four scenarios registered under
``scenario_adapters/`` and driven through ``training_service.TrainingService``.
Results are written to ``evaluation/results/rewindsec-formal/`` -- never to
``evaluation/results/formal/``.

WHAT THIS MEASURES (system properties only)
--------------------------------------------
  A. complete ordered pair-matrix coverage per scenario
  B. deterministic repeatability of one representative pair per scenario
  C. independent rewind-integrity verification (S0 == S0')
  D. staged factual-preview integrity (ransomware only -- the only current
     learner flow that stages a preview; verified against training_routes.py)
  E. six-event training-lifecycle telemetry correctness
  F. server-side pair latency (per scenario, never averaged across scenarios)
  G. bounded-concurrency isolation

Every check is judged against ``evaluation/rewindsec_specifications.py``, an
oracle that imports no production scenario/telemetry table (see that module's
docstring).

WHAT THIS DOES NOT MEASURE
---------------------------
Nothing here is a claim about educational effectiveness, learning improvement,
behavioural transfer, retention, or statistical significance between study
arms. No ``StudyEnrollment``/``StudyIntervention``/``StudyAssessmentAttempt``
row is read. Human efficacy is a separate future study, entirely out of scope
for this module. See ``docs/rewindsec-formal-evaluation.md``.

DIRTY-TREE POLICY
------------------
A formal run refuses to start against a dirty git working tree unless
``--allow-dirty`` is given. With the override, every result file is stamped
``admissible: false`` and ``development_run: true`` -- such numbers are never
citable.

DOCKER REQUIREMENT
-------------------
The ransomware scenario is Docker-only, never LocalBackend. A default complete
run (which includes ransomware) refuses to start if Docker or the target image
is unavailable, exactly like the historical harness's own guard
(``evaluation.environment.require_docker_backend``, reused here rather than
reimplemented). In-memory-only smoke selections (``--experiments`` excluding
ransomware) may be run without Docker by explicitly excluding it; this is never
the default.
"""

import argparse
import contextlib
import json
import os
import shutil
import statistics
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation import rewindsec_specifications as spec
from evaluation.containment import run_containment_checks, summarise_containment
from evaluation.environment import (docker_engine_version, git_commit,
                                    require_docker_backend)
from evaluation.metrics import summarise, time_call

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "results", "rewindsec-formal")

#: Prefix on every temporary sandbox id this module creates, so a final sweep
#: can never mistake a leaked run-of-this-harness sandbox for a real learner's,
#: and never delete a concurrently-running learner/instructor sandbox that
#: happens to belong to the same application.
SANDBOX_PREFIX = "rwsf-"

DEFAULT_REPEATABILITY_RUNS = 30
DEFAULT_STAGING_RUNS = 30
DEFAULT_PERFORMANCE_RUNS = 50
DEFAULT_TELEMETRY_RUNS = 30
DEFAULT_CONCURRENCY_LEVELS = (1, 2, 4, 8)
DEFAULT_CONCURRENCY_TRIALS = 3

EXPERIMENT_LETTERS = ("A", "B", "C", "D", "E", "F", "G")


# =============================================================================
# Independent digest verification (spec section 8) -- delegates to the
# independent canonical-JSON + SHA-256 implementation in
# rewindsec_specifications.py (a second, from-scratch implementation of the
# scheme, not a reuse of training.snapshots.canonical_json/fingerprint), so a
# self-check bug in the production serializer cannot silently pass its own
# verification.
# =============================================================================

independent_canonical_json = spec.independent_canonical_json
independent_digest = spec.independent_digest
verify_stored_digest = spec.verify_stored_digest


# =============================================================================
# Application bootstrap: a real Flask app + real SQLAlchemy models on a
# throwaway SQLite database, exactly like tests/conftest.py's flask_app
# fixture -- because Experiment sections require the REAL TrainingExecution
# table and the REAL SecurityEvent telemetry path, not a reimplementation of
# either.
# =============================================================================

#: Every os.environ key bootstrap_app deliberately sets, so it can restore
#: exactly these keys (and no others) to their pre-harness state on exit --
#: whether bootstrap succeeded, failed mid-way, or an experiment later
#: raised -- making it safe to call from pytest or any other long-lived
#: Python process, not only a fresh CLI subprocess.
_BOOTSTRAP_ENV_KEYS = (
    "SIMULATOR_DATABASE_URI", "SANDBOX_LOCAL_ROOT", "SANDBOX_BACKEND",
    "FLASK_SECRET_KEY", "SYNTHETIC_IDENTITY_SECRET", "INSTRUCTOR_PASSWORD",
)


@contextlib.contextmanager
def bootstrap_app(root_dir):
    env_snapshot = {key: (key in os.environ, os.environ.get(key))
                    for key in _BOOTSTRAP_ENV_KEYS}
    app_module_existed = "app" in sys.modules
    prev_app_module = sys.modules.get("app")
    # telemetry_ledger.attach() is idempotent via a process-global cache
    # (telemetry_ledger._TABLE) set on first call and never reassigned --
    # correct for a single long-lived app, but if it stays bound to this
    # harness's throwaway metadata, the NEXT app import in this process
    # (e.g. a pytest fixture importing the real app afterward) sees attach()
    # short-circuit and never registers progression_milestone on its own
    # metadata, so db.create_all() silently omits that table for it. Snapshot
    # and restore it alongside os.environ/sys.modules["app"].
    import telemetry_ledger
    prev_ledger_table = telemetry_ledger._TABLE
    try:
        db_path = os.path.join(root_dir, "rewindsec_formal.db")
        os.environ["SIMULATOR_DATABASE_URI"] = "sqlite:///" + db_path.replace("\\", "/")
        os.environ["SANDBOX_LOCAL_ROOT"] = os.path.join(root_dir, "sandboxes")
        os.environ["SANDBOX_BACKEND"] = "local"
        os.environ.setdefault("FLASK_SECRET_KEY", "rewindsec-formal-eval-key")
        os.environ.setdefault("SYNTHETIC_IDENTITY_SECRET",
                              "rewindsec-formal-eval-identity-secret")
        os.environ.setdefault("INSTRUCTOR_PASSWORD", "rewindsec-formal-eval-pw")
        sys.modules.pop("app", None)
        import app as app_module
        app_module.app.config["TESTING"] = True
        with app_module.app.app_context():
            app_module.db.create_all()
        yield app_module
    finally:
        for key, (existed, value) in env_snapshot.items():
            if existed:
                os.environ[key] = value
            else:
                os.environ.pop(key, None)
        if app_module_existed:
            sys.modules["app"] = prev_app_module
        else:
            sys.modules.pop("app", None)
        telemetry_ledger._TABLE = prev_ledger_table


# =============================================================================
# Scenario/adapter wiring -- the harness legitimately imports the REAL
# ScenarioDefinition objects and adapters to execute pairs (only the ORACLE in
# rewindsec_specifications.py must stay independent of them).
# =============================================================================

def _scenario_definition(scenario_key):
    if scenario_key == spec.PHISHING:
        from scenario_adapters.phishing import PHISHING_SCENARIO
        return PHISHING_SCENARIO
    if scenario_key == spec.RANSOMWARE:
        from scenario_adapters.ransomware import RANSOMWARE_SCENARIO
        return RANSOMWARE_SCENARIO
    if scenario_key == spec.MFA:
        from scenario_adapters.mfa import MFA_SCENARIO
        return MFA_SCENARIO
    if scenario_key == spec.BEC:
        from scenario_adapters.bec import BEC_SCENARIO
        return BEC_SCENARIO
    raise ValueError("unknown scenario key %r" % scenario_key)


def new_sandbox_id():
    return "%s%s" % (SANDBOX_PREFIX, uuid.uuid4().hex[:16])


class AdapterFactory:
    """Builds a fresh consequence adapter per invocation.

    For the three in-memory scenarios this is trivial. For ransomware it owns
    one Docker-backed ``SandboxManager`` for the whole harness run, creates one
    disposable sandbox per adapter it hands out, and tracks every sandbox id it
    created so :func:`cleanup_sandboxes` can destroy them all in a ``finally``
    block -- and ONLY them.
    """

    def __init__(self, docker_image=None):
        self._docker_manager = None
        self._docker_image = docker_image
        self.created_sandbox_ids = []

    def _manager(self):
        if self._docker_manager is None:
            from sandbox import EventCollector, SandboxManager
            from sandbox.backends.docker import DEFAULT_IMAGE, DockerBackend
            image = self._docker_image or DEFAULT_IMAGE
            self._docker_manager = SandboxManager(
                DockerBackend(image=image), recorder=EventCollector())
        return self._docker_manager

    def build(self, scenario_key, session_id=None):
        if scenario_key == spec.PHISHING:
            from scenario_adapters.phishing import PhishingConsequenceAdapter
            return PhishingConsequenceAdapter()
        if scenario_key == spec.MFA:
            from scenario_adapters.mfa import MfaConsequenceAdapter
            return MfaConsequenceAdapter()
        if scenario_key == spec.BEC:
            from scenario_adapters.bec import BecConsequenceAdapter
            return BecConsequenceAdapter()
        if scenario_key == spec.RANSOMWARE:
            from scenario_adapters.ransomware import RansomwareConsequenceAdapter
            manager = self._manager()
            sandbox_id = new_sandbox_id()
            manager.create(sandbox_id, session_id=session_id)
            self.created_sandbox_ids.append(sandbox_id)
            return RansomwareConsequenceAdapter(manager, sandbox_id,
                                                session_id=session_id)
        raise ValueError("unknown scenario key %r" % scenario_key)

    def cleanup(self):
        """Destroy only the sandboxes THIS factory created, then report leftovers.

        Never touches a sandbox lacking the ``SANDBOX_PREFIX`` this run used,
        so a concurrently active learner or instructor sandbox is left alone
        even though it belongs to the same application (spec section 21).
        """
        report = {"owned_before_cleanup": [], "cleaned": [], "remaining": [],
                  "other_owned_untouched": []}
        if self._docker_manager is None:
            return report
        try:
            owned = self._docker_manager.backend.sandbox_metadata()
            owned_ids = [row["sandbox_id"] for row in owned]
        except Exception:  # noqa: BLE001
            owned_ids = list(self.created_sandbox_ids)
        report["owned_before_cleanup"] = owned_ids
        report["other_owned_untouched"] = [
            sid for sid in owned_ids if not sid.startswith(SANDBOX_PREFIX)]
        for sandbox_id in list(self.created_sandbox_ids):
            try:
                self._docker_manager.destroy(sandbox_id)
                report["cleaned"].append(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
        try:
            still = self._docker_manager.backend.sandbox_metadata()
            report["remaining"] = [
                row["sandbox_id"] for row in still
                if row["sandbox_id"].startswith(SANDBOX_PREFIX)]
        except Exception:  # noqa: BLE001
            report["remaining"] = None
        return report


# =============================================================================
# Core single-pair execution + full independent verification (spec sections
# 6, 8, 9, 10, 13)
# =============================================================================

def run_and_verify_pair(app_module, factory, scenario_key, factual_choice_id,
                        counterfactual_choice_id, session_id=None,
                        expect_staged_mismatch_from=None):
    """Run one paired execution end to end and independently verify it.

    Returns a flat dict row: every field the pair-matrix / repeatability /
    telemetry experiments need, plus ``trial_succeeded`` and ``error``.
    Never raises for a verification failure -- callers get a row with
    ``trial_succeeded: False`` and the reasons in ``verification_failures``.
    """
    session_id = session_id or ("rwsf-sess-" + uuid.uuid4().hex[:16])
    row = {
        "scenario_key": scenario_key,
        "factual_choice_id": factual_choice_id,
        "counterfactual_choice_id": counterfactual_choice_id,
        "session_id": session_id,
        "trial_succeeded": False,
        "error": None,
        "verification_failures": [],
        "execution_id": None,
        "pair_id": None,
    }
    scenario = _scenario_definition(scenario_key)
    adapter = factory.build(scenario_key, session_id=session_id)
    decision_id = spec.SCENARIOS[scenario_key]["decision_id"]

    with app_module.app.app_context():
        service = app_module.training_service()
        started = time.perf_counter()
        try:
            execution_id, pair = service.run_pair(
                scenario, adapter, decision_id,
                factual_choice_id=factual_choice_id,
                counterfactual_choice_id=counterfactual_choice_id,
                session_id=session_id,
                factual_confidence=50, counterfactual_confidence=50,
                factual_response_ms=1000, counterfactual_response_ms=1000)
        except Exception as exc:  # noqa: BLE001 -- a raised failure IS a result
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            row["server_side_pair_seconds"] = time.perf_counter() - started
            return row
        row["server_side_pair_seconds"] = time.perf_counter() - started
        row["execution_id"] = execution_id
        row["pair_id"] = pair.pair_id

        failures = row["verification_failures"]

        # -- request/response identity ---------------------------------
        if pair.factual.choice_id != factual_choice_id:
            failures.append("factual choice mismatch")
        if pair.counterfactual.choice_id != counterfactual_choice_id:
            failures.append("counterfactual choice mismatch")
        if pair.factual.choice_id == pair.counterfactual.choice_id:
            failures.append("factual == counterfactual choice")

        # -- baseline/rewind digest equality (production's own claim) ---
        if not pair.baseline_digest or not pair.rewound_snapshot.digest:
            failures.append("missing baseline or rewound digest")
        elif pair.baseline_digest != pair.rewound_snapshot.digest:
            failures.append("baseline digest != rewound digest")

        # -- reload the persisted row and independently re-verify -------
        db = app_module.db
        record = db.session.query(app_module.TrainingExecution).filter_by(
            execution_id=execution_id).all()
        if len(record) != 1:
            failures.append("expected exactly one TrainingExecution row for "
                            "this execution_id, found %d" % len(record))
        else:
            stored = record[0]
            if stored.status != app_module.TrainingExecution.STATUS_COMPLETED:
                failures.append("stored status != completed (%r)" % stored.status)
            if stored.factual_choice_id != factual_choice_id:
                failures.append("stored factual_choice_id mismatch")
            if stored.counterfactual_choice_id != counterfactual_choice_id:
                failures.append("stored counterfactual_choice_id mismatch")

            ok_f, recomputed_f = verify_stored_digest(
                stored.factual_state_json, stored.factual_result_digest)
            if not ok_f:
                failures.append(
                    "independent factual digest mismatch (stored=%s, "
                    "recomputed=%s)" % (stored.factual_result_digest,
                                        recomputed_f))
            ok_c, recomputed_c = verify_stored_digest(
                stored.counterfactual_state_json,
                stored.counterfactual_result_digest)
            if not ok_c:
                failures.append(
                    "independent counterfactual digest mismatch (stored=%s, "
                    "recomputed=%s)" % (stored.counterfactual_result_digest,
                                        recomputed_c))

            # -- consequence-fact oracle, against the independently
            #    re-parsed (never production-trusted) resulting states ----
            try:
                factual_state = json.loads(stored.factual_state_json)
                fact_failures = spec.check_consequence_facts(
                    scenario_key, factual_choice_id, factual_state)
                failures.extend("factual " + f for f in fact_failures)
            except (TypeError, ValueError) as exc:
                failures.append("could not parse factual_state_json: %s" % exc)
            try:
                counterfactual_state = json.loads(
                    stored.counterfactual_state_json)
                fact_failures = spec.check_consequence_facts(
                    scenario_key, counterfactual_choice_id,
                    counterfactual_state)
                failures.extend(
                    "counterfactual " + f for f in fact_failures)
            except (TypeError, ValueError) as exc:
                failures.append(
                    "could not parse counterfactual_state_json: %s" % exc)

            row["baseline_digest"] = stored.baseline_digest
            row["rewound_digest"] = stored.rewound_digest
            row["factual_result_digest"] = stored.factual_result_digest
            row["counterfactual_result_digest"] = (
                stored.counterfactual_result_digest)

        # -- six-event lifecycle telemetry -------------------------------
        telemetry_failures, telemetry_detail = verify_telemetry(
            app_module, execution_id, session_id)
        failures.extend(telemetry_failures)
        row["telemetry"] = telemetry_detail

        row["trial_succeeded"] = not failures

    return row


def verify_telemetry(app_module, execution_id, session_id):
    """Independent verification of the six-event lifecycle for one execution.

    Queried straight from the real ``SecurityEvent`` table -- correlated via
    ``scenario_id == execution_id``, matching training_service.py's documented
    overload -- and scored purely against the literal oracle in
    ``rewindsec_specifications``, never against
    ``training_service.SUCCESS_EVENT_ORDER``.
    """
    db = app_module.db
    rows = (db.session.query(app_module.SecurityEvent)
           .filter_by(scenario_id=execution_id)
           .order_by(app_module.SecurityEvent.id.asc()).all())
    failures = []
    types = [r.event_type for r in rows]

    training_types = [t for t in types if t.startswith("TRAINING_")]
    unexpected = [t for t in training_types
                 if t not in spec.KNOWN_TRAINING_EVENT_TYPES]
    if unexpected:
        failures.append("unexpected TRAINING_* event type(s): %s" % unexpected)

    if spec.TRAINING_EXECUTION_FAILED in training_types:
        failures.append("TRAINING_EXECUTION_FAILED present in a run being "
                        "scored as successful")

    counts = {t: training_types.count(t) for t in set(training_types)}
    for event_type in spec.SUCCESS_EVENT_SEQUENCE:
        if counts.get(event_type, 0) != 1:
            failures.append("expected exactly one %s, observed %d"
                            % (event_type, counts.get(event_type, 0)))

    observed_success_sequence = [
        t for t in training_types if t in spec.SUCCESS_EVENT_SEQUENCE]
    exact_sequence = (
        tuple(observed_success_sequence) == spec.SUCCESS_EVENT_SEQUENCE)
    if not exact_sequence:
        failures.append("event order %r != expected %r"
                        % (observed_success_sequence,
                           spec.SUCCESS_EVENT_SEQUENCE))

    session_ok = all(r.session_id == session_id for r in rows) and bool(rows)
    if not session_ok:
        failures.append("session_id correlation failed")

    source_ok = all(
        r.source == spec.EXPECTED_TELEMETRY_SOURCE
        for r in rows if r.event_type in spec.KNOWN_TRAINING_EVENT_TYPES)
    if not source_ok:
        failures.append("source != %r for a TRAINING_* row"
                        % spec.EXPECTED_TELEMETRY_SOURCE)

    timestamps = [r.timestamp for r in rows if r.timestamp is not None]
    chronological = timestamps == sorted(timestamps)
    if not chronological:
        failures.append("event timestamps are not chronologically ordered")

    detail = {
        "completeness_ok": counts.get(spec.SUCCESS_EVENT_SEQUENCE[0], 0) >= 1
                           and len(counts) >= len(spec.SUCCESS_EVENT_SEQUENCE),
        "exact_sequence_ok": exact_sequence,
        "session_correlation_ok": session_ok,
        "timestamp_order_ok": chronological,
        "duplicate_lifecycle_events": sum(
            max(0, counts.get(t, 0) - 1) for t in spec.SUCCESS_EVENT_SEQUENCE),
        "unexpected_training_event_count": len(unexpected),
        "observed_event_types": types,
    }
    return failures, detail


# =============================================================================
# Experiment A: complete ordered pair matrix
# =============================================================================

def experiment_a(app_module, factory, scenario_keys):
    rows = []
    for scenario_key in scenario_keys:
        for factual, counterfactual in spec.ordered_pairs(scenario_key):
            rows.append(run_and_verify_pair(
                app_module, factory, scenario_key, factual, counterfactual))
    summary = _pass_fail_summary(rows)
    return "pair_matrix", summary, rows


# =============================================================================
# Experiment B: deterministic repeatability -- one fixed pair/scenario, N reps
# =============================================================================

def experiment_b(app_module, factory, scenario_keys, reps):
    rows = []
    per_scenario = {}
    for scenario_key in scenario_keys:
        factual, counterfactual = spec.representative_pair(scenario_key)
        observed = []
        for _ in range(reps):
            record = run_and_verify_pair(
                app_module, factory, scenario_key, factual, counterfactual)
            rows.append(record)
            observed.append(record)
        per_scenario[scenario_key] = _repeatability_summary(observed)
    summary = {"per_scenario": per_scenario,
              "overall": _pass_fail_summary(rows)}
    return "repeatability", summary, rows


def _repeatability_summary(records):
    succeeded = [r for r in records if r["trial_succeeded"]]
    execution_ids = [r["execution_id"] for r in records if r["execution_id"]]
    pair_ids = {r["pair_id"] for r in succeeded if r["pair_id"]}
    baseline_digests = {r.get("baseline_digest") for r in succeeded}
    factual_digests = {r.get("factual_result_digest") for r in succeeded}
    counterfactual_digests = {
        r.get("counterfactual_result_digest") for r in succeeded}
    return {
        "n": len(records),
        "repeatability_success_rate": (
            len(succeeded) / len(records) if records else None),
        "baseline_equality_rate": (
            1.0 if len(baseline_digests) <= 1 and succeeded else
            (0.0 if succeeded else None)),
        "rewind_equality_rate": (
            1.0 if all(r.get("baseline_digest") == r.get("rewound_digest")
                      for r in succeeded) and succeeded else
            (0.0 if succeeded else None)),
        "factual_digest_reproducibility_rate": (
            1.0 if len(factual_digests) <= 1 and succeeded else
            (0.0 if succeeded else None)),
        "counterfactual_digest_reproducibility_rate": (
            1.0 if len(counterfactual_digests) <= 1 and succeeded else
            (0.0 if succeeded else None)),
        "pair_id_reproducibility_rate": (
            1.0 if len(pair_ids) <= 1 and succeeded else
            (0.0 if succeeded else None)),
        "execution_id_uniqueness_ok": len(execution_ids) == len(set(execution_ids)),
        "failed_runs": [r for r in records if not r["trial_succeeded"]],
    }


# =============================================================================
# Experiment C: independent rewind integrity (digest(S0) == digest(S0'))
#
# Reuses the rows already produced by Experiment A/B rather than re-running an
# identical workload -- explicitly recorded in the written summary.
# =============================================================================

def experiment_c_from_rows(rows):
    per_scenario = {}
    for scenario_key in {r["scenario_key"] for r in rows}:
        subset = [r for r in rows if r["scenario_key"] == scenario_key]
        mismatches = [
            r["execution_id"] for r in subset
            if r["execution_id"] and (
                r.get("baseline_digest") != r.get("rewound_digest")
                or "baseline digest != rewound digest"
                in r["verification_failures"])]
        per_scenario[scenario_key] = {
            "n": len(subset),
            "rewind_verification_rate": (
                (len(subset) - len(mismatches)) / len(subset)
                if subset else None),
            "mismatch_count": len(mismatches),
            "mismatched_execution_ids": mismatches,
        }
    return {"reused_observations_from": "experiment A/B rows",
           "per_scenario": per_scenario}


def negative_rewind_corruption_check():
    """Controlled negative test: a corrupted rewind must be REFUSED, not
    reported as success. Not a paper measurement -- exercised by pytest and by
    the CLI's own self-check, never counted into any experiment's rows."""
    from training.adapters import DriftingRewindAdapter
    from training.definitions import (Choice, ConsequenceSpec, DecisionPoint,
                                      ScenarioDefinition)
    from training.errors import BaselineVerificationError
    from training.runtime import CounterfactualRuntime

    def _a(state):
        state["marker"] = "a"

    def _b(state):
        state["marker"] = "b"

    scenario = ScenarioDefinition(
        scenario_key="rewindsec_formal_negative_probe", version=1,
        title="negative probe",
        decision_points=(DecisionPoint(
            "d", "p", (
                Choice("c1", "one", ConsequenceSpec("act_a")),
                Choice("c2", "two", ConsequenceSpec("act_b")),
            )),))
    adapter = DriftingRewindAdapter({"marker": None},
                                    {"act_a": _a, "act_b": _b})
    runtime = CounterfactualRuntime(scenario, adapter)
    try:
        runtime.run_decision_pair("d", "c1", "c2")
    except BaselineVerificationError:
        return True
    return False


# =============================================================================
# Experiment D: staged factual-preview integrity.
#
# Measures every scenario whose CURRENT learner flow actually stages a
# preview -- verified from code to be ransomware, MFA and BEC (via
# training_routes.py's ransomware route and training_flow.py's
# register_synthetic_module, which drives both MFA and BEC). Phishing does
# not stage a preview and is correctly excluded. This generalises over
# spec.staged_preview_scenarios() rather than hardcoding one scenario, so a
# future scenario declared staged in the oracle is picked up automatically.
# =============================================================================

def experiment_d(app_module, factory, scenario_keys, reps):
    rows = []
    targets = [k for k in scenario_keys if k in spec.staged_preview_scenarios()]
    for scenario_key in targets:
        scenario = _scenario_definition(scenario_key)
        decision_id = spec.SCENARIOS[scenario_key]["decision_id"]
        factual_choice, counterfactual_choice = spec.representative_pair(
            scenario_key)
        factual_action = spec.SCENARIOS[scenario_key]["action_keys"][
            factual_choice]
        for _ in range(reps):
            session_id = "rwsf-sess-" + uuid.uuid4().hex[:16]
            row = {"scenario_key": scenario_key, "session_id": session_id,
                  "trial_succeeded": False, "error": None}
            try:
                staging_adapter = factory.build(scenario_key,
                                                session_id=session_id)
                staging_adapter.prepare()
                staged_baseline = staging_adapter.capture_state()
                staged_baseline_digest = spec.independent_digest(
                    staged_baseline)
                staging_adapter.apply(factual_action)
                staged_factual = staging_adapter.capture_state()
                staged_factual_digest = spec.independent_digest(
                    staged_factual)
            except Exception as exc:  # noqa: BLE001
                row["error"] = "staging failed: %s" % exc
                rows.append(row)
                continue

            with app_module.app.app_context():
                service = app_module.training_service()
                # A fresh adapter for the authoritative run, exactly like the
                # real routes do: the adapter re-establishes S0 itself, so
                # staging and the authoritative run never share adapter state.
                auth_adapter = factory.build(scenario_key,
                                             session_id=session_id)
                try:
                    execution_id, pair = service.run_pair(
                        scenario, auth_adapter, decision_id,
                        factual_choice_id=factual_choice,
                        counterfactual_choice_id=counterfactual_choice,
                        session_id=session_id,
                        factual_confidence=50, counterfactual_confidence=50)
                except Exception as exc:  # noqa: BLE001
                    row["error"] = "authoritative run failed: %s" % exc
                    rows.append(row)
                    continue
                row["execution_id"] = execution_id
                row["staged_baseline_digest"] = staged_baseline_digest
                row["staged_factual_digest"] = staged_factual_digest
                row["authoritative_baseline_digest"] = pair.baseline_digest
                row["authoritative_factual_digest"] = pair.factual.digest
                baseline_match = (
                    staged_baseline_digest == pair.baseline_digest)
                factual_match = (staged_factual_digest == pair.factual.digest)
                row["staged_baseline_matches_authoritative"] = baseline_match
                row["staged_factual_matches_authoritative"] = factual_match
                row["trial_succeeded"] = baseline_match and factual_match
            rows.append(row)

        # Fail-closed check (spec section 11): a deliberately mismatched
        # staged digest must cause run_pair's own guard to raise and the row
        # to remain 'failed', never 'completed'. Kept out of the reps loop
        # above so a real reps count is never diluted by an intentionally-
        # broken trial.
        rows.append(_staged_mismatch_fails_closed(app_module, factory,
                                                   scenario_key))

    summary = _pass_fail_summary(rows)
    summary["scenarios_measured"] = targets
    return "staging", summary, rows


def _staged_mismatch_fails_closed(app_module, factory, scenario_key):
    from training_service import TrainingExecutionError
    scenario = _scenario_definition(scenario_key)
    decision_id = spec.SCENARIOS[scenario_key]["decision_id"]
    ids = spec.SCENARIOS[scenario_key]["choice_ids"]
    session_id = "rwsf-sess-" + uuid.uuid4().hex[:16]
    adapter = factory.build(scenario_key, session_id=session_id)
    row = {"scenario_key": scenario_key, "session_id": session_id,
          "check": "staged_mismatch_fails_closed", "trial_succeeded": False,
          "error": None}
    with app_module.app.app_context():
        service = app_module.training_service()
        try:
            service.run_pair(
                scenario, adapter, decision_id,
                factual_choice_id=ids[0], counterfactual_choice_id=ids[1],
                session_id=session_id,
                # Deliberately wrong digest: the real run cannot possibly
                # reproduce it, so run_pair must refuse and record 'failed'.
                expected_baseline_digest="0" * 64)
            row["error"] = "run_pair did not raise on a staged mismatch"
        except TrainingExecutionError:
            db = app_module.db
            stored = db.session.query(app_module.TrainingExecution).filter_by(
                session_id=session_id).all()
            row["trial_succeeded"] = (
                len(stored) == 1
                and stored[0].status == app_module.TrainingExecution.STATUS_FAILED
                and stored[0].failure_type == "StagedExecutionMismatchError")
    return row


# =============================================================================
# Experiment E: training telemetry correctness (per scenario)
# =============================================================================

def experiment_e_from_rows(rows):
    per_scenario = {}
    for scenario_key in {r["scenario_key"] for r in rows}:
        subset = [r for r in rows if r["scenario_key"] == scenario_key
                 and "telemetry" in r]
        n = len(subset)
        completeness = sum(1 for r in subset if r["telemetry"]["completeness_ok"])
        exact = sum(1 for r in subset if r["telemetry"]["exact_sequence_ok"])
        session_ok = sum(1 for r in subset
                         if r["telemetry"]["session_correlation_ok"])
        ts_ok = sum(1 for r in subset if r["telemetry"]["timestamp_order_ok"])
        dup = sum(r["telemetry"]["duplicate_lifecycle_events"] for r in subset)
        unexpected = sum(
            r["telemetry"]["unexpected_training_event_count"] for r in subset)
        failed = [r["execution_id"] for r in subset if not r["trial_succeeded"]]
        per_scenario[scenario_key] = {
            "n": n,
            "telemetry_completeness_rate": completeness / n if n else None,
            "exact_sequence_rate": exact / n if n else None,
            "session_correlation_rate": session_ok / n if n else None,
            "timestamp_order_rate": ts_ok / n if n else None,
            "duplicate_lifecycle_event_count": dup,
            "unexpected_training_event_count": unexpected,
            "failed_runs": failed,
        }
    return {"reused_observations_from": "experiment A/B rows",
           "per_scenario": per_scenario}


# =============================================================================
# Experiment F: server-side pair latency (per scenario, never combined)
# =============================================================================

def experiment_f(app_module, factory, scenario_keys, reps):
    rows = []
    per_scenario = {}
    for scenario_key in scenario_keys:
        factual, counterfactual = spec.representative_pair(scenario_key)
        latencies = []
        for _ in range(reps):
            record = run_and_verify_pair(
                app_module, factory, scenario_key, factual, counterfactual)
            rows.append(record)
            if record["trial_succeeded"]:
                latencies.append(record["server_side_pair_seconds"])
        per_scenario[scenario_key] = summarise(latencies, unit="seconds")
        per_scenario[scenario_key]["metric_name"] = "server_side_pair_seconds"
    summary = {"per_scenario": per_scenario, "overall": _pass_fail_summary(rows)}
    return "performance", summary, rows


# =============================================================================
# Experiment G: bounded concurrency / isolation
# =============================================================================

def _concurrency_worker(app_module, factory, scenario_key, worker_index):
    session_id = "rwsf-conc-%d-%s" % (worker_index, uuid.uuid4().hex[:8])
    factual, counterfactual = spec.representative_pair(scenario_key)
    record = run_and_verify_pair(app_module, factory, scenario_key, factual,
                                 counterfactual, session_id=session_id)
    record["worker_index"] = worker_index
    return record


def experiment_g(app_module, factory, scenario_keys, levels, trials):
    rows = []
    per_level = {}
    for level in levels:
        level_rows = []
        for _trial in range(trials):
            with ThreadPoolExecutor(max_workers=level) as pool:
                futures = [
                    pool.submit(_concurrency_worker, app_module, factory,
                               scenario_keys[i % len(scenario_keys)], i)
                    for i in range(level)]
                results = []
                for future in futures:
                    try:
                        results.append(future.result())
                    except Exception as exc:  # noqa: BLE001
                        results.append({
                            "trial_succeeded": False,
                            "error": "worker raised: %s" % exc,
                            "scenario_key": None, "session_id": None})
            # cross-worker isolation: unique execution ids, unique session ids
            exec_ids = [r["execution_id"] for r in results if r["execution_id"]]
            session_ids = [r["session_id"] for r in results if r["session_id"]]
            isolation_ok = (len(exec_ids) == len(set(exec_ids))
                            and len(session_ids) == len(set(session_ids)))
            for r in results:
                r["concurrency_level"] = level
                r["cross_worker_isolation_ok"] = isolation_ok
                level_rows.append(r)
        rows.extend(level_rows)
        succeeded = [r for r in level_rows if r["trial_succeeded"]]
        per_level[level] = {
            "n": len(level_rows),
            "success_rate": (len(succeeded) / len(level_rows)
                             if level_rows else None),
            "isolation_ok_rate": (
                sum(1 for r in level_rows if r.get("cross_worker_isolation_ok"))
                / len(level_rows) if level_rows else None),
            "failed_runs": [r.get("execution_id") for r in level_rows
                           if not r["trial_succeeded"]],
        }
    summary = {"per_level": per_level, "overall": _pass_fail_summary(rows)}
    return "concurrency", summary, rows


# =============================================================================
# Shared helpers
# =============================================================================

def _pass_fail_summary(rows):
    n = len(rows)
    succeeded = [r for r in rows if r.get("trial_succeeded")]
    failed_indices = [i for i, r in enumerate(rows) if not r.get("trial_succeeded")]
    return {
        "n": n,
        "succeeded": len(succeeded),
        "failed": n - len(succeeded),
        "success_rate": (len(succeeded) / n) if n else None,
        "failed_row_indices": failed_indices,
        "failed_execution_ids": [
            rows[i].get("execution_id") for i in failed_indices],
    }


def write_json(path, payload):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str, sort_keys=True)


def write_csv(path, rows, fields):
    import csv
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            flat = {}
            for key in fields:
                value = row.get(key)
                flat[key] = json.dumps(value, default=str) if isinstance(
                    value, (dict, list)) else value
            writer.writerow(flat)


def _flatten_field_union(rows):
    fields = []
    seen = set()
    for row in rows:
        for key in row:
            if key not in seen:
                seen.add(key)
                fields.append(key)
    return fields


# =============================================================================
# Dirty-tree / admissibility policy
# =============================================================================

class RewindSecFormalRunRefused(RuntimeError):
    """The run cannot proceed under the conditions it requires."""


def check_dirty_tree(allow_dirty):
    sha, dirty = git_commit()
    if dirty and not allow_dirty:
        raise RewindSecFormalRunRefused(
            "the git working tree is dirty; a formal (admissible) RewindSec "
            "run refuses to start against uncommitted changes. Commit/stash "
            "first, or pass --allow-dirty for an explicitly non-admissible "
            "development_run.")
    return sha, dirty


# =============================================================================
# CLI
# =============================================================================

def main(argv=None):
    parser = argparse.ArgumentParser(
        description="RewindSec formal SYSTEMS evaluation (new, separate "
                    "harness -- see module docstring)")
    parser.add_argument("--experiments", default=",".join(EXPERIMENT_LETTERS))
    parser.add_argument("--scenarios", default=",".join(spec.SCENARIO_KEYS))
    parser.add_argument("--repeatability-runs", type=int,
                        default=DEFAULT_REPEATABILITY_RUNS)
    parser.add_argument("--staging-runs", type=int,
                        default=DEFAULT_STAGING_RUNS)
    parser.add_argument("--performance-runs", type=int,
                        default=DEFAULT_PERFORMANCE_RUNS)
    parser.add_argument("--concurrency",
                        default=",".join(str(c)
                                         for c in DEFAULT_CONCURRENCY_LEVELS))
    parser.add_argument("--concurrency-trials", type=int,
                        default=DEFAULT_CONCURRENCY_TRIALS)
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument("--allow-dirty", action="store_true")
    parser.add_argument("--smoke", action="store_true",
                        help="tiny non-admissible development_run config: "
                            "pair matrix once, 2 reps for B/D/F, concurrency "
                            "1,2 x1 trial, containment once")
    parser.add_argument("--skip-containment", action="store_true")
    parser.add_argument("--docker-image", default=None)
    args = parser.parse_args(argv)

    if args.smoke:
        args.repeatability_runs = 2
        args.staging_runs = 2
        args.performance_runs = 2
        args.concurrency = "1,2"
        args.concurrency_trials = 1
        args.allow_dirty = True

    sha, dirty = check_dirty_tree(args.allow_dirty)
    admissible = (not dirty) and (not args.smoke)
    development_run = bool(dirty) or args.smoke

    selected = [s.strip().upper() for s in args.experiments.split(",")
               if s.strip()]
    scenario_keys = [s.strip() for s in args.scenarios.split(",") if s.strip()]
    unknown_scn = [s for s in scenario_keys if s not in spec.SCENARIO_KEYS]
    if unknown_scn:
        raise SystemExit("unknown scenario key(s): %s" % unknown_scn)
    concurrency_levels = tuple(int(v) for v in args.concurrency.split(",")
                              if v.strip())

    needs_docker = (spec.RANSOMWARE in scenario_keys) and bool(
        set(selected) & {"A", "B", "D", "E", "F", "G"})
    if needs_docker:
        require_docker_backend("docker", args.docker_image
                               or _default_docker_image())

    results_dir = os.path.abspath(args.results_dir)
    if args.smoke:
        results_dir = os.path.join(results_dir, "smoke")
    os.makedirs(results_dir, exist_ok=True)

    import tempfile
    root_dir = tempfile.mkdtemp(prefix="rewindsec-formal-")
    app_module = None
    factory = AdapterFactory(docker_image=args.docker_image)
    summaries = {}
    metadata = {
        "harness": "evaluation.rewindsec_formal_run",
        "distinct_from": "evaluation.formal_run (historical, untouched)",
        "rewindsec_specification_version":
            spec.REWINDSEC_SPECIFICATION_VERSION,
        "specification_manifest": spec.specification_manifest(),
        "git_commit": sha,
        "git_tree_dirty": dirty,
        "admissible": admissible,
        "development_run": development_run,
        "smoke": args.smoke,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python_version": sys.version.split()[0],
        "cpu_count": os.cpu_count(),
        "os": sys.platform,
        "docker_engine_version": docker_engine_version(),
        "scenarios_selected": scenario_keys,
        "experiments_selected": selected,
        "configuration": {
            "repeatability_runs": args.repeatability_runs,
            "staging_runs": args.staging_runs,
            "performance_runs": args.performance_runs,
            "concurrency_levels": list(concurrency_levels),
            "concurrency_trials": args.concurrency_trials,
        },
    }

    started = time.perf_counter()
    matrix_rows = []
    try:
        with bootstrap_app(root_dir) as app_module:
            if not args.skip_containment and needs_docker:
                print("=== containment re-validation (reusing evaluation.containment) ===")
                checks, elapsed = time_call(run_containment_checks,
                                            factory._manager().backend)
                containment_summary = summarise_containment(checks)
                containment_summary["elapsed_seconds"] = elapsed
                write_json(os.path.join(results_dir, "containment.json"),
                          {"metadata": metadata, "summary": containment_summary,
                           "checks": checks})
                write_csv(os.path.join(results_dir, "containment.csv"), checks,
                         ["check", "category", "description", "passed",
                          "expected", "observed"])
                summaries["containment"] = containment_summary
                print("  %d/%d checks passed"
                     % (containment_summary["passed"],
                        containment_summary["checks_run"]))

            for letter in selected:
                print("\n=== RewindSec Experiment %s ===" % letter)
                estart = time.perf_counter()
                if letter == "A":
                    name, summary, rows = experiment_a(
                        app_module, factory, scenario_keys)
                    matrix_rows.extend(rows)
                elif letter == "B":
                    name, summary, rows = experiment_b(
                        app_module, factory, scenario_keys,
                        args.repeatability_runs)
                    matrix_rows.extend(rows)
                elif letter == "C":
                    name = "rewind_integrity"
                    summary = experiment_c_from_rows(matrix_rows)
                    summary["negative_corruption_check_passed"] = (
                        negative_rewind_corruption_check())
                    rows = []
                elif letter == "D":
                    staged_selected = [k for k in scenario_keys
                                      if k in spec.staged_preview_scenarios()]
                    if not staged_selected:
                        print("  skipped: no staged-preview scenario selected "
                             "(ransomware/mfa/bec)")
                        continue
                    name, summary, rows = experiment_d(
                        app_module, factory, scenario_keys, args.staging_runs)
                elif letter == "E":
                    name = "telemetry"
                    summary = experiment_e_from_rows(matrix_rows)
                    rows = []
                elif letter == "F":
                    name, summary, rows = experiment_f(
                        app_module, factory, scenario_keys,
                        args.performance_runs)
                else:
                    name, summary, rows = experiment_g(
                        app_module, factory, scenario_keys, concurrency_levels,
                        args.concurrency_trials)
                elapsed = time.perf_counter() - estart
                summary["wall_seconds"] = elapsed
                summary["admissible"] = admissible
                summary["development_run"] = development_run
                if rows:
                    fields = _flatten_field_union(rows)
                    write_csv(os.path.join(results_dir, name + ".csv"), rows, fields)
                write_json(os.path.join(results_dir, name + ".json"),
                          {"metadata": metadata, "summary": summary,
                           "observations": rows})
                summaries[name] = summary
                print(json.dumps(summary, indent=2, default=str)[:1500])
    finally:
        cleanup = factory.cleanup()
        try:
            shutil.rmtree(root_dir, ignore_errors=True)
        except OSError:
            pass
        metadata["cleanup"] = cleanup
        metadata["total_wall_seconds"] = time.perf_counter() - started
        write_json(os.path.join(results_dir, "metadata.json"), metadata)
        write_json(os.path.join(results_dir, "summary.json"),
                  {"metadata": metadata, "experiments": summaries})

    print("\n=== admissibility ===")
    print("  admissible      : %s" % admissible)
    print("  development_run : %s" % development_run)
    print("\n=== cleanup ===")
    print("  owned before cleanup : %s" % cleanup["owned_before_cleanup"])
    print("  cleaned              : %s" % cleanup["cleaned"])
    print("  remaining            : %s" % cleanup["remaining"])
    print("  other owned untouched: %s" % cleanup["other_owned_untouched"])
    print("\nresults written to %s" % results_dir)
    return 0


def _default_docker_image():
    from sandbox.backends.docker import DEFAULT_IMAGE
    return DEFAULT_IMAGE


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except RewindSecFormalRunRefused as error:
        print("RewindSec formal run refused: %s" % error, file=sys.stderr)
        raise SystemExit(2)
