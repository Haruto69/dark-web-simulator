"""Integration tests for the RewindSec training service (milestone R2).

These exercise the seam between the pure runtime, the persisted result artifact
and the authoritative SecurityEvent timeline, under a real Flask application
context and a real SQLite database. No Docker, no learner-facing route, and the
deterministic in-memory adapter throughout -- a sandbox adapter is R3/R4.
"""

import json
import uuid

import pytest

from sandbox.events import EventType
from training import (BaselineVerificationError, Choice, ConsequenceSpec,
                      DecisionPoint, ScenarioDefinition)
from training.adapters import DriftingRewindAdapter, InMemoryConsequenceAdapter
from training_service import (SUCCESS_EVENT_ORDER, TELEMETRY_SOURCE,
                              TrainingExecutionError, safe_details)

TRAINING_EVENT_TYPES = frozenset(SUCCESS_EVENT_ORDER) | {
    EventType.TRAINING_EXECUTION_FAILED}

BASELINE_STATE = {
    "account": {"compromised": False, "sessions": 1},
    "files": {"impacted": 0, "total": 5},
    "endpoint": {"isolated": False},
}


def _reuse(state):
    state["account"]["compromised"] = True
    state["files"]["impacted"] = 5


def _isolate(state):
    state["endpoint"]["isolated"] = True
    state["files"]["impacted"] = 1


ACTIONS = {"credentials_reused": _reuse, "endpoint_isolated": _isolate}


def make_adapter(cls=InMemoryConsequenceAdapter):
    return cls(BASELINE_STATE, ACTIONS)


def make_scenario():
    return ScenarioDefinition(
        scenario_key="credential_prompt", version=1,
        title="Unexpected credential prompt",
        competency_tags=("phishing",),
        decision_points=(DecisionPoint(
            "respond_to_prompt", "unexpected_login_prompt", (
                Choice("reuse_password", "Enter the usual password",
                       ConsequenceSpec("credentials_reused")),
                Choice("isolate_endpoint", "Disconnect and report",
                       ConsequenceSpec("endpoint_isolated")),
            )),))


@pytest.fixture
def app_module(flask_app):
    import app as module
    return module


@pytest.fixture
def service(app_module):
    with app_module.app.app_context():
        yield app_module.training_service()


@pytest.fixture
def session_id():
    """A fresh learner session id per test, so rows never collide."""
    return "sess-" + uuid.uuid4().hex[:12]


def run_once(service, session_id, factual="reuse_password",
             counterfactual="isolate_endpoint", adapter=None, **kwargs):
    return service.run_pair(
        scenario=make_scenario(), adapter=adapter or make_adapter(),
        decision_id="respond_to_prompt", factual_choice_id=factual,
        counterfactual_choice_id=counterfactual, session_id=session_id,
        **kwargs)


def executions_for(app_module, session_id):
    return (app_module.TrainingExecution.query
            .filter_by(session_id=session_id)
            .order_by(app_module.TrainingExecution.id.asc()).all())


def training_events(app_module, execution_id):
    """Every TRAINING_* event for one execution, in recorded order."""
    return (app_module.SecurityEvent.query
            .filter_by(scenario_id=execution_id)
            .order_by(app_module.SecurityEvent.timestamp.asc(),
                      app_module.SecurityEvent.id.asc()).all())


# --------------------------------------------------------------------------
# A / B / E / F / G / H  the stored result
# --------------------------------------------------------------------------

def test_a_successful_pair_creates_exactly_one_completed_row(app_module,
                                                             service,
                                                             session_id):
    with app_module.app.app_context():
        execution_id, pair = run_once(service, session_id)

        rows = executions_for(app_module, session_id)
        assert len(rows) == 1
        row = rows[0]
        assert row.execution_id == execution_id
        assert row.status == app_module.TrainingExecution.STATUS_COMPLETED
        assert row.completed_at is not None
        assert row.failure_type is None and row.error_ref is None
        assert row.pair_id == pair.pair_id


def test_the_row_exists_as_started_before_the_experiment_finishes(app_module,
                                                                  service,
                                                                  session_id):
    """A run that dies mid-experiment must still be observable."""
    seen = {}

    class Watcher(InMemoryConsequenceAdapter):
        def apply(self, action_key):
            with app_module.app.app_context():
                rows = executions_for(app_module, session_id)
                seen["status"] = rows[0].status if rows else None
            return super().apply(action_key)

    with app_module.app.app_context():
        run_once(service, session_id, adapter=Watcher(BASELINE_STATE, ACTIONS))

    assert seen["status"] == app_module.TrainingExecution.STATUS_STARTED


def test_scenario_decision_and_branch_metadata_are_persisted(app_module,
                                                             service,
                                                             session_id):
    with app_module.app.app_context():
        _, pair = run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

        assert row.session_id == session_id
        assert row.scenario_key == "credential_prompt"
        assert row.scenario_version == 1
        assert row.decision_id == "respond_to_prompt"

        assert row.factual_choice_id == "reuse_password"
        assert row.factual_action_key == "credentials_reused"
        assert row.counterfactual_choice_id == "isolate_endpoint"
        assert row.counterfactual_action_key == "endpoint_isolated"

        assert row.to_dict()["scenario_identity"] == "credential_prompt@1"
        assert row.to_dict()["factual"]["choice_id"] == pair.factual.choice_id


def test_confidence_and_response_time_are_persisted_exactly(app_module,
                                                            service,
                                                            session_id):
    with app_module.app.app_context():
        run_once(service, session_id, factual_confidence=0,
                 counterfactual_confidence=100, factual_response_ms=4200)
        row = executions_for(app_module, session_id)[0]

        assert row.factual_confidence == 0
        assert row.counterfactual_confidence == 100
        assert row.factual_response_time_ms == 4200
        assert row.counterfactual_response_time_ms is None


def test_invalid_confidence_is_rejected_and_recorded_as_failed(app_module,
                                                               service,
                                                               session_id):
    with app_module.app.app_context():
        with pytest.raises(TrainingExecutionError) as raised:
            run_once(service, session_id, factual_confidence=101)

        row = executions_for(app_module, session_id)[0]
        assert row.status == app_module.TrainingExecution.STATUS_FAILED
        assert row.failure_type == "ConfidenceValueError"
        assert raised.value.error_ref == row.error_ref


# --------------------------------------------------------------------------
# C / D / P  identity
# --------------------------------------------------------------------------

def test_execution_id_is_unique_per_invocation(app_module, service,
                                               session_id):
    with app_module.app.app_context():
        first, _ = run_once(service, session_id)
        second, _ = run_once(service, session_id)

    assert first != second
    assert first.startswith("exec-") and len(first) == 37


def test_repeated_identical_pairs_share_pair_id_but_not_execution_id(
        app_module, service, session_id):
    """The R1/R2 identity split, stated as a test.

    ``pair_id`` is the deterministic identity of the *experiment*; two runs of
    the same experiment from the same baseline are the same experiment, and
    later reproducibility work depends on that. ``execution_id`` is the
    identity of the *occurrence*, and is never shared.
    """
    with app_module.app.app_context():
        first_execution, first_pair = run_once(service, session_id)
        second_execution, second_pair = run_once(service, session_id)

        assert first_pair.pair_id == second_pair.pair_id
        assert first_execution != second_execution

        rows = executions_for(app_module, session_id)
        assert len(rows) == 2
        assert rows[0].pair_id == rows[1].pair_id
        assert rows[0].execution_id != rows[1].execution_id


def test_repeated_runs_do_not_deduplicate_each_others_telemetry(app_module,
                                                                service,
                                                                session_id):
    """The progression gate keys on (session, execution_id, event_type).

    Because ``execution_id`` is unique per invocation, two executions of the
    same experiment each get a full lifecycle -- while a repeat *within* one
    execution would still be collapsed.
    """
    with app_module.app.app_context():
        first_execution, _ = run_once(service, session_id)
        second_execution, _ = run_once(service, session_id)

        first = [row.event_type for row in training_events(app_module,
                                                           first_execution)]
        second = [row.event_type for row in training_events(app_module,
                                                            second_execution)]

    assert first == list(SUCCESS_EVENT_ORDER)
    assert second == list(SUCCESS_EVENT_ORDER)


def test_the_idempotency_gate_still_collapses_a_repeat_within_one_execution(
        app_module, service, session_id):
    with app_module.app.app_context():
        execution_id, _ = run_once(service, session_id)
        before = len(training_events(app_module, execution_id))
        # Re-emitting a lifecycle event for the same execution is a no-op.
        service._emit(EventType.TRAINING_BASELINE_CAPTURED, execution_id,
                      session_id, details={"baseline_digest": "x"})
        assert len(training_events(app_module, execution_id)) == before


# --------------------------------------------------------------------------
# I / J / K / L  research evidence
# --------------------------------------------------------------------------

def test_completed_execution_persists_verified_identical_baseline_digests(
        app_module, service, session_id):
    """A stored execution cannot claim counterfactual comparability unless the
    environment provably returned to the baseline both branches started from.

    Enforced at the service layer, not only here: ``_complete_row`` refuses to
    write a completed row whose baseline and rewound digests differ.
    """
    with app_module.app.app_context():
        _, pair = run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

        assert row.baseline_digest == row.rewound_digest
        assert row.baseline_digest == pair.baseline_digest
        assert row.baseline_verified is True
        assert row.to_dict()["baseline_verified"] is True


def test_no_completed_row_can_exist_without_verified_baseline_digests(
        app_module, service, session_id):
    """The invariant holds over the whole table, not just this test's row."""
    with app_module.app.app_context():
        run_once(service, session_id)
        completed = (app_module.TrainingExecution.query
                     .filter_by(status="completed").all())
        assert completed
        for row in completed:
            assert row.baseline_digest and row.baseline_digest == row.rewound_digest


def test_persisted_result_digests_match_the_runtime_snapshots(app_module,
                                                              service,
                                                              session_id):
    with app_module.app.app_context():
        _, pair = run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

        assert row.factual_result_digest == pair.factual.digest
        assert row.counterfactual_result_digest == pair.counterfactual.digest
        assert row.factual_result_digest != row.counterfactual_result_digest


def test_persisted_state_json_round_trips_exactly(app_module, service,
                                                  session_id):
    with app_module.app.app_context():
        _, pair = run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

        assert json.loads(row.factual_state_json) == pair.factual.resulting_snapshot.state
        assert (json.loads(row.counterfactual_state_json)
                == pair.counterfactual.resulting_snapshot.state)

        # Byte-identical to what was fingerprinted, so the digest can be
        # re-derived from the stored text -- one canonical serializer only.
        from training.snapshots import fingerprint
        assert fingerprint(json.loads(row.factual_state_json)) == pair.factual.digest
        assert row.factual_state_json == pair.factual.resulting_snapshot.canonical_json


def test_persisted_state_diff_round_trips_exactly(app_module, service,
                                                  session_id):
    with app_module.app.app_context():
        _, pair = run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

        stored = json.loads(row.difference_json)
        assert stored == pair.difference.as_dict()

        by_pointer = {change["pointer"]: change for change in stored["changes"]}
        assert by_pointer["account.compromised"]["from"] is True
        assert by_pointer["account.compromised"]["to"] is False
        assert by_pointer["files.impacted"]["from"] == 5
        assert by_pointer["files.impacted"]["to"] == 1


def test_the_baseline_state_itself_is_not_persisted(app_module, service,
                                                    session_id):
    """Data minimisation: the fingerprint is the evidence, not the state."""
    with app_module.app.app_context():
        run_once(service, session_id)
        row = executions_for(app_module, session_id)[0]

    columns = {column.name for column in
               app_module.TrainingExecution.__table__.columns}
    assert "baseline_state_json" not in columns
    assert not any("baseline" in name and name.endswith("_json")
                   for name in columns)
    assert row.baseline_digest


# --------------------------------------------------------------------------
# M / N / O  telemetry
# --------------------------------------------------------------------------

def test_persisted_training_execution_and_telemetry_preserve_counterfactual_order(
        app_module, service, session_id):
    """The ordered timeline of one paired execution.

    The events are emitted from *inside* the runtime as each step happens, not
    reconstructed from a finished result, so this order is the causal order of
    the experiment: baseline captured, factual observed, rewind verified, and
    only then the counterfactual.
    """
    with app_module.app.app_context():
        execution_id, pair = run_once(service, session_id)
        rows = training_events(app_module, execution_id)

    assert [row.event_type for row in rows] == [
        EventType.TRAINING_EXECUTION_STARTED,
        EventType.TRAINING_BASELINE_CAPTURED,
        EventType.TRAINING_FACTUAL_CAPTURED,
        EventType.TRAINING_REWIND_VERIFIED,
        EventType.TRAINING_COUNTERFACTUAL_CAPTURED,
        EventType.TRAINING_EXECUTION_COMPLETED,
    ]

    by_type = {row.event_type: row for row in rows}
    assert pair.baseline_digest in by_type[EventType.TRAINING_REWIND_VERIFIED].details
    assert "rewound_digest" in by_type[EventType.TRAINING_REWIND_VERIFIED].details
    assert pair.pair_id in by_type[EventType.TRAINING_EXECUTION_COMPLETED].details
    assert "reuse_password" in by_type[EventType.TRAINING_FACTUAL_CAPTURED].details
    assert "isolate_endpoint" in by_type[
        EventType.TRAINING_COUNTERFACTUAL_CAPTURED].details


def test_every_training_event_is_correlated_and_sourced(app_module, service,
                                                        session_id):
    with app_module.app.app_context():
        execution_id, _ = run_once(service, session_id)
        rows = training_events(app_module, execution_id)

    assert rows
    for row in rows:
        assert row.session_id == session_id
        # For TRAINING_* events scenario_id carries the execution_id.
        assert row.scenario_id == execution_id
        assert row.source == TELEMETRY_SOURCE
        assert row.event_type in TRAINING_EVENT_TYPES


def test_no_snapshot_state_appears_in_security_event_details(app_module,
                                                             service,
                                                             session_id):
    with app_module.app.app_context():
        execution_id, pair = run_once(service, session_id)
        rows = training_events(app_module, execution_id)

    factual_json = pair.factual.resulting_snapshot.canonical_json
    for row in rows:
        blob = "%s|%s" % (row.details or "", row.target or "")
        assert factual_json not in blob
        assert "compromised" not in blob
        assert "{" not in blob
        assert len(row.details or "") <= 400


def test_detail_building_drops_anything_not_allow_listed():
    details = safe_details({"pair_id": "p1", "state": {"secret": 1},
                            "password": "hunter2", "confidence": 80,
                            "message": "Expected digest abc at C:/Users/x"})
    assert details == "confidence=80,pair_id=p1"


# --------------------------------------------------------------------------
# Q / R / S  failure
# --------------------------------------------------------------------------

def test_failed_rewind_never_records_counterfactual_capture(app_module,
                                                            service,
                                                            session_id):
    """A rewind that does not restore the baseline stops the experiment.

    No alternative consequence is applied, and no event claims one was.
    """
    adapter = make_adapter(DriftingRewindAdapter)

    with app_module.app.app_context():
        with pytest.raises(TrainingExecutionError) as raised:
            run_once(service, session_id, adapter=adapter)

        row = executions_for(app_module, session_id)[0]
        events = [item.event_type
                  for item in training_events(app_module, row.execution_id)]

    # The alternative consequence was never executed.
    assert adapter.applied == ["credentials_reused"]

    assert EventType.TRAINING_COUNTERFACTUAL_CAPTURED not in events
    assert EventType.TRAINING_REWIND_VERIFIED not in events
    assert EventType.TRAINING_EXECUTION_COMPLETED not in events
    assert events == [
        EventType.TRAINING_EXECUTION_STARTED,
        EventType.TRAINING_BASELINE_CAPTURED,
        EventType.TRAINING_FACTUAL_CAPTURED,
        EventType.TRAINING_EXECUTION_FAILED,
    ]

    assert row.status == app_module.TrainingExecution.STATUS_FAILED
    assert row.failure_type == BaselineVerificationError.__name__
    assert row.error_ref and row.error_ref.startswith("err-")
    assert raised.value.failure_type == "BaselineVerificationError"
    # Nothing may claim a comparison was produced.
    assert row.pair_id is None
    assert row.counterfactual_result_digest is None
    assert row.difference_json is None


def test_failure_telemetry_and_storage_contain_no_raw_exception_message(
        app_module, service, session_id):
    with app_module.app.app_context():
        with pytest.raises(TrainingExecutionError):
            run_once(service, session_id,
                     adapter=make_adapter(DriftingRewindAdapter))
        row = executions_for(app_module, session_id)[0]
        failed = [item for item in training_events(app_module, row.execution_id)
                  if item.event_type == EventType.TRAINING_EXECUTION_FAILED]

    assert len(failed) == 1
    detail = failed[0].details
    assert detail == "error_ref=%s,failure_type=BaselineVerificationError" % row.error_ref
    for leak in ("expected", "observed", "rewound baseline does not match",
                 "Traceback", "C:", "/"):
        assert leak not in detail
        assert leak not in (row.failure_type or "")


def test_an_unsupported_action_fails_safely_and_is_recorded(app_module,
                                                            service,
                                                            session_id):
    unresolvable = ScenarioDefinition(
        scenario_key="unresolvable", version=1, title="Unresolvable",
        decision_points=(DecisionPoint("d", "p", (
            Choice("a", "A", ConsequenceSpec("no_such_action")),
            Choice("b", "B", ConsequenceSpec("endpoint_isolated")))),))
    adapter = make_adapter()

    with app_module.app.app_context():
        with pytest.raises(TrainingExecutionError):
            service.run_pair(scenario=unresolvable, adapter=adapter,
                             decision_id="d", factual_choice_id="a",
                             counterfactual_choice_id="b",
                             session_id=session_id)

        row = executions_for(app_module, session_id)[0]
        events = [item.event_type
                  for item in training_events(app_module, row.execution_id)]

    # Refused before the environment was touched at all.
    assert adapter.applied == [] and adapter.prepare_count == 0
    assert row.status == app_module.TrainingExecution.STATUS_FAILED
    assert row.failure_type == "UnknownActionError"
    assert events == [EventType.TRAINING_EXECUTION_STARTED,
                      EventType.TRAINING_EXECUTION_FAILED]


def test_no_execution_is_ever_left_permanently_started(app_module, service,
                                                       session_id):
    with app_module.app.app_context():
        run_once(service, session_id)
        with pytest.raises(TrainingExecutionError):
            run_once(service, session_id,
                     adapter=make_adapter(DriftingRewindAdapter))

        stuck = (app_module.TrainingExecution.query
                 .filter_by(status="started").all())
        assert stuck == []


def test_a_failing_observer_stops_the_run_rather_than_losing_the_timeline(
        app_module, session_id):
    """Telemetry that cannot be written must not be silently discarded."""
    from training_service import TrainingService

    class BrokenRecorder:
        def __init__(self, real):
            self.real = real
            self.calls = 0

        def __call__(self, event):
            self.calls += 1
            if event["event_type"] == EventType.TRAINING_FACTUAL_CAPTURED:
                raise RuntimeError("recorder unavailable")
            return self.real(event)

    with app_module.app.app_context():
        from sandbox_routes import make_recorder
        recorder = BrokenRecorder(make_recorder(app_module.db,
                                                app_module.SecurityEvent))
        service = TrainingService(app_module.db, app_module.TrainingExecution,
                                  recorder)
        adapter = make_adapter()
        with pytest.raises(TrainingExecutionError):
            run_once(service, session_id, adapter=adapter)

        row = executions_for(app_module, session_id)[0]

    assert adapter.applied == ["credentials_reused"]
    assert row.status == app_module.TrainingExecution.STATUS_FAILED
    assert row.failure_type == "RuntimeError"


# --------------------------------------------------------------------------
# T / U / V / W / X  the rest of the system
# --------------------------------------------------------------------------

def test_startup_creates_the_table_without_destroying_existing_rows(app_module,
                                                                    service,
                                                                    session_id):
    with app_module.app.app_context():
        assert "training_execution" in app_module.db.metadata.tables
        run_once(service, session_id)
        before = len(app_module.TrainingExecution.query.all())
        events_before = len(app_module.SecurityEvent.query.all())

        # Non-destructive startup: re-running init_db must not clear results.
        app_module.init_db()

        assert len(app_module.TrainingExecution.query.all()) == before
        assert len(app_module.SecurityEvent.query.all()) >= events_before
        assert executions_for(app_module, session_id)[0].status == "completed"


def test_no_parallel_training_event_table_was_introduced(app_module):
    """TrainingExecution is a result artifact, not a second telemetry stream.

    Milestone 3 removed PhishingFunnel/RansomwareFunnel for exactly this
    mistake; R2 must not reintroduce it.
    """
    tables = set(app_module.db.metadata.tables)
    for forbidden in ("training_event", "training_funnel", "training_telemetry",
                      "phishing_funnel", "ransomware_funnel"):
        assert forbidden not in tables

    # One execution is one row, updated in place -- never appended to.
    columns = {column.name for column in
               app_module.TrainingExecution.__table__.columns}
    assert "event_type" not in columns
    assert "stage" not in columns


def test_existing_scenario_event_semantics_are_unchanged():
    """Adding TRAINING_* must not reclassify or disturb existing telemetry."""
    from sandbox.telemetry import (INTERACTION_EVENTS, PROGRESSION_EVENTS,
                                   is_progression)

    for event_type in (EventType.PHISHING_EXPOSED, EventType.CREDENTIAL_SUBMITTED,
                       EventType.RANSOMWARE_TRIGGERED,
                       EventType.RANSOMWARE_DEBRIEFED,
                       EventType.SCENARIO_COMPLETED):
        assert is_progression(event_type)
    assert not is_progression(EventType.PAGE_VIEW)
    assert EventType.PAGE_VIEW in INTERACTION_EVENTS

    # The new types are classified, and as milestones -- which is what makes
    # them exactly-once per execution through the existing ledger.
    for event_type in TRAINING_EVENT_TYPES:
        assert event_type in PROGRESSION_EVENTS
    assert PROGRESSION_EVENTS.isdisjoint(INTERACTION_EVENTS)


def test_training_events_do_not_appear_in_the_existing_scenario_funnels():
    from sandbox.progression import PHISHING_FUNNEL, RANSOMWARE_FUNNEL

    funnel_events = set()
    for funnel in (PHISHING_FUNNEL, RANSOMWARE_FUNNEL):
        for stage in funnel:
            funnel_events.add(getattr(stage, "event_type", None)
                              or getattr(stage, "event", None))
    assert funnel_events.isdisjoint(TRAINING_EVENT_TYPES)


def test_the_pure_runtime_stays_framework_independent():
    """R1's defining property, re-checked now that R2 has been layered on."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "training"
    forbidden = re.compile(
        r"^\s*(?:from|import)\s+(flask|sqlalchemy|app|sandbox|telemetry_ledger|"
        r"training_service)\b", re.MULTILINE | re.IGNORECASE)
    for module in root.rglob("*.py"):
        assert not forbidden.search(module.read_text(encoding="utf-8")), \
            "{0} imports an application-layer dependency".format(module)
