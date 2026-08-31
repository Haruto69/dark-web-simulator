"""End-to-end tests for the RewindSec ransomware training flow (milestone R4).

These drive the complete learner workflow through the real Flask app, the real
R1 runtime, the real R2 service and the real ``SandboxManager`` file-impact
path: briefing -> workstation -> response -> factual preview -> rewind ->
executed comparison -> persisted result.

Docker is not required. The flow demands the *contained* backend and refuses to
fall back, so these tests supply a deterministic stand-in: ``ContainedFake`` is
the real ``LocalBackend`` presented under the contained backend's name, which
means every file operation, digest and refusal in the path below is genuine
while nothing on the developer's machine leaves ``tmp_path``. Real container
behaviour is covered by ``tests/test_docker_ransomware_scenario.py``.
"""

import json

import pytest

from sandbox.backends.local import LocalBackend
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.events import EventType
from sandbox.manager import SandboxManager
from scenario_adapters.ransomware import (IMPACT_PROGRESSION, INITIAL_IMPACT,
                                          RANSOMWARE_CHOICE_IDS,
                                          RANSOMWARE_SCENARIO_KEY,
                                          REQUIRED_BACKEND)
from tests.conftest import csrf_for
from training_service import SUCCESS_EVENT_ORDER

TRAINING_EVENTS = frozenset(SUCCESS_EVENT_ORDER) | {
    EventType.TRAINING_EXECUTION_FAILED}

#: Legacy marketplace ransomware events. The new flow must not emit these.
LEGACY_RANSOMWARE_EVENTS = frozenset({
    EventType.SCENARIO_STARTED, EventType.SCENARIO_COMPLETED,
    EventType.SCENARIO_FAILED, EventType.FILE_IMPACT,
    EventType.FILE_IMPACT_STARTED, EventType.FILE_IMPACT_COMPLETED,
    EventType.FILE_IMPACT_REJECTED,
})

HOME = "/training"
BRIEF = "/training/ransomware"
START = "/training/ransomware/start"
WORKSTATION = "/training/ransomware/workstation"
DECISION = "/training/ransomware/decision"
OUTCOME = "/training/ransomware/outcome"
REWIND = "/training/ransomware/rewind"
RESULT = "/training/ransomware/result"


class ContainedFake(LocalBackend):
    """The local backend, presented as the contained backend.

    Deterministic and Docker-free, but every workspace operation is the real
    one, so the flow's digests, refusals and file states are genuine. Used only
    by the test suite: the application never constructs this.
    """

    name = REQUIRED_BACKEND
    isolation_summary = "Deterministic test double for the contained backend."

    def image_available(self):
        return True


@pytest.fixture
def contained(flask_app, tmp_path):
    """Pin the app's sandbox manager to the contained stand-in for one test."""
    import app as app_module
    previous = getattr(app_module.app, "_sandbox_manager", None)
    from sandbox_routes import make_recorder
    manager = SandboxManager(
        ContainedFake(str(tmp_path / "contained")),
        recorder=make_recorder(app_module.db, app_module.SecurityEvent),
        default_sandbox_id=None)
    app_module.app._sandbox_manager = manager
    yield manager
    app_module.app._sandbox_manager = previous


@pytest.fixture
def uncontained(flask_app):
    """Leave the app on its real (local, non-contained) backend."""
    import app as app_module
    previous = getattr(app_module.app, "_sandbox_manager", None)
    app_module.app._sandbox_manager = None
    yield
    app_module.app._sandbox_manager = previous


# -- helpers ----------------------------------------------------------------
def post(client, path, form_page, **fields):
    fields["csrf_token"] = csrf_for(client, form_page)
    return client.post(path, data=fields)


def start(client):
    return post(client, START, BRIEF)


def respond(client, choice_id, confidence=50):
    client.get(WORKSTATION)
    return post(client, DECISION, WORKSTATION, choice_id=choice_id,
                confidence=str(confidence))


def rewind(client, choice_id, confidence=50):
    client.get(OUTCOME)
    return post(client, REWIND, OUTCOME, choice_id=choice_id,
                confidence=str(confidence))


def session_id_of(client):
    with client.session_transaction() as sess:
        return sess.get("session_id")


def rw_session(client):
    with client.session_transaction() as sess:
        return dict(sess.get("rewindsec_training_ransomware") or {})


def executions(flask_app, session_id, scenario_key=RANSOMWARE_SCENARIO_KEY):
    import app as app_module
    with flask_app.app_context():
        return (app_module.TrainingExecution.query
                .filter_by(session_id=session_id, scenario_key=scenario_key)
                .order_by(app_module.TrainingExecution.id.asc()).all())


def all_events(flask_app, session_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.SecurityEvent.query
                .filter_by(session_id=session_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())


def training_event_types(flask_app, session_id):
    return [row.event_type for row in all_events(flask_app, session_id)
            if row.event_type in TRAINING_EVENTS]


def run_full_flow(flask_app, client, factual="continue_working",
                  counterfactual="isolate_and_report",
                  factual_confidence=78, counterfactual_confidence=93):
    start(client)
    respond(client, factual, factual_confidence)
    rewind(client, counterfactual, counterfactual_confidence)
    return client.get(RESULT)


def counts_of(state):
    return state["files"]["impacted_count"], state["files"]["available_count"]


# -- P/Q/R/S: entry point and the containment requirement -------------------
def test_ransomware_briefing_loads(contained, client):
    """P: the module has its own briefing under the training blueprint."""
    page = client.get(BRIEF)
    assert page.status_code == 200
    body = page.data.decode()
    assert "Ransomware Incident Response" in body
    assert 'action="/training/ransomware/start"' in body


def test_module_needs_no_marketplace_navigation(contained, client):
    """Q: nothing in the flow routes through the legacy demo."""
    for path in (HOME, BRIEF):
        body = client.get(path).data.decode()
        for legacy in ("/ransomware/menu", "/marketplace", "/products",
                       "/download", "Bitcoin", "countdown", "ransom note",
                       "decrypt", "LockBit", "WannaCry"):
            assert legacy not in body


def test_docker_unavailable_state_is_explicit(uncontained, client):
    """R: the unavailable state says so, on the home page and the module."""
    home = client.get(HOME).data.decode()
    assert "Unavailable here" in home
    assert "contained Docker sandbox" in home

    brief = client.get(BRIEF)
    assert brief.status_code == 200
    assert "currently unavailable" in brief.data.decode()


def test_docker_unavailable_flow_never_silently_uses_the_local_backend(
        uncontained, flask_app, client):
    """S: every state-changing route refuses, and nothing is executed."""
    # The unavailable briefing deliberately renders no start form, so the
    # token is taken from another page of the same session.
    token = csrf_for(client)
    response = client.post(START, data={"csrf_token": token})
    assert response.status_code == 503
    assert "unavailable" in response.data.decode().lower()

    for path, fields in ((DECISION, {"choice_id": "continue_working",
                                     "confidence": "50"}),
                         (REWIND, {"choice_id": "isolate_and_report",
                                   "confidence": "50"})):
        refused = client.post(path, data=dict(fields, csrf_token=token))
        assert refused.status_code in (302, 303, 503)
    assert executions(flask_app, session_id_of(client)) == []
    assert training_event_types(flask_app, session_id_of(client)) == []


# -- T: the sandbox is session-scoped ---------------------------------------
def test_start_uses_the_session_scoped_sandbox_id(contained, client):
    """T: the id is derived from the session, never supplied."""
    from sandbox.session_scope import sandbox_id_for_session
    start(client)
    expected = sandbox_id_for_session(session_id_of(client))
    assert contained.list_sandboxes() == [expected]
    # Nothing in the flow exposes it.
    for path in (BRIEF, WORKSTATION):
        assert expected not in client.get(path).data.decode()


# -- U/V/W/X/Y: the decision page -------------------------------------------
def test_workstation_shows_one_impacted_and_four_available(contained, client):
    """U: from observed state, not from a separately faked file list."""
    start(client)
    page = client.get(WORKSTATION)
    assert page.status_code == 200
    body = page.data.decode()
    assert "1 of 5 synthetic files impacted" in body
    assert "4 synthetic files still available" in body
    assert "Unusual file activity detected" in body
    for name in BASELINE_FILENAMES:
        assert name in body
    # The impacted one is the predetermined file, and it is the only one.
    assert body.count("No longer available") == 1
    assert body.count("Available</td>") == 4

    observed = {row["name"]: row["status"]
                for row in contained.workspace_state(
                    __import__("sandbox.session_scope", fromlist=["x"])
                    .sandbox_id_for_session(session_id_of(client)))}
    assert observed[INITIAL_IMPACT] == "impacted"


def test_workstation_offers_exactly_the_supported_choices(contained, client):
    """V: four responses, no more, no fewer."""
    start(client)
    body = client.get(WORKSTATION).data.decode()
    for choice_id in RANSOMWARE_CHOICE_IDS:
        assert 'value="%s"' % choice_id in body
    assert body.count('name="choice_id"') == len(RANSOMWARE_CHOICE_IDS) == 4
    # And no verdict language anywhere on the page.
    for word in ("correct", "incorrect", "wrong answer", "safe choice",
                 "unsafe choice"):
        assert word not in body.lower()


@pytest.mark.parametrize("choice_id", ["", "delete_everything", "employee_records.csv",
                                       "../../etc/passwd"])
def test_unsupported_response_is_rejected_server_side(contained, flask_app,
                                                      client, choice_id):
    """W / AR: no arbitrary target or path is accepted over HTTP."""
    start(client)
    response = respond(client, choice_id, 50)
    assert response.status_code == 400
    assert rw_session(client)["factual_choice"] is None
    assert executions(flask_app, session_id_of(client)) == []


@pytest.mark.parametrize("confidence", [0, 100])
def test_boundary_confidence_values_are_accepted(contained, client, confidence):
    """X."""
    start(client)
    assert respond(client, "restart_workstation",
                   confidence).status_code in (302, 303)
    assert rw_session(client)["factual_confidence"] == confidence


@pytest.mark.parametrize("raw", ["", "  ", "50.0", "-1", "101", "abc", "٥٠",
                                 "1e2", "0x10"])
def test_malformed_confidence_is_rejected_server_side(contained, client, raw):
    """Y."""
    start(client)
    client.get(WORKSTATION)
    response = post(client, DECISION, WORKSTATION,
                    choice_id="restart_workstation", confidence=raw)
    assert response.status_code == 400
    assert rw_session(client)["factual_choice"] is None


# -- Z/AA/AB: the factual preview -------------------------------------------
def test_factual_preview_executes_exactly_once(contained, client):
    """Z: one response, one application of the authored progression."""
    start(client)
    respond(client, "restart_workstation", 60)
    state = rw_session(client)
    assert state["preview_digest"]
    assert counts_of(json.loads(state["preview_state_json"])) == (3, 2)
    # A resubmitted decision does not apply a second response.
    again = post(client, DECISION, OUTCOME, choice_id="continue_working",
                 confidence="90")
    assert again.status_code in (302, 303)
    assert again.headers["Location"].endswith("/outcome")
    assert rw_session(client)["preview_digest"] == state["preview_digest"]
    assert counts_of(json.loads(
        rw_session(client)["preview_state_json"])) == (3, 2)


def test_refreshing_the_factual_outcome_does_not_execute_impact_again(
        contained, client):
    """AA."""
    start(client)
    respond(client, "report_without_isolating", 55)
    first = client.get(OUTCOME)
    assert first.status_code == 200
    digest = rw_session(client)["preview_digest"]
    for _ in range(3):
        page = client.get(OUTCOME)
        assert page.status_code == 200
        assert "2 of 5 synthetic files impacted" in page.data.decode()
    assert rw_session(client)["preview_digest"] == digest


def test_outcome_page_renders_the_adapter_captured_preview_state(contained,
                                                                 client):
    """AB: the page shows observed state, not a count inferred from a choice."""
    start(client)
    respond(client, "continue_working", 70)
    body = client.get(OUTCOME).data.decode()
    assert "5 of 5 synthetic files impacted" in body
    assert "0 synthetic files still available" in body
    assert "The workstation stayed connected to the network" in body
    assert "The incident was not reported" in body
    preview = json.loads(rw_session(client)["preview_state_json"])
    assert counts_of(preview) == (5, 0)
    assert preview["files"]["impacted"] == list(IMPACT_PROGRESSION)


# -- AC/AD/AE/AF: the paired execution --------------------------------------
def test_alternative_must_differ_from_the_factual_response(contained,
                                                           flask_app, client):
    """AC."""
    start(client)
    respond(client, "isolate_and_report", 60)
    assert rewind(client, "isolate_and_report", 60).status_code == 400
    assert rewind(client, "not_a_choice", 60).status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_successful_rewind_produces_exactly_one_execution(contained,
                                                          flask_app, client):
    """AD."""
    assert run_full_flow(flask_app, client).status_code == 200
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    assert rows[0].status == "completed"
    assert rows[0].scenario_key == RANSOMWARE_SCENARIO_KEY
    assert rows[0].scenario_version == 1
    assert rows[0].decision_id == "respond_to_file_impact"


def test_baseline_digest_equals_rewound_digest(contained, flask_app, client):
    """AE."""
    run_full_flow(flask_app, client)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.baseline_digest
    assert row.baseline_digest == row.rewound_digest
    assert row.baseline_verified


def test_persisted_factual_digest_equals_the_preview_digest(contained,
                                                            flask_app, client):
    """AF: what the learner saw is what the authoritative run recorded."""
    start(client)
    respond(client, "restart_workstation", 61)
    preview_digest = rw_session(client)["preview_digest"]
    rewind(client, "isolate_and_report", 88)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_result_digest == preview_digest


# -- AG/AH: the preview consistency check fails closed ----------------------
def test_preview_mismatch_fails_closed(contained, flask_app, client):
    """AG/AH: a mismatch leaves no completed execution."""
    start(client)
    respond(client, "restart_workstation", 61)
    # Corrupt only the recorded preview digest: the authoritative run will
    # reproduce the real one and the two will disagree.
    with client.session_transaction() as sess:
        state = dict(sess["rewindsec_training_ransomware"])
        state["preview_digest"] = "0" * 64
        sess["rewindsec_training_ransomware"] = state

    response = rewind(client, "isolate_and_report", 88)
    assert response.status_code == 500
    assert "could not be executed" in response.data.decode()

    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    assert rows[0].status == "failed"
    assert rows[0].failure_type == "StagedExecutionMismatchError"
    assert rows[0].completed_at is not None
    # Nothing is rendered as a completed comparison.
    assert client.get(RESULT).status_code in (302, 303, 409)
    emitted = training_event_types(flask_app, session_id_of(client))
    assert EventType.TRAINING_EXECUTION_COMPLETED not in emitted
    assert emitted[-1] == EventType.TRAINING_EXECUTION_FAILED


def test_baseline_mismatch_also_fails_closed(contained, flask_app, client):
    start(client)
    respond(client, "restart_workstation", 61)
    with client.session_transaction() as sess:
        state = dict(sess["rewindsec_training_ransomware"])
        state["baseline_digest"] = "f" * 64
        sess["rewindsec_training_ransomware"] = state
    assert rewind(client, "isolate_and_report", 88).status_code == 500
    rows = executions(flask_app, session_id_of(client))
    assert [row.status for row in rows] == ["failed"]


# -- AI/AJ/AK: branch order and the rendered result -------------------------
def test_factual_branch_stays_the_learners_actual_first_response(
        contained, flask_app, client):
    """AI/AJ: no silent swapping, in either direction."""
    run_full_flow(flask_app, client, factual="isolate_and_report",
                  counterfactual="continue_working")
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_choice_id == "isolate_and_report"
    assert row.counterfactual_choice_id == "continue_working"
    factual = json.loads(row.factual_state_json)
    counterfactual = json.loads(row.counterfactual_state_json)
    assert counts_of(factual) == (1, 4)
    assert counts_of(counterfactual) == (5, 0)
    assert factual["endpoint"]["isolated"] is True
    assert factual["incident"]["reported"] is True
    assert counterfactual["endpoint"]["isolated"] is False


def test_result_page_renders_from_the_persisted_execution(contained,
                                                          flask_app, client):
    """AK."""
    result = run_full_flow(flask_app, client, factual="continue_working",
                           counterfactual="isolate_and_report")
    body = result.data.decode()
    row = executions(flask_app, session_id_of(client))[0]
    assert row.execution_id in body and row.pair_id in body
    # Your path is the learner's actual first response, on the left.
    assert body.index("Your path") < body.index("Rewind path")
    assert body.index("Keep working") < body.index("Isolate the workstation")
    assert "5 of 5 synthetic files impacted" in body
    assert "1 of 5 synthetic files impacted" in body
    assert "The workstation was isolated from the network" in body
    assert "Verified" in body
    # Deterministic presentation only: no raw JSON reaches the learner.
    assert "impacted_count" not in body
    assert "{&#34;" not in body and '{"' not in body


def test_result_page_shows_the_learner_order_not_a_fixed_severity_order(
        contained, flask_app, client):
    body = run_full_flow(flask_app, client, factual="isolate_and_report",
                         counterfactual="continue_working").data.decode()
    assert body.index("Isolate the workstation") < body.index("Keep working")


# -- AL/AM/AN/AO: refresh, ordering and legacy separation -------------------
def test_result_refresh_creates_no_new_execution_or_events(contained,
                                                           flask_app, client):
    """AL/AM."""
    run_full_flow(flask_app, client)
    sid = session_id_of(client)
    before_rows = len(executions(flask_app, sid))
    before_events = training_event_types(flask_app, sid)
    for _ in range(3):
        assert client.get(RESULT).status_code == 200
    assert len(executions(flask_app, sid)) == before_rows == 1
    assert training_event_types(flask_app, sid) == before_events


def test_resubmitting_the_rewind_does_not_create_a_second_execution(
        contained, flask_app, client):
    start(client)
    respond(client, "continue_working", 78)
    rewind(client, "isolate_and_report", 93)
    again = post(client, REWIND, RESULT, choice_id="restart_workstation",
                 confidence="10")
    assert again.status_code in (302, 303)
    assert again.headers["Location"].endswith("/result")
    assert len(executions(flask_app, session_id_of(client))) == 1


def test_standard_training_event_order_is_preserved(contained, flask_app,
                                                    client):
    """AN."""
    run_full_flow(flask_app, client)
    assert training_event_types(
        flask_app, session_id_of(client)) == list(SUCCESS_EVENT_ORDER)


def test_new_flow_emits_no_legacy_ransomware_progression_events(
        contained, flask_app, client):
    """AO: no SCENARIO_* / FILE_IMPACT_* duplication from the training flow."""
    run_full_flow(flask_app, client)
    emitted = {event.event_type
               for event in all_events(flask_app, session_id_of(client))}
    assert not emitted & LEGACY_RANSOMWARE_EVENTS
    # Low-level sandbox lifecycle events may legitimately coexist.
    assert emitted <= (frozenset(SUCCESS_EVENT_ORDER)
                       | {EventType.SANDBOX_CREATED, EventType.SANDBOX_RESET,
                          EventType.SANDBOX_DESTROYED})


def test_training_events_carry_only_bounded_metadata(contained, flask_app,
                                                     client):
    run_full_flow(flask_app, client)
    for event in all_events(flask_app, session_id_of(client)):
        if event.event_type in TRAINING_EVENTS:
            assert event.source == "training:counterfactual"
            assert event.scenario_id.startswith("exec-")
        if event.details:
            assert len(event.details) <= 400


# -- AP: session isolation ---------------------------------------------------
def test_one_session_cannot_reach_another_sessions_sandbox_or_result(
        contained, flask_app, client, other_client):
    """AP."""
    from sandbox.session_scope import sandbox_id_for_session
    run_full_flow(flask_app, client)
    mine = sandbox_id_for_session(session_id_of(client))

    # The second learner has no attempt, so no result and no outcome.
    assert other_client.get(RESULT).headers["Location"].endswith("/ransomware")
    assert other_client.get(OUTCOME).headers["Location"].endswith("/ransomware")
    assert other_client.get(WORKSTATION).headers["Location"].endswith(
        "/ransomware")

    # Starting their own attempt creates a *separate* sandbox and leaves the
    # first learner's row untouched.
    start(other_client)
    theirs = sandbox_id_for_session(session_id_of(other_client))
    assert theirs != mine
    assert sorted(contained.list_sandboxes()) == sorted([mine, theirs])
    assert len(executions(flask_app, session_id_of(client))) == 1
    assert executions(flask_app, session_id_of(other_client)) == []


def test_no_route_accepts_a_sandbox_id_from_request_data(contained, flask_app,
                                                         client):
    """AR: there is no parameter through which a sandbox could be named."""
    from sandbox.session_scope import sandbox_id_for_session
    start(client)
    mine = sandbox_id_for_session(session_id_of(client))
    client.get(WORKSTATION)
    post(client, DECISION, WORKSTATION, choice_id="restart_workstation",
         confidence="50", sandbox_id="sess-deadbeefdeadbeef",
         target="../../etc/passwd")
    # The learner's own sandbox is the only one that exists, and the impact
    # landed only on allow-listed synthetic files.
    assert contained.list_sandboxes() == [mine]
    observed = {row["name"]: row["status"]
                for row in contained.workspace_state(mine)}
    assert set(observed) == set(BASELINE_FILENAMES)
    assert sorted(k for k, v in observed.items() if v == "impacted") == sorted(
        IMPACT_PROGRESSION[:3])


# -- AQ: CSRF ----------------------------------------------------------------
@pytest.mark.parametrize("path,fields", [
    (START, {}),
    (DECISION, {"choice_id": "continue_working", "confidence": "50"}),
    (REWIND, {"choice_id": "isolate_and_report", "confidence": "50"}),
])
def test_state_changing_posts_require_csrf(contained, flask_app, client, path,
                                           fields):
    """AQ."""
    start(client)
    respond(client, "restart_workstation", 50)
    assert client.post(path, data=fields).status_code == 400
    assert client.post(path, data=dict(fields, csrf_token="not-the-token")
                       ).status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_no_state_changing_route_accepts_get(contained, client):
    for path in (START, DECISION, REWIND):
        assert client.get(path).status_code == 405


# -- AS/AT: what the record may contain -------------------------------------
def test_no_file_contents_or_host_paths_are_persisted(contained, flask_app,
                                                      client, tmp_path):
    """AS/AT."""
    from sandbox.dataset import SYNTHETIC_FILES
    run_full_flow(flask_app, client)
    sid = session_id_of(client)
    blobs = []
    for row in executions(flask_app, sid):
        blobs.append(" ".join(str(value) for value in (
            row.to_dict(), row.factual_state_json,
            row.counterfactual_state_json, row.difference_json)))
    for event in all_events(flask_app, sid):
        blobs.append(json.dumps(event.to_dict()))
    for blob in blobs:
        assert str(tmp_path) not in blob
        assert "demo_locked" not in blob
        assert "DWS-DEMO-STATE" not in blob
        assert "C:\\\\" not in blob and "/workspace" not in blob
        for content in SYNTHETIC_FILES.values():
            assert content.strip().splitlines()[0] not in blob


# -- explicit research tests (section 29) -----------------------------------
def test_ransomware_counterfactual_rewind_restores_same_one_impact_baseline(
        contained, flask_app, client):
    """Every state in the experiment originates from one S0.

    Proves: the baseline the learner was first shown, the baseline the factual
    preview ran from, the paired execution's baseline and the rewound baseline
    are all the same fingerprint -- and that fingerprint really is the
    one-impacted/four-available starting point.
    """
    start(client)
    visible = rw_session(client)
    baseline_digest = visible["baseline_digest"]
    assert counts_of(json.loads(visible["baseline_state_json"])) == (1, 4)

    # The workstation page re-observes the live workspace and is served only
    # because it still fingerprints as that same baseline.
    assert client.get(WORKSTATION).status_code == 200

    respond(client, "continue_working", 78)
    rewind(client, "isolate_and_report", 93)
    row = executions(flask_app, session_id_of(client))[0]

    assert row.baseline_digest == baseline_digest
    assert row.rewound_digest == baseline_digest
    assert row.baseline_verified
    # The counterfactual branch ran from the one-impact baseline, so isolating
    # leaves exactly the file that was already gone.
    assert counts_of(json.loads(row.counterfactual_state_json)) == (1, 4)
    assert json.loads(row.counterfactual_state_json)["files"]["impacted"] == [
        INITIAL_IMPACT]


def test_ransomware_factual_preview_matches_authoritative_pair_factual_digest(
        contained, flask_app, client):
    for factual, counterfactual in (("continue_working", "isolate_and_report"),
                                    ("isolate_and_report", "continue_working"),
                                    ("restart_workstation",
                                     "report_without_isolating")):
        start(client)
        respond(client, factual, 70)
        preview = rw_session(client)
        rewind(client, counterfactual, 70)
        row = executions(flask_app, session_id_of(client))[-1]
        assert row.factual_choice_id == factual
        assert row.factual_result_digest == preview["preview_digest"]
        assert (json.loads(row.factual_state_json)
                == json.loads(preview["preview_state_json"]))


def test_ransomware_result_refresh_never_reexecutes_file_impact(
        contained, flask_app, client):
    from sandbox.session_scope import sandbox_id_for_session
    run_full_flow(flask_app, client, factual="isolate_and_report",
                  counterfactual="restart_workstation")
    sandbox = sandbox_id_for_session(session_id_of(client))
    before = contained.workspace_state(sandbox)
    events_before = len(all_events(flask_app, session_id_of(client)))
    for _ in range(3):
        assert client.get(RESULT).status_code == 200
    assert contained.workspace_state(sandbox) == before
    assert len(all_events(flask_app, session_id_of(client))) == events_before
    assert len(executions(flask_app, session_id_of(client))) == 1


def test_ransomware_training_never_impacts_non_baseline_files(
        contained, flask_app, client, tmp_path):
    """Only the fixed synthetic dataset is ever touched."""
    from sandbox.session_scope import sandbox_id_for_session
    import os
    run_full_flow(flask_app, client, factual="continue_working",
                  counterfactual="report_without_isolating")
    sandbox = sandbox_id_for_session(session_id_of(client))
    workspace = os.path.join(str(tmp_path / "contained"), sandbox, "workspace")
    present = sorted(os.listdir(workspace))
    allowed = set(BASELINE_FILENAMES) | {
        name + ".demo_locked" for name in BASELINE_FILENAMES}
    assert set(present) <= allowed
    # Every impacted entry corresponds to an allow-listed synthetic filename.
    for entry in present:
        assert entry.replace(".demo_locked", "") in BASELINE_FILENAMES
