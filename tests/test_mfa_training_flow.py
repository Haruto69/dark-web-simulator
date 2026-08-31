"""End-to-end tests for the RewindSec MFA fatigue training flow (R5).

These drive the complete learner workflow through the real Flask app, the real
R1 runtime and the real R2 service: briefing -> prompt -> response -> factual
preview -> rewind -> executed comparison -> persisted result.

No Docker daemon and no sandbox are involved anywhere in this module: the MFA
consequence environment is a deterministic in-memory state machine, and the
flow must not reach ``SandboxManager`` at all.
"""

import json

import pytest

from sandbox.events import EventType
from scenario_adapters.mfa import (MFA_CHOICE_IDS, MFA_DECISION_ID,
                                   MFA_SCENARIO_KEY)
from tests.conftest import csrf_for
from training_service import SUCCESS_EVENT_ORDER

TRAINING_EVENTS = frozenset(SUCCESS_EVENT_ORDER) | {
    EventType.TRAINING_EXECUTION_FAILED}

HOME = "/training"
BRIEF = "/training/mfa"
START = "/training/mfa/start"
PROMPT = "/training/mfa/prompt"
DECISION = "/training/mfa/decision"
OUTCOME = "/training/mfa/outcome"
REWIND = "/training/mfa/rewind"
RESULT = "/training/mfa/result"

SESSION_KEY = "rewindsec_training_mfa"


# -- helpers ----------------------------------------------------------------
def post(client, path, form_page, **fields):
    fields.setdefault("csrf_token", csrf_for(client, form_page))
    return client.post(path, data=fields)


def start(client):
    return post(client, START, BRIEF)


def respond(client, choice_id, confidence=50):
    client.get(PROMPT)
    return post(client, DECISION, PROMPT, choice_id=choice_id,
                confidence=str(confidence))


def rewind(client, choice_id, confidence=50):
    client.get(OUTCOME)
    return post(client, REWIND, OUTCOME, choice_id=choice_id,
                confidence=str(confidence))


def full_run(client, factual, counterfactual):
    start(client)
    respond(client, factual)
    rewind(client, counterfactual)
    return client.get(RESULT)


def flow_session(client):
    with client.session_transaction() as sess:
        return dict(sess.get(SESSION_KEY) or {})


def session_id_of(client):
    with client.session_transaction() as sess:
        return sess.get("session_id")


def executions(flask_app, session_id, scenario_key=MFA_SCENARIO_KEY):
    import app as app_module
    with flask_app.app_context():
        return (app_module.TrainingExecution.query
                .filter_by(session_id=session_id, scenario_key=scenario_key)
                .order_by(app_module.TrainingExecution.id.asc()).all())


def training_events(flask_app, session_id):
    import app as app_module
    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(session_id=session_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())
    return [r for r in rows if r.event_type in TRAINING_EVENTS]


# -- AA/AB/AC. the pages ----------------------------------------------------
def test_briefing_loads(client):
    page = client.get(BRIEF)
    assert page.status_code == 200
    assert b"MFA Fatigue" in page.data


def test_home_offers_the_module_without_any_containment_check(client):
    page = client.get(HOME)
    assert page.status_code == 200
    assert b"MFA Fatigue" in page.data
    assert BRIEF.encode() in page.data


def test_the_module_needs_no_sandbox_manager(flask_app, client):
    """AB/BY. Removing the sandbox entirely leaves the flow fully working."""
    import app as app_module
    previous = getattr(app_module.app, "_sandbox_manager", None)
    app_module.app._sandbox_manager = None
    try:
        assert client.get(BRIEF).status_code == 200
        assert full_run(client, "approve_request",
                        "deny_and_report").status_code == 200
    finally:
        app_module.app._sandbox_manager = previous


def test_the_prompt_renders_the_four_stable_choices(client):
    start(client)
    page = client.get(PROMPT)
    assert page.status_code == 200
    for choice_id in MFA_CHOICE_IDS:
        assert ('value="%s"' % choice_id).encode() in page.data
    assert b"Northgate Identity" in page.data
    # An authenticator-style card, not a real vendor's interface.
    for vendor in (b"Microsoft", b"Google", b"Duo", b"Okta"):
        assert vendor not in page.data


def test_the_prompt_carries_a_live_confidence_readout(client):
    start(client)
    page = client.get(PROMPT)
    assert b'id="confidence-readout"' in page.data
    assert b'type="range"' in page.data


# -- AD..AF. server-side validation -----------------------------------------
@pytest.mark.parametrize("choice_id", [
    "", "not_a_choice", "isolate_and_report", "authorize_payment",
    "approve_request_x"])
def test_a_malformed_choice_is_refused(client, flask_app, choice_id):
    start(client)
    client.get(PROMPT)
    response = post(client, DECISION, PROMPT, choice_id=choice_id,
                    confidence="50")
    assert response.status_code == 400
    assert flow_session(client)["factual_choice"] is None
    assert executions(flask_app, session_id_of(client)) == []


@pytest.mark.parametrize("confidence", ["0", "100"])
def test_boundary_confidence_values_are_accepted(client, confidence):
    start(client)
    assert respond(client, "approve_request",
                   confidence).status_code in (302, 303)
    assert flow_session(client)["factual_confidence"] == int(confidence)


@pytest.mark.parametrize("confidence", ["", "-1", "101", "50.5", "abc",
                                        " 50", "٥٠", "1000"])
def test_a_malformed_confidence_is_refused(client, confidence):
    start(client)
    client.get(PROMPT)
    response = post(client, DECISION, PROMPT, choice_id="approve_request",
                    confidence=confidence)
    assert response.status_code == 400
    assert flow_session(client)["factual_choice"] is None


# -- AG/AH. the factual preview ---------------------------------------------
def test_the_factual_preview_executes_once_and_is_shown(client):
    start(client)
    respond(client, "approve_request")
    state = flow_session(client)
    assert state["preview_digest"]
    preview = json.loads(state["preview_state_json"])
    assert preview["account"]["synthetic_session_created"] is True
    page = client.get(OUTCOME)
    assert page.status_code == 200
    assert b"synthetic signed-in session was created" in page.data


def test_refreshing_the_outcome_does_not_reapply_the_consequence(client):
    start(client)
    respond(client, "approve_request")
    before = flow_session(client)
    for _ in range(3):
        assert client.get(OUTCOME).status_code == 200
    after = flow_session(client)
    assert after["preview_digest"] == before["preview_digest"]
    assert after["preview_state_json"] == before["preview_state_json"]


def test_resubmitting_the_decision_does_not_apply_a_second_response(client):
    start(client)
    respond(client, "approve_request")
    first = flow_session(client)
    response = post(client, DECISION, OUTCOME, choice_id="deny_and_report",
                    confidence="90")
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/outcome")
    after = flow_session(client)
    for key in ("factual_choice", "factual_confidence", "preview_digest",
                "preview_state_json", "baseline_digest"):
        assert after[key] == first[key]


# -- AI..AL. the executed pair ----------------------------------------------
def test_the_counterfactual_must_differ_from_the_factual_choice(client,
                                                                flask_app):
    start(client)
    respond(client, "approve_request")
    client.get(OUTCOME)
    response = post(client, REWIND, OUTCOME, choice_id="approve_request",
                    confidence="50")
    assert response.status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_one_completed_execution_with_verified_identical_baseline(client,
                                                                  flask_app):
    full_run(client, "approve_request", "deny_and_report")
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "completed"
    assert row.scenario_key == MFA_SCENARIO_KEY
    assert row.scenario_version == 1
    assert row.decision_id == MFA_DECISION_ID
    assert row.baseline_digest == row.rewound_digest
    assert row.pair_id


def test_mfa_rewind_executes_both_responses_from_verified_identical_baseline(
        client, flask_app):
    """The research invariant, stated as its own named test."""
    full_run(client, "approve_request", "deny_and_report")
    row = executions(flask_app, session_id_of(client))[0]
    session_baseline = flow_session(client)["baseline_digest"]
    assert session_baseline == row.baseline_digest == row.rewound_digest
    factual = json.loads(row.factual_state_json)
    counterfactual = json.loads(row.counterfactual_state_json)
    assert factual["account"]["synthetic_session_created"] is True
    assert counterfactual["account"]["synthetic_session_created"] is False
    assert row.factual_result_digest != row.counterfactual_result_digest


def test_mfa_factual_preview_matches_authoritative_pair(client, flask_app):
    """AL. What the learner was shown is what the stored comparison holds."""
    start(client)
    respond(client, "approve_request", 80)
    preview = flow_session(client)
    rewind(client, "verify_through_known_channel", 20)
    row = executions(flask_app, session_id_of(client))[0]
    assert preview["preview_digest"] == row.factual_result_digest
    assert preview["preview_state_json"] == row.factual_state_json
    assert preview["baseline_digest"] == row.baseline_digest


# -- AM. branch order --------------------------------------------------------
@pytest.mark.parametrize("factual,counterfactual", [
    ("approve_request", "deny_and_report"),
    ("deny_and_report", "approve_request"),
    ("review_signin_details", "verify_through_known_channel"),
])
def test_the_branch_order_is_the_learners_own(client, flask_app, factual,
                                              counterfactual):
    full_run(client, factual, counterfactual)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_choice_id == factual
    assert row.counterfactual_choice_id == counterfactual


def test_confidence_and_latency_are_recorded_per_branch(client, flask_app):
    start(client)
    respond(client, "deny_and_report", 90)
    rewind(client, "approve_request", 10)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_confidence == 90
    assert row.counterfactual_confidence == 10
    for value in (row.factual_response_time_ms,
                  row.counterfactual_response_time_ms):
        assert isinstance(value, int) and 0 <= value < 60 * 60 * 1000


# -- AN/AO. the result page --------------------------------------------------
def test_the_result_renders_the_persisted_state(client, flask_app):
    page = full_run(client, "approve_request", "deny_and_report")
    assert page.status_code == 200
    row = executions(flask_app, session_id_of(client))[0]
    assert row.execution_id.encode() in page.data
    assert b"Approve the sign-in request" in page.data
    assert b"Deny the request and report it" in page.data
    assert b"synthetic signed-in session was created" in page.data
    assert b"No session was created" in page.data
    # No raw state JSON reaches the learner.
    assert b"synthetic_session_created" not in page.data
    assert b"request_pending" not in page.data


def test_mfa_result_refresh_does_not_reexecute_pair(client, flask_app):
    full_run(client, "approve_request", "deny_and_report")
    session_id = session_id_of(client)
    before_rows = executions(flask_app, session_id)
    before_events = training_events(flask_app, session_id)
    for _ in range(3):
        assert client.get(RESULT).status_code == 200
    after_rows = executions(flask_app, session_id)
    assert [r.execution_id for r in after_rows] == [
        r.execution_id for r in before_rows]
    assert len(training_events(flask_app, session_id)) == len(before_events)


def test_a_repeated_rewind_post_returns_the_existing_result(client, flask_app):
    full_run(client, "approve_request", "deny_and_report")
    session_id = session_id_of(client)
    response = post(client, REWIND, RESULT, choice_id="review_signin_details",
                    confidence="10")
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/result")
    assert len(executions(flask_app, session_id)) == 1


# -- AP/AQ. telemetry --------------------------------------------------------
def test_exactly_six_training_events_in_the_expected_order(client, flask_app):
    full_run(client, "approve_request", "deny_and_report")
    events = training_events(flask_app, session_id_of(client))
    assert [e.event_type for e in events] == list(SUCCESS_EVENT_ORDER)
    row = executions(flask_app, session_id_of(client))[0]
    for event in events:
        assert event.scenario_id == row.execution_id


def test_no_mfa_specific_event_family_is_introduced(flask_app, client):
    full_run(client, "approve_request", "deny_and_report")
    import app as app_module
    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(session_id=session_id_of(client)).all())
    for row in rows:
        assert not row.event_type.startswith("MFA_")
    assert not [name for name in dir(EventType) if name.startswith("MFA_")]


# -- AR. session isolation ---------------------------------------------------
def test_one_session_cannot_reach_another_sessions_result(client,
                                                          other_client,
                                                          flask_app):
    full_run(client, "approve_request", "deny_and_report")
    owner = executions(flask_app, session_id_of(client))[0]

    # A second browser has no attempt at all: the result redirects to the
    # briefing rather than showing someone else's comparison.
    response = other_client.get(RESULT)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/mfa")

    # Even after planting the owner's execution id, the row's session_id no
    # longer matches, so it is not served.
    with other_client.session_transaction() as sess:
        sess[SESSION_KEY] = {"execution_id": owner.execution_id}
    response = other_client.get(RESULT)
    assert response.status_code in (302, 303)
    assert owner.execution_id.encode() not in response.data


def test_a_second_sessions_attempt_does_not_disturb_the_first(client,
                                                              other_client,
                                                              flask_app):
    start(client)
    respond(client, "approve_request", 70)
    mine = flow_session(client)

    full_run(other_client, "deny_and_report", "approve_request")

    assert flow_session(client) == mine
    page = client.get(OUTCOME)
    assert page.status_code == 200
    rewind(client, "deny_and_report", 30)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_choice_id == "approve_request"
    assert row.session_id == session_id_of(client)


# -- AS. CSRF ----------------------------------------------------------------
@pytest.mark.parametrize("path", [START, DECISION, REWIND])
def test_state_changing_posts_require_csrf(client, flask_app, path):
    start(client)
    respond(client, "approve_request")
    response = client.post(path, data={"choice_id": "deny_and_report",
                                       "confidence": "50"})
    assert response.status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


# -- AT. explicit restart ----------------------------------------------------
def test_restart_creates_a_new_execution_with_a_reproducible_pair_id(
        client, flask_app):
    full_run(client, "approve_request", "deny_and_report")
    first = executions(flask_app, session_id_of(client))[0]

    full_run(client, "approve_request", "deny_and_report")
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 2
    second = rows[1]
    # A deliberate restart is a new invocation...
    assert second.execution_id != first.execution_id
    # ...but the same experiment: the pair id is derived from the scenario,
    # decision, both choices, the baseline and the session reference.
    assert second.pair_id == first.pair_id
    assert second.baseline_digest == first.baseline_digest


def test_a_different_comparison_gets_a_different_pair_id(client, flask_app):
    full_run(client, "approve_request", "deny_and_report")
    full_run(client, "approve_request", "review_signin_details")
    rows = executions(flask_app, session_id_of(client))
    assert rows[0].pair_id != rows[1].pair_id


def test_only_a_post_can_start_or_restart(client):
    assert client.get(START).status_code == 405
