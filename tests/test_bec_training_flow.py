"""End-to-end tests for the RewindSec business email compromise flow (R5).

Briefing -> inbox -> response -> factual preview -> rewind -> executed
comparison -> persisted result, through the real Flask app, the real R1 runtime
and the real R2 service.

No Docker daemon and no sandbox are involved. Nor is any payment system: every
figure in the flow is an authored fixture, and the flow accepts no amount, no
account and no destination from the browser.
"""

import json

import pytest

from sandbox.events import EventType
from scenario_adapters.bec import (BEC_CHOICE_IDS, BEC_DECISION_ID,
                                   BEC_SCENARIO_KEY, SYNTHETIC_INVOICE_AMOUNT,
                                   SYNTHETIC_INVOICE_ID)
from tests.conftest import csrf_for
from training_service import SUCCESS_EVENT_ORDER

TRAINING_EVENTS = frozenset(SUCCESS_EVENT_ORDER) | {
    EventType.TRAINING_EXECUTION_FAILED}

HOME = "/training"
BRIEF = "/training/bec"
START = "/training/bec/start"
INBOX = "/training/bec/inbox"
DECISION = "/training/bec/decision"
OUTCOME = "/training/bec/outcome"
REWIND = "/training/bec/rewind"
RESULT = "/training/bec/result"

SESSION_KEY = "rewindsec_training_bec"


# -- helpers ----------------------------------------------------------------
def post(client, path, form_page, **fields):
    fields.setdefault("csrf_token", csrf_for(client, form_page))
    return client.post(path, data=fields)


def start(client):
    return post(client, START, BRIEF)


def respond(client, choice_id, confidence=50, **extra):
    client.get(INBOX)
    return post(client, DECISION, INBOX, choice_id=choice_id,
                confidence=str(confidence), **extra)


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


def executions(flask_app, session_id, scenario_key=BEC_SCENARIO_KEY):
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


# -- AU..AX. the pages -------------------------------------------------------
def test_briefing_loads(client):
    page = client.get(BRIEF)
    assert page.status_code == 200
    assert b"Business Email Compromise" in page.data


def test_home_offers_the_module(client):
    page = client.get(HOME)
    assert b"Business Email Compromise" in page.data
    assert BRIEF.encode() in page.data


def test_the_module_needs_no_sandbox_manager(flask_app, client):
    """BY. The flow works with the sandbox removed entirely."""
    import app as app_module
    previous = getattr(app_module.app, "_sandbox_manager", None)
    app_module.app._sandbox_manager = None
    try:
        assert client.get(BRIEF).status_code == 200
        assert full_run(client, "authorize_payment",
                        "verify_via_known_contact").status_code == 200
    finally:
        app_module.app._sandbox_manager = previous


def test_the_inbox_is_not_a_credential_form(client):
    """AV. The learning objective is payment verification, not sign-in."""
    start(client)
    page = client.get(INBOX)
    assert page.status_code == 200
    for forbidden in (b'type="password"', b'name="password"',
                      b'name="username"', b"Sign in", b"sign in"):
        assert forbidden not in page.data


def test_the_inbox_shows_only_the_fixed_synthetic_invoice(client):
    """AW/AY. Fixed fixtures, and no field through which one could be set."""
    start(client)
    page = client.get(INBOX)
    assert SYNTHETIC_INVOICE_ID.encode() in page.data
    assert b"18,450" in page.data
    assert b"Asterline Office Supplies" in page.data
    # The only inputs are the choice, the confidence slider and the CSRF token.
    for forbidden in (b'name="amount"', b'name="account"', b'name="iban"',
                      b'name="sort_code"', b'name="destination"',
                      b'name="recipient"'):
        assert forbidden not in page.data


def test_the_inbox_renders_the_four_stable_choices(client):
    start(client)
    page = client.get(INBOX)
    for choice_id in BEC_CHOICE_IDS:
        assert ('value="%s"' % choice_id).encode() in page.data


# -- AY/AZ. server-side validation ------------------------------------------
def test_extra_financial_form_fields_are_ignored(client, flask_app):
    """An attacker-supplied amount or destination changes nothing."""
    start(client)
    respond(client, "authorize_payment", 50, amount="999999",
            account="12345678", destination="attacker", synthetic_loss="1")
    preview = json.loads(flow_session(client)["preview_state_json"])
    assert preview["payment"]["synthetic_loss"] == SYNTHETIC_INVOICE_AMOUNT
    assert "destination" not in json.dumps(preview)


@pytest.mark.parametrize("choice_id", [
    "", "not_a_choice", "approve_request", "isolate_and_report"])
def test_a_malformed_choice_is_refused(client, flask_app, choice_id):
    start(client)
    client.get(INBOX)
    response = post(client, DECISION, INBOX, choice_id=choice_id,
                    confidence="50")
    assert response.status_code == 400
    assert flow_session(client)["factual_choice"] is None
    assert executions(flask_app, session_id_of(client)) == []


@pytest.mark.parametrize("confidence", ["0", "100"])
def test_boundary_confidence_values_are_accepted(client, confidence):
    start(client)
    assert respond(client, "authorize_payment",
                   confidence).status_code in (302, 303)
    assert flow_session(client)["factual_confidence"] == int(confidence)


@pytest.mark.parametrize("confidence", ["", "-1", "101", "7.5", "abc", " 50"])
def test_a_malformed_confidence_is_refused(client, confidence):
    start(client)
    client.get(INBOX)
    response = post(client, DECISION, INBOX, choice_id="authorize_payment",
                    confidence=confidence)
    assert response.status_code == 400
    assert flow_session(client)["factual_choice"] is None


# -- BA/BB. the factual preview ---------------------------------------------
def test_the_factual_preview_executes_once_and_is_shown(client):
    start(client)
    respond(client, "authorize_payment")
    preview = json.loads(flow_session(client)["preview_state_json"])
    assert preview["payment"]["authorized"] is True
    page = client.get(OUTCOME)
    assert page.status_code == 200
    assert b"Synthetic loss recorded" in page.data


def test_refreshing_the_outcome_does_not_reapply_the_consequence(client):
    start(client)
    respond(client, "authorize_payment")
    before = flow_session(client)
    for _ in range(3):
        assert client.get(OUTCOME).status_code == 200
    after = flow_session(client)
    assert after["preview_digest"] == before["preview_digest"]
    assert after["preview_state_json"] == before["preview_state_json"]


def test_resubmitting_the_decision_does_not_apply_a_second_response(client):
    start(client)
    respond(client, "authorize_payment")
    first = flow_session(client)
    response = post(client, DECISION, OUTCOME,
                    choice_id="escalate_to_finance_security", confidence="90")
    assert response.headers["Location"].endswith("/outcome")
    after = flow_session(client)
    for key in ("factual_choice", "preview_digest", "preview_state_json",
                "baseline_digest"):
        assert after[key] == first[key]


# -- BC..BF. the executed pair ----------------------------------------------
def test_the_counterfactual_must_differ(client, flask_app):
    start(client)
    respond(client, "authorize_payment")
    client.get(OUTCOME)
    response = post(client, REWIND, OUTCOME, choice_id="authorize_payment",
                    confidence="50")
    assert response.status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_one_completed_execution_with_verified_identical_baseline(client,
                                                                  flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "completed"
    assert row.scenario_key == BEC_SCENARIO_KEY
    assert row.scenario_version == 1
    assert row.decision_id == BEC_DECISION_ID
    assert row.baseline_digest == row.rewound_digest


def test_bec_rewind_executes_both_responses_from_verified_identical_baseline(
        client, flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    row = executions(flask_app, session_id_of(client))[0]
    assert flow_session(client)["baseline_digest"] == row.baseline_digest
    assert row.baseline_digest == row.rewound_digest
    factual = json.loads(row.factual_state_json)
    counterfactual = json.loads(row.counterfactual_state_json)
    assert factual["payment"]["authorized"] is True
    assert factual["payment"]["synthetic_loss"] == SYNTHETIC_INVOICE_AMOUNT
    assert counterfactual["payment"]["authorized"] is False
    assert counterfactual["payment"]["synthetic_loss"] == 0
    assert counterfactual["verification"]["change_confirmed"] is False


def test_bec_factual_preview_matches_authoritative_pair(client, flask_app):
    start(client)
    respond(client, "authorize_payment", 85)
    preview = flow_session(client)
    rewind(client, "escalate_to_finance_security", 40)
    row = executions(flask_app, session_id_of(client))[0]
    assert preview["preview_digest"] == row.factual_result_digest
    assert preview["preview_state_json"] == row.factual_state_json
    assert preview["baseline_digest"] == row.baseline_digest


# -- BG. branch order --------------------------------------------------------
@pytest.mark.parametrize("factual,counterfactual", [
    ("authorize_payment", "verify_via_known_contact"),
    ("verify_via_known_contact", "authorize_payment"),
    ("reply_to_request", "escalate_to_finance_security"),
])
def test_the_branch_order_is_the_learners_own(client, flask_app, factual,
                                              counterfactual):
    full_run(client, factual, counterfactual)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_choice_id == factual
    assert row.counterfactual_choice_id == counterfactual


# -- BH/BI/BJ. the result page ----------------------------------------------
def test_the_synthetic_loss_shown_comes_from_the_stored_state(client,
                                                              flask_app):
    page = full_run(client, "authorize_payment", "verify_via_known_contact")
    row = executions(flask_app, session_id_of(client))[0]
    stored = json.loads(row.factual_state_json)["payment"]["synthetic_loss"]
    assert stored == SYNTHETIC_INVOICE_AMOUNT
    assert b"Synthetic loss recorded: GBP 18,450" in page.data
    assert b"No synthetic loss was recorded" in page.data


def test_the_result_renders_the_persisted_execution(client, flask_app):
    page = full_run(client, "authorize_payment", "verify_via_known_contact")
    assert page.status_code == 200
    row = executions(flask_app, session_id_of(client))[0]
    assert row.execution_id.encode() in page.data
    assert b"Approve the payment using the new details" in page.data
    assert b"Call the supplier using the saved contact details" in page.data
    # No raw state JSON reaches the learner.
    for pointer in (b"synthetic_loss", b"change_confirmed",
                    b"replied_to_unverified_thread"):
        assert pointer not in page.data


def test_bec_result_refresh_does_not_reexecute_pair(client, flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    session_id = session_id_of(client)
    before_rows = executions(flask_app, session_id)
    before_events = training_events(flask_app, session_id)
    for _ in range(3):
        assert client.get(RESULT).status_code == 200
    assert [r.execution_id for r in executions(flask_app, session_id)] == [
        r.execution_id for r in before_rows]
    assert len(training_events(flask_app, session_id)) == len(before_events)


def test_a_repeated_rewind_post_returns_the_existing_result(client, flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    response = post(client, REWIND, RESULT, choice_id="reply_to_request",
                    confidence="10")
    assert response.headers["Location"].endswith("/result")
    assert len(executions(flask_app, session_id_of(client))) == 1


# -- BK/BL. telemetry --------------------------------------------------------
def test_exactly_six_training_events_in_the_expected_order(client, flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    events = training_events(flask_app, session_id_of(client))
    assert [e.event_type for e in events] == list(SUCCESS_EVENT_ORDER)
    row = executions(flask_app, session_id_of(client))[0]
    for event in events:
        assert event.scenario_id == row.execution_id


def test_no_bec_specific_event_family_is_introduced(flask_app, client):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    import app as app_module
    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(session_id=session_id_of(client)).all())
    for row in rows:
        assert not row.event_type.startswith("BEC_")
        assert not row.event_type.startswith("PAYMENT_")
    assert not [n for n in dir(EventType)
                if n.startswith("BEC_") or n.startswith("PAYMENT_")]


# -- BM. session isolation ---------------------------------------------------
def test_one_session_cannot_reach_another_sessions_result(client,
                                                          other_client,
                                                          flask_app):
    full_run(client, "authorize_payment", "verify_via_known_contact")
    owner = executions(flask_app, session_id_of(client))[0]

    response = other_client.get(RESULT)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/bec")

    with other_client.session_transaction() as sess:
        sess[SESSION_KEY] = {"execution_id": owner.execution_id}
    response = other_client.get(RESULT)
    assert response.status_code in (302, 303)
    assert owner.execution_id.encode() not in response.data


# -- BN. CSRF ----------------------------------------------------------------
@pytest.mark.parametrize("path", [START, DECISION, REWIND])
def test_state_changing_posts_require_csrf(client, flask_app, path):
    start(client)
    respond(client, "authorize_payment")
    response = client.post(path, data={"choice_id": "verify_via_known_contact",
                                       "confidence": "50"})
    assert response.status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_only_a_post_can_start_or_restart(client):
    assert client.get(START).status_code == 405
