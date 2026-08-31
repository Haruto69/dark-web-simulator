"""End-to-end tests for the RewindSec phishing training flow (milestone R3).

These exercise the complete learner workflow through the real Flask app, the
real R1 runtime and the real R2 service: briefing -> inbox -> decision ->
synthetic sign-in -> rewind -> executed comparison -> persisted result.

No Docker is involved anywhere in this module: the phishing consequence adapter
is a pure in-process state machine, so the flow runs on a machine with no
container runtime at all.
"""

import json

import pytest

from sandbox.events import EventType
from scenario_adapters import PHISHING_SCENARIO, PhishingConsequenceAdapter
from scenario_adapters.phishing import (PHISHING_BASELINE_STATE,
                                        PHISHING_CHOICE_IDS,
                                        PHISHING_DECISION_ID,
                                        PHISHING_SCENARIO_KEY)
from scenario_adapters.presentation import describe_state
from tests.conftest import csrf_for
from training.snapshots import StateSnapshot
from training_service import SUCCESS_EVENT_ORDER

TRAINING_EVENTS = frozenset(SUCCESS_EVENT_ORDER) | {
    EventType.TRAINING_EXECUTION_FAILED}

#: Legacy marketplace phishing events. The new flow must not emit these.
LEGACY_PHISHING_EVENTS = frozenset({
    EventType.PHISHING_EXPOSED, EventType.PHISHING_FORM_VIEWED,
    EventType.CREDENTIAL_SUBMITTED, EventType.CREDENTIAL_VALIDATED,
    EventType.CREDENTIAL_VALIDATION_FAILED,
    EventType.SANDBOX_LOGIN_SUCCEEDED,
    EventType.SYNTHETIC_RESOURCE_ACCESSED, EventType.CONSENT_GRANTED,
})

BRIEF = "/training/phishing"
START = "/training/phishing/start"
INBOX = "/training/phishing/inbox"
DECISION = "/training/phishing/decision"
SIGNIN = "/training/phishing/signin"
CF_SIGNIN = "/training/phishing/signin/counterfactual"
OUTCOME = "/training/phishing/outcome"
REWIND = "/training/phishing/rewind"
RESULT = "/training/phishing/result"

REAL_PASSWORD = "Sup3rSecret-RealPassword!"
REAL_EMAIL = "student@real-university.example"


# -- helpers ----------------------------------------------------------------
def post(client, path, form_page, **fields):
    """POST with a CSRF token scraped from the page that renders the form."""
    fields["csrf_token"] = csrf_for(client, form_page)
    return client.post(path, data=fields)


def start(client):
    return post(client, START, BRIEF)


def session_id_of(client):
    """The server-issued session id of this test client.

    Every fixture client is a distinct browser session, so filtering the shared
    test database by this id is what isolates one test's rows from another's.
    The tables are never wiped: other suites depend on the telemetry they
    wrote, and deleting it here would break them.
    """
    with client.session_transaction() as sess:
        return sess.get("session_id")


def identities_for(flask_app, client):
    import app as app_module
    return app_module.IDENTITIES.identities(session_id_of(client))


def choose(client, choice_id, confidence=50):
    client.get(INBOX)
    return post(client, DECISION, INBOX, choice_id=choice_id,
                confidence=str(confidence))


def sign_in(flask_app, client, username=None, password=None, path=SIGNIN):
    identity = identities_for(flask_app, client)[0]
    return post(client, path, path,
                username=username if username is not None else identity["username"],
                password=password if password is not None else identity["password"])


def rewind(client, choice_id, confidence=50):
    client.get(OUTCOME)
    return post(client, REWIND, OUTCOME, choice_id=choice_id,
                confidence=str(confidence))


def executions(flask_app, session_id):
    """Every TrainingExecution belonging to one session, oldest first."""
    import app as app_module
    with flask_app.app_context():
        return (app_module.TrainingExecution.query
                .filter_by(session_id=session_id)
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


def run_full_flow(flask_app, client, factual="follow_link_and_sign_in",
                  counterfactual="report_message", factual_confidence=82,
                  counterfactual_confidence=91):
    """Drive one complete attempt and return the final result response."""
    start(client)
    choose(client, factual, factual_confidence)
    if factual == "follow_link_and_sign_in":
        sign_in(flask_app, client)
    rewind(client, counterfactual, counterfactual_confidence)
    if counterfactual == "follow_link_and_sign_in":
        sign_in(flask_app, client, path=CF_SIGNIN)
    return client.get(RESULT)


# -- A/B: the new learner entry point ---------------------------------------
def test_training_home_is_the_rewindsec_learner_entry(client):
    page = client.get("/training")
    assert page.status_code == 200
    assert b"RewindSec" in page.data
    assert b"Phishing" in page.data


def test_phishing_module_needs_no_marketplace_navigation(flask_app, client):
    """B: the scenario is reachable without any dark-web/marketplace step."""
    assert client.get(BRIEF).status_code == 200
    assert start(client).status_code in (302, 303)
    inbox = client.get(INBOX)
    assert inbox.status_code == 200
    assert b"/marketplace" not in inbox.data
    assert b"product" not in inbox.data.lower()


def test_main_navigation_points_at_the_training_entry(client):
    assert b'href="/training' in client.get("/").data


# -- C: the decision offers exactly the supported stable choices -------------
def test_decision_page_offers_exactly_the_supported_choices(client):
    start(client)
    page = client.get(INBOX).data.decode()
    for choice_id in PHISHING_CHOICE_IDS:
        assert 'value="%s"' % choice_id in page
    assert page.count('name="choice_id"') == len(PHISHING_CHOICE_IDS)
    assert set(PHISHING_CHOICE_IDS) == {
        "follow_link_and_sign_in", "inspect_sender", "verify_independently",
        "report_message"}


# -- D/E: confidence validation ---------------------------------------------
@pytest.mark.parametrize("confidence", [0, 100, 50])
def test_boundary_confidence_values_are_accepted(client, confidence):
    start(client)
    response = choose(client, "report_message", confidence)
    assert response.status_code in (302, 303)


@pytest.mark.parametrize("raw", ["101", "-1", "", "fifty", "50.5", "٣٠",
                                 "1e2", " 50 ", "9999"])
def test_malformed_confidence_is_rejected_server_side(client, raw):
    start(client)
    client.get(INBOX)
    response = post(client, DECISION, INBOX, choice_id="report_message",
                    confidence=raw)
    assert response.status_code == 400


# -- F: unsupported choices --------------------------------------------------
@pytest.mark.parametrize("choice_id", ["", "delete_everything", "REPORT_MESSAGE",
                                       "message_reported_to_security"])
def test_unsupported_choice_is_rejected_server_side(client, choice_id):
    start(client)
    client.get(INBOX)
    response = post(client, DECISION, INBOX, choice_id=choice_id,
                    confidence="50")
    assert response.status_code == 400


# -- G/H/I/K: the synthetic credential path ---------------------------------
def test_follow_link_choice_requires_synthetic_credential_validation(client):
    start(client)
    assert choose(client, "follow_link_and_sign_in", 70).headers["Location"].endswith(
        "/signin")
    # The factual branch is not executable until the sign-in actually happened.
    assert client.get(OUTCOME).headers["Location"].endswith("/signin")
    client.get(OUTCOME)
    response = post(client, REWIND, SIGNIN, choice_id="report_message",
                    confidence="50")
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/signin")


def test_session_issued_lab_identity_is_accepted(flask_app, client):
    start(client)
    choose(client, "follow_link_and_sign_in", 70)
    response = sign_in(flask_app, client)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/outcome")
    assert client.get(OUTCOME).status_code == 200


def test_another_sessions_identity_does_not_validate(flask_app, client,
                                                     other_client):
    other_client.get(BRIEF)
    foreign = identities_for(flask_app, other_client)[0]
    start(client)
    choose(client, "follow_link_and_sign_in", 70)
    response = sign_in(flask_app, client, username=foreign["username"],
                       password=foreign["password"])
    assert response.status_code == 401


def test_non_synthetic_username_is_not_persisted_or_echoed(flask_app, client):
    start(client)
    choose(client, "follow_link_and_sign_in", 70)
    response = sign_in(flask_app, client, username=REAL_EMAIL,
                       password=REAL_PASSWORD)
    assert response.status_code == 401
    assert REAL_EMAIL.encode() not in response.data

    for event in all_events(flask_app, session_id_of(client)):
        blob = json.dumps(event.to_dict())
        assert REAL_EMAIL not in blob
        assert "real-university" not in blob
    for row in executions(flask_app, session_id_of(client)):
        assert REAL_EMAIL not in json.dumps(row.to_dict())
    with client.session_transaction() as sess:
        assert REAL_EMAIL not in json.dumps(dict(sess), default=str)


def test_safe_choice_completes_without_any_credential_entry(flask_app, client):
    start(client)
    assert choose(client, "report_message", 60).headers["Location"].endswith(
        "/outcome")
    assert client.get(OUTCOME).status_code == 200
    assert rewind(client, "inspect_sender", 40).status_code in (302, 303)
    assert client.get(RESULT).status_code == 200


# -- J: the submitted password appears nowhere ------------------------------
def test_phishing_training_never_persists_submitted_password(flask_app, client):
    """The named invariant test from the milestone brief."""
    start(client)
    choose(client, "follow_link_and_sign_in", 82)
    # A wrong password first, then the correct synthetic one: neither may be
    # retained anywhere.
    rejected = sign_in(flask_app, client, password=REAL_PASSWORD)
    assert rejected.status_code == 401
    assert REAL_PASSWORD.encode() not in rejected.data

    identity = identities_for(flask_app, client)[0]
    accepted = sign_in(flask_app, client)
    assert accepted.status_code in (302, 303)
    rewind(client, "report_message", 91)
    result = client.get(RESULT)
    assert result.status_code == 200

    secrets = (REAL_PASSWORD, identity["password"])
    for secret in secrets:
        assert secret.encode() not in result.data
        for row in executions(flask_app, session_id_of(client)):
            blob = " ".join(str(value) for value in (
                row.to_dict(), row.factual_state_json,
                row.counterfactual_state_json, row.difference_json))
            assert secret not in blob
        for event in all_events(flask_app, session_id_of(client)):
            assert secret not in json.dumps(event.to_dict())
        with client.session_transaction() as sess:
            assert secret not in json.dumps(dict(sess), default=str)


# -- R3 review: the counterfactual credential branch is gated the same way ---
def _to_unsafe_counterfactual(client, factual="report_message"):
    """Drive as far as the rewind that selects ``follow_link_and_sign_in``."""
    start(client)
    choose(client, factual, 60)
    return rewind(client, "follow_link_and_sign_in", 77)


def test_counterfactual_follow_link_requires_synthetic_signin(flask_app,
                                                              client):
    response = _to_unsafe_counterfactual(client)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/signin/counterfactual")
    # The result is not reachable until that branch is actually experienced.
    assert client.get(RESULT).headers["Location"].endswith("/phishing")
    assert client.get(CF_SIGNIN).status_code == 200

    completed = sign_in(flask_app, client, path=CF_SIGNIN)
    assert completed.status_code in (302, 303)
    assert completed.headers["Location"].endswith("/result")
    assert client.get(RESULT).status_code == 200


def test_counterfactual_follow_link_does_not_execute_pair_before_valid_signin(
        flask_app, client):
    _to_unsafe_counterfactual(client)
    assert executions(flask_app, session_id_of(client)) == []
    assert training_event_types(flask_app, session_id_of(client)) == []

    # A rejected sign-in still executes nothing.
    rejected = sign_in(flask_app, client, username=REAL_EMAIL,
                       password=REAL_PASSWORD, path=CF_SIGNIN)
    assert rejected.status_code == 401
    assert executions(flask_app, session_id_of(client)) == []
    assert training_event_types(flask_app, session_id_of(client)) == []

    sign_in(flask_app, client, path=CF_SIGNIN)
    assert len(executions(flask_app, session_id_of(client))) == 1


def test_counterfactual_follow_link_accepts_only_current_session_synthetic_identity(
        flask_app, client, other_client):
    other_client.get(BRIEF)
    foreign = identities_for(flask_app, other_client)[0]
    _to_unsafe_counterfactual(client)

    # Exactly as on the factual path: another session's identity, and a
    # non-synthetic one, both fail.
    assert sign_in(flask_app, client, username=foreign["username"],
                   password=foreign["password"],
                   path=CF_SIGNIN).status_code == 401
    assert sign_in(flask_app, client, username=REAL_EMAIL,
                   password=REAL_PASSWORD, path=CF_SIGNIN).status_code == 401
    assert executions(flask_app, session_id_of(client)) == []

    assert sign_in(flask_app, client,
                   path=CF_SIGNIN).status_code in (302, 303)


def test_counterfactual_signin_password_is_never_persisted(flask_app, client):
    _to_unsafe_counterfactual(client)
    rejected = sign_in(flask_app, client, password=REAL_PASSWORD,
                       path=CF_SIGNIN)
    assert rejected.status_code == 401
    assert REAL_PASSWORD.encode() not in rejected.data

    identity = identities_for(flask_app, client)[0]
    sign_in(flask_app, client, path=CF_SIGNIN)
    result = client.get(RESULT)
    assert result.status_code == 200

    for secret in (REAL_PASSWORD, identity["password"], identity["username"]):
        assert secret.encode() not in result.data
        for row in executions(flask_app, session_id_of(client)):
            blob = " ".join(str(value) for value in (
                row.to_dict(), row.factual_state_json,
                row.counterfactual_state_json, row.difference_json))
            assert secret not in blob
        for event in all_events(flask_app, session_id_of(client)):
            assert secret not in json.dumps(event.to_dict())
        with client.session_transaction() as sess:
            assert secret not in json.dumps(dict(sess), default=str)


def test_safe_factual_to_unsafe_counterfactual_preserves_actual_branch_order(
        flask_app, client):
    """The compromise landing on the second branch must not swap the pair."""
    _to_unsafe_counterfactual(client)
    sign_in(flask_app, client, path=CF_SIGNIN)
    assert client.get(RESULT).status_code == 200

    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    row = rows[0]
    assert row.factual_choice_id == "report_message"
    assert row.counterfactual_choice_id == "follow_link_and_sign_in"
    assert row.baseline_digest == row.rewound_digest
    assert row.baseline_verified

    factual = json.loads(row.factual_state_json)
    counterfactual = json.loads(row.counterfactual_state_json)
    assert factual["identity"]["exposed"] is False
    assert factual["message"]["reported"] is True
    assert counterfactual["identity"]["exposed"] is True
    assert counterfactual["account"]["synthetic_access"] is True
    assert counterfactual["resource"]["accessed"] is True

    assert training_event_types(
        flask_app, session_id_of(client)) == list(SUCCESS_EVENT_ORDER)

    # And a refresh of the result re-reads the one stored row.
    assert client.get(RESULT).status_code == 200
    assert len(executions(flask_app, session_id_of(client))) == 1
    assert training_event_types(
        flask_app, session_id_of(client)) == list(SUCCESS_EVENT_ORDER)


# -- L/M: choosing the counterfactual ---------------------------------------
def test_outcome_page_offers_only_the_other_choices(client):
    start(client)
    choose(client, "report_message", 60)
    page = client.get(OUTCOME).data.decode()
    assert 'value="report_message"' not in page
    for choice_id in PHISHING_CHOICE_IDS:
        if choice_id != "report_message":
            assert 'value="%s"' % choice_id in page


def test_identical_factual_and_counterfactual_choice_is_rejected(flask_app,
                                                                 client):
    start(client)
    choose(client, "report_message", 60)
    response = rewind(client, "report_message", 60)
    assert response.status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_unsupported_counterfactual_choice_is_rejected(flask_app, client):
    start(client)
    choose(client, "report_message", 60)
    assert rewind(client, "wipe_the_disk", 60).status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


# -- N/O/P/Q/R: the executed comparison -------------------------------------
def test_successful_comparison_creates_exactly_one_execution(flask_app, client):
    run_full_flow(flask_app, client)
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1
    row = rows[0]
    assert row.status == "completed"
    assert row.scenario_key == PHISHING_SCENARIO_KEY
    assert row.scenario_version == 1
    assert row.decision_id == PHISHING_DECISION_ID
    assert row.pair_id
    assert row.factual_confidence == 82
    assert row.counterfactual_confidence == 91
    assert row.factual_response_time_ms is not None
    assert row.counterfactual_response_time_ms is not None
    assert row.factual_result_digest and row.counterfactual_result_digest


def test_completed_row_records_a_verified_identical_baseline(flask_app, client):
    run_full_flow(flask_app, client)
    row = executions(flask_app, session_id_of(client))[0]
    assert row.baseline_digest
    assert row.baseline_digest == row.rewound_digest
    assert row.baseline_verified


def test_factual_branch_is_the_choice_the_learner_actually_made_first(
        flask_app, client):
    """P/Q, and the semantics of section 8: no silent swapping."""
    run_full_flow(flask_app, client, factual="report_message",
                  counterfactual="follow_link_and_sign_in")
    row = executions(flask_app, session_id_of(client))[0]
    assert row.factual_choice_id == "report_message"
    assert row.counterfactual_choice_id == "follow_link_and_sign_in"

    factual = json.loads(row.factual_state_json)
    counterfactual = json.loads(row.counterfactual_state_json)
    assert factual["message"]["reported"] is True
    assert factual["identity"]["exposed"] is False
    assert counterfactual["identity"]["exposed"] is True
    assert counterfactual["account"]["synthetic_access"] is True
    assert counterfactual["resource"]["accessed"] is True


def test_result_page_renders_from_the_persisted_result(flask_app, client):
    result = run_full_flow(flask_app, client)
    assert result.status_code == 200
    row = executions(flask_app, session_id_of(client))[0]
    body = result.data.decode()
    assert row.execution_id in body
    assert row.pair_id in body
    assert "Your path" in body
    assert "Rewind path" in body
    assert "Synthetic credential was exposed" in body
    assert "The suspicious message was reported" in body
    # Deterministic sentences, never a raw JSON dump of the state.
    assert '"identity"' not in body
    assert "sender_mismatch_visible" not in body


def test_result_page_shows_the_learner_order_not_a_fixed_order(flask_app,
                                                               client):
    result = run_full_flow(flask_app, client, factual="verify_independently",
                           counterfactual="follow_link_and_sign_in")
    body = result.data.decode()
    your_path = body.index("Your path")
    rewind_path = body.index("Rewind path")
    assert your_path < body.index("Verify through a trusted channel")
    assert rewind_path < body.index("Follow the link and sign in")


# -- S/T: refresh safety -----------------------------------------------------
def test_phishing_result_refresh_does_not_reexecute_counterfactual_pair(
        flask_app, client):
    """The named idempotency test from the milestone brief."""
    run_full_flow(flask_app, client)
    before_rows = [row.execution_id for row in executions(flask_app, session_id_of(client))]
    before_events = training_event_types(flask_app, session_id_of(client))

    for _ in range(4):
        assert client.get(RESULT).status_code == 200

    assert [row.execution_id for row in executions(flask_app, session_id_of(client))] == before_rows
    assert training_event_types(flask_app, session_id_of(client)) == before_events


def test_resubmitting_the_rewind_does_not_create_a_second_execution(
        flask_app, client):
    run_full_flow(flask_app, client)
    first = executions(flask_app, session_id_of(client))[0].execution_id
    # A repeated POST (double-click, back-then-submit) is refused server-side,
    # not merely by a disabled button.
    again = post(client, REWIND, RESULT, choice_id="inspect_sender",
                 confidence="10")
    assert again.status_code in (302, 303)
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 1 and rows[0].execution_id == first


# -- U/V: telemetry ----------------------------------------------------------
def test_standard_training_event_order_is_preserved(flask_app, client):
    run_full_flow(flask_app, client)
    assert training_event_types(flask_app, session_id_of(client)) == list(SUCCESS_EVENT_ORDER)


def test_new_flow_emits_no_legacy_phishing_events(flask_app, client):
    run_full_flow(flask_app, client)
    emitted = {event.event_type for event in all_events(flask_app, session_id_of(client))}
    assert not emitted & LEGACY_PHISHING_EVENTS
    # ...and nothing outside the training lifecycle either.
    assert emitted <= frozenset(SUCCESS_EVENT_ORDER)


def test_training_events_carry_only_bounded_metadata(flask_app, client):
    run_full_flow(flask_app, client)
    for event in all_events(flask_app, session_id_of(client)):
        assert event.source == "training:counterfactual"
        assert event.scenario_id.startswith("exec-")
        if event.details:
            assert len(event.details) <= 400
            assert "password" not in event.details.lower()


# -- W: session isolation ----------------------------------------------------
def test_result_access_is_session_isolated(flask_app, client, other_client):
    run_full_flow(flask_app, client)
    owner_row = executions(flask_app, session_id_of(client))[0]

    # The second learner has no result of their own...
    stranger = other_client.get(RESULT)
    assert stranger.status_code in (302, 303)
    assert owner_row.execution_id.encode() not in stranger.data

    # ...and no URL, id or form field addresses somebody else's.
    for attempt in ("%s?execution_id=%s" % (RESULT, owner_row.execution_id),
                    "%s/%s" % (RESULT, owner_row.execution_id)):
        response = other_client.get(attempt)
        assert response.status_code in (302, 303, 404)
        assert owner_row.execution_id.encode() not in response.data

    # Forcing the id into the stranger's own session is still refused, because
    # the loaded row's session_id must match.
    with other_client.session_transaction() as sess:
        sess["rewindsec_training"] = {"attempt_id": "x", "factual_choice": None,
                                      "execution_id": owner_row.execution_id}
    response = other_client.get(RESULT)
    assert response.status_code in (302, 303)
    assert owner_row.execution_id.encode() not in response.data


def test_two_sessions_keep_separate_progress(flask_app, client, other_client):
    start(client)
    choose(client, "report_message", 10)
    start(other_client)
    choose(other_client, "inspect_sender", 90)
    rewind(client, "inspect_sender", 20)
    rewind(other_client, "report_message", 80)

    with client.session_transaction() as sess:
        session_a = sess["session_id"]
    with other_client.session_transaction() as sess:
        session_b = sess["session_id"]
    assert session_a != session_b

    row_a = executions(flask_app, session_a)[0]
    row_b = executions(flask_app, session_b)[0]
    assert row_a.execution_id != row_b.execution_id
    assert row_a.factual_choice_id == "report_message"
    assert row_a.factual_confidence == 10
    assert row_b.factual_choice_id == "inspect_sender"
    assert row_b.factual_confidence == 90


# -- X: CSRF -----------------------------------------------------------------
@pytest.mark.parametrize("path,fields", [
    (START, {}),
    (DECISION, {"choice_id": "report_message", "confidence": "50"}),
    (SIGNIN, {"username": "a@lab.local", "password": "x"}),
    (CF_SIGNIN, {"username": "a@lab.local", "password": "x"}),
    (REWIND, {"choice_id": "report_message", "confidence": "50"}),
])
def test_state_changing_posts_require_csrf(flask_app, client, path, fields):
    start(client)
    choose(client, "follow_link_and_sign_in", 50)
    assert client.post(path, data=fields).status_code == 400
    assert client.post(path, data=dict(fields, csrf_token="not-the-token")
                       ).status_code == 400
    assert executions(flask_app, session_id_of(client)) == []


def test_no_state_changing_route_accepts_get(client):
    start(client)
    for path in (START, DECISION, REWIND):
        assert client.get(path).status_code == 405


# -- AA: repeated experiments ------------------------------------------------
def test_repeating_the_same_pair_shares_pair_id_not_execution_id(flask_app,
                                                                 client):
    run_full_flow(flask_app, client, factual="report_message",
                  counterfactual="inspect_sender", factual_confidence=50,
                  counterfactual_confidence=50)
    # An explicit restart is meant to create a new attempt.
    run_full_flow(flask_app, client, factual="report_message",
                  counterfactual="inspect_sender", factual_confidence=50,
                  counterfactual_confidence=50)
    rows = executions(flask_app, session_id_of(client))
    assert len(rows) == 2
    assert rows[0].pair_id == rows[1].pair_id
    assert rows[0].execution_id != rows[1].execution_id


# -- Y/Z/AE: the adapter itself ---------------------------------------------
def test_adapter_reset_returns_the_exact_baseline_digest():
    adapter = PhishingConsequenceAdapter()
    adapter.prepare()
    baseline = StateSnapshot.capture(adapter.capture_state())
    for action in sorted(adapter.supported_actions):
        adapter.apply(action)
        adapter.rewind()
        assert StateSnapshot.capture(
            adapter.capture_state()).digest == baseline.digest


def test_adapter_is_deterministic_across_instances():
    def run(actions):
        adapter = PhishingConsequenceAdapter()
        adapter.prepare()
        for action in actions:
            adapter.apply(action)
        return StateSnapshot.capture(adapter.capture_state()).digest

    assert run(["message_reported_to_security"]) == run(
        ["message_reported_to_security"])
    assert run(["message_reported_to_security"]) != run(
        ["credential_submitted_to_lookalike"])


def test_adapter_uses_no_network(monkeypatch):
    """Y: any socket use inside the adapter is a hard failure."""
    import socket

    def forbidden(*args, **kwargs):
        raise AssertionError("the phishing adapter must not use the network")

    monkeypatch.setattr(socket, "socket", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)

    adapter = PhishingConsequenceAdapter()
    adapter.prepare()
    for action in sorted(adapter.supported_actions):
        adapter.apply(action)
        adapter.capture_state()
        adapter.rewind()


def test_adapter_vocabulary_is_closed():
    adapter = PhishingConsequenceAdapter()
    assert adapter.supported_actions == frozenset(PHISHING_SCENARIO.action_keys)
    with pytest.raises(Exception):
        adapter.apply("rm_minus_rf")


def test_baseline_state_carries_no_secret_or_destination():
    blob = json.dumps(PHISHING_BASELINE_STATE).lower()
    for banned in ("password", "secret", "token", "http", "://", "\\", "@"):
        assert banned not in blob


def test_scenario_definition_names_only_symbolic_actions():
    for key in PHISHING_SCENARIO.action_keys:
        assert key.replace("_", "").isalnum()
        assert key.islower()


# -- presentation ------------------------------------------------------------
def test_presentation_ignores_undescribed_state_fields():
    lines = describe_state({"identity": {"exposed": True},
                            "future_field": {"internal_detail": "raw value"}})
    rendered = " ".join(line["text"] for line in lines)
    assert "Synthetic credential was exposed" in rendered
    assert "raw value" not in rendered
    assert "future_field" not in rendered


# -- 24: the explicit end-to-end invariant ----------------------------------
def test_phishing_rewind_comparison_executes_both_choices_from_identical_baseline(
        flask_app, client):
    """The named invariant test from the milestone brief.

    Proves that the stored comparison was produced from one verified starting
    state: the baseline digest captured before the factual branch equals the
    digest re-captured after the rewind, and the counterfactual branch is only
    represented in the record because that check passed.
    """
    run_full_flow(flask_app, client, factual="follow_link_and_sign_in",
                  counterfactual="report_message")
    row = executions(flask_app, session_id_of(client))[0]

    assert row.status == "completed"
    assert row.baseline_digest == row.rewound_digest
    assert row.factual_result_digest != row.counterfactual_result_digest

    order = training_event_types(flask_app, session_id_of(client))
    assert order.index(EventType.TRAINING_REWIND_VERIFIED) < order.index(
        EventType.TRAINING_COUNTERFACTUAL_CAPTURED)

    # The digests are re-derivable from the stored canonical state, so the
    # record is self-checking rather than self-asserting.
    from training.snapshots import fingerprint
    assert fingerprint(json.loads(row.factual_state_json)) == \
        row.factual_result_digest
    assert fingerprint(json.loads(row.counterfactual_state_json)) == \
        row.counterfactual_result_digest


# -- AD/AE: layering and the absence of a container runtime -----------------
def test_scenario_adapters_stay_out_of_the_http_layer():
    """The adapter package is application-level but not Flask-aware.

    ``training/`` may not import the application (pinned in
    ``test_training_runtime``); ``scenario_adapters/`` may import ``training``
    and ``sandbox`` constants, but not Flask, SQLAlchemy or the routes -- a
    consequence adapter must be runnable with no request in flight.
    """
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent
    forbidden = re.compile(
        r"^\s*(?:from|import)\s+(flask|sqlalchemy|app|training_routes|"
        r"training_service)\b", re.MULTILINE)
    for module in (root / "scenario_adapters").rglob("*.py"):
        assert not forbidden.search(module.read_text(encoding="utf-8")), \
            "%s reaches into the HTTP layer" % module

    reverse = re.compile(r"^\s*(?:from|import)\s+scenario_adapters\b",
                         re.MULTILINE)
    for module in (root / "training").rglob("*.py"):
        assert not reverse.search(module.read_text(encoding="utf-8")), \
            "%s depends on a concrete application scenario" % module


def test_phishing_training_flow_needs_no_sandbox_or_docker(flask_app, client,
                                                           monkeypatch):
    """AE: the whole flow runs with the sandbox manager unavailable."""
    import app as app_module

    def unavailable(*args, **kwargs):
        raise AssertionError("the phishing training flow must not need a "
                             "sandbox or a container runtime")

    monkeypatch.setattr(app_module, "sandbox_manager", unavailable)
    result = run_full_flow(flask_app, client)
    assert result.status_code == 200
    assert executions(flask_app, session_id_of(client))[0].status == "completed"
