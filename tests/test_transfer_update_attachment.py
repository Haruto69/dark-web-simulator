"""The malicious-update / attachment unseen transfer probe.

Source scenario: ``ransomware_incident_response``. The probe moves the
principle to the step *before* impact -- where software is allowed to come
from -- and records the learner's first response.

The completed source execution is produced without Docker (see
``tests/learning_helpers``), which is itself part of what this suite proves:
the learning layer and its probe run with no daemon, no container, no sandbox
operation and no file impact.
"""

import os
import re

import pytest

import learning
from tests.learning_helpers import (FEEDBACK, SESSION_KEYS, attempts,
                                    complete_phishing,
                                    complete_ransomware_execution, evidence,
                                    execution_row, post,
                                    preferred_explanation_id, session_id_of,
                                    submit_reflection, training_event_types)

PROBE = "/training/transfer/update-attachment"
PROBE_FEEDBACK = PROBE + "/feedback"
PROBE_KEY = "unexpected_update_attachment"
TOKEN_PAGE = "/training/phishing"

DEFINITION = learning.probe_for_key(PROBE_KEY)


def unlock(flask_app, client, factual="continue_working", confidence=85):
    """Complete the ransomware learning sequence, so the probe is reachable."""
    execution_id = complete_ransomware_execution(
        flask_app, client, factual, "isolate_and_report",
        factual_confidence=confidence)
    submit_reflection(client, "ransomware",
                      preferred_explanation_id(learning.RANSOMWARE))
    return execution_id


def respond(client, choice_id, confidence=60):
    return post(client, PROBE, TOKEN_PAGE, choice_id=choice_id,
                confidence=str(confidence))


# ==========================================================================
# BD/BE: locked before the sequence, unlocked after it
# ==========================================================================
def test_probe_is_inaccessible_before_any_ransomware_execution(client):
    response = client.get(PROBE)
    assert response.status_code in (302, 303)
    assert "/transfer/" not in response.headers["Location"]
    assert client.get(PROBE_FEEDBACK).status_code in (302, 303)


def test_probe_is_inaccessible_before_the_reflection_is_recorded(flask_app,
                                                                 client):
    execution_id = complete_ransomware_execution(flask_app, client)
    response = client.get(PROBE)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith(
        "/training/learn/ransomware/reflection")
    assert respond(client, "run_attached_update").status_code in (302, 303)
    assert attempts(flask_app, execution_id) == []


def test_completed_execution_and_reflection_unlock_the_probe(flask_app,
                                                             client):
    unlock(flask_app, client)
    page = client.get(PROBE)
    assert page.status_code == 200
    assert DEFINITION.title in page.data.decode()


def test_the_ransomware_learning_feedback_offers_the_probe(flask_app, client):
    unlock(flask_app, client)
    assert PROBE in client.get(FEEDBACK % "ransomware").data.decode()


def test_a_phishing_execution_does_not_unlock_this_probe(flask_app, client):
    complete_phishing(flask_app, client)
    submit_reflection(client, "phishing",
                      preferred_explanation_id(learning.PHISHING))
    assert client.get(PROBE).status_code in (302, 303)


# ==========================================================================
# BF/50: there is no attachment, and nothing can be run or downloaded
# ==========================================================================
def test_no_real_attachment_or_download_exists_on_the_probe_page(flask_app,
                                                                 client):
    unlock(flask_app, client)
    body = client.get(PROBE).data.decode()
    main = body.split("<main")[1].split("</main")[0].lower()

    for forbidden in ("href=", "src=", "download", "<a ", "<img", "<iframe",
                      "<object", "<embed", "data:", "://", ".exe", ".msi",
                      ".zip", ".ps1", ".sh", ".bat"):
        assert forbidden not in main, forbidden
    # The package name is inert display text and nothing more.
    assert "riverbend-endpoint-patch" in main


def test_update_attachment_probe_never_executes_or_downloads_attachment(
        flask_app, client, monkeypatch):
    """The named R6 test: structural and behavioural, together.

    Structural: no executable fixture exists in the repository and no route
    serves one. Behavioural: driving the whole probe with ``subprocess`` and
    ``socket`` made to raise proves nothing reaches either.
    """
    import socket
    import subprocess

    import app as app_module

    # -- structural: no download endpoint on the learning blueprint ---------
    learning_rules = [str(rule) for rule in app_module.app.url_map.iter_rules()
                      if rule.endpoint.startswith("learning.")]
    assert learning_rules
    for rule in learning_rules:
        lowered = rule.lower()
        for forbidden in ("download", "attachment/", "file", "update.exe",
                          "package"):
            assert forbidden not in lowered, rule

    # -- structural: no executable fixture anywhere in the repository -------
    for base in ("templates", "static", "learning"):
        for dirpath, _dirnames, filenames in os.walk(base):
            for name in filenames:
                assert not name.lower().endswith(
                    (".exe", ".msi", ".dll", ".bat", ".ps1", ".scr", ".jar")), (
                        os.path.join(dirpath, name))
    assert not os.path.exists("riverbend-endpoint-patch")

    # -- behavioural: no subprocess and no socket -------------------------
    unlock(flask_app, client)

    def refuse(*args, **kwargs):
        raise AssertionError("the probe must not execute or fetch anything")

    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)
    monkeypatch.setattr(subprocess, "call", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(os, "system", refuse)

    assert client.get(PROBE).status_code == 200
    assert respond(client, "run_attached_update").status_code in (302, 303)
    assert client.get(PROBE_FEEDBACK).status_code == 200


# ==========================================================================
# BG/BH/BI: exactly four choices, validated server-side
# ==========================================================================
def test_the_probe_offers_exactly_the_four_authored_choices(flask_app, client):
    unlock(flask_app, client)
    body = client.get(PROBE).data.decode()
    rendered = set(re.findall(r'name="choice_id" value="([a-z_]+)"', body))
    assert rendered == set(DEFINITION.choice_ids)
    assert len(rendered) == 4


def test_an_arbitrary_choice_is_rejected(flask_app, client):
    execution_id = unlock(flask_app, client)
    for choice_id in ("", "not_a_choice", "scan_and_sign_in",
                      "isolate_and_report"):
        assert respond(client, choice_id).status_code == 400
    assert attempts(flask_app, execution_id) == []


@pytest.mark.parametrize("confidence", ["", "-1", "101", "abc", "60.5"])
def test_a_malformed_confidence_is_rejected(flask_app, client, confidence):
    execution_id = unlock(flask_app, client)
    response = post(client, PROBE, TOKEN_PAGE,
                    choice_id="verify_update_through_it", confidence=confidence)
    assert response.status_code == 400
    assert attempts(flask_app, execution_id) == []


@pytest.mark.parametrize("confidence", [0, 100, 69, 70])
def test_a_valid_confidence_at_the_bounds_is_accepted(flask_app, client,
                                                      confidence):
    execution_id = unlock(flask_app, client)
    assert respond(client, "verify_update_through_it",
                   confidence).status_code in (302, 303)
    assert attempts(flask_app, execution_id)[0].confidence == confidence


def test_the_probe_post_requires_a_csrf_token(flask_app, client):
    execution_id = unlock(flask_app, client)
    response = client.post(PROBE, data={"choice_id": "run_attached_update",
                                        "confidence": "50"})
    assert response.status_code in (400, 403)
    assert attempts(flask_app, execution_id) == []


# ==========================================================================
# BJ/BK: recorded once, against the owning session's source execution
# ==========================================================================
def test_the_first_response_persists_exactly_once(flask_app, client):
    execution_id = unlock(flask_app, client)
    response = respond(client, "run_attached_update", 55)
    assert response.status_code in (302, 303)

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    attempt = rows[0]
    assert attempt.probe_key == PROBE_KEY
    assert attempt.probe_version == 1
    assert attempt.choice_id == "run_attached_update"
    assert attempt.confidence == 55
    assert attempt.source_execution_id == execution_id
    assert attempt.source_scenario_key == learning.RANSOMWARE
    assert attempt.session_id == session_id_of(client)
    assert attempt.response_time_ms is None or attempt.response_time_ms >= 0


def test_source_execution_ownership_is_enforced(flask_app, client,
                                                other_client):
    execution_id = unlock(flask_app, client)
    other_client.get("/training")
    with other_client.session_transaction() as sess:
        sess[SESSION_KEYS["ransomware"]] = {"execution_id": execution_id}

    assert other_client.get(PROBE).status_code in (302, 303)
    response = post(other_client, PROBE, TOKEN_PAGE,
                    choice_id="run_attached_update", confidence="50")
    assert response.status_code in (302, 303)
    assert attempts(flask_app, execution_id) == []


def test_the_source_execution_is_the_ransomware_execution(flask_app, client):
    execution_id = unlock(flask_app, client)
    respond(client, "verify_update_through_it")
    attempt = attempts(flask_app, execution_id)[0]
    row = execution_row(flask_app, attempt.source_execution_id)
    assert row.scenario_key == learning.RANSOMWARE
    assert row.status == "completed"


# ==========================================================================
# BL/BM/BN: authored classifications
# ==========================================================================
@pytest.mark.parametrize("choice_id,expected", [
    ("run_attached_update", learning.RISKY),
    ("restart_then_try_update", learning.RISKY),
    ("verify_update_through_it", learning.PROTECTIVE),
    ("isolate_and_report_attachment", learning.PROTECTIVE),
])
def test_each_choice_is_recorded_with_its_authored_quality(flask_app, client,
                                                           choice_id,
                                                           expected):
    execution_id = unlock(flask_app, client)
    respond(client, choice_id)
    assert attempts(flask_app, execution_id)[0].response_quality == expected


def test_a_submitted_response_quality_is_ignored(flask_app, client):
    execution_id = unlock(flask_app, client)
    post(client, PROBE, TOKEN_PAGE, choice_id="run_attached_update",
         confidence="50", response_quality="PROTECTIVE",
         evidence_signal="supporting_evidence")
    assert attempts(flask_app, execution_id)[0].response_quality == (
        learning.RISKY)


# ==========================================================================
# BO/BP: idempotent result, unreplaceable first response
# ==========================================================================
def test_refreshing_the_result_creates_nothing(flask_app, client):
    execution_id = unlock(flask_app, client)
    respond(client, "run_attached_update")
    before = attempts(flask_app, execution_id)[0].to_dict()

    for _ in range(3):
        client.get(PROBE)
        client.get(PROBE_FEEDBACK)

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    assert rows[0].to_dict() == before


def test_resubmitting_cannot_overwrite_the_first_response(flask_app, client):
    execution_id = unlock(flask_app, client)
    assert respond(client, "run_attached_update", 75).status_code in (302, 303)
    assert respond(client, "isolate_and_report_attachment",
                   20).status_code in (302, 303)

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    assert rows[0].choice_id == "run_attached_update"
    assert rows[0].response_quality == learning.RISKY
    assert rows[0].confidence == 75


# ==========================================================================
# 31: no feedback before submission
# ==========================================================================
def test_no_feedback_is_shown_before_a_response_is_recorded(flask_app, client):
    unlock(flask_app, client)
    body = client.get(PROBE).data.decode()
    assert DEFINITION.principle not in body
    for quality in ("Protective response", "Risky response"):
        assert quality not in body

    response = client.get(PROBE_FEEDBACK)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/transfer/update-attachment")


def test_the_feedback_page_shows_the_authored_principle(flask_app, client):
    unlock(flask_app, client)
    respond(client, "verify_update_through_it", 72)
    body = client.get(PROBE_FEEDBACK).data.decode()
    assert DEFINITION.principle in body
    assert "You chose this response with 72% confidence." in body
    assert "Protective response" in body
    for forbidden in ("mastery", "grade", "badge", "leaderboard", "points"):
        assert forbidden not in body.lower()


# ==========================================================================
# BQ/BR/BS: the probe is not a technical execution
# ==========================================================================
def test_the_probe_creates_no_training_execution(flask_app, client):
    import app as app_module

    unlock(flask_app, client)
    session_id = session_id_of(client)
    with flask_app.app_context():
        before = (app_module.TrainingExecution.query
                  .filter_by(session_id=session_id).count())

    client.get(PROBE)
    respond(client, "run_attached_update")
    client.get(PROBE_FEEDBACK)

    with flask_app.app_context():
        after = (app_module.TrainingExecution.query
                 .filter_by(session_id=session_id).count())
    assert after == before


def test_the_probe_triggers_no_sandbox_operation_or_file_impact(flask_app,
                                                                client,
                                                                monkeypatch):
    import app as app_module

    unlock(flask_app, client)

    def refuse(*args, **kwargs):
        raise AssertionError("a transfer probe must not touch the sandbox")

    monkeypatch.setattr(app_module, "sandbox_manager", refuse)
    monkeypatch.setattr(app_module, "session_sandbox_id", refuse,
                        raising=False)

    assert client.get(PROBE).status_code == 200
    assert respond(client, "run_attached_update").status_code in (302, 303)
    assert client.get(PROBE_FEEDBACK).status_code == 200


def test_the_probe_emits_no_training_pair_lifecycle_events(flask_app, client):
    from training_service import SUCCESS_EVENT_ORDER

    execution_id = unlock(flask_app, client)
    before = training_event_types(flask_app, execution_id)
    assert before == list(SUCCESS_EVENT_ORDER)

    client.get(PROBE)
    respond(client, "run_attached_update")
    client.get(PROBE_FEEDBACK)

    assert training_event_types(flask_app, execution_id) == before


def test_the_probe_leaves_the_source_execution_unchanged(flask_app, client):
    execution_id = unlock(flask_app, client)
    before = execution_row(flask_app, execution_id).to_dict()
    evidence_before = [row.to_dict() for row in evidence(flask_app,
                                                         execution_id)]

    client.get(PROBE)
    respond(client, "run_attached_update")
    client.get(PROBE_FEEDBACK)

    after = execution_row(flask_app, execution_id).to_dict()
    assert after == before
    assert after["pair_id"] == before["pair_id"]
    assert after["baseline_digest"] == before["baseline_digest"]
    assert after["rewound_digest"] == before["rewound_digest"]
    assert [row.to_dict()
            for row in evidence(flask_app, execution_id)] == evidence_before


def test_the_probe_runs_no_counterfactual_runtime(flask_app, client,
                                                  monkeypatch):
    import training.runtime as runtime_module

    unlock(flask_app, client)

    def refuse(*args, **kwargs):
        raise AssertionError("a transfer probe must not run the runtime")

    monkeypatch.setattr(runtime_module.CounterfactualRuntime,
                        "run_decision_pair", refuse)
    assert client.get(PROBE).status_code == 200
    assert respond(client, "verify_update_through_it").status_code in (302, 303)


def test_no_free_text_input_exists_on_the_probe_or_its_feedback(flask_app,
                                                                client):
    unlock(flask_app, client)
    bodies = [client.get(PROBE).data]
    respond(client, "verify_update_through_it")
    bodies.append(client.get(PROBE_FEEDBACK).data)
    for body in bodies:
        text = body.decode().lower()
        assert "<textarea" not in text
        assert 'type="text"' not in text


# ==========================================================================
# Both probes together
# ==========================================================================
def test_one_session_may_hold_an_attempt_at_each_probe_independently(
        flask_app, client):
    ransomware_execution = unlock(flask_app, client)
    phishing_execution = complete_phishing(flask_app, client)
    submit_reflection(client, "phishing",
                      preferred_explanation_id(learning.PHISHING))

    respond(client, "isolate_and_report_attachment")
    post(client, "/training/transfer/quishing", TOKEN_PAGE,
         choice_id="report_qr_message", confidence="50")

    assert len(attempts(flask_app, ransomware_execution, PROBE_KEY)) == 1
    assert len(attempts(flask_app, phishing_execution,
                        "quishing_portal_qr")) == 1
    # Neither attempt was recorded against the other's source execution.
    assert attempts(flask_app, ransomware_execution, "quishing_portal_qr") == []
    assert attempts(flask_app, phishing_execution, PROBE_KEY) == []
