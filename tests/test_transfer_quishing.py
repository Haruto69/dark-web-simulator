"""The quishing / QR-phishing unseen transfer probe.

Source scenario: ``phishing_credential_compromise``. The probe measures the
learner's *first* response on a different surface, after the learning
intervention and before any feedback about it.

Nothing in this module involves Docker, a sandbox, a subprocess, a socket or a
``CounterfactualRuntime``, and the probe must not reach any of them either.
"""

import re

import pytest

import learning
from tests.learning_helpers import (FEEDBACK, REFLECTION, SESSION_KEYS,
                                    attempts, complete_phishing,
                                    complete_synthetic, evidence,
                                    execution_id_of, execution_row, post,
                                    preferred_explanation_id, session_id_of,
                                    submit_reflection, training_event_types)

PROBE = "/training/transfer/quishing"
PROBE_FEEDBACK = PROBE + "/feedback"
PROBE_KEY = "quishing_portal_qr"
TOKEN_PAGE = "/training/phishing"

DEFINITION = learning.probe_for_key(PROBE_KEY)


def unlock(flask_app, client, factual="follow_link_and_sign_in",
           confidence=90):
    """Complete the phishing learning sequence, so the probe is reachable."""
    execution_id = complete_phishing(flask_app, client, factual,
                                     "verify_independently",
                                     factual_confidence=confidence)
    submit_reflection(client, "phishing",
                      preferred_explanation_id(learning.PHISHING))
    return execution_id


def respond(client, choice_id, confidence=80):
    return post(client, PROBE, TOKEN_PAGE, choice_id=choice_id,
                confidence=str(confidence))


# ==========================================================================
# AL/AM: locked before the sequence, unlocked after it
# ==========================================================================
def test_probe_is_inaccessible_before_any_phishing_execution(client):
    response = client.get(PROBE)
    assert response.status_code in (302, 303)
    assert "/transfer/" not in response.headers["Location"]
    assert client.get(PROBE_FEEDBACK).status_code in (302, 303)


def test_probe_is_inaccessible_after_the_comparison_but_before_the_reflection(
        flask_app, client):
    """The technical result alone does not unlock the probe."""
    execution_id = complete_phishing(flask_app, client)
    assert client.get("/training/phishing/result").status_code == 200

    response = client.get(PROBE)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith(
        "/training/learn/phishing/reflection")
    assert respond(client, "scan_and_sign_in").status_code in (302, 303)
    assert attempts(flask_app, execution_id) == []


def test_completed_execution_and_reflection_unlock_the_probe(flask_app,
                                                             client):
    unlock(flask_app, client)
    page = client.get(PROBE)
    assert page.status_code == 200
    assert DEFINITION.title in page.data.decode()


def test_the_learning_feedback_page_offers_the_probe(flask_app, client):
    unlock(flask_app, client)
    body = client.get(FEEDBACK % "phishing").data.decode()
    assert PROBE in body


# ==========================================================================
# AN: the probe is a different surface, in different words
# ==========================================================================
def test_probe_prompt_is_meaningfully_different_from_the_phishing_message(
        flask_app, client):
    from training_routes import ORG

    unlock(flask_app, client)
    probe_body = client.get(PROBE).data.decode()
    inbox_body = client.get("/training/phishing/inbox").data.decode()

    # None of the R3 scenario's fictional organisation, sender or lure domain
    # appears on the probe.
    for value in ORG.values():
        assert value not in probe_body, value
    # And the probe's own situation lines appear only on the probe. Compared
    # against the escaped form, since Jinja escapes the authored quotes.
    from markupsafe import escape

    for line in DEFINITION.situation:
        rendered = str(escape(line))
        assert rendered in probe_body
        assert rendered not in inbox_body


# ==========================================================================
# AO/BC: the QR figure is inert and there is no destination anywhere
# ==========================================================================
def test_the_qr_visual_contains_no_url_or_destination(flask_app, client):
    unlock(flask_app, client)
    body = client.get(PROBE).data.decode()
    main = body.split("<main")[1].split("</main")[0]

    assert "<svg" in main
    # No scheme, no link, no embedded resource, no data URI anywhere in the
    # page body -- the figure is drawn from coordinates and nothing else.
    for forbidden in ("http://", "https://", "://", "href=", "src=", "data:",
                      "xlink", "<a ", "<img", "<iframe", "<form action=\"http"):
        assert forbidden not in main.lower(), forbidden


def test_the_qr_figure_is_generated_from_coordinates_only():
    from learning_routes import inert_qr_cells

    cells = inert_qr_cells()
    assert cells == inert_qr_cells()          # deterministic
    assert all(isinstance(cell, tuple) and len(cell) == 2 for cell in cells)
    assert all(0 <= x < 15 and 0 <= y < 15 for x, y in cells)


def test_the_probe_makes_no_network_or_subprocess_call(flask_app, client,
                                                       monkeypatch):
    import socket
    import subprocess

    def refuse(*args, **kwargs):
        raise AssertionError("a transfer probe must not reach outside")

    unlock(flask_app, client)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(subprocess, "Popen", refuse)
    monkeypatch.setattr(subprocess, "run", refuse)

    assert client.get(PROBE).status_code == 200
    respond(client, "verify_via_official_portal")
    assert client.get(PROBE_FEEDBACK).status_code == 200


# ==========================================================================
# AP/AQ/AR/AS: exactly four choices, validated server-side
# ==========================================================================
def test_the_probe_offers_exactly_the_four_authored_choices(flask_app, client):
    unlock(flask_app, client)
    body = client.get(PROBE).data.decode()
    rendered = set(re.findall(r'name="choice_id" value="([a-z_]+)"', body))
    assert rendered == set(DEFINITION.choice_ids)
    assert len(rendered) == 4


def test_an_arbitrary_choice_is_rejected(flask_app, client):
    execution_id = unlock(flask_app, client)
    for choice_id in ("", "not_a_choice", "run_attached_update",
                      "verify_independently"):
        response = respond(client, choice_id)
        assert response.status_code == 400
    assert attempts(flask_app, execution_id) == []


@pytest.mark.parametrize("confidence", ["", "-1", "101", "abc", "70.0", "  70"])
def test_a_malformed_confidence_is_rejected(flask_app, client, confidence):
    execution_id = unlock(flask_app, client)
    response = post(client, PROBE, TOKEN_PAGE, choice_id="report_qr_message",
                    confidence=confidence)
    assert response.status_code == 400
    assert attempts(flask_app, execution_id) == []


@pytest.mark.parametrize("confidence", [0, 100, 70])
def test_a_valid_confidence_at_the_bounds_is_accepted(flask_app, client,
                                                      confidence):
    execution_id = unlock(flask_app, client)
    assert respond(client, "report_qr_message",
                   confidence).status_code in (302, 303)
    assert attempts(flask_app, execution_id)[0].confidence == confidence


def test_the_probe_post_requires_a_csrf_token(flask_app, client):
    execution_id = unlock(flask_app, client)
    response = client.post(PROBE, data={"choice_id": "report_qr_message",
                                        "confidence": "50"})
    assert response.status_code in (400, 403)
    assert attempts(flask_app, execution_id) == []


def test_response_time_is_measured_server_side_and_bounded(flask_app, client):
    execution_id = unlock(flask_app, client)
    client.get(PROBE)
    # A client-supplied duration is ignored; the measurement is the server's.
    post(client, PROBE, TOKEN_PAGE, choice_id="report_qr_message",
         confidence="50", response_time_ms="999999999")
    attempt = attempts(flask_app, execution_id)[0]
    assert attempt.response_time_ms is not None
    assert 0 <= attempt.response_time_ms <= 60 * 60 * 1000


# ==========================================================================
# AT/AU/AV: one attempt, tied to the right execution and session
# ==========================================================================
def test_the_first_response_creates_exactly_one_attempt(flask_app, client):
    execution_id = unlock(flask_app, client)
    response = respond(client, "scan_and_sign_in", 80)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/feedback")

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    attempt = rows[0]
    assert attempt.probe_key == PROBE_KEY
    assert attempt.probe_version == 1
    assert attempt.choice_id == "scan_and_sign_in"
    assert attempt.confidence == 80
    assert attempt.attempt_id.startswith("xfer-")
    assert attempt.source_execution_id == execution_id
    assert attempt.source_scenario_key == learning.PHISHING
    assert attempt.session_id == session_id_of(client)


def test_the_attempts_source_execution_is_the_phishing_execution(flask_app,
                                                                 client):
    execution_id = unlock(flask_app, client)
    respond(client, "report_qr_message")
    attempt = attempts(flask_app, execution_id)[0]
    row = execution_row(flask_app, attempt.source_execution_id)
    assert row.scenario_key == learning.PHISHING
    assert row.status == "completed"


def test_source_session_ownership_is_enforced(flask_app, client, other_client):
    """Another session cannot answer a probe against this execution."""
    execution_id = unlock(flask_app, client)
    other_client.get("/training")
    with other_client.session_transaction() as sess:
        sess[SESSION_KEYS["phishing"]] = {"execution_id": execution_id}

    assert other_client.get(PROBE).status_code in (302, 303)
    response = post(other_client, PROBE, TOKEN_PAGE,
                    choice_id="scan_and_sign_in", confidence="50")
    assert response.status_code in (302, 303)
    assert attempts(flask_app, execution_id) == []


def test_a_bec_execution_does_not_unlock_the_quishing_probe(flask_app,
                                                            client):
    """The probe's source is its authored scenario, not whatever is in session."""
    complete_synthetic(client, "bec", "authorize_payment",
                       "verify_via_known_contact")
    submit_reflection(client, "bec", preferred_explanation_id(learning.BEC))
    assert client.get(PROBE).status_code in (302, 303)


def test_no_source_execution_id_is_accepted_from_the_request(flask_app, client,
                                                             other_client):
    victim = unlock(flask_app, other_client)
    attacker = unlock(flask_app, client)
    post(client, PROBE, TOKEN_PAGE, choice_id="scan_and_sign_in",
         confidence="50", source_execution_id=victim,
         execution_id=victim, probe_key="unexpected_update_attachment")

    assert attempts(flask_app, victim) == []
    rows = attempts(flask_app, attacker)
    assert len(rows) == 1
    assert rows[0].probe_key == PROBE_KEY


# ==========================================================================
# AW/AX: authored classifications, recomputed server-side
# ==========================================================================
def test_scan_and_sign_in_is_classified_risky(flask_app, client):
    execution_id = unlock(flask_app, client)
    respond(client, "scan_and_sign_in")
    assert attempts(flask_app, execution_id)[0].response_quality == (
        learning.RISKY)


def test_verify_via_official_portal_is_classified_protective(flask_app,
                                                             client):
    execution_id = unlock(flask_app, client)
    respond(client, "verify_via_official_portal")
    assert attempts(flask_app, execution_id)[0].response_quality == (
        learning.PROTECTIVE)


def test_a_submitted_response_quality_is_ignored(flask_app, client):
    execution_id = unlock(flask_app, client)
    post(client, PROBE, TOKEN_PAGE, choice_id="scan_and_sign_in",
         confidence="50", response_quality="PROTECTIVE")
    assert attempts(flask_app, execution_id)[0].response_quality == (
        learning.RISKY)


# ==========================================================================
# AY/AZ/48: the first response is the measurement
# ==========================================================================
def test_refreshing_the_probe_or_its_feedback_creates_nothing(flask_app,
                                                              client):
    execution_id = unlock(flask_app, client)
    respond(client, "scan_and_sign_in")
    before = attempts(flask_app, execution_id)[0].to_dict()

    for _ in range(3):
        client.get(PROBE)
        client.get(PROBE_FEEDBACK)

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    assert rows[0].to_dict() == before


def test_quishing_probe_records_first_unassisted_response_only_once(flask_app,
                                                                    client):
    """The named R6 test.

    First response ``scan_and_sign_in``; a later attempt says
    ``report_qr_message``. The recorded response stays the first one.
    """
    execution_id = unlock(flask_app, client)

    assert respond(client, "scan_and_sign_in", 80).status_code in (302, 303)
    second = respond(client, "report_qr_message", 10)
    assert second.status_code in (302, 303)

    rows = attempts(flask_app, execution_id)
    assert len(rows) == 1
    assert rows[0].choice_id == "scan_and_sign_in"
    assert rows[0].response_quality == learning.RISKY
    assert rows[0].confidence == 80

    body = client.get(PROBE_FEEDBACK).data.decode()
    assert DEFINITION.choice("scan_and_sign_in").label in body
    assert DEFINITION.choice("report_qr_message").label not in body


def test_revisiting_the_probe_after_answering_shows_the_feedback(flask_app,
                                                                 client):
    unlock(flask_app, client)
    respond(client, "report_qr_message")
    response = client.get(PROBE)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/feedback")


# ==========================================================================
# 31: feedback only after submission
# ==========================================================================
def test_no_feedback_is_shown_before_a_response_is_recorded(flask_app, client):
    unlock(flask_app, client)
    page = client.get(PROBE)
    body = page.data.decode()

    # The authored principle, the quality labels and the classifications are
    # all absent from the probe page itself.
    assert DEFINITION.principle not in body
    for quality in ("Protective response", "Partial response",
                    "Risky response"):
        assert quality not in body
    for choice in DEFINITION.choices:
        assert choice.response_quality not in body

    response = client.get(PROBE_FEEDBACK)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/transfer/quishing")


def test_the_feedback_page_shows_the_authored_principle(flask_app, client):
    unlock(flask_app, client)
    respond(client, "verify_via_official_portal", 65)
    body = client.get(PROBE_FEEDBACK).data.decode()
    assert DEFINITION.principle in body
    assert "You chose this response with 65% confidence." in body
    assert "Protective response" in body
    for forbidden in ("mastery", "grade", "badge", "leaderboard", "points"):
        assert forbidden not in body.lower()


# ==========================================================================
# BA/BB: the probe is not a training execution
# ==========================================================================
def test_the_probe_creates_no_training_execution(flask_app, client):
    import app as app_module

    execution_id = unlock(flask_app, client)
    session_id = session_id_of(client)
    with flask_app.app_context():
        before = (app_module.TrainingExecution.query
                  .filter_by(session_id=session_id).count())

    client.get(PROBE)
    respond(client, "scan_and_sign_in")
    client.get(PROBE_FEEDBACK)

    with flask_app.app_context():
        after = (app_module.TrainingExecution.query
                 .filter_by(session_id=session_id).count())
    assert after == before

    # ... and the source execution row itself is untouched.
    assert execution_row(flask_app, execution_id).status == "completed"


def test_the_probe_emits_no_training_pair_lifecycle_events(flask_app, client):
    from training_service import SUCCESS_EVENT_ORDER

    execution_id = unlock(flask_app, client)
    before = training_event_types(flask_app, execution_id)
    assert before == list(SUCCESS_EVENT_ORDER)

    client.get(PROBE)
    respond(client, "scan_and_sign_in")
    client.get(PROBE_FEEDBACK)

    assert training_event_types(flask_app, execution_id) == before


def test_the_probe_runs_no_counterfactual_runtime(flask_app, client,
                                                  monkeypatch):
    import training.runtime as runtime_module

    unlock(flask_app, client)

    def refuse(*args, **kwargs):
        raise AssertionError("a transfer probe must not run the runtime")

    monkeypatch.setattr(runtime_module.CounterfactualRuntime,
                        "run_decision_pair", refuse)
    assert client.get(PROBE).status_code == 200
    assert respond(client, "scan_and_sign_in").status_code in (302, 303)
    assert client.get(PROBE_FEEDBACK).status_code == 200


def test_the_probe_needs_no_docker(flask_app, client, monkeypatch):
    import app as app_module

    def refuse(*args, **kwargs):
        raise AssertionError("a transfer probe must not reach the sandbox")

    unlock(flask_app, client)
    monkeypatch.setattr(app_module, "sandbox_manager", refuse)
    assert client.get(PROBE).status_code == 200
    respond(client, "report_qr_message")
    assert client.get(PROBE_FEEDBACK).status_code == 200


def test_the_probe_writes_no_concept_evidence_against_the_source_decision(
        flask_app, client):
    """A probe is its own measurement; it does not revise the source evidence."""
    execution_id = unlock(flask_app, client)
    before = [row.to_dict() for row in evidence(flask_app, execution_id)]
    respond(client, "scan_and_sign_in")
    assert [row.to_dict()
            for row in evidence(flask_app, execution_id)] == before


def test_no_free_text_input_exists_on_the_probe_or_its_feedback(flask_app,
                                                                client):
    unlock(flask_app, client)
    bodies = [client.get(PROBE).data]
    respond(client, "report_qr_message")
    bodies.append(client.get(PROBE_FEEDBACK).data)
    for body in bodies:
        text = body.decode().lower()
        assert "<textarea" not in text
        assert 'type="text"' not in text


def test_an_unknown_probe_slug_is_not_addressable(client):
    for path in ("/training/transfer/nope", "/training/transfer/nope/feedback",
                 "/training/transfer/quishing_portal_qr"):
        assert client.get(path).status_code == 404
