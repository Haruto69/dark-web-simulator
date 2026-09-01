"""The two study measurements: the immediate probe and the retention probe.

Two properties dominate this file.

**Feedback suppression.** In study mode, nothing after a probe tells the
participant anything about their answer. Feedback would be a further training
intervention sitting between the intervention under study and the outcome being
measured, and it would contaminate the retention probe that follows.

**The window.** The retention probe is inaccessible before it opens and after it
closes, and the boundaries are tested by moving the stored window rather than by
waiting a week.
"""

from datetime import timedelta

import pytest

import study
from tests.study_helpers import (COMPLETE, IMMEDIATE, IMMEDIATE_DONE,
                                 RETENTION, answer_immediate, answer_retention,
                                 attempts_of, complete_intervention,
                                 enroll, enrollment_of,
                                 executions_for_session, first_decision, post,
                                 research_mode, session_id_of, shift_window)
from tests.test_study_flow import force_arm


@pytest.fixture
def study_mode(flask_app):
    with research_mode(flask_app) as configured:
        yield configured


def ready(flask_app, client, arm_key=study.AWARENESS_DEBRIEF):
    """One participant, intervention finished, at the immediate probe."""
    enroll(client)
    force_arm(flask_app, client, arm_key)
    first_decision(client, "follow_link_and_sign_in", 90)
    complete_intervention(flask_app, client)
    return client


class TestImmediateProbeIsIdenticalAcrossArms:
    def test_the_same_probe_definition_in_every_arm(self, study_mode,
                                                    flask_app, client,
                                                    other_client):
        import re
        third = flask_app.test_client()
        bodies = []
        for browser, arm in ((client, study.AWARENESS_DEBRIEF),
                             (other_client, study.FACTUAL_CONSEQUENCE),
                             (third, study.COUNTERFACTUAL_REPLAY)):
            ready(flask_app, browser, arm)
            bodies.append(re.sub(rb'name="csrf_token" value="[^"]+"', b"",
                                 browser.get(IMMEDIATE).data))
        assert bodies[0] == bodies[1] == bodies[2]

    def test_it_is_the_authored_quishing_probe(self, study_mode, flask_app,
                                               client):
        ready(flask_app, client)
        probe = study.probe_for_phase(study.IMMEDIATE_TRANSFER)
        body = client.get(IMMEDIATE).data.decode()
        assert probe.title in body
        for choice in probe.choices:
            assert 'value="%s"' % choice.choice_id in body

    def test_choice_order_is_the_authored_order(self, study_mode, flask_app,
                                                client):
        ready(flask_app, client)
        body = client.get(IMMEDIATE).data.decode()
        probe = study.probe_for_phase(study.IMMEDIATE_TRANSFER)
        positions = [body.index('value="%s"' % c) for c in probe.choice_ids]
        assert positions == sorted(positions)


class TestImmediateProbeRecording:
    def test_the_first_response_is_stored_exactly_once(self, study_mode,
                                                       flask_app, client):
        ready(flask_app, client)
        answer_immediate(client, "verify_via_official_portal", 70)
        answer_immediate(client, "scan_and_sign_in", 10)
        rows = attempts_of(flask_app, client, study.IMMEDIATE_TRANSFER)
        assert len(rows) == 1
        assert rows[0].choice_id == "verify_via_official_portal"
        assert rows[0].confidence == 70
        assert rows[0].response_quality == "PROTECTIVE"
        assert rows[0].response_time_ms is not None

    @pytest.mark.parametrize("confidence", ["0", "100"])
    def test_the_confidence_bounds_are_accepted(self, study_mode, flask_app,
                                                client, confidence):
        ready(flask_app, client)
        client.get(IMMEDIATE)
        response = post(client, IMMEDIATE, IMMEDIATE,
                        choice_id="report_qr_message", confidence=confidence)
        assert response.status_code in (302, 303)
        assert attempts_of(flask_app, client,
                           study.IMMEDIATE_TRANSFER)[0].confidence == int(
                               confidence)

    @pytest.mark.parametrize("fields", [
        {"choice_id": "report_qr_message", "confidence": "101"},
        {"choice_id": "report_qr_message", "confidence": "-1"},
        {"choice_id": "report_qr_message", "confidence": "seven"},
        {"choice_id": "report_qr_message", "confidence": ""},
        {"choice_id": "invented_choice", "confidence": "50"},
        # A choice id belonging to the *other* probe is as invalid as an
        # invented one: classification is scoped by (phase, choice id).
        {"choice_id": "open_official_service", "confidence": "50"},
    ])
    def test_malformed_submissions_are_refused_and_store_nothing(
            self, study_mode, flask_app, client, fields):
        ready(flask_app, client)
        client.get(IMMEDIATE)
        assert post(client, IMMEDIATE, IMMEDIATE,
                    **fields).status_code == 400
        assert attempts_of(flask_app, client, study.IMMEDIATE_TRANSFER) == []

    def test_no_training_execution_or_reflection_is_created_by_a_probe(
            self, study_mode, flask_app, client):
        ready(flask_app, client, study.AWARENESS_DEBRIEF)
        answer_immediate(client)
        assert executions_for_session(flask_app, session_id_of(client)) == []


class TestNoFeedbackBeforeRetention:
    def test_the_completion_page_says_only_that_it_was_recorded(
            self, study_mode, flask_app, client):
        ready(flask_app, client)
        answer_immediate(client, "scan_and_sign_in", 95)
        body = client.get(IMMEDIATE_DONE).data.lower()
        assert b"response recorded" in body

    def test_no_quality_correctness_or_principle_is_revealed(
            self, study_mode, flask_app, client):
        ready(flask_app, client)
        answer_immediate(client, "scan_and_sign_in", 95)
        body = client.get(IMMEDIATE_DONE).data.lower()
        probe = study.probe_for_phase(study.IMMEDIATE_TRANSFER)
        for token in (b"protective", b"risky", b"partial", b"correct",
                      b"incorrect", b"better", b"should have",
                      probe.principle.lower()[:40].encode()):
            assert token not in body

    def test_the_probe_page_itself_carries_no_feedback(self, study_mode,
                                                       flask_app, client):
        ready(flask_app, client)
        body = client.get(IMMEDIATE).data.lower()
        for token in (b"protective", b"risky", b"partial", b"correct answer"):
            assert token not in body

    def test_the_normal_r6_transfer_feedback_is_unchanged(self, flask_app,
                                                          client):
        """Study mode suppresses feedback. The ordinary flow must not.

        Driven through the real non-study R3/R6 flow with research mode off, so
        this is exactly what an ordinary learner gets.
        """
        from tests.learning_helpers import (complete_phishing,
                                            preferred_explanation_id,
                                            submit_reflection)
        complete_phishing(flask_app, client)
        submit_reflection(client, "phishing",
                          preferred_explanation_id(study.SOURCE_SCENARIO_KEY))
        client.get("/training/transfer/quishing")
        post(client, "/training/transfer/quishing",
             "/training/transfer/quishing",
             choice_id="scan_and_sign_in", confidence="80")
        body = client.get("/training/transfer/quishing/feedback").data.lower()
        # The ordinary probe still tells the learner what their answer was and
        # states the authored principle.
        assert b"risky" in body
        assert study.probe_for_phase(
            study.IMMEDIATE_TRANSFER).principle.lower()[:30].encode() in body


class TestRetentionWindow:
    def test_the_window_is_scheduled_from_the_immediate_response(
            self, study_mode, flask_app, client):
        ready(flask_app, client)
        answer_immediate(client)
        row = enrollment_of(flask_app, client)
        assert row.immediate_transfer_completed_at is not None
        assert row.retention_open_at == (
            row.immediate_transfer_completed_at + timedelta(days=7))
        assert row.retention_close_at == (
            row.immediate_transfer_completed_at + timedelta(days=14))

    def test_inaccessible_before_the_window_opens(self, study_mode, flask_app,
                                                  client):
        ready(flask_app, client)
        answer_immediate(client)
        page = client.get(RETENTION)
        assert page.status_code == 200
        assert b"not quite yet" in page.data.lower()
        assert b'name="choice_id"' not in page.data

    def test_submission_before_the_window_is_refused(self, study_mode,
                                                     flask_app, client):
        ready(flask_app, client)
        answer_immediate(client)
        response = post(client, RETENTION, IMMEDIATE_DONE,
                        choice_id="open_official_service", confidence="50")
        assert response.status_code == 403
        assert attempts_of(flask_app, client, study.RETENTION_TRANSFER) == []

    def test_accessible_at_the_exact_opening_boundary(self, study_mode,
                                                      flask_app, client):
        """Arriving on the instant the window opens is admitted, not refused."""
        ready(flask_app, client)
        answer_immediate(client)
        # Move the window so it opens a moment ago: the boundary is inclusive,
        # and a strict inequality here would turn a punctual participant away.
        shift_window(flask_app, client, -timedelta(days=7, seconds=1))
        assert client.get(RETENTION).status_code == 200
        assert b'name="choice_id"' in client.get(RETENTION).data

    def test_accessible_inside_the_window(self, study_mode, flask_app, client):
        ready(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))
        page = client.get(RETENTION)
        assert page.status_code == 200
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        assert probe.title.encode() in page.data

    def test_inaccessible_after_the_window_closes(self, study_mode, flask_app,
                                                  client):
        ready(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=15))
        page = client.get(RETENTION)
        assert b"this part has closed" in page.data.lower()
        assert post(client, RETENTION, IMMEDIATE_DONE,
                    choice_id="open_official_service",
                    confidence="50").status_code == 403
        assert attempts_of(flask_app, client, study.RETENTION_TRANSFER) == []

    def test_an_expired_window_is_not_recorded_as_a_response(
            self, study_mode, flask_app, client):
        """Missing data stays missing; it never becomes a risky answer."""
        ready(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=20))
        client.get(RETENTION)
        row = enrollment_of(flask_app, client)
        assert row.retention_completed_at is None
        assert attempts_of(flask_app, client, study.RETENTION_TRANSFER) == []


class TestRetentionProbe:
    def _due(self, flask_app, client, arm=study.AWARENESS_DEBRIEF):
        ready(flask_app, client, arm)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))
        return client

    def test_the_probe_is_the_study_only_smishing_probe(self, study_mode,
                                                        flask_app, client):
        self._due(flask_app, client)
        body = client.get(RETENTION).data.decode()
        probe = study.probe_for_phase(study.RETENTION_TRANSFER)
        assert probe.title in body
        for choice in probe.choices:
            assert 'value="%s"' % choice.choice_id in body

    def test_it_carries_no_link_credential_field_or_destination(
            self, study_mode, flask_app, client):
        self._due(flask_app, client)
        body = client.get(RETENTION).data.decode().lower()
        # The page chrome carries the project's own stylesheet link; what must
        # be absent is any destination belonging to the probe itself.
        assert "http://" not in body
        assert 'type="password"' not in body
        assert "sms:" not in body and "tel:" not in body
        # No anchor anywhere in the probe's own content sections.
        assert "smishing" not in body

    def test_the_first_response_is_stored_exactly_once(self, study_mode,
                                                       flask_app, client):
        self._due(flask_app, client)
        answer_retention(client, "open_official_service", 65)
        answer_retention(client, "follow_message_and_sign_in", 5)
        rows = attempts_of(flask_app, client, study.RETENTION_TRANSFER)
        assert len(rows) == 1
        assert rows[0].choice_id == "open_official_service"
        assert rows[0].response_quality == "PROTECTIVE"
        assert rows[0].confidence == 65
        assert rows[0].probe_key == "smishing_account_notice"
        assert rows[0].probe_version == 1

    def test_a_repeat_post_returns_the_existing_result(self, study_mode,
                                                       flask_app, client):
        self._due(flask_app, client)
        answer_retention(client, "open_official_service", 65)
        response = post(client, RETENTION, COMPLETE,
                        choice_id="follow_message_and_sign_in",
                        confidence="99")
        assert response.status_code in (302, 303)
        rows = attempts_of(flask_app, client, study.RETENTION_TRANSFER)
        assert len(rows) == 1
        assert rows[0].choice_id == "open_official_service"

    def test_an_immediate_probe_choice_is_refused_here(self, study_mode,
                                                       flask_app, client):
        self._due(flask_app, client)
        client.get(RETENTION)
        assert post(client, RETENTION, RETENTION,
                    choice_id="scan_and_sign_in",
                    confidence="50").status_code == 400

    def test_no_training_execution_is_created(self, study_mode, flask_app,
                                              client):
        self._due(flask_app, client)
        answer_retention(client)
        assert executions_for_session(flask_app, session_id_of(client)) == []

    def test_completion_still_reveals_no_response_quality(self, study_mode,
                                                          flask_app, client):
        self._due(flask_app, client)
        answer_retention(client, "follow_message_and_sign_in", 95)
        body = client.get(COMPLETE).data.lower()
        assert b"that is everything" in body
        for token in (b"protective", b"risky", b"partial", b"incorrect"):
            assert token not in body

    def test_the_enrollment_is_marked_complete(self, study_mode, flask_app,
                                               client):
        self._due(flask_app, client)
        answer_retention(client)
        row = enrollment_of(flask_app, client)
        assert row.phase == study.RETENTION_COMPLETED
        assert row.status == "completed"
        assert row.retention_completed_at is not None

    def test_every_arm_answers_the_same_retention_probe(self, study_mode,
                                                        flask_app, client,
                                                        other_client):
        import re
        third = flask_app.test_client()
        bodies = []
        for browser, arm in ((client, study.AWARENESS_DEBRIEF),
                             (other_client, study.FACTUAL_CONSEQUENCE),
                             (third, study.COUNTERFACTUAL_REPLAY)):
            self._due(flask_app, browser, arm)
            bodies.append(re.sub(rb'name="csrf_token" value="[^"]+"', b"",
                                 browser.get(RETENTION).data))
        assert bodies[0] == bodies[1] == bodies[2]
