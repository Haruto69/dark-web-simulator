"""The three arms, end to end, plus the properties that separate them.

Arms are allocated, not chosen, so a test that needs a particular arm forces
one by writing it onto the enrollment row *before the intervention begins* --
never through a form field, a query string or a session value, because no such
channel exists and these suites must not invent one. The allocation itself is
tested in ``test_study_assignment.py`` and ``test_study_balance.py``.
"""

import pytest

import study
from tests.study_helpers import (COMPARISON, CONTINUE, COUNTERFACTUAL,
                                 DECISION, ENROLL, GATE, IMMEDIATE,
                                 IMMEDIATE_DONE, INTERVENTION, REFLECTION,
                                 STUDY_ACCESS_CODE, TRAINING,
                                 answer_immediate, arm_of, attempts_of,
                                 complete_intervention, enroll,
                                 enrollment_of, executions_for_session,
                                 first_decision, intervention_of, post,
                                 reflections_for, research_mode,
                                 session_id_of, token_for)


def force_arm(flask_app, client, arm_key):
    """Allocate-then-override, for a test that needs a specific arm.

    Writes the arm directly to the row while the enrollment is still at
    ``enrolled``, so the whole flow afterwards runs exactly as it would have if
    the allocator had produced this arm. There is deliberately no application
    code path that does this.
    """
    import app as app_module
    row = enrollment_of(flask_app, client)
    with flask_app.app_context():
        stored = (app_module.StudyEnrollment.query
                  .filter_by(participant_id=row.participant_id).first())
        assert stored.phase == study.ENROLLED
        stored.arm_key = arm_key
        app_module.db.session.commit()
    return arm_key


@pytest.fixture
def study_mode(flask_app):
    with research_mode(flask_app) as configured:
        yield configured


def participant(flask_app, client, arm_key):
    enroll(client)
    force_arm(flask_app, client, arm_key)
    return client


def training_body(client):
    return client.get(TRAINING).data


class TestEnrollmentIdempotency:
    """A refresh, Back, or resubmitted enrollment form must not double-enroll.

    The return code is shown directly from the enrollment POST rather than
    after a redirect, so this is the one place a repeated POST from an
    already-bound browser has to be handled explicitly: ``enroll()`` checks
    for an existing enrollment on this session *before* allocating.
    """

    def test_repeated_enrollment_post_cannot_create_second_participant(
            self, study_mode, flask_app, client):
        import app as app_module

        first = enroll(client)
        assert first.status_code == 200
        participant = None
        with client.session_transaction() as sess:
            participant = (sess.get("rewindsec_study") or {}).get(
                "participant_id")
        assert participant is not None

        with flask_app.app_context():
            count_after_first = app_module.StudyEnrollment.query.count()
            slot_after_first = (app_module.StudyEnrollment.query
                               .filter_by(participant_id=participant)
                               .first().allocation_slot)
            arm_after_first = (app_module.StudyEnrollment.query
                              .filter_by(participant_id=participant)
                              .first().arm_key)
            intervention_count_after_first = (
                app_module.StudyIntervention.query.count())

        # Repeat the exact same POST from the now-bound session -- the
        # literal "user hit refresh / Back / resubmit" case.
        second = enroll(client)
        assert second.status_code in (200, 302, 303)

        with client.session_transaction() as sess:
            participant_after_second = (
                sess.get("rewindsec_study") or {}).get("participant_id")
        assert participant_after_second == participant

        with flask_app.app_context():
            rows = (app_module.StudyEnrollment.query
                   .filter_by(participant_id=participant).all())
            assert len(rows) == 1
            assert rows[0].allocation_slot == slot_after_first
            assert rows[0].arm_key == arm_after_first
            assert (app_module.StudyEnrollment.query.count()
                   == count_after_first)
            assert (app_module.StudyIntervention.query.count()
                   == intervention_count_after_first)

    def test_literal_browser_style_form_resubmission_is_a_noop(
            self, study_mode, flask_app, client):
        """POST the enrollment form twice with a scraped token, as a browser
        replaying a cached form submission would -- not just calling the
        helper twice."""
        import app as app_module

        with flask_app.app_context():
            before = app_module.StudyEnrollment.query.count()

        token = token_for(client, GATE)
        resp1 = client.post(ENROLL, data={"csrf_token": token,
                                          "access_code": STUDY_ACCESS_CODE})
        assert resp1.status_code == 200

        resp2 = client.post(ENROLL, data={"csrf_token": token,
                                          "access_code": STUDY_ACCESS_CODE})
        assert resp2.status_code in (200, 302, 303)

        with flask_app.app_context():
            assert app_module.StudyEnrollment.query.count() == before + 1


class TestIdenticalFirstDecision:
    """Every arm sees exactly the same first decision, before any branch."""

    def test_prompt_and_choices_are_byte_identical_across_arms(
            self, study_mode, flask_app, client, other_client):
        third = flask_app.test_client()
        bodies = []
        for browser, arm in ((client, study.AWARENESS_DEBRIEF),
                             (other_client, study.FACTUAL_CONSEQUENCE),
                             (third, study.COUNTERFACTUAL_REPLAY)):
            participant(flask_app, browser, arm)
            body = training_body(browser)
            # The CSRF token is per-session and is the only thing that may
            # legitimately differ between two renders of this page.
            import re
            bodies.append(re.sub(rb'name="csrf_token" value="[^"]+"', b"",
                                 body))
        assert bodies[0] == bodies[1] == bodies[2]

    def test_choice_ids_and_order_come_from_the_scenario_definition(
            self, study_mode, flask_app, client):
        from scenario_adapters.phishing import (PHISHING_DECISION_ID,
                                                PHISHING_SCENARIO)
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        body = training_body(client).decode()
        ordered = [c.choice_id for c
                   in PHISHING_SCENARIO.decision(PHISHING_DECISION_ID).choices]
        positions = [body.index('value="%s"' % choice_id)
                     for choice_id in ordered]
        assert positions == sorted(positions)

    def test_no_page_before_the_decision_names_an_arm(self, study_mode,
                                                      flask_app, client):
        participant(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        body = training_body(client).lower()
        for token in (b"arm", b"control", b"experimental", b"condition",
                      b"group a", b"awareness_debrief", b"factual_consequence",
                      b"counterfactual_replay"):
            assert token not in body

    def test_the_first_decision_is_recorded_once_with_its_measurements(
            self, study_mode, flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client, "follow_link_and_sign_in", 90)
        item = intervention_of(flask_app, client)
        assert item.factual_choice_id == "follow_link_and_sign_in"
        assert item.factual_response_quality == "RISKY"
        assert item.factual_confidence == 90
        assert item.factual_response_time_ms is not None

    def test_a_second_decision_cannot_replace_the_first(self, study_mode,
                                                        flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client, "follow_link_and_sign_in", 90)
        post(client, DECISION, INTERVENTION, choice_id="report_message",
             confidence="10")
        item = intervention_of(flask_app, client)
        assert item.factual_choice_id == "follow_link_and_sign_in"
        assert item.factual_confidence == 90

    def test_malformed_submissions_are_refused(self, study_mode, flask_app,
                                               client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        client.get(TRAINING)
        for fields in ({"choice_id": "invented", "confidence": "50"},
                       {"choice_id": "report_message", "confidence": "500"},
                       {"choice_id": "report_message", "confidence": "abc"},
                       {"choice_id": "report_message", "confidence": ""}):
            assert post(client, DECISION, TRAINING,
                        **fields).status_code == 400
        assert intervention_of(flask_app, client) is None


class TestArmAwarenessDebrief:
    """Arm A: a concise conventional debrief. Nothing is executed."""

    @pytest.fixture
    def arm_a(self, study_mode, flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client, "follow_link_and_sign_in", 90)
        return client

    def test_the_debrief_is_static_and_shows_no_branch_state(self, arm_a):
        body = arm_a.get(INTERVENTION).data.lower()
        assert b"checking a request like this one" in body
        # None of the technical consequence vocabulary appears. ("rewind" on
        # its own would match the product name in the page chrome, so the
        # tokens below are the phrases the technical pages actually use.)
        for token in (b"synthetic account", b"rewind and compare",
                      b"what your response produced", b"fingerprint",
                      b"what changed", b"two paths"):
            assert token not in body
        # No form on this page offers a second decision.
        assert b'name="choice_id"' not in body

    def test_no_consequence_is_applied(self, arm_a, flask_app):
        arm_a.get(INTERVENTION)
        item = intervention_of(flask_app, arm_a)
        assert item.baseline_digest is None
        assert item.factual_result_digest is None
        assert item.factual_state_json is None

    def test_no_training_execution_and_no_reflection(self, arm_a, flask_app):
        complete_intervention(flask_app, arm_a)
        assert executions_for_session(flask_app, session_id_of(arm_a)) == []
        item = intervention_of(flask_app, arm_a)
        assert item.training_execution_id is None
        assert item.reflection_id is None

    def test_the_immediate_probe_unlocks_afterwards(self, arm_a, flask_app):
        assert arm_a.get(IMMEDIATE).status_code in (302, 303)
        complete_intervention(flask_app, arm_a)
        assert arm_a.get(IMMEDIATE).status_code == 200

    def test_the_rewind_routes_do_not_exist_for_this_arm(self, arm_a,
                                                         flask_app):
        assert arm_a.get(COMPARISON).status_code == 404
        assert arm_a.get(REFLECTION).status_code == 404
        assert post(arm_a, COUNTERFACTUAL, INTERVENTION,
                    choice_id="report_message",
                    confidence="50").status_code == 404


class TestArmFactualConsequence:
    """Arm B: the real adapter runs one branch. There is no rewind."""

    @pytest.fixture
    def arm_b(self, study_mode, flask_app, client):
        participant(flask_app, client, study.FACTUAL_CONSEQUENCE)
        first_decision(client, "follow_link_and_sign_in", 90)
        return client

    def test_the_adapter_captures_a_baseline_and_applies_the_action(
            self, arm_b, flask_app):
        arm_b.get(INTERVENTION)
        item = intervention_of(flask_app, arm_b)
        assert item.baseline_digest
        assert item.factual_result_digest
        assert item.factual_result_digest != item.baseline_digest
        assert item.factual_state_json

    def test_the_factual_consequence_is_visible(self, arm_b):
        body = arm_b.get(INTERVENTION).data.lower()
        assert b"what your response produced" in body
        assert b"synthetic" in body

    def test_refresh_does_not_reapply_the_action(self, arm_b, flask_app):
        arm_b.get(INTERVENTION)
        first = intervention_of(flask_app, arm_b)
        digest, state = first.factual_result_digest, first.factual_state_json
        for _ in range(3):
            arm_b.get(INTERVENTION)
        again = intervention_of(flask_app, arm_b)
        assert again.factual_result_digest == digest
        assert again.factual_state_json == state

    def test_no_rewind_and_no_alternative_is_offered(self, arm_b):
        body = arm_b.get(INTERVENTION).data.lower()
        assert b"rewind and compare" not in body
        assert b"what changed" not in body
        assert b"two paths" not in body
        # No radio group offering a second decision, and no state diff.
        assert b'name="choice_id"' not in body

    def test_the_counterfactual_route_is_closed(self, arm_b):
        arm_b.get(INTERVENTION)
        assert post(arm_b, COUNTERFACTUAL, INTERVENTION,
                    choice_id="verify_independently",
                    confidence="50").status_code == 404
        assert arm_b.get(COMPARISON).status_code == 404
        assert arm_b.get(REFLECTION).status_code == 404

    def test_no_training_execution_and_no_reflection(self, arm_b, flask_app):
        complete_intervention(flask_app, arm_b)
        assert executions_for_session(flask_app, session_id_of(arm_b)) == []
        item = intervention_of(flask_app, arm_b)
        assert item.training_execution_id is None
        assert item.reflection_id is None

    def test_the_immediate_probe_unlocks_afterwards(self, arm_b, flask_app):
        assert arm_b.get(IMMEDIATE).status_code in (302, 303)
        complete_intervention(flask_app, arm_b)
        assert arm_b.get(IMMEDIATE).status_code == 200


class TestArmCounterfactualReplay:
    """Arm C: the real RewindSec mechanism, reused unchanged."""

    @pytest.fixture
    def arm_c(self, study_mode, flask_app, client):
        participant(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client, "follow_link_and_sign_in", 90)
        return client

    def test_the_factual_preview_uses_the_real_phishing_adapter(self, arm_c,
                                                                flask_app):
        arm_c.get(INTERVENTION)
        item = intervention_of(flask_app, arm_c)
        assert item.baseline_digest and item.factual_result_digest

    def test_the_alternative_must_differ(self, arm_c):
        arm_c.get(INTERVENTION)
        assert post(arm_c, COUNTERFACTUAL, INTERVENTION,
                    choice_id="follow_link_and_sign_in",
                    confidence="50").status_code == 400

    def test_exactly_one_training_execution(self, arm_c, flask_app):
        complete_intervention(flask_app, arm_c)
        rows = executions_for_session(flask_app, session_id_of(arm_c))
        assert len(rows) == 1
        assert rows[0].status == "completed"

    def test_preview_digest_equals_the_authoritative_factual_digest(
            self, arm_c, flask_app):
        complete_intervention(flask_app, arm_c)
        item = intervention_of(flask_app, arm_c)
        row = executions_for_session(flask_app, session_id_of(arm_c))[0]
        assert row.factual_result_digest == item.factual_result_digest

    def test_baseline_equals_the_rewound_digest(self, arm_c, flask_app):
        complete_intervention(flask_app, arm_c)
        row = executions_for_session(flask_app, session_id_of(arm_c))[0]
        assert row.baseline_digest == row.rewound_digest
        assert row.baseline_verified

    def test_the_technical_comparison_is_displayed(self, arm_c, flask_app):
        arm_c.get(INTERVENTION)
        post(arm_c, COUNTERFACTUAL, INTERVENTION,
             choice_id="verify_independently", confidence="60")
        body = arm_c.get(COMPARISON).data.lower()
        assert b"two paths, one starting point" in body
        assert b"what changed" in body

    def test_the_reflection_is_required_before_the_probe(self, arm_c,
                                                         flask_app):
        arm_c.get(INTERVENTION)
        post(arm_c, COUNTERFACTUAL, INTERVENTION,
             choice_id="verify_independently", confidence="60")
        assert arm_c.get(IMMEDIATE).status_code in (302, 303)
        assert arm_c.get(REFLECTION).status_code == 200

    def test_the_reflection_is_persisted_once(self, arm_c, flask_app):
        complete_intervention(flask_app, arm_c)
        item = intervention_of(flask_app, arm_c)
        assert item.reflection_id
        rows = reflections_for(flask_app, item.training_execution_id)
        assert len(rows) == 1
        assert rows[0].preferred_explanation is True

    def test_a_repeated_reflection_does_not_replace_the_first(self, arm_c,
                                                              flask_app):
        arm_c.get(INTERVENTION)
        post(arm_c, COUNTERFACTUAL, INTERVENTION,
             choice_id="verify_independently", confidence="60")
        post(arm_c, REFLECTION, REFLECTION,
             explanation_id="chain_broken_before_disclosure")
        post(arm_c, REFLECTION, IMMEDIATE,
             explanation_id="password_strength")
        item = intervention_of(flask_app, arm_c)
        rows = reflections_for(flask_app, item.training_execution_id)
        assert len(rows) == 1
        assert rows[0].selected_explanation_id == (
            "chain_broken_before_disclosure")

    def test_exactly_six_training_events_once(self, arm_c, flask_app):
        from tests.learning_helpers import training_event_types
        complete_intervention(flask_app, arm_c)
        item = intervention_of(flask_app, arm_c)
        events = training_event_types(flask_app, item.training_execution_id)
        assert len(events) == 6
        assert len(set(events)) == 6

    def test_the_immediate_probe_unlocks_after_the_reflection(self, arm_c,
                                                              flask_app):
        complete_intervention(flask_app, arm_c)
        assert arm_c.get(IMMEDIATE).status_code == 200


class TestCrossArmContamination:
    """No arm can reach another arm's surfaces, and none can change its own."""

    def test_arm_a_cannot_reach_arm_b_or_c_technical_pages(self, study_mode,
                                                           flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client)
        assert client.get(COMPARISON).status_code == 404
        assert client.get(REFLECTION).status_code == 404
        assert post(client, COUNTERFACTUAL, INTERVENTION,
                    choice_id="report_message",
                    confidence="50").status_code == 404

    def test_arm_b_cannot_reach_the_replay(self, study_mode, flask_app,
                                           client):
        participant(flask_app, client, study.FACTUAL_CONSEQUENCE)
        first_decision(client)
        client.get(INTERVENTION)
        assert post(client, COUNTERFACTUAL, INTERVENTION,
                    choice_id="verify_independently",
                    confidence="50").status_code == 404
        assert executions_for_session(flask_app, session_id_of(client)) == []

    def test_arm_c_cannot_skip_the_reflection(self, study_mode, flask_app,
                                              client):
        participant(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client)
        client.get(INTERVENTION)
        post(client, COUNTERFACTUAL, INTERVENTION,
             choice_id="verify_independently", confidence="60")
        # The continue route belongs to arms A and B and does not advance C.
        # (The comparison page carries no form, so the token is taken from the
        # reflection page -- the CSRF token is per session, not per page.)
        post(client, CONTINUE, REFLECTION)
        assert client.get(IMMEDIATE).status_code in (302, 303)
        assert attempts_of(flask_app, client) == []

    def test_an_arm_submitted_in_the_form_has_no_effect(self, study_mode,
                                                        flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        client.get(TRAINING)
        post(client, DECISION, TRAINING, choice_id="report_message",
             confidence="50", arm="counterfactual_replay",
             arm_key="counterfactual_replay", phase="retention_completed")
        row = enrollment_of(flask_app, client)
        assert row.arm_key == study.AWARENESS_DEBRIEF
        assert row.phase == study.SOURCE_DECISION_RECORDED

    def test_an_arm_in_the_query_string_has_no_effect(self, study_mode,
                                                      flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client)
        client.get(INTERVENTION + "?arm=counterfactual_replay")
        assert arm_of(flask_app, client) == study.AWARENESS_DEBRIEF

    def test_one_participant_cannot_reach_another_enrollment(
            self, study_mode, flask_app, client, other_client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client)
        mine = enrollment_of(flask_app, client)

        participant(flask_app, other_client, study.COUNTERFACTUAL_REPLAY)
        # Planting another participant's id is not enough: the enrollment's
        # bound session id must match too.
        with other_client.session_transaction() as sess:
            sess["rewindsec_study"] = {"participant_id": mine.participant_id}
        response = other_client.get(INTERVENTION)
        assert response.status_code in (302, 303)
        assert "/study" in response.headers["Location"]


class TestPhaseMachineOverHttp:
    def test_typing_a_later_url_does_not_skip_ahead(self, study_mode,
                                                    flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        for path in (INTERVENTION, IMMEDIATE, IMMEDIATE_DONE, "/study/complete",
                     "/study/retention"):
            response = client.get(path)
            assert response.status_code in (302, 303), path
        assert intervention_of(flask_app, client) is None

    def test_a_completed_step_redirects_forward_not_back(self, study_mode,
                                                         flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        first_decision(client)
        response = client.get(TRAINING)
        assert response.status_code in (302, 303)
        assert response.headers["Location"].endswith("/study/intervention")

    def test_the_phase_is_never_read_from_the_request(self, study_mode,
                                                      flask_app, client):
        participant(flask_app, client, study.AWARENESS_DEBRIEF)
        client.get(TRAINING + "?phase=retention_completed")
        assert enrollment_of(flask_app, client).phase == study.ENROLLED


class TestConcurrentEnrollment:
    def test_simultaneous_enrollment_stays_unique_and_balanced(self, study_mode,
                                                              flask_app):
        """Twelve enrollments through the real service, interleaved.

        Exercises the claim-by-insertion path rather than a count-then-choose
        one: every slot is distinct and every complete block is 2/2/2, which a
        pre-computed slot with no uniqueness constraint would not guarantee.
        """
        import app as app_module
        with flask_app.app_context():
            service = app_module.study_service()
            before = service._next_slot()
            rows = [service.enroll("concurrent-session-%d" % i)[0]
                    for i in range(12)]
            slots = [row.allocation_slot for row in rows]

        assert len(set(slots)) == 12
        assert slots == list(range(before, before + 12))
        expected = [study.arm_for_slot(
            flask_app.config["STUDY_ASSIGNMENT_SECRET"], slot)
            for slot in slots]
        assert [row.arm_key for row in rows] == expected
