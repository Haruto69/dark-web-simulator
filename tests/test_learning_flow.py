"""The structured self-explanation and learning feedback flow, end to end.

Driven through the real Flask app, the real R1 runtime, the real R2 service and
the real R6 learning service, for all four shipped scenarios. No Docker daemon
is involved anywhere in this module -- including for the ransomware scenario,
whose completed execution is produced without one (see
``tests/learning_helpers``).
"""

import json

import pytest

import learning
from learning import assessment as A
from tests.conftest import csrf_for
from tests.learning_helpers import (FEEDBACK, REFLECTION, SESSION_KEYS,
                                    attempts, complete_phishing,
                                    complete_ransomware_execution,
                                    complete_synthetic, evidence,
                                    execution_id_of, execution_row, post,
                                    preferred_explanation_id, reflections,
                                    session_id_of, submit_reflection,
                                    training_event_types)

#: ``module -> (scenario_key, factual choice, counterfactual choice)``.
#: The factual choice is risky and stated with high confidence in every case,
#: so the interesting signal is exercised for all four.
MODULES = {
    "phishing": (learning.PHISHING, "follow_link_and_sign_in",
                 "verify_independently"),
    "ransomware": (learning.RANSOMWARE, "continue_working",
                   "isolate_and_report"),
    "mfa": (learning.MFA, "approve_request", "deny_and_report"),
    "bec": (learning.BEC, "authorize_payment", "verify_via_known_contact"),
}

ALL_MODULES = sorted(MODULES)


def complete(flask_app, client, module):
    """Complete ``module``'s technical comparison and return its execution id."""
    _scenario, factual, counterfactual = MODULES[module]
    if module == "phishing":
        return complete_phishing(flask_app, client, factual, counterfactual)
    if module == "ransomware":
        return complete_ransomware_execution(flask_app, client, factual,
                                             counterfactual)
    return complete_synthetic(client, module, factual, counterfactual)


# ==========================================================================
# W/X: the reflection is unavailable without an owned, completed execution
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_reflection_is_unavailable_without_a_completed_execution(client,
                                                                 module):
    response = client.get(REFLECTION % module)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].rstrip("/").endswith("/training")
    assert client.get(FEEDBACK % module).status_code in (302, 303)


@pytest.mark.parametrize("module", ALL_MODULES)
def test_reflection_is_unavailable_for_another_sessions_execution(
        flask_app, client, other_client, module):
    """One learner's execution is not reachable from another's browser.

    There is no address to try: the execution id lives only in the owner's
    server-side session. Planting it in a second session's state still fails,
    because the loaded row's ``session_id`` is checked against the caller's.
    """
    execution_id = complete(flask_app, client, module)
    with other_client.session_transaction() as sess:
        sess[SESSION_KEYS[module]] = {"execution_id": execution_id}

    assert other_client.get(REFLECTION % module).status_code in (302, 303)
    submit_reflection(other_client, module, preferred_explanation_id(
        MODULES[module][0]))
    assert reflections(flask_app, execution_id) == []


@pytest.mark.parametrize("module", ALL_MODULES)
def test_a_row_from_another_scenario_is_not_reviewed_with_these_words(
        flask_app, client, module):
    """A mismatched execution under a module's key is refused, not rendered."""
    other = "bec" if module != "bec" else "mfa"
    execution_id = complete(flask_app, client, other)
    with client.session_transaction() as sess:
        sess[SESSION_KEYS[module]] = {"execution_id": execution_id}
    assert client.get(REFLECTION % module).status_code in (302, 303)


def test_an_unknown_module_is_not_addressable(client):
    for path in ("/training/learn/nope/reflection",
                 "/training/learn/phishing.evil/reflection",
                 "/training/learn/nope/feedback"):
        assert client.get(path).status_code == 404


# ==========================================================================
# Y: the reflection page renders only the authored options
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_reflection_page_renders_only_this_scenarios_authored_options(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    page = client.get(REFLECTION % module)
    assert page.status_code == 200
    body = page.data.decode()

    definition = learning.reflection_for(scenario_key)
    assert definition.prompt in body
    for option in definition.options:
        assert ('value="%s"' % option.explanation_id) in body
    # No other scenario's explanation ids appear anywhere on the page.
    for other_key, other in learning.REFLECTIONS.items():
        if other_key == scenario_key:
            continue
        for option in other.options:
            assert ('value="%s"' % option.explanation_id) not in body


# ==========================================================================
# AK: there is no free-text input anywhere in the flow
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_no_free_text_input_exists_on_the_reflection_or_feedback_pages(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    pages = [client.get(REFLECTION % module).data]
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    pages.append(client.get(FEEDBACK % module).data)
    for body in pages:
        text = body.decode().lower()
        assert "<textarea" not in text
        assert 'type="text"' not in text
        assert 'type="email"' not in text
        assert "contenteditable" not in text


# ==========================================================================
# Z: CSRF is required
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_reflection_post_requires_a_csrf_token(flask_app, client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    response = client.post(REFLECTION % module, data={
        "explanation_id": preferred_explanation_id(scenario_key)})
    assert response.status_code in (400, 403)
    assert reflections(flask_app, execution_id) == []


# ==========================================================================
# AA/AB/AC/AD: recorded once, and only once
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_a_valid_explanation_is_persisted_exactly_once(flask_app, client,
                                                       module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    chosen = preferred_explanation_id(scenario_key)

    response = submit_reflection(client, module, chosen)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/feedback")

    rows = reflections(flask_app, execution_id)
    assert len(rows) == 1
    row = rows[0]
    assert row.selected_explanation_id == chosen
    assert row.preferred_explanation is True
    assert row.scenario_key == scenario_key
    assert row.session_id == session_id_of(client)
    assert row.reflection_id.startswith("refl-")


@pytest.mark.parametrize("module", ALL_MODULES)
def test_refreshing_the_reflection_or_feedback_page_writes_nothing(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    before = [row.to_dict() for row in reflections(flask_app, execution_id)]
    evidence_before = [row.to_dict() for row in evidence(flask_app,
                                                         execution_id)]

    for _ in range(3):
        client.get(REFLECTION % module)
        client.get(FEEDBACK % module)

    assert [row.to_dict() for row in reflections(flask_app,
                                                 execution_id)] == before
    assert [row.to_dict() for row in evidence(flask_app,
                                              execution_id)] == evidence_before


@pytest.mark.parametrize("module", ALL_MODULES)
def test_a_repeat_post_cannot_change_the_first_recorded_explanation(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    definition = learning.reflection_for(scenario_key)
    first = definition.preferred.explanation_id
    other = next(o.explanation_id for o in definition.options
                 if not o.preferred)

    submit_reflection(client, module, first)
    response = submit_reflection(client, module, other)
    assert response.status_code in (302, 303)

    rows = reflections(flask_app, execution_id)
    assert len(rows) == 1
    assert rows[0].selected_explanation_id == first
    assert rows[0].preferred_explanation is True


@pytest.mark.parametrize("module", ALL_MODULES)
def test_visiting_the_reflection_again_goes_to_the_review_not_the_prompt(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    response = client.get(REFLECTION % module)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/feedback")


@pytest.mark.parametrize("module", ALL_MODULES)
def test_an_unauthored_explanation_is_refused(flask_app, client, module):
    execution_id = complete(flask_app, client, module)
    response = submit_reflection(client, module, "not_an_explanation")
    assert response.status_code == 400
    assert reflections(flask_app, execution_id) == []


def test_an_explanation_from_another_scenario_is_refused(flask_app, client):
    execution_id = complete(flask_app, client, "bec")
    response = submit_reflection(client, "bec",
                                 "isolation_stopped_progression")
    assert response.status_code == 400
    assert reflections(flask_app, execution_id) == []


# ==========================================================================
# AE/AF/AH: the factual choice is the behavioural evidence
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_assessment_uses_the_factual_choice_and_confidence(flask_app, client,
                                                           module):
    scenario_key, factual, counterfactual = MODULES[module]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))

    row = execution_row(flask_app, execution_id)
    assert row.factual_choice_id == factual
    assert row.counterfactual_choice_id == counterfactual

    expected = learning.assess_decision(scenario_key, factual,
                                        row.factual_confidence)
    alternative = learning.assess_decision(scenario_key, counterfactual,
                                           row.counterfactual_confidence)
    assert expected.response_quality == learning.RISKY
    assert alternative.response_quality != expected.response_quality

    decision_rows = evidence(flask_app, execution_id,
                             source="factual_decision")
    assert decision_rows
    for evidence_row in decision_rows:
        assert evidence_row.response_quality == expected.response_quality
        assert evidence_row.confidence == row.factual_confidence
        assert evidence_row.evidence_signal == expected.evidence_signal


@pytest.mark.parametrize("module", ALL_MODULES)
def test_the_counterfactual_choice_is_never_recorded_as_behavioural_evidence(
        flask_app, client, module):
    """The alternative is part of the intervention, not a second measurement."""
    scenario_key, _factual, counterfactual = MODULES[module]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))

    counterfactual_assessment = learning.assess_decision(
        scenario_key, counterfactual,
        execution_row(flask_app, execution_id).counterfactual_confidence)
    stored = {(row.concept_tag, row.evidence_signal, row.response_quality)
              for row in evidence(flask_app, execution_id,
                                  source="factual_decision")}
    for tag in counterfactual_assessment.concept_tags:
        assert (tag, counterfactual_assessment.evidence_signal,
                counterfactual_assessment.response_quality) not in stored


def test_high_confidence_risky_factual_choice_creates_misconception_candidate_evidence(
        flask_app, client):
    """The named R6 test: phishing, ``follow_link_and_sign_in``, confidence 90."""
    execution_id = complete_phishing(flask_app, client,
                                     "follow_link_and_sign_in",
                                     "verify_independently",
                                     factual_confidence=90)
    submit_reflection(client, "phishing",
                      preferred_explanation_id(learning.PHISHING))

    row = execution_row(flask_app, execution_id)
    assert row.factual_confidence == 90
    decision_rows = evidence(flask_app, execution_id,
                             source="factual_decision")
    assert decision_rows
    for evidence_row in decision_rows:
        assert evidence_row.response_quality == learning.RISKY
        assert evidence_row.evidence_signal == A.MISCONCEPTION_CANDIDATE

    # ... and the learner is never told they are misconceived.
    body = client.get(FEEDBACK % "phishing").data.decode().lower()
    for word in ("misconception", "misconceived", "diagnos", "mastery"):
        assert word not in body, word
    assert "may need reinforcement" in body


def test_fragile_protective_bec_response_creates_fragile_understanding_evidence(
        flask_app, client):
    """The named R6 test: BEC, ``verify_via_known_contact``, confidence 42."""
    execution_id = complete_synthetic(client, "bec",
                                      "verify_via_known_contact",
                                      "authorize_payment",
                                      factual_confidence=42)
    submit_reflection(client, "bec", preferred_explanation_id(learning.BEC))

    assert execution_row(flask_app, execution_id).factual_confidence == 42
    rows = evidence(flask_app, execution_id, source="factual_decision")
    assert rows
    for row in rows:
        assert row.response_quality == learning.PROTECTIVE
        assert row.evidence_signal == A.FRAGILE_UNDERSTANDING
        assert row.confidence == 42


# ==========================================================================
# AG: concept evidence is deterministic and idempotent
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_concept_evidence_is_derived_deterministically(flask_app, client,
                                                       module):
    scenario_key, factual, _counterfactual = MODULES[module]
    execution_id = complete(flask_app, client, module)
    chosen = preferred_explanation_id(scenario_key)
    submit_reflection(client, module, chosen)

    expected_decision = set(learning.concepts_for_choice(scenario_key, factual))
    expected_reflection = set(
        learning.reflection_for(scenario_key).preferred.concept_tags)

    assert {row.concept_tag for row in evidence(flask_app, execution_id,
                                                source="factual_decision")
            } == expected_decision
    assert {row.concept_tag for row in evidence(flask_app, execution_id,
                                                source="structured_reflection")
            } == expected_reflection


@pytest.mark.parametrize("module", ALL_MODULES)
def test_concept_evidence_is_not_duplicated_by_repeated_submission(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    chosen = preferred_explanation_id(scenario_key)

    for _ in range(3):
        submit_reflection(client, module, chosen)
        client.get(FEEDBACK % module)

    rows = evidence(flask_app, execution_id)
    keys = [(row.evidence_source, row.concept_tag) for row in rows]
    assert len(keys) == len(set(keys))


def test_evidence_carries_no_global_score_column(flask_app):
    """R6 stores signals, never an averaged number about a learner."""
    import app as app_module

    columns = set(app_module.ConceptEvidence.__table__.columns.keys())
    for forbidden in ("score", "mastery", "percentage", "grade", "level",
                      "rating"):
        assert not any(forbidden in name for name in columns), forbidden


# ==========================================================================
# AI/AJ: the feedback page renders from persisted data only
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_feedback_renders_from_the_persisted_execution_and_reflection(
        flask_app, client, module):
    scenario_key, factual, _counterfactual = MODULES[module]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))

    page = client.get(FEEDBACK % module)
    assert page.status_code == 200
    body = page.data.decode()

    row = execution_row(flask_app, execution_id)
    assessment = learning.assess_decision(scenario_key, factual,
                                          row.factual_confidence)
    from learning import feedback as F
    assert F.quality_label(assessment.response_quality) in body
    assert F.confidence_sentence(assessment) in body
    assert ("You chose this response with %d%% confidence."
            % row.factual_confidence) in body
    assert learning.reflection_for(scenario_key).preferred.text in body


@pytest.mark.parametrize("module", ALL_MODULES)
def test_feedback_is_unreachable_before_the_reflection_is_recorded(
        flask_app, client, module):
    complete(flask_app, client, module)
    response = client.get(FEEDBACK % module)
    assert response.status_code in (302, 303)
    assert response.headers["Location"].endswith("/reflection")


@pytest.mark.parametrize("module", ALL_MODULES)
def test_feedback_contains_no_raw_state_json_and_no_grade(flask_app, client,
                                                          module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    body = client.get(FEEDBACK % module).data.decode()

    row = execution_row(flask_app, execution_id)
    for stored in (row.factual_state_json, row.counterfactual_state_json,
                   row.difference_json):
        assert stored
        assert stored not in body
    # No fragment of the canonical state, either.
    for key in json.loads(row.factual_state_json):
        assert ('"%s"' % key) not in body

    lowered = body.lower()
    for forbidden in ("mastery", "score:", "grade", "badge", "points",
                      "leaderboard", "%  correct", "you have a misconception"):
        assert forbidden not in lowered, forbidden


@pytest.mark.parametrize("module", ALL_MODULES)
def test_feedback_never_trusts_a_submitted_classification(flask_app, client,
                                                          module):
    """Hidden fields claiming a quality or a signal change nothing."""
    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    path = REFLECTION % module
    post(client, path, path,
         explanation_id=preferred_explanation_id(scenario_key),
         response_quality="PROTECTIVE", evidence_signal="supporting_evidence",
         correct="1", confidence="5", confidence_band="high")

    execution_id = execution_id_of(client, module)
    expected = learning.assess_decision(
        scenario_key, MODULES[module][1],
        execution_row(flask_app, execution_id).factual_confidence)
    for row in evidence(flask_app, execution_id, source="factual_decision"):
        assert row.response_quality == expected.response_quality
        assert row.evidence_signal == expected.evidence_signal


# ==========================================================================
# 53: every result page offers the learning review
# ==========================================================================
@pytest.mark.parametrize("module", ["phishing", "mfa", "bec"])
def test_the_result_page_offers_the_learning_review(flask_app, client, module):
    """The three modules whose result page is reachable without Docker."""
    complete(flask_app, client, module)
    page = client.get("/training/%s/result" % module)
    assert page.status_code == 200
    body = page.data.decode()
    assert "Continue to learning review" in body
    assert ("/training/learn/%s/reflection" % module) in body
    # The technical comparison is still there, complete.
    assert "What changed" in body
    assert "Rewind path" in body


def test_the_ransomware_result_template_offers_the_learning_review():
    """The ransomware result page's CTA, checked at the template level.

    Its route needs the contained backend, which the HTTP suite deliberately
    does not provide; the template is what carries the call to action.
    """
    with open("templates/training_ransomware_result.html",
              encoding="utf-8") as handle:
        body = handle.read()
    assert 'learn_module = "ransomware"' in body
    assert "_training_learning_cta.html" in body


# ==========================================================================
# BT-BX: the completed technical pair is untouched by R6
# ==========================================================================
@pytest.mark.parametrize("module", ALL_MODULES)
def test_completing_the_learning_review_does_not_change_the_execution_row(
        flask_app, client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    before = execution_row(flask_app, execution_id).to_dict()

    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    client.get(FEEDBACK % module)
    client.get(REFLECTION % module)

    after = execution_row(flask_app, execution_id).to_dict()
    assert after == before
    assert after["pair_id"] == before["pair_id"]
    assert after["baseline_digest"] == after["rewound_digest"]
    assert after["baseline_verified"] is True


@pytest.mark.parametrize("module", ALL_MODULES)
def test_the_learning_review_creates_no_second_execution(flask_app, client,
                                                         module):
    import app as app_module

    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    session_id = session_id_of(client)
    with flask_app.app_context():
        before = (app_module.TrainingExecution.query
                  .filter_by(session_id=session_id,
                             scenario_key=scenario_key).count())

    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    client.get(FEEDBACK % module)

    with flask_app.app_context():
        after = (app_module.TrainingExecution.query
                 .filter_by(session_id=session_id,
                            scenario_key=scenario_key).count())
    assert after == before == 1


@pytest.mark.parametrize("module", ALL_MODULES)
def test_the_six_training_lifecycle_events_stay_exactly_six(flask_app, client,
                                                            module):
    from training_service import SUCCESS_EVENT_ORDER

    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    assert training_event_types(flask_app,
                                execution_id) == list(SUCCESS_EVENT_ORDER)

    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    client.get(FEEDBACK % module)
    client.get(REFLECTION % module)

    events = training_event_types(flask_app, execution_id)
    assert events == list(SUCCESS_EVENT_ORDER)
    assert len(events) == 6


def test_r6_adds_no_new_security_event_types():
    """The telemetry decision, asserted rather than only documented.

    R6 persists timestamped artifacts and adds no event taxonomy, so the
    declared universe is unchanged and ``sandbox.telemetry``'s partition
    assertion continues to hold.
    """
    from sandbox.events import ALL_EVENT_TYPES

    for event_type in ALL_EVENT_TYPES:
        assert "LEARNING" not in event_type
        assert "REFLECTION" not in event_type
        assert "TRANSFER" not in event_type
        assert "CONCEPT" not in event_type


# ==========================================================================
# BY: MFA and BEC finish at the feedback page, with no probe
# ==========================================================================
@pytest.mark.parametrize("module", ["mfa", "bec"])
def test_mfa_and_bec_finish_at_the_feedback_page_with_no_probe(flask_app,
                                                               client, module):
    scenario_key = MODULES[module][0]
    execution_id = complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))

    body = client.get(FEEDBACK % module).data.decode()
    assert "Return to training modules" in body
    assert "/training/transfer/" not in body
    assert attempts(flask_app, execution_id) == []


@pytest.mark.parametrize("module", ["mfa", "bec"])
def test_mfa_and_bec_learning_review_needs_no_docker(flask_app, client, module,
                                                     monkeypatch):
    """The whole R5 + R6 sequence, with the sandbox manager made unusable."""
    import app as app_module

    def refuse(*args, **kwargs):
        raise AssertionError("the learning layer must not reach the sandbox")

    monkeypatch.setattr(app_module, "sandbox_manager", refuse)
    scenario_key = MODULES[module][0]
    complete(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    assert client.get(FEEDBACK % module).status_code == 200


# ==========================================================================
# Ownership of the learning artifacts themselves
# ==========================================================================
def test_one_session_cannot_read_another_sessions_learning_artifacts(
        flask_app, client, other_client):
    execution_id = complete(flask_app, client, "mfa")
    submit_reflection(client, "mfa", preferred_explanation_id(learning.MFA))

    other_client.get("/training")
    with other_client.session_transaction() as sess:
        sess[SESSION_KEYS["mfa"]] = {"execution_id": execution_id}

    assert other_client.get(FEEDBACK % "mfa").status_code in (302, 303)
    assert len(reflections(flask_app, execution_id)) == 1


def test_authorisation_is_by_canonical_session_id_not_by_pseudonym(flask_app,
                                                                   client):
    """A pseudonymous label is a display artifact and never an authenticator."""
    import app as app_module

    execution_id = complete(flask_app, client, "mfa")
    submit_reflection(client, "mfa", preferred_explanation_id(learning.MFA))
    with flask_app.app_context():
        row = (app_module.LearningReflection.query
               .filter_by(execution_id=execution_id).first())
        assert row.session_id == session_id_of(client)
        display = row.display_dict()
    assert "session_id" not in display
    assert display["session_label"] != session_id_of(client)


def test_learning_service_refuses_an_execution_that_is_not_completed(
        flask_app, client):
    import app as app_module
    from learning_service import ExecutionNotEligibleError

    complete(flask_app, client, "mfa")
    execution_id = execution_id_of(client, "mfa")
    session_id = session_id_of(client)
    with flask_app.app_context():
        row = (app_module.TrainingExecution.query
               .filter_by(execution_id=execution_id).first())
        row.status = app_module.TrainingExecution.STATUS_STARTED
        app_module.db.session.commit()
        try:
            with pytest.raises(ExecutionNotEligibleError):
                app_module.learning_service().completed_execution(execution_id,
                                                                  session_id)
        finally:
            row.status = app_module.TrainingExecution.STATUS_COMPLETED
            app_module.db.session.commit()


# ==========================================================================
# Same-major-outcome comparisons
#
# Not every valid comparison is "one branch was safe, the other was not".
# Two protective responses differ in technical state while the major security
# outcome -- credential exposure, synthetic session creation, payment
# authorisation -- is the same on both. The reflection prompt and the learning
# feedback are scenario-level, so they must be correct for these too, and must
# never claim a major outcome differed when it did not.
#
# The technical state diff is deliberately *not* weakened here: it still shows
# the real differences, and these tests assert that it does.
# ==========================================================================

#: ``module -> (factual, counterfactual, {state pointer: shared value})``.
#: The pointers name the scenario's *major* outcome, which both responses leave
#: in the same place.
SAME_OUTCOME_CASES = {
    "phishing": (
        "inspect_sender", "report_message",
        {("identity", "exposed"): False,
         ("account", "synthetic_access"): False,
         ("resource", "accessed"): False},
    ),
    "mfa": (
        "deny_and_report", "verify_through_known_channel",
        {("mfa", "approved"): False,
         ("account", "synthetic_session_created"): False,
         ("resource", "accessed"): False},
    ),
    "bec": (
        "verify_via_known_contact", "escalate_to_finance_security",
        {("payment", "authorized"): False,
         ("payment", "synthetic_loss"): 0,
         ("message", "replied_to_unverified_thread"): False},
    ),
}

SAME_OUTCOME_MODULES = sorted(SAME_OUTCOME_CASES)

#: Phrases a page may not contain when the major outcome did not differ. A
#: fixed literal list, not natural-language analysis. Every entry is wording
#: that actually appeared before the semantic review, so the check bites.
DIVERGENCE_CLAIMS = (
    "why the paths differed",
    "why did the two paths differ",
    "different account-access outcomes",
    "produced different outcomes",
    "the two paths produced different",
    "change the account outcome",
    "changed the account outcome",
    "why did the response choice change how many",
    "stronger than replying",
    "make sense of the difference",
    "account for why they differed",
)


def complete_same_outcome(flask_app, client, module):
    factual, counterfactual, _shared = SAME_OUTCOME_CASES[module]
    if module == "phishing":
        return complete_phishing(flask_app, client, factual, counterfactual,
                                 factual_confidence=75,
                                 counterfactual_confidence=60)
    return complete_synthetic(client, module, factual, counterfactual,
                              factual_confidence=75,
                              counterfactual_confidence=60)


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_the_named_pair_really_does_share_its_major_security_outcome(
        flask_app, client, module):
    """Step 1, and the premise the rest of these cases rest on.

    Both branches are executed for real; this reads the *persisted* states and
    proves the major outcome is identical while the states still differ.
    """
    _factual, _counterfactual, shared = SAME_OUTCOME_CASES[module]
    execution_id = complete_same_outcome(flask_app, client, module)
    row = execution_row(flask_app, execution_id)

    factual_state = json.loads(row.factual_state_json)
    counterfactual_state = json.loads(row.counterfactual_state_json)
    for (section, key), value in shared.items():
        assert factual_state[section][key] == value, (section, key)
        assert counterfactual_state[section][key] == value, (section, key)

    # Both responses are protective, and the states are nonetheless different --
    # which is exactly why the technical diff must stay and the prompt must not
    # presuppose a divergent outcome.
    scenario_key = MODULES[module][0]
    assert learning.response_quality(
        scenario_key, row.factual_choice_id) == learning.PROTECTIVE
    assert learning.response_quality(
        scenario_key, row.counterfactual_choice_id) == learning.PROTECTIVE
    assert factual_state != counterfactual_state
    assert json.loads(row.difference_json)


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_the_reflection_does_not_claim_the_major_outcome_differed(flask_app,
                                                                  client,
                                                                  module):
    """Steps 2 and 3: the prompt is scenario-level and stays truthful."""
    scenario_key = MODULES[module][0]
    complete_same_outcome(flask_app, client, module)

    page = client.get(REFLECTION % module)
    assert page.status_code == 200
    body = page.data.decode()
    lowered = body.lower()

    for claim in DIVERGENCE_CLAIMS:
        assert claim not in lowered, claim

    # It is the same prompt the risky/protective comparison gets: the question
    # is about the scenario's principle, not about this particular pair.
    definition = learning.reflection_for(scenario_key)
    assert definition.prompt in body
    assert "principle" in lowered
    for option in definition.options:
        assert ('value="%s"' % option.explanation_id) in body


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_the_feedback_stays_semantically_correct_for_a_same_outcome_pair(
        flask_app, client, module):
    """Steps 4 and 5: submit the preferred explanation, then read the review."""
    from learning import feedback as F

    scenario_key = MODULES[module][0]
    execution_id = complete_same_outcome(flask_app, client, module)
    chosen = preferred_explanation_id(scenario_key)

    assert submit_reflection(client, module, chosen).status_code in (302, 303)
    page = client.get(FEEDBACK % module)
    assert page.status_code == 200
    body = page.data.decode()
    lowered = body.lower()

    # The neutral heading, and none of the divergence claims.
    assert "what the comparison shows" in lowered
    for claim in DIVERGENCE_CLAIMS:
        assert claim not in lowered, claim

    # The authored principle is shown, and the learner's selection matched it.
    definition = learning.reflection_for(scenario_key)
    assert definition.preferred.text in body
    assert "matches the explanation you selected" in lowered

    # The factual response is still reported as what it was: protective, at the
    # learner's own stated confidence.
    row = execution_row(flask_app, execution_id)
    assessment = learning.assess_decision(scenario_key, row.factual_choice_id,
                                          row.factual_confidence)
    assert assessment.response_quality == learning.PROTECTIVE
    assert F.quality_label(learning.PROTECTIVE) in body
    assert F.confidence_sentence(assessment) in body
    assert ("You chose this response with %d%% confidence."
            % row.factual_confidence) in body


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_a_same_outcome_pair_still_records_the_normal_evidence_semantics(
        flask_app, client, module):
    """The evidence semantics are unchanged by the wording fix.

    Factual choice -> behavioural evidence; counterfactual -> intervention
    context and never behavioural evidence; reflection -> explanation evidence.
    """
    scenario_key = MODULES[module][0]
    execution_id = complete_same_outcome(flask_app, client, module)
    submit_reflection(client, module, preferred_explanation_id(scenario_key))
    row = execution_row(flask_app, execution_id)

    factual_assessment = learning.assess_decision(
        scenario_key, row.factual_choice_id, row.factual_confidence)
    decision_rows = evidence(flask_app, execution_id,
                             source="factual_decision")
    assert {r.concept_tag for r in decision_rows} == set(
        factual_assessment.concept_tags)
    for evidence_row in decision_rows:
        assert evidence_row.response_quality == learning.PROTECTIVE
        assert evidence_row.confidence == row.factual_confidence
        assert evidence_row.evidence_signal == (
            factual_assessment.evidence_signal)

    # The counterfactual response's own concepts are not recorded as behaviour.
    counterfactual_only = set(learning.concepts_for_choice(
        scenario_key, row.counterfactual_choice_id)) - set(
            factual_assessment.concept_tags)
    assert counterfactual_only, "expected the pair to differ in concept tags"
    assert counterfactual_only.isdisjoint(
        {r.concept_tag for r in decision_rows})

    reflection_rows = evidence(flask_app, execution_id,
                               source="structured_reflection")
    assert {r.concept_tag for r in reflection_rows} == set(
        learning.reflection_for(scenario_key).preferred.concept_tags)


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_the_reflection_is_the_same_whichever_branch_was_factual(flask_app,
                                                                 client,
                                                                 other_client,
                                                                 module):
    """Reflection correctness does not depend on which choice was factual.

    Two learners run the same pair in opposite orders. They are asked the same
    question, the same preferred explanation is correct for both, and both
    reach a valid review.
    """
    scenario_key = MODULES[module][0]
    factual, counterfactual, _shared = SAME_OUTCOME_CASES[module]
    chosen = preferred_explanation_id(scenario_key)

    if module == "phishing":
        complete_phishing(flask_app, client, factual, counterfactual)
        complete_phishing(flask_app, other_client, counterfactual, factual)
    else:
        complete_synthetic(client, module, factual, counterfactual)
        complete_synthetic(other_client, module, counterfactual, factual)

    forward = client.get(REFLECTION % module).data.decode()
    reversed_ = other_client.get(REFLECTION % module).data.decode()
    definition = learning.reflection_for(scenario_key)
    for body in (forward, reversed_):
        assert definition.prompt in body
        for option in definition.options:
            assert ('value="%s"' % option.explanation_id) in body

    for browser in (client, other_client):
        assert submit_reflection(browser, module,
                                 chosen).status_code in (302, 303)
        review = browser.get(FEEDBACK % module)
        assert review.status_code == 200
        assert "matches the explanation you selected" in (
            review.data.decode().lower())

    # ... and each learner's own first response is what was assessed.
    assert (execution_row(flask_app, execution_id_of(client, module))
            .factual_choice_id == factual)
    assert (execution_row(flask_app, execution_id_of(other_client, module))
            .factual_choice_id == counterfactual)


@pytest.mark.parametrize("module", SAME_OUTCOME_MODULES)
def test_the_technical_state_comparison_is_not_weakened(flask_app, client,
                                                        module):
    """The factual comparison stays complete and keeps showing real diffs."""
    complete_same_outcome(flask_app, client, module)
    page = client.get("/training/%s/result" % module)
    assert page.status_code == 200
    body = page.data.decode()

    assert "What changed" in body
    assert "Your path" in body and "Rewind path" in body
    # A real difference is rendered, not the "no difference" fallback.
    assert "no difference in the recorded state" not in body
    assert "Continue to learning review" in body
