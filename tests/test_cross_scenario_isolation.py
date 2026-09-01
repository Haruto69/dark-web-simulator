"""Four scenarios coexist without leaking into one another (R5).

Choice labels and state sentences are both scenario-scoped. A choice id and a
state pointer are scenario-*local*: two scenarios may legitimately use the same
one, so resolution must never fall through to another scenario's vocabulary.

Also asserts the structural invariants R5 must not have broken: ``training/``
stays framework-independent, ``TrainingExecution`` keeps its schema, no second
event table appears, and no new event family is introduced.
"""

import ast
import inspect
import json

import pytest

from sandbox.events import EventType
from scenario_adapters import presentation
from scenario_adapters.bec import (BEC_BASELINE_STATE, BEC_SCENARIO,
                                   BEC_SCENARIO_KEY, BecConsequenceAdapter,
                                   ACTION_PAYMENT_AUTHORIZED)
from scenario_adapters.mfa import (MFA_BASELINE_STATE, MFA_SCENARIO,
                                   MFA_SCENARIO_KEY, MfaConsequenceAdapter,
                                   ACTION_APPROVED)
from scenario_adapters.phishing import PHISHING_SCENARIO, PHISHING_SCENARIO_KEY
from scenario_adapters.presentation import (CHOICE_LABEL_SOURCES,
                                            EMPTY_VOCABULARY,
                                            STATE_VOCABULARIES,
                                            choice_labels_for, describe_state,
                                            label_for_choice, vocabulary_for)
from scenario_adapters.ransomware import (RANSOMWARE_SCENARIO,
                                          RANSOMWARE_SCENARIO_KEY)
from training_service import SUCCESS_EVENT_ORDER

ALL_SCENARIOS = (PHISHING_SCENARIO, RANSOMWARE_SCENARIO, MFA_SCENARIO,
                 BEC_SCENARIO)
ALL_KEYS = tuple(s.scenario_key for s in ALL_SCENARIOS)


def applied(adapter_class, action_key):
    adapter = adapter_class()
    adapter.prepare()
    adapter.apply(action_key)
    return adapter.capture_state()


# -- BO/BP. isolated choice vocabularies ------------------------------------
def test_all_four_scenarios_have_their_own_registered_vocabularies():
    for scenario in ALL_SCENARIOS:
        assert scenario.scenario_key in CHOICE_LABEL_SOURCES
        assert scenario.scenario_key in STATE_VOCABULARIES
        labels = choice_labels_for(scenario.scenario_key)
        for point in scenario.decision_points:
            for choice in point.choices:
                assert labels[choice.choice_id] == choice.label


@pytest.mark.parametrize("owner", ALL_SCENARIOS)
def test_no_scenarios_choice_resolves_under_another_scenario_key(owner):
    others = [key for key in ALL_KEYS if key != owner.scenario_key]
    for point in owner.decision_points:
        for choice_id in point.choice_ids:
            for other in others:
                # Rendered neutrally as the id itself, never as another
                # scenario's label.
                assert label_for_choice(other, choice_id) == choice_id


def test_an_identical_choice_id_resolves_differently_per_scenario(monkeypatch):
    """BP. Two test vocabularies deliberately share one choice id."""
    monkeypatch.setitem(CHOICE_LABEL_SOURCES, "scenario_one",
                        lambda: {"same_id": "One's version"})
    monkeypatch.setitem(CHOICE_LABEL_SOURCES, "scenario_two",
                        lambda: {"same_id": "Two's version"})
    assert label_for_choice("scenario_one", "same_id") == "One's version"
    assert label_for_choice("scenario_two", "same_id") == "Two's version"


# -- BQ/BR. isolated state vocabularies -------------------------------------
def test_mfa_state_cannot_be_rendered_with_the_bec_vocabulary():
    state = applied(MfaConsequenceAdapter, ACTION_APPROVED)
    assert describe_state(state, vocabulary=vocabulary_for(MFA_SCENARIO_KEY))
    assert describe_state(state,
                          vocabulary=vocabulary_for(BEC_SCENARIO_KEY)) == []


def test_bec_state_cannot_be_rendered_with_the_phishing_vocabulary():
    state = applied(BecConsequenceAdapter, ACTION_PAYMENT_AUTHORIZED)
    assert describe_state(state, vocabulary=vocabulary_for(BEC_SCENARIO_KEY))
    assert describe_state(
        state, vocabulary=vocabulary_for(PHISHING_SCENARIO_KEY)) == []


@pytest.mark.parametrize("scenario_key", [
    "not_a_scenario", "", None, "mfa", "MFA_FATIGUE_RESPONSE"])
def test_an_unknown_scenario_key_renders_nothing(scenario_key):
    assert vocabulary_for(scenario_key) is EMPTY_VOCABULARY
    assert describe_state(MFA_BASELINE_STATE,
                          vocabulary=vocabulary_for(scenario_key)) == []
    assert choice_labels_for(scenario_key) == {}


def test_every_scenario_renders_its_own_baseline_and_no_other_scenarios():
    """Each vocabulary describes its own state and stays silent on others."""
    states = {MFA_SCENARIO_KEY: MFA_BASELINE_STATE,
              BEC_SCENARIO_KEY: BEC_BASELINE_STATE}
    for owner, state in states.items():
        assert describe_state(state, vocabulary=vocabulary_for(owner))
        for other in states:
            if other != owner:
                assert describe_state(
                    state, vocabulary=vocabulary_for(other)) == []


def test_presentation_still_exposes_no_global_state_lookup():
    """Vocabulary resolution takes a scenario key, never a bare pointer."""
    assert list(inspect.signature(vocabulary_for).parameters) == [
        "scenario_key"]
    assert not hasattr(presentation, "_LABEL_SOURCES")


# -- BS. two modules in two sessions ----------------------------------------
BEC_SESSION_KEY = "rewindsec_training_bec"
MFA_SESSION_KEY = "rewindsec_training_mfa"


def _csrf(client, path):
    from tests.conftest import csrf_for
    return csrf_for(client, path)


def test_starting_mfa_does_not_corrupt_an_in_progress_bec_attempt(
        client, other_client, flask_app):
    from tests.test_bec_training_flow import (flow_session as bec_session,
                                              respond as bec_respond,
                                              start as bec_start)
    from tests.test_mfa_training_flow import (full_run as mfa_run,
                                              flow_session as mfa_session)

    bec_start(client)
    bec_respond(client, "authorize_payment", 70)
    mid_attempt = bec_session(client)
    assert mid_attempt["preview_digest"]

    # A different learner runs the whole MFA module in their own session.
    mfa_run(other_client, "approve_request", "deny_and_report")

    assert bec_session(client) == mid_attempt
    assert mfa_session(client) == {}


def test_the_two_modules_keep_independent_state_in_one_session(client,
                                                               flask_app):
    """One browser may have an attempt open in each module at once."""
    from tests.test_bec_training_flow import (flow_session as bec_session,
                                              respond as bec_respond,
                                              start as bec_start)
    from tests.test_mfa_training_flow import (flow_session as mfa_session,
                                              respond as mfa_respond,
                                              start as mfa_start)

    bec_start(client)
    bec_respond(client, "authorize_payment", 60)
    bec_before = bec_session(client)

    mfa_start(client)
    mfa_respond(client, "deny_and_report", 40)

    assert bec_session(client) == bec_before
    assert mfa_session(client)["factual_choice"] == "deny_and_report"
    assert (mfa_session(client)["baseline_digest"]
            != bec_session(client)["baseline_digest"])


def test_each_module_stores_its_own_scenario_identity(client, flask_app):
    from tests.test_bec_training_flow import (full_run as bec_run,
                                              session_id_of)
    from tests.test_mfa_training_flow import full_run as mfa_run

    mfa_run(client, "approve_request", "deny_and_report")
    bec_run(client, "authorize_payment", "verify_via_known_contact")

    import app as app_module
    with flask_app.app_context():
        rows = (app_module.TrainingExecution.query
                .filter_by(session_id=session_id_of(client))
                .order_by(app_module.TrainingExecution.id.asc()).all())
    identities = {(r.scenario_key, r.scenario_version, r.decision_id)
                  for r in rows}
    assert identities == {
        (MFA_SCENARIO_KEY, 1, "respond_to_unexpected_mfa_prompt"),
        (BEC_SCENARIO_KEY, 1, "respond_to_payment_change_request")}
    # Two distinct experiments, never merged into one pair.
    assert len({r.pair_id for r in rows}) == 2


# -- BV..BX. the structural invariants --------------------------------------
FRAMEWORK_MODULES = ("flask", "sqlalchemy", "sandbox", "docker",
                     "scenario_adapters", "app", "training_service",
                     "training_routes", "training_flow")


def _imports_of(path):
    import io
    tree = ast.parse(io.open(path, encoding="utf-8").read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            names.add(node.module.split(".")[0])
    return names


def test_training_package_remains_framework_independent():
    """BV. R5 added no application dependency to the pure runtime."""
    import pathlib

    import training
    root = pathlib.Path(training.__file__).parent
    for path in root.rglob("*.py"):
        imported = _imports_of(str(path))
        assert not imported & set(FRAMEWORK_MODULES), (path.name, imported)


EXPECTED_COLUMNS = {
    "id", "execution_id", "pair_id", "session_id", "scenario_key",
    "scenario_version", "decision_id", "status", "created_at", "completed_at",
    "baseline_digest", "rewound_digest",
    "factual_choice_id", "factual_action_key", "factual_confidence",
    "factual_response_time_ms", "factual_result_digest",
    "counterfactual_choice_id", "counterfactual_action_key",
    "counterfactual_confidence", "counterfactual_response_time_ms",
    "counterfactual_result_digest",
    "factual_state_json", "counterfactual_state_json", "difference_json",
    "failure_type", "error_ref",
}


def test_training_execution_schema_is_unchanged(flask_app):
    """BW. R5 added no scenario-specific column."""
    import app as app_module
    columns = {c.name for c in app_module.TrainingExecution.__table__.columns}
    assert columns == EXPECTED_COLUMNS


#: The tables that existed before R5. R5 introduces none.
PRE_R5_TABLES = {
    "security_event", "training_execution", "progression_milestone",
    "demo_file", "ransomware_run_state", "credential_interaction", "product",
}

#: R6 adds exactly three, and every one is a *learning artifact* keyed by
#: ``execution_id``. None of them is an event table: ``security_event`` remains
#: the single ordered timeline, and R6 adds no event types to it.
R6_LEARNING_TABLES = {
    "learning_reflection", "concept_evidence", "transfer_attempt",
}

#: R7 adds exactly three more, and every one is a *research artifact* keyed by
#: an enrollment. None of them is an event table either: R7 declares no
#: ``STUDY_*`` event type and opens no second event stream, because the study
#: artifacts already carry the timestamps a study needs.
R7_STUDY_TABLES = {
    "study_enrollment", "study_intervention", "study_assessment_attempt",
}

ARTIFACT_TABLES = R6_LEARNING_TABLES | R7_STUDY_TABLES


def test_no_new_event_table_exists(flask_app):
    """BX. Still exactly one event stream; R6's and R7's additions are artifacts."""
    import app as app_module
    tables = set(app_module.db.metadata.tables)
    assert tables == PRE_R5_TABLES | ARTIFACT_TABLES
    # security_event stays the one ordered timeline: no table added since R5
    # is an event log, and neither R6 nor R7 declares a new event type at all.
    assert all("event" not in name for name in ARTIFACT_TABLES)
    for name in tables:
        assert not any(word in name for word in ("mfa", "bec", "payment",
                                                 "invoice"))


def test_the_training_lifecycle_is_the_only_event_family(flask_app):
    assert len(SUCCESS_EVENT_ORDER) == 6
    for name in dir(EventType):
        assert not name.startswith(("MFA_", "BEC_", "PAYMENT_", "INVOICE_"))


# -- BT/BU. the earlier milestones still pass -------------------------------
def test_r3_and_r4_scenarios_are_untouched():
    """A cheap structural guard; the R3/R4 suites are the real check."""
    assert PHISHING_SCENARIO.version == 1
    assert RANSOMWARE_SCENARIO.version == 1
    assert len(PHISHING_SCENARIO.decision_points) == 1
    assert len(RANSOMWARE_SCENARIO.decision_points) == 1
    assert json.loads(json.dumps(MFA_BASELINE_STATE)) == MFA_BASELINE_STATE
    assert json.loads(json.dumps(BEC_BASELINE_STATE)) == BEC_BASELINE_STATE
