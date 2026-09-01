"""Milestone 3, section 4: SecurityEvent is the single telemetry model."""

import pytest
import sqlalchemy

from conftest import csrf_for, login_instructor, ransomware_post
from sandbox import EventType
from sandbox.progression import (EXPECTED_SEQUENCES, PHISHING_FUNNEL,
                                 RANSOMWARE_FUNNEL, completeness,
                                 conversion_rates, funnel_counts, is_ordered,
                                 matches_expected_sequence, scenario_progress)

LEGACY_TABLES = ("phishing_funnel", "ransomware_funnel", "simulated_credential")


# -- the legacy analytics system is gone -------------------------------------

@pytest.mark.parametrize("table", LEGACY_TABLES)
def test_legacy_tables_are_dropped(flask_app, table):
    import app as app_module
    with flask_app.app_context():
        inspector = sqlalchemy.inspect(app_module.db.engine)
        assert table not in inspector.get_table_names()


@pytest.mark.parametrize("model", ["PhishingFunnel", "RansomwareFunnel",
                                   "SimulatedCredential"])
def test_legacy_models_are_gone(flask_app, model):
    import app as app_module
    assert not hasattr(app_module, model)


def test_only_one_telemetry_table_remains(flask_app):
    import app as app_module
    with flask_app.app_context():
        tables = set(sqlalchemy.inspect(app_module.db.engine).get_table_names())
    # Event telemetry lives in exactly one place.
    assert "security_event" in tables
    assert not (tables & set(LEGACY_TABLES))


# -- every event carries the required correlation fields ---------------------

# NOTE (UI consolidation pass): four tests used to live here, driving the
# *legacy* conference-simulator routes (``/product/<id>``, ``/phishing/*``,
# ``/marketplace/tools``, ``/download/tool/<id>``, ``/ransomware/activate``)
# that this pass removed:
#
#   * ``test_scenario_events_carry_the_required_fields`` and
#     ``test_ransomware_routes_emit_correlated_security_events`` asserted that
#     every scenario event carries session/scenario/type/timestamp/source and
#     shares one correlated scenario id across a run. That invariant is still
#     exercised for the current architecture by
#     ``test_phishing_training_flow.py`` and ``test_ransomware_training_flow.py``
#     (``all_events``/``training_event_types`` helpers, ``run_full_flow``).
#   * ``test_no_event_ever_carries_a_password`` is superseded by
#     ``test_phishing_training_flow.py::test_phishing_training_never_persists_submitted_password``
#     and ``test_counterfactual_signin_password_is_never_persisted``, which
#     check the same invariant against the current sign-in routes.
#   * ``test_dashboard_funnel_counts_track_security_events`` asserted a
#     stage-conversion funnel keyed on the legacy ``RANSOMWARE_LURE_VIEWED``
#     event and rendered on ``/dashboard``. The instructor dashboard no longer
#     computes or renders that funnel (the legacy routes that produced its
#     inputs are gone); the current dashboard's descriptive counts come
#     straight from the retained subsystems (TrainingExecution,
#     LearningReflection, TransferAttempt, StudyEnrollment, sandbox status) and
#     are covered by tests/test_ui_consolidation.py.
#
# They were removed rather than ported, since porting them would just
# duplicate coverage that already exists against the current routes.


def test_dashboard_renders_without_the_legacy_tables(instructor):
    page = instructor.get("/dashboard")
    assert page.status_code == 200
    assert b"Instructor console" in page.data
    assert b"marketplace" not in page.data.lower()


# -- progression helpers -----------------------------------------------------

def make_events(types, session_id="s1", scenario_id="sc1", start=0):
    return [{"event_type": t, "session_id": session_id,
             "scenario_id": scenario_id, "timestamp": start + index}
            for index, t in enumerate(types)]


def test_expected_sequences_are_defined_for_both_scenarios():
    assert set(EXPECTED_SEQUENCES) == {"file_impact", "credential_reuse_phishing"}
    for sequence in EXPECTED_SEQUENCES.values():
        assert sequence[0] == EventType.SCENARIO_STARTED
        assert sequence[-1] == EventType.SCENARIO_COMPLETED


def test_completeness_is_one_for_a_full_run():
    events = make_events(EXPECTED_SEQUENCES["file_impact"])
    score = completeness(events, "file_impact")
    assert score["ratio"] == 1.0
    assert score["missing"] == []


def test_completeness_reports_what_is_missing():
    partial = [e for e in EXPECTED_SEQUENCES["file_impact"]
               if e != EventType.FILE_IMPACT_COMPLETED]
    score = completeness(make_events(partial), "file_impact")
    assert score["captured"] == len(EXPECTED_SEQUENCES["file_impact"]) - 1
    assert score["missing"] == [EventType.FILE_IMPACT_COMPLETED]
    assert 0 < score["ratio"] < 1


def test_repeated_events_do_not_inflate_completeness():
    types = list(EXPECTED_SEQUENCES["file_impact"])
    inflated = types[:2] + [EventType.FILE_IMPACT] * 5 + types[3:]
    assert completeness(make_events(inflated), "file_impact")["ratio"] == 1.0


def test_exact_sequence_matching_collapses_legitimate_repeats():
    types = list(EXPECTED_SEQUENCES["file_impact"])
    with_repeats = types[:2] + [EventType.FILE_IMPACT] * 5 + types[3:]
    assert matches_expected_sequence(make_events(with_repeats), "file_impact")


def test_out_of_order_events_are_not_an_exact_match():
    types = list(EXPECTED_SEQUENCES["file_impact"])
    types[0], types[1] = types[1], types[0]
    assert not matches_expected_sequence(make_events(types), "file_impact")


def test_ordering_check_accepts_equal_timestamps():
    events = make_events(EXPECTED_SEQUENCES["file_impact"])
    for event in events:
        event["timestamp"] = 5
    assert is_ordered(events)


def test_ordering_check_rejects_a_backwards_timestamp():
    events = make_events(EXPECTED_SEQUENCES["file_impact"])
    events[-1]["timestamp"] = -1
    assert not is_ordered(events)


def test_scenario_progress_reports_the_furthest_stage():
    partial = list(EXPECTED_SEQUENCES["credential_reuse_phishing"])[:4]
    progress = scenario_progress(make_events(partial),
                                 "credential_reuse_phishing")
    assert progress["stages_reached"] == 4
    assert progress["completed"] is False
    assert progress["furthest_event"] == EventType.PHISHING_FORM_VIEWED

    full = scenario_progress(
        make_events(EXPECTED_SEQUENCES["credential_reuse_phishing"]),
        "credential_reuse_phishing")
    assert full["completed"] is True
    assert full["stages_reached"] == full["stages_total"]


def test_funnel_counts_and_conversions_are_derived_from_events():
    events = make_events([EventType.PHISHING_EXPOSED] * 4
                         + [EventType.PHISHING_FORM_VIEWED] * 2
                         + [EventType.CREDENTIAL_SUBMITTED])
    counts = funnel_counts(events, PHISHING_FUNNEL)
    assert counts == {"marketplace": 4, "payment": 2, "credentials": 1}

    rates = conversion_rates(counts, PHISHING_FUNNEL)
    assert rates["conv_1_2"] == 50.0
    assert rates["conv_2_3"] == 50.0
    assert rates["conv_total"] == 25.0


def test_conversion_rates_handle_an_empty_funnel():
    counts = funnel_counts([], RANSOMWARE_FUNNEL)
    assert set(counts.values()) == {0}
    assert conversion_rates(counts, RANSOMWARE_FUNNEL) == {
        "conv_1_2": 0.0, "conv_2_3": 0.0, "conv_total": 0.0}
