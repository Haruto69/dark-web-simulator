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

def test_scenario_events_carry_the_required_fields(client, other_client):
    from test_phishing_scenario import run_full_scenario
    run_full_scenario(client)

    instructor = login_instructor(other_client)
    events = instructor.get("/sandbox/events?limit=500").get_json()["events"]
    scenario_events = [e for e in events
                       if e["source"] == "scenario:credential_reuse_phishing"]
    assert scenario_events
    for event in scenario_events:
        assert event["session_id"], "every event must name its session"
        assert event["scenario_id"], "every event must name its scenario"
        assert event["event_type"]
        assert event["timestamp"]
        assert event["source"]


def test_ransomware_routes_emit_correlated_security_events(client, other_client):
    client.get("/marketplace/tools")
    client.get("/download/tool/1")
    ransomware_post(client, "/ransomware/activate")

    # Scope to *this* client's run. The events table is shared across the test
    # session, so filtering only by source would also pick up ransomware events
    # emitted by other tests and make the correlation assertions below
    # accidentally depend on test ordering.
    with client.session_transaction() as flask_session:
        own_session_id = flask_session["session_id"]

    instructor = login_instructor(other_client)
    events = instructor.get("/sandbox/events?limit=500").get_json()["events"]
    ransomware = [e for e in events
                  if e["source"] == "scenario:ransomware_awareness"
                  and e["session_id"] == own_session_id]
    assert ransomware

    types = [e["event_type"] for e in ransomware]
    for expected in (EventType.RANSOMWARE_LURE_VIEWED,
                     EventType.RANSOMWARE_DOWNLOAD_CLICKED,
                     EventType.RANSOMWARE_TRIGGERED):
        assert expected in types

    # One correlated scenario id across the whole run, one session.
    assert len({e["scenario_id"] for e in ransomware}) == 1
    assert len({e["session_id"] for e in ransomware}) == 1


def test_no_event_ever_carries_a_password(client, other_client, flask_app):
    from test_phishing_scenario import consent, identities_for, submit
    secret = "UNIFIED-TELEMETRY-SECRET-77"
    consent(client)
    submit(client, identities_for(client)[0][0], secret)

    import app as app_module
    with flask_app.app_context():
        for row in app_module.SecurityEvent.query.all():
            blob = "%s %s %s" % (row.target or "", row.details or "",
                                 row.source or "")
            assert secret not in blob


# -- the dashboard derives its funnel from events ----------------------------

def test_dashboard_funnel_counts_track_security_events(client, other_client,
                                                       flask_app):
    instructor = login_instructor(other_client)

    import app as app_module
    with flask_app.app_context():
        before = app_module.SecurityEvent.query.filter_by(
            event_type=EventType.RANSOMWARE_LURE_VIEWED).count()

    assert instructor.get("/dashboard").status_code == 200
    client.get("/marketplace/tools")

    with flask_app.app_context():
        after = app_module.SecurityEvent.query.filter_by(
            event_type=EventType.RANSOMWARE_LURE_VIEWED).count()
    assert after == before + 1
    assert instructor.get("/dashboard").status_code == 200


def test_dashboard_renders_without_the_legacy_tables(instructor):
    page = instructor.get("/dashboard")
    assert page.status_code == 200
    assert b"Conference Sandbox" in page.data


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
