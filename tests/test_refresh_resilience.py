"""Milestone 4.2, section 2: refreshes and prefetches cannot inflate progression.

The property under test is the one that makes the funnel a measurement rather
than a request counter: for a given ``(session_id, scenario_id, event_type)``,
a progression milestone is recorded **once**, no matter how many times the route
that emits it is requested.

Every scenario is driven at 1, 5 and 20 requests and the progression outcome is
asserted identical across all three. Raw ``PAGE_VIEW`` telemetry is asserted to
grow with the request count, because throwing observation data away was never
the goal -- separating it from progression was.
"""

import pytest

from conftest import csrf_for, login_instructor, ransomware_post
from sandbox import EventType
from sandbox.progression import (PHISHING_FUNNEL, RANSOMWARE_FUNNEL,
                                 conversion_rates, for_scenario, funnel_counts,
                                 matches_expected_sequence, scenario_progress)
from sandbox.telemetry import PROGRESSION_EVENTS, drop_scoring_noise

#: The repetition counts the milestone asks for.
REPEATS = (1, 5, 20)


def session_id_of(client):
    with client.session_transaction() as flask_session:
        return flask_session["session_id"]


def events_for(flask_app, session_id):
    """This session's telemetry, in stored order."""
    import app as app_module
    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(session_id=session_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())
        return [{"event_type": r.event_type, "scenario_id": r.scenario_id,
                 "session_id": r.session_id, "timestamp": r.timestamp,
                 "target": r.target} for r in rows]


def milestones(events):
    return [e["event_type"] for e in events
            if e["event_type"] in PROGRESSION_EVENTS]


def type_count(events, event_type):
    return sum(1 for e in events if e["event_type"] == event_type)


def first_product_id(flask_app):
    import app as app_module
    with flask_app.app_context():
        return app_module.Product.query.order_by(
            app_module.Product.id.asc()).first().id


# -- a refreshed product page advances progression once ----------------------

@pytest.mark.parametrize("repeats", REPEATS)
def test_refreshing_a_product_page_exposes_the_lure_once(flask_app, repeats):
    client = flask_app.test_client()
    product_id = first_product_id(flask_app)

    for _ in range(repeats):
        assert client.get("/product/%d" % product_id).status_code == 200

    events = events_for(flask_app, session_id_of(client))
    assert milestones(events) == [EventType.SCENARIO_STARTED,
                                  EventType.PHISHING_EXPOSED]
    # ...while the raw page views scale with the requests, as they should.
    assert type_count(events, EventType.PAGE_VIEW) == repeats


def test_the_product_page_outcome_is_identical_at_1_5_and_20_requests(flask_app):
    product_id = first_product_id(flask_app)
    outcomes = []
    for repeats in REPEATS:
        client = flask_app.test_client()
        for _ in range(repeats):
            client.get("/product/%d" % product_id)
        outcomes.append(milestones(events_for(flask_app, session_id_of(client))))
    assert outcomes[0] == outcomes[1] == outcomes[2]


def test_a_refreshed_product_page_keeps_one_scenario_id(flask_app):
    """Twenty refreshes must be one run, not twenty runs stuck at stage 1."""
    client = flask_app.test_client()
    product_id = first_product_id(flask_app)
    for _ in range(20):
        client.get("/product/%d" % product_id)

    events = events_for(flask_app, session_id_of(client))
    assert len({e["scenario_id"] for e in events}) == 1


# -- repeated ransomware GETs do not advance the funnel ----------------------

@pytest.mark.parametrize("repeats", REPEATS)
def test_repeated_marketplace_and_download_gets_record_one_milestone_each(
        flask_app, repeats):
    client = flask_app.test_client()
    for _ in range(repeats):
        assert client.get("/marketplace/tools").status_code == 200
        assert client.get("/download/tool/1").status_code == 200

    events = events_for(flask_app, session_id_of(client))
    assert milestones(events) == [EventType.RANSOMWARE_LURE_VIEWED,
                                  EventType.RANSOMWARE_DOWNLOAD_CLICKED]
    assert type_count(events, EventType.PAGE_VIEW) == repeats * 2


@pytest.mark.parametrize("repeats", REPEATS)
def test_a_repeated_post_does_not_re_trigger_the_scenario(flask_app, repeats):
    """The guarantee is not GET-only: a resubmitted POST is idempotent too."""
    client = flask_app.test_client()
    client.get("/marketplace/tools")
    client.get("/download/tool/1")
    for _ in range(repeats):
        assert ransomware_post(client, "/ransomware/activate").status_code == 200

    events = events_for(flask_app, session_id_of(client))
    assert type_count(events, EventType.RANSOMWARE_TRIGGERED) == 1


# -- funnel counts and conversion rates are refresh-invariant ----------------

def run_ransomware_scenario(flask_app, repeats):
    """Drive a full ransomware run, requesting each GET ``repeats`` times."""
    client = flask_app.test_client()
    for _ in range(repeats):
        client.get("/ransomware/menu")
        client.get("/marketplace/tools")
        client.get("/download/tool/1")
        client.get("/files/browser")
    ransomware_post(client, "/ransomware/activate")
    for _ in range(repeats):
        client.get("/ransomware/screen")
    ransomware_post(client, "/ransomware/reveal")
    return client


def test_funnel_counts_are_identical_at_1_5_and_20_requests(flask_app):
    counts = []
    for repeats in REPEATS:
        client = run_ransomware_scenario(flask_app, repeats)
        events = events_for(flask_app, session_id_of(client))
        counts.append(funnel_counts(events, RANSOMWARE_FUNNEL))

    assert counts[0] == counts[1] == counts[2]
    assert counts[0] == {"menu": 1, "interaction": 1, "triggered": 1}


def test_conversion_rates_are_identical_at_1_5_and_20_requests(flask_app):
    rates = []
    for repeats in REPEATS:
        client = run_ransomware_scenario(flask_app, repeats)
        events = events_for(flask_app, session_id_of(client))
        rates.append(conversion_rates(
            funnel_counts(events, RANSOMWARE_FUNNEL), RANSOMWARE_FUNNEL))

    assert rates[0] == rates[1] == rates[2]
    assert rates[0] == {"conv_1_2": 100.0, "conv_2_3": 100.0,
                        "conv_total": 100.0}


def test_scenario_completion_is_unchanged_by_refresh_count(flask_app):
    """A refreshed run is still exactly one completed run."""
    from test_phishing_scenario import run_full_scenario

    progresses = []
    for repeats in REPEATS:
        client = flask_app.test_client()
        product_id = first_product_id(flask_app)
        for _ in range(repeats):
            client.get("/product/%d" % product_id)
        run_full_scenario(client)
        for _ in range(repeats):
            client.get("/phishing/debrief")

        events = events_for(flask_app, session_id_of(client))
        progresses.append(scenario_progress(events, "credential_reuse_phishing"))
        assert type_count(events, EventType.SCENARIO_COMPLETED) == 1

    assert progresses[0] == progresses[1] == progresses[2]
    assert progresses[0]["completed"] is True
    assert progresses[0]["stages_reached"] == progresses[0]["stages_total"]


def test_the_dashboard_funnel_does_not_move_when_a_page_is_refreshed(flask_app):
    """The instructor-visible figure, not just the underlying rows."""
    import app as app_module

    client = flask_app.test_client()
    client.get("/marketplace/tools")
    with flask_app.app_context():
        before = app_module.funnel_event_counts(RANSOMWARE_FUNNEL)

    for _ in range(20):
        client.get("/marketplace/tools")

    with flask_app.app_context():
        after = app_module.funnel_event_counts(RANSOMWARE_FUNNEL)
    assert after == before


def test_a_second_session_does_move_the_dashboard_funnel(flask_app):
    """The counter is deduplicated, not frozen: a new learner still counts."""
    import app as app_module

    with flask_app.app_context():
        before = app_module.funnel_event_counts(RANSOMWARE_FUNNEL)["menu"]
    flask_app.test_client().get("/marketplace/tools")
    with flask_app.app_context():
        after = app_module.funnel_event_counts(RANSOMWARE_FUNNEL)["menu"]
    assert after == before + 1


# -- sequence scoring ignores the interaction noise --------------------------

def test_sequence_scoring_ignores_page_view_noise(flask_app):
    from test_phishing_scenario import run_full_scenario

    client = flask_app.test_client()
    product_id = first_product_id(flask_app)
    for _ in range(20):
        client.get("/product/%d" % product_id)
    run_full_scenario(client)

    with client.session_transaction() as flask_session:
        scenario_id = flask_session["phishing_scenario"]["scenario_id"]
    events = for_scenario(events_for(flask_app, session_id_of(client)), scenario_id)

    assert type_count(events, EventType.PAGE_VIEW) == 20
    assert matches_expected_sequence(events, "credential_reuse_phishing")


def test_the_frozen_oracle_ignores_page_view_noise(flask_app):
    """Refresh noise must not make a correct run score as incorrect."""
    from evaluation.specifications import evaluate

    client = run_ransomware_scenario(flask_app, 20)
    with client.session_transaction() as flask_session:
        session_id = flask_session["session_id"]
        scenario_id = flask_session["ransomware_scenario_id"]

    events = [e for e in events_for(flask_app, session_id)
              if e["scenario_id"] == scenario_id]
    assert any(e["event_type"] == EventType.PAGE_VIEW for e in events)

    verdict = evaluate(events, "ransomware_awareness", scenario_id=scenario_id,
                       session_id=session_id)
    assert verdict.ok, verdict.as_dict()
    assert verdict.completeness == 1.0
    assert EventType.PAGE_VIEW not in verdict.observed


def test_page_views_alone_never_complete_a_run(flask_app):
    """Dropping noise must not turn browsing into a passing verdict."""
    from evaluation.specifications import evaluate

    client = flask_app.test_client()
    for _ in range(20):
        client.get("/ransomware/menu")
        client.get("/files/browser")
    with client.session_transaction() as flask_session:
        session_id = flask_session["session_id"]
        scenario_id = flask_session["ransomware_scenario_id"]

    events = [e for e in events_for(flask_app, session_id)
              if e["scenario_id"] == scenario_id]
    assert events and drop_scoring_noise(events) == []

    verdict = evaluate(events, "ransomware_awareness", scenario_id=scenario_id,
                       session_id=session_id)
    assert not verdict.ok
    assert verdict.completeness == 0.0


# -- the ledger itself -------------------------------------------------------

def test_the_ledger_claims_a_milestone_exactly_once(flask_app):
    import telemetry_ledger

    import app as app_module
    event = {"session_id": "ledger-test-session", "scenario_id": "ledger-test",
             "event_type": EventType.RANSOMWARE_TRIGGERED}
    with flask_app.app_context():
        assert telemetry_ledger.claim(app_module.db.session, event) is True
        app_module.db.session.commit()
        for _ in range(20):
            assert telemetry_ledger.claim(app_module.db.session, event) is False
        app_module.db.session.commit()

        keys = telemetry_ledger.claimed_keys(app_module.db.session,
                                             "ledger-test-session")
        assert keys == [("ledger-test-session", "ledger-test",
                         EventType.RANSOMWARE_TRIGGERED)]


def test_the_ledger_never_gates_raw_interaction_telemetry(flask_app):
    import telemetry_ledger

    import app as app_module
    event = {"session_id": "ledger-noise-session", "scenario_id": "ledger-noise",
             "event_type": EventType.PAGE_VIEW}
    with flask_app.app_context():
        for _ in range(20):
            assert telemetry_ledger.claim(app_module.db.session, event) is True
        app_module.db.session.commit()
        assert telemetry_ledger.claimed_keys(app_module.db.session,
                                             "ledger-noise-session") == []


def test_the_ledger_is_not_an_analytics_table(flask_app):
    """Nothing derives a displayed number from the ledger.

    Milestone 3's single-telemetry-model property must survive Milestone 4.2:
    the dashboard and the evaluation harness read ``security_event`` only.
    """
    import os
    import re

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    # The application, the blueprint and the evaluation harness are what produce
    # displayed and scored numbers. ``manage.py`` is excluded deliberately: it is
    # the maintenance CLI, and reporting how many claims the ledger holds is a
    # diagnostic about the ledger itself, not a telemetry metric.
    surfaces = ["app.py", "sandbox_routes.py", "security.py"]
    for package in ("sandbox", "evaluation"):
        for directory, _dirs, files in os.walk(os.path.join(repo_root, package)):
            if "__pycache__" in directory:
                continue
            surfaces += [os.path.join(directory, n) for n in files
                         if n.endswith(".py")]

    # ``claim`` gates a write and ``attach`` defines the table. Neither reads a
    # number out of the ledger, so no figure anywhere can be derived from it.
    allowed = {"attach", "claim"}
    for path in surfaces:
        source = open(os.path.join(repo_root, path), encoding="utf-8").read()
        # ``telemetry_ledger.py`` appears in prose cross-references; it is a
        # filename, not an attribute access.
        source = source.replace("telemetry_ledger.py", "")
        used = set(re.findall(r"telemetry_ledger\.(\w+)", source))
        assert used <= allowed, "%s uses telemetry_ledger.%s" % (
            path, sorted(used - allowed))
