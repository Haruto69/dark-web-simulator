"""Milestone 4.2, section 3: stale ransomware run state can be cleaned.

``RansomwareRunState`` holds one row per learner session and, before this
milestone, held it for ever. The reaper added here is deliberately narrow: it
selects by age and by nothing else, so there is no parameter through which a
request could name a row, and it is invoked explicitly
(``python manage.py reap-state``) rather than by a background scheduler.

The negative properties are the important ones and are tested first: a row with
an unknown age is never selected, a recent row survives, and nothing outside
``ransomware_run_state`` is touched.
"""

from datetime import timedelta

import pytest

from conftest import ransomware_post
from sandbox import EventType
from sandbox.ransomware_state import (DEFAULT_MAX_AGE_SECONDS,
                                      MIN_MAX_AGE_SECONDS, STATE_BASELINE,
                                      STATE_IMPACTED, age_seconds, is_stale,
                                      select_stale)
from sandbox.timeutil import utcnow

MAX_AGE = 3600


class Row:
    """The only thing ``select_stale`` needs to know about a row."""

    def __init__(self, updated_at, name="row"):
        self.updated_at = updated_at
        self.name = name


def aged(seconds, now=None):
    return Row((now or utcnow()) - timedelta(seconds=seconds), "aged-%s" % seconds)


# -- the pure selection rule --------------------------------------------------

def test_a_row_older_than_the_threshold_is_stale():
    assert is_stale(utcnow() - timedelta(seconds=MAX_AGE + 1), MAX_AGE)


def test_a_row_younger_than_the_threshold_is_not_stale():
    assert not is_stale(utcnow() - timedelta(seconds=MAX_AGE - 1), MAX_AGE)


def test_the_boundary_is_inclusive_and_deterministic():
    """Exactly at the threshold counts as stale, so the rule has no grey zone."""
    now = utcnow()
    at_boundary = now - timedelta(seconds=MAX_AGE)
    assert is_stale(at_boundary, MAX_AGE, now=now)
    just_inside = now - timedelta(seconds=MAX_AGE) + timedelta(microseconds=1)
    assert not is_stale(just_inside, MAX_AGE, now=now)


def test_a_row_with_no_timestamp_is_never_stale():
    """An unreadable age means "leave it alone", never "assume it is old"."""
    assert age_seconds(None) is None
    assert not is_stale(None, MAX_AGE)
    assert select_stale([Row(None)], MAX_AGE) == []


def test_selection_returns_only_the_stale_rows_with_their_ages():
    now = utcnow()
    old, young = aged(MAX_AGE + 10, now), aged(10, now)
    selected = select_stale([old, young, Row(None)], MAX_AGE, now=now)
    assert [row.name for row, _age in selected] == [old.name]
    assert selected[0][1] == pytest.approx(MAX_AGE + 10, abs=1)


def test_a_threshold_below_the_floor_is_refused_rather_than_widened():
    with pytest.raises(ValueError):
        select_stale([aged(10_000)], MIN_MAX_AGE_SECONDS - 1)


def test_the_default_threshold_outlasts_a_classroom_session():
    assert DEFAULT_MAX_AGE_SECONDS >= 24 * 3600


# -- the application-level reaper --------------------------------------------

def make_run(app_module, session_id, age_seconds_, state=STATE_IMPACTED):
    run = app_module.RansomwareRunState(
        session_id=session_id, scenario_id="scen-%s" % session_id,
        state=state, variant="browser", remark="test row",
        updated_at=utcnow() - timedelta(seconds=age_seconds_))
    app_module.db.session.add(run)
    app_module.db.session.commit()
    return run


def run_exists(app_module, session_id):
    return app_module.RansomwareRunState.query.filter_by(
        session_id=session_id).first() is not None


def test_a_stale_row_is_removed_and_a_recent_row_is_retained(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-stale-1", MAX_AGE + 60)
        make_run(app_module, "reap-fresh-1", 5)

        reaped = app_module.reap_ransomware_state(MAX_AGE)

        assert not run_exists(app_module, "reap-stale-1")
        assert run_exists(app_module, "reap-fresh-1")
        assert len(reaped) == 1
        assert reaped[0]["deleted"] is True
        assert reaped[0]["age_seconds"] == pytest.approx(MAX_AGE + 60, abs=5)


def test_the_boundary_row_is_reaped_and_the_one_beneath_it_is_not(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-boundary-at", MAX_AGE + 1)
        make_run(app_module, "reap-boundary-under", MAX_AGE - 60)

        app_module.reap_ransomware_state(MAX_AGE)

        assert not run_exists(app_module, "reap-boundary-at")
        assert run_exists(app_module, "reap-boundary-under")


def test_a_row_with_no_timestamp_survives_the_reaper(flask_app):
    import app as app_module
    with flask_app.app_context():
        run = make_run(app_module, "reap-no-timestamp", MAX_AGE + 60)
        run.updated_at = None
        app_module.db.session.commit()

        assert app_module.reap_ransomware_state(MAX_AGE) == []
        assert run_exists(app_module, "reap-no-timestamp")


def test_a_dry_run_reports_the_selection_and_deletes_nothing(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-dry-1", MAX_AGE + 60)

        reaped = app_module.reap_ransomware_state(MAX_AGE, dry_run=True)

        assert [row["deleted"] for row in reaped] == [False]
        assert run_exists(app_module, "reap-dry-1")


def test_the_reaper_refuses_a_threshold_below_the_floor(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-floor-1", 10_000)
        with pytest.raises(ValueError):
            app_module.reap_ransomware_state(MIN_MAX_AGE_SECONDS - 1)
        assert run_exists(app_module, "reap-floor-1")


def test_the_reaper_reports_a_pseudonym_not_a_session_id(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-label-1", MAX_AGE + 60)
        reaped = app_module.reap_ransomware_state(MAX_AGE)
        assert "session_id" not in reaped[0]
        assert "reap-label-1" not in reaped[0]["session_label"]


def test_the_reaper_is_deterministic(flask_app):
    """Same rows, same clock, same selection -- twice."""
    import app as app_module
    with flask_app.app_context():
        for index in range(3):
            make_run(app_module, "reap-det-%d" % index, MAX_AGE + 100 + index)
        now = utcnow()
        first = app_module.reap_ransomware_state(MAX_AGE, now=now, dry_run=True)
        second = app_module.reap_ransomware_state(MAX_AGE, now=now, dry_run=True)
        assert first == second


# -- the negative property: nothing else is touched --------------------------

def test_reaping_leaves_recorded_telemetry_and_seed_data_alone(flask_app):
    import app as app_module
    with flask_app.app_context():
        make_run(app_module, "reap-untouched-1", MAX_AGE + 60)
        app_module.db.session.add(app_module.SecurityEvent(
            event_type=EventType.RANSOMWARE_TRIGGERED,
            session_id="reap-untouched-1", scenario_id="scen-reap-untouched-1",
            source="test"))
        app_module.db.session.add(app_module.CredentialInteraction(
            session_id="reap-untouched-1", scenario_id="scen-reap-untouched-1",
            synthetic_username="employee01@lab.local", credential_valid=True))
        app_module.db.session.commit()

        events_before = app_module.SecurityEvent.query.count()
        interactions_before = app_module.CredentialInteraction.query.count()
        products_before = app_module.Product.query.count()
        files_before = app_module.DemoFile.query.count()

        app_module.reap_ransomware_state(MAX_AGE)

        assert not run_exists(app_module, "reap-untouched-1")
        # Simulation *state* is gone; the record of what happened is not.
        assert app_module.SecurityEvent.query.count() == events_before
        assert app_module.CredentialInteraction.query.count() == interactions_before
        assert app_module.Product.query.count() == products_before
        assert app_module.DemoFile.query.count() == files_before
        assert app_module.SecurityEvent.query.filter_by(
            session_id="reap-untouched-1").count() == 1


def test_reaping_does_not_disturb_an_active_learner(flask_app):
    """A session mid-exercise keeps its row and its view of the catalogue."""
    import app as app_module

    client = flask_app.test_client()
    client.get("/marketplace/tools")
    assert ransomware_post(client, "/ransomware/activate").status_code == 200
    with client.session_transaction() as flask_session:
        active_session = flask_session["session_id"]

    with flask_app.app_context():
        make_run(app_module, "reap-active-decoy", MAX_AGE + 60)
        app_module.reap_ransomware_state(MAX_AGE)
        assert run_exists(app_module, active_session)
        assert not run_exists(app_module, "reap-active-decoy")
        assert app_module.RansomwareRunState.query.filter_by(
            session_id=active_session).first().state == STATE_IMPACTED

    assert client.get("/files/browser").status_code == 200


def test_the_reaper_takes_no_session_or_scenario_parameter():
    """There must be no argument through which request data could pick a row."""
    import inspect

    import app as app_module
    parameters = set(inspect.signature(
        app_module.reap_ransomware_state).parameters)
    assert parameters == {"max_age_seconds", "now", "dry_run"}
    assert set(inspect.signature(select_stale).parameters) == {
        "rows", "max_age_seconds", "now"}


def test_no_request_handler_calls_the_reaper():
    """Reaping is maintenance. A route that could trigger it would be a bug."""
    import os

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    for name in ("app.py", "sandbox_routes.py"):
        source = open(os.path.join(repo_root, name), encoding="utf-8").read()
        body = source.split("def reap_ransomware_state", 1)[-1]
        calls = [line for line in body.splitlines()
                 if "reap_ransomware_state(" in line
                 and not line.strip().startswith("#")]
        assert calls == [], "%s calls the reaper outside manage.py" % name


# -- the progression-milestone ledger has the same release valve -------------

def test_stale_milestone_claims_can_be_released(flask_app):
    import telemetry_ledger

    import app as app_module
    with flask_app.app_context():
        session = app_module.db.session
        stale = {"session_id": "claim-stale", "scenario_id": "claim-stale",
                 "event_type": EventType.RANSOMWARE_TRIGGERED}
        fresh = {"session_id": "claim-fresh", "scenario_id": "claim-fresh",
                 "event_type": EventType.RANSOMWARE_TRIGGERED}
        assert telemetry_ledger.claim(session, stale,
                                      now=utcnow() - timedelta(seconds=MAX_AGE + 60))
        assert telemetry_ledger.claim(session, fresh)
        session.commit()

        released = telemetry_ledger.reap_claims(session, MAX_AGE)
        session.commit()

        assert released == 1
        assert telemetry_ledger.claimed_keys(session, "claim-stale") == []
        assert telemetry_ledger.claimed_keys(session, "claim-fresh")


def test_releasing_claims_refuses_a_threshold_below_the_floor(flask_app):
    import telemetry_ledger

    import app as app_module
    with flask_app.app_context():
        with pytest.raises(ValueError):
            telemetry_ledger.reap_claims(app_module.db.session,
                                         telemetry_ledger.MIN_MAX_AGE_SECONDS - 1)


def test_releasing_claims_removes_no_telemetry(flask_app):
    import telemetry_ledger

    import app as app_module
    with flask_app.app_context():
        before = app_module.SecurityEvent.query.count()
        telemetry_ledger.reap_claims(app_module.db.session, MIN_MAX_AGE_SECONDS)
        app_module.db.session.commit()
        assert app_module.SecurityEvent.query.count() == before


# -- the maintenance command -------------------------------------------------

def test_manage_reap_state_is_wired_to_the_reaper():
    import manage
    assert manage.COMMANDS["reap-state"] is manage.cmd_reap_state
    assert "reap-state" in manage.DESTRUCTIVE


def test_a_dry_run_reap_is_not_confirmation_gated(flask_app, monkeypatch):
    """Reporting what *would* go destroys nothing, so it must not prompt."""
    import manage

    def refuse(*_args, **_kwargs):
        raise AssertionError("a dry run must not ask for confirmation")

    monkeypatch.setattr("builtins.input", refuse)
    assert manage.main(["reap-state", "--dry-run", "--max-age", "999999"]) == 0


def test_a_real_reap_is_confirmation_gated(flask_app, monkeypatch):
    import manage
    import app as app_module

    with flask_app.app_context():
        make_run(app_module, "reap-gated-1", 999_999 + 60)

    monkeypatch.setattr("builtins.input", lambda *_a, **_k: "no")
    assert manage.main(["reap-state", "--max-age", "999999"]) == 1

    with flask_app.app_context():
        assert run_exists(app_module, "reap-gated-1"), "an abort must change nothing"


def test_the_baseline_state_constant_is_still_what_a_fresh_run_starts_from():
    """Guards the reap tests above from silently testing the wrong state."""
    assert STATE_BASELINE != STATE_IMPACTED
