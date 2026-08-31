"""Milestone 4.1: ransomware run state is session-scoped, and mutating it
requires a CSRF-protected POST.

Before this milestone the three ransomware routes rewrote the global
``DemoFile`` rows on a **GET**. One learner clicking the lure flipped every
other learner's file browser to "encrypted", and one learner reaching the
debrief restored everybody's. These tests hold both lines: state belongs to a
session, and a safe method cannot change it.
"""

import pytest

from conftest import csrf_for, login_instructor, ransomware_post
from sandbox import EventType
from sandbox.telemetry import drop_scoring_noise
from sandbox.ransomware_state import (BASELINE_STATUS, IMPACTED_STATUS,
                                      STATE_BASELINE, STATE_IMPACTED)

MUTATING = ["/ransomware/trigger", "/ransomware/activate", "/ransomware/reveal",
            "/ransomware/simulate", "/ransomware/restore"]
LEARNER_MUTATING = ["/ransomware/trigger", "/ransomware/activate",
                    "/ransomware/reveal"]

#: Number of synthetic filenames seeded into the baseline catalogue.
CATALOGUE_SIZE = 15


def run_state(client):
    """The persisted run state for ``client``'s session, or None."""
    import app as app_module

    with client.session_transaction() as flask_session:
        session_id = flask_session.get("session_id")
    if not session_id:
        return None
    with app_module.app.app_context():
        row = (app_module.RansomwareRunState.query
               .filter_by(session_id=session_id).first())
        return row.state if row else None


def browser_statuses(client):
    """How many file cards this client's own browser renders in each state.

    The page mentions "encrypted" in its chrome and its stylesheet too, so the
    per-card marker classes are counted rather than the bare word.
    """
    page = client.get("/files/browser")
    assert page.status_code == 200
    body = page.data.decode("utf-8")
    return {"impacted": body.count("file-status status-" + IMPACTED_STATUS),
            "baseline": body.count("file-status status-" + BASELINE_STATUS)}


# -- 2. GET may not mutate ---------------------------------------------------

@pytest.mark.parametrize("path", MUTATING)
def test_get_is_rejected_on_every_mutating_route(instructor, path):
    """Even authenticated, a GET must not reach a state-changing handler."""
    assert instructor.get(path).status_code == 405


@pytest.mark.parametrize("path", LEARNER_MUTATING)
def test_get_cannot_change_ransomware_state(client, path):
    assert client.get("/files/browser").status_code == 200
    before = run_state(client)
    assert client.get(path).status_code == 405
    assert run_state(client) == before


def test_a_get_flood_leaves_the_state_at_baseline(client):
    ransomware_post(client, "/ransomware/trigger")
    assert run_state(client) == STATE_IMPACTED
    for path in MUTATING:
        client.get(path)
    # Still impacted: no GET restored it either.
    assert run_state(client) == STATE_IMPACTED


@pytest.mark.parametrize("path", LEARNER_MUTATING)
def test_post_without_csrf_is_rejected(client, path):
    before = run_state(client)
    assert client.post(path).status_code == 400
    assert run_state(client) == before


@pytest.mark.parametrize("path", LEARNER_MUTATING)
def test_post_with_a_wrong_token_is_rejected(client, path):
    assert client.post(path, data={"csrf_token": "not-the-token"}).status_code == 400


@pytest.mark.parametrize("path", LEARNER_MUTATING)
def test_post_with_a_valid_token_succeeds(client, path):
    assert ransomware_post(client, path).status_code == 200


def test_another_sessions_token_does_not_authorise_a_trigger(client, other_client):
    stolen = csrf_for(other_client)
    response = client.post("/ransomware/trigger", data={"csrf_token": stolen})
    assert response.status_code == 400
    assert run_state(client) is None


# -- instructor-only mutations stay closed ----------------------------------

@pytest.mark.parametrize("path", ["/ransomware/simulate", "/ransomware/restore"])
def test_instructor_only_mutations_are_inaccessible_unauthenticated(client, path):
    response = client.post(path, data={"csrf_token": csrf_for(client)})
    assert response.status_code == 302
    assert "/instructor/login" in response.headers["Location"]
    assert run_state(client) is None


@pytest.mark.parametrize("path", ["/ransomware/simulate", "/ransomware/restore"])
def test_instructor_only_mutations_reject_a_get_even_when_authenticated(instructor,
                                                                       path):
    assert instructor.get(path).status_code == 405


def test_the_instructor_demo_does_not_touch_a_learner_session(client, other_client):
    """The instructor's own demo used to flip the whole classroom's view."""
    ransomware_post(client, "/ransomware/trigger")
    assert run_state(client) == STATE_IMPACTED

    instructor = login_instructor(other_client)
    assert instructor.post("/ransomware/restore",
                           data={"csrf_token": csrf_for(instructor)}
                           ).status_code in (302, 303)

    # The learner's run is untouched by the instructor's restore.
    assert run_state(client) == STATE_IMPACTED
    assert run_state(instructor) == STATE_BASELINE


def test_the_url_map_declares_no_state_changing_get(flask_app):
    """Every ransomware mutation is POST-only in the routing table itself."""
    declared = {}
    for rule in flask_app.url_map.iter_rules():
        declared.setdefault(str(rule), set()).update(
            rule.methods - {"HEAD", "OPTIONS"})
    for path in MUTATING:
        assert declared[path] == {"POST"}, (path, declared[path])
    # The read-only views stay GET-only.
    for path in ("/files/browser", "/ransomware/screen", "/ransomware/menu"):
        assert declared[path] == {"GET"}, (path, declared[path])


# -- 4. cross-session isolation ---------------------------------------------

def test_triggering_a_does_not_affect_b(client, other_client):
    assert client.get("/files/browser").status_code == 200
    assert other_client.get("/files/browser").status_code == 200

    ransomware_post(client, "/ransomware/trigger")

    assert run_state(client) == STATE_IMPACTED
    assert run_state(other_client) is None
    assert browser_statuses(client)["impacted"] == CATALOGUE_SIZE
    assert browser_statuses(other_client)["impacted"] == 0
    assert browser_statuses(other_client)["baseline"] == CATALOGUE_SIZE


def test_triggering_b_does_not_affect_a(client, other_client):
    ransomware_post(other_client, "/ransomware/activate")

    assert run_state(other_client) == STATE_IMPACTED
    assert run_state(client) is None
    assert browser_statuses(client)["impacted"] == 0


def test_revealing_in_a_does_not_restore_b(client, other_client):
    ransomware_post(client, "/ransomware/trigger")
    ransomware_post(other_client, "/ransomware/trigger")
    assert run_state(client) == STATE_IMPACTED
    assert run_state(other_client) == STATE_IMPACTED

    assert ransomware_post(client, "/ransomware/reveal").status_code == 200

    assert run_state(client) == STATE_BASELINE
    assert run_state(other_client) == STATE_IMPACTED
    assert browser_statuses(other_client)["impacted"] == CATALOGUE_SIZE
    assert browser_statuses(client)["impacted"] == 0


def test_each_session_keeps_its_own_scenario_correlation(client, other_client):
    import app as app_module

    for c in (client, other_client):
        c.get("/marketplace/tools")
        c.get("/download/tool/1")
        ransomware_post(c, "/ransomware/activate")
        ransomware_post(c, "/ransomware/reveal")

    ids = []
    for c in (client, other_client):
        with c.session_transaction() as flask_session:
            ids.append((flask_session["session_id"],
                        flask_session["ransomware_scenario_id"]))
    (session_a, scenario_a), (session_b, scenario_b) = ids
    assert session_a != session_b and scenario_a != scenario_b

    with app_module.app.app_context():
        for session_id, scenario_id in ids:
            rows = (app_module.SecurityEvent.query
                    .filter_by(scenario_id=scenario_id)
                    .order_by(app_module.SecurityEvent.timestamp.asc(),
                              app_module.SecurityEvent.id.asc()).all())
            # Every event of this run belongs to exactly one session.
            assert {r.session_id for r in rows} == {session_id}
            # Milestone 4.2: the run's *progression* is the milestone sequence.
            # Raw PAGE_VIEW telemetry is correlated to the same scenario but is
            # browsing noise, so it is dropped before the sequence is compared.
            assert [r.event_type for r in drop_scoring_noise(rows)] == [
                EventType.RANSOMWARE_LURE_VIEWED,
                EventType.RANSOMWARE_DOWNLOAD_CLICKED,
                EventType.RANSOMWARE_TRIGGERED,
                EventType.RANSOMWARE_DEBRIEFED]
            # ...and the noise is genuinely there, still scoped to one session.
            views = [r for r in rows if r.event_type == EventType.PAGE_VIEW]
            assert views and {r.session_id for r in views} == {session_id}

            # And each session's run state row is its own.
            state = (app_module.RansomwareRunState.query
                     .filter_by(session_id=session_id).first())
            assert state is not None and state.scenario_id == scenario_id


# -- no global state remains -------------------------------------------------

def test_the_catalogue_table_has_no_mutable_state_columns():
    """DemoFile is a baseline catalogue; run state lives elsewhere."""
    import app as app_module

    columns = set(app_module.DemoFile.__table__.columns.keys())
    assert columns == {"id", "name"}
    assert "status" not in columns and "remark" not in columns


def test_a_run_cannot_be_addressed_by_request_parameters(client, other_client):
    """No parameter selects another learner's run: the key is the cookie."""
    assert other_client.get("/files/browser").status_code == 200
    with other_client.session_transaction() as flask_session:
        victim_session = flask_session["session_id"]
    ransomware_post(other_client, "/ransomware/trigger")

    token = csrf_for(client)
    for payload in ({"session_id": victim_session},
                    {"scenario_id": "anything"},
                    {"sandbox_id": "sess-deadbeefdeadbeef"}):
        payload = dict(payload, csrf_token=token)
        assert client.post("/ransomware/reveal", data=payload).status_code == 200

    # The victim's run is still impacted; only the caller's own run moved.
    assert run_state(other_client) == STATE_IMPACTED
    assert run_state(client) == STATE_BASELINE
