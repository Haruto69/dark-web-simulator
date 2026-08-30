"""Milestone 4, section 2: start-up is non-destructive and the clock is current.

Before this milestone, importing ``app`` executed ``DROP TABLE`` against the
configured database and deleted every product and demo-file row. Starting the
server therefore destroyed whatever a classroom session had recorded. Schema
destruction is now an explicit ``manage.py`` command; these tests hold that line.
"""

import os
import subprocess
import sys

import pytest
import sqlalchemy

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from conftest import csrf_for, ransomware_post
from sandbox import EventType

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


# -- start-up does not destroy data ------------------------------------------

def test_init_db_leaves_existing_demo_content_alone(flask_app):
    import app as app_module
    with flask_app.app_context():
        marker = app_module.Product(name="operator-added-row", description="keep me",
                                    price=1.0, image="")
        app_module.db.session.add(marker)
        app_module.db.session.commit()
        before = app_module.Product.query.count()

        seeded = app_module.init_db()

        assert seeded is False, "a populated database must not be reseeded"
        assert app_module.Product.query.count() == before
        assert app_module.Product.query.filter_by(
            name="operator-added-row").first() is not None


def test_init_db_leaves_recorded_telemetry_alone(flask_app):
    import app as app_module
    with flask_app.app_context():
        app_module.db.session.add(app_module.SecurityEvent(
            event_type=EventType.SANDBOX_CREATED, session_id="startup-test",
            source="test"))
        app_module.db.session.commit()
        before = app_module.SecurityEvent.query.count()
        app_module.init_db()
        assert app_module.SecurityEvent.query.count() == before


def test_force_reseed_is_opt_in_and_replaces_demo_content(flask_app):
    import app as app_module
    with flask_app.app_context():
        app_module.db.session.add(app_module.Product(
            name="doomed-row", description="", price=1.0, image=""))
        app_module.db.session.commit()

        assert app_module.init_db(force_reseed=True) is True
        assert app_module.Product.query.filter_by(
            name="doomed-row").first() is None
        assert app_module.Product.query.count() > 0


# -- dropping is explicit ----------------------------------------------------

def test_dropping_legacy_tables_is_not_wired_into_start_up():
    """No import-time code path may call the destructive helper."""
    source = open(os.path.join(REPO_ROOT, "app.py"), encoding="utf-8").read()
    body = source.split("def drop_legacy_tables", 1)[1]
    # The only remaining mention outside the definition is documentation.
    calls = [line for line in body.splitlines()
             if "drop_legacy_tables()" in line and not line.strip().startswith("#")]
    assert calls == [], "drop_legacy_tables() must only be called from manage.py"


def test_drop_legacy_tables_removes_a_leftover_table_and_reports_it(flask_app):
    import app as app_module
    with flask_app.app_context():
        with app_module.db.engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE IF NOT EXISTS phishing_funnel (id INTEGER PRIMARY KEY)")
        inspector = sqlalchemy.inspect(app_module.db.engine)
        assert "phishing_funnel" in inspector.get_table_names()

        dropped = app_module.drop_legacy_tables()

        assert dropped == ["phishing_funnel"]
        inspector = sqlalchemy.inspect(app_module.db.engine)
        assert "phishing_funnel" not in inspector.get_table_names()


def test_dropping_when_nothing_is_legacy_reports_nothing(flask_app):
    import app as app_module
    with flask_app.app_context():
        assert app_module.drop_legacy_tables() == []


def test_manage_py_exposes_the_explicit_commands():
    completed = subprocess.run(
        [sys.executable, os.path.join(REPO_ROOT, "manage.py"), "--help"],
        capture_output=True, text=True, cwd=REPO_ROOT, timeout=120,
        env={**os.environ, "SIMULATOR_DATABASE_URI": "sqlite:///",
             "INSTRUCTOR_PASSWORD": "unused"})
    assert completed.returncode == 0, completed.stderr
    for command in ("status", "init", "reset-demo", "drop-legacy", "reset-all"):
        assert command in completed.stdout


def test_every_destructive_manage_command_is_confirmation_gated():
    import manage
    assert set(manage.DESTRUCTIVE) == {"reset-demo", "drop-legacy", "reset-all"}
    assert set(manage.DESTRUCTIVE) <= set(manage.COMMANDS)
    # The read-only commands are deliberately not gated.
    assert "status" not in manage.DESTRUCTIVE and "init" not in manage.DESTRUCTIVE


# -- the declared-but-never-emitted event now fires --------------------------

def test_the_ransomware_debrief_emits_its_declared_event(client):
    for path in ("/marketplace/tools", "/download/tool/1"):
        assert client.get(path).status_code == 200
    assert ransomware_post(client, "/ransomware/activate").status_code == 200
    with client.session_transaction() as flask_session:
        scenario_id = flask_session["ransomware_scenario_id"]

    assert ransomware_post(client, "/ransomware/reveal").status_code == 200

    import app as app_module
    with app_module.app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(scenario_id=scenario_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())
    types = [r.event_type for r in rows]
    assert types == [EventType.RANSOMWARE_LURE_VIEWED,
                     EventType.RANSOMWARE_DOWNLOAD_CLICKED,
                     EventType.RANSOMWARE_TRIGGERED,
                     EventType.RANSOMWARE_DEBRIEFED]
    debrief = rows[-1]
    assert debrief.session_id and debrief.scenario_id == scenario_id
    assert debrief.source == "scenario:ransomware_awareness"


def test_the_debrief_matches_the_frozen_specification(client):
    from evaluation.specifications import evaluate

    for path in ("/marketplace/tools", "/download/tool/1"):
        assert client.get(path).status_code == 200
    for path in ("/ransomware/activate", "/ransomware/reveal"):
        assert ransomware_post(client, path).status_code == 200
    with client.session_transaction() as flask_session:
        scenario_id = flask_session["ransomware_scenario_id"]
        session_id = flask_session["session_id"]

    import app as app_module
    with app_module.app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(scenario_id=scenario_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())
    verdict = evaluate(rows, "ransomware_awareness", scenario_id=scenario_id,
                       session_id=session_id)
    assert verdict.ok, verdict.as_dict()


def test_every_declared_event_type_is_emitted_somewhere_in_the_codebase():
    """A declared-but-dead event type is a telemetry gap; catch new ones."""
    from sandbox.events import ALL_EVENT_TYPES

    sources = []
    for directory, _dirs, files in os.walk(REPO_ROOT):
        if any(part in directory for part in
               ("__pycache__", ".git", "node_modules", "tests")):
            continue
        for name in files:
            if name.endswith(".py") and name != "events.py":
                sources.append(open(os.path.join(directory, name),
                                    encoding="utf-8").read())
    corpus = "\n".join(sources)
    dead = [event_type for event_type in ALL_EVENT_TYPES
            if ("EventType.%s" % event_type) not in corpus]
    assert dead == [], "declared but never emitted: %s" % dead


# -- the deprecated clock is gone --------------------------------------------

@pytest.mark.parametrize("module", ["app.py", "sandbox_routes.py", "security.py",
                                    "manage.py"])
def test_no_module_calls_the_deprecated_utcnow(module):
    source = open(os.path.join(REPO_ROOT, module), encoding="utf-8").read()
    assert "datetime.utcnow" not in source


def test_the_sandbox_package_uses_the_shared_clock():
    for directory, _dirs, files in os.walk(os.path.join(REPO_ROOT, "sandbox")):
        if "__pycache__" in directory:
            continue
        for name in files:
            # timeutil.py is the replacement, and names the deprecated call in
            # its docstring to explain what it replaces.
            if not name.endswith(".py") or name == "timeutil.py":
                continue
            source = open(os.path.join(directory, name), encoding="utf-8").read()
            assert "datetime.utcnow" not in source, name


def test_the_shared_clock_returns_naive_utc():
    from datetime import datetime, timezone

    from sandbox.timeutil import utcnow

    now = utcnow()
    assert now.tzinfo is None, "the SQLite schema stores naive datetimes"
    reference = datetime.now(timezone.utc).replace(tzinfo=None)
    assert abs((reference - now).total_seconds()) < 5


def test_the_application_emits_no_deprecation_warnings_during_a_scenario(client,
                                                                        recwarn):
    for path in ("/marketplace/tools", "/download/tool/1"):
        client.get(path)
    for path in ("/ransomware/activate", "/ransomware/reveal"):
        ransomware_post(client, path)
    deprecations = [w for w in recwarn
                    if issubclass(w.category, DeprecationWarning)
                    and "utcnow" in str(w.message)]
    assert deprecations == []
