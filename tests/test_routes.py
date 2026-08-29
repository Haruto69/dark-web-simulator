"""Integration tests for the Flask instructor sandbox routes.

The app is imported with a throwaway SQLite database and a throwaway sandbox
root, so the developer's real ``simulator.db`` and workspaces are untouched.
"""

import os
import sys

import pytest


@pytest.fixture(scope="module")
def flask_app(tmp_path_factory):
    root = tmp_path_factory.mktemp("app")
    os.environ["SIMULATOR_DATABASE_URI"] = "sqlite:///" + str(root / "test.db").replace("\\", "/")
    os.environ["SANDBOX_LOCAL_ROOT"] = str(root / "sandboxes")
    os.environ["FLASK_SECRET_KEY"] = "test-only-key"
    os.environ.pop("SANDBOX_INSTRUCTOR_TOKEN", None)
    sys.modules.pop("app", None)

    import app as app_module
    app_module.app.config["TESTING"] = True
    return app_module.app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


JSON = {"Accept": "application/json"}


def test_status_reports_absent_before_creation(client):
    body = client.get("/sandbox/status").get_json()
    assert body["ok"] is True
    assert body["sandbox"]["ready"] is False
    assert len(body["dataset"]) == 5


def test_scenario_without_sandbox_returns_409(client):
    response = client.post("/sandbox/scenario/file-impact", headers=JSON)
    assert response.status_code == 409
    assert response.get_json()["ok"] is False


def test_create_impact_reset_flow(client):
    assert client.post("/sandbox/create", headers=JSON).status_code == 200
    assert client.get("/sandbox/status").get_json()["sandbox"]["ready"] is True

    result = client.post("/sandbox/scenario/file-impact", headers=JSON).get_json()
    assert result["ok"] is True
    assert result["result"]["impacted"] == 5

    files = client.get("/sandbox/status").get_json()["files"]
    assert all(f["status"] == "impacted" for f in files)

    assert client.post("/sandbox/reset", headers=JSON).status_code == 200
    files = client.get("/sandbox/status").get_json()["files"]
    assert all(f["status"] == "baseline" for f in files)


def test_events_endpoint_is_timestamp_ordered(client):
    body = client.get("/sandbox/events?limit=200").get_json()
    events = body["events"]
    assert events, "expected telemetry from the previous flow"
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)

    types = [e["event_type"] for e in events]
    for expected in ("SANDBOX_CREATED", "SCENARIO_STARTED", "FILE_IMPACT",
                     "FILE_IMPACT_COMPLETED", "SANDBOX_RESET"):
        assert expected in types


def test_events_can_be_filtered_by_scenario(client):
    client.post("/sandbox/create", headers=JSON)
    result = client.post("/sandbox/scenario/file-impact", headers=JSON).get_json()
    scenario_id = result["result"]["scenario_id"]

    events = client.get("/sandbox/events?scenario_id=" + scenario_id).get_json()["events"]
    assert events
    assert {e["scenario_id"] for e in events} == {scenario_id}


def test_dashboard_renders_the_sandbox_panel(client):
    page = client.get("/dashboard")
    assert page.status_code == 200
    assert b"Conference Sandbox" in page.data


def test_instructor_token_gate(flask_app, client, monkeypatch):
    monkeypatch.setenv("SANDBOX_INSTRUCTOR_TOKEN", "s3cret")
    assert client.post("/sandbox/create", headers=JSON).status_code == 403
    ok = client.post("/sandbox/create", headers=dict(JSON, **{"X-Instructor-Token": "s3cret"}))
    assert ok.status_code == 200


def test_control_routes_reject_get(client):
    assert client.get("/sandbox/create").status_code == 405
    assert client.get("/sandbox/reset").status_code == 405
