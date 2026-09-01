"""Integration tests for the instructor sandbox routes.

The app runs against a throwaway SQLite database and a throwaway sandbox root
(see ``conftest.flask_app``), so the developer's real ``simulator.db`` and
workspaces are untouched.
"""

from conftest import csrf_for

JSON = {"Accept": "application/json"}


def post(client, path, **kwargs):
    headers = dict(JSON, **{"X-CSRF-Token": csrf_for(client)})
    headers.update(kwargs.pop("headers", {}))
    return client.post(path, headers=headers, **kwargs)


def test_status_reports_absent_before_creation(instructor):
    body = instructor.get("/sandbox/status").get_json()
    assert body["ok"] is True
    assert body["sandbox"]["ready"] is False
    assert len(body["dataset"]) == 5


def test_scenario_without_sandbox_returns_409(instructor):
    response = post(instructor, "/sandbox/scenario/file-impact")
    assert response.status_code == 409
    assert response.get_json()["ok"] is False


def test_create_impact_reset_flow(instructor):
    assert post(instructor, "/sandbox/create").status_code == 200
    assert instructor.get("/sandbox/status").get_json()["sandbox"]["ready"] is True

    result = post(instructor, "/sandbox/scenario/file-impact").get_json()
    assert result["ok"] is True
    assert result["result"]["impacted"] == 5

    files = instructor.get("/sandbox/status").get_json()["files"]
    assert all(f["status"] == "impacted" for f in files)

    assert post(instructor, "/sandbox/reset").status_code == 200
    files = instructor.get("/sandbox/status").get_json()["files"]
    assert all(f["status"] == "baseline" for f in files)

    assert post(instructor, "/sandbox/destroy").status_code == 200
    assert instructor.get("/sandbox/status").get_json()["sandbox"]["ready"] is False


def test_events_endpoint_is_timestamp_ordered(instructor):
    post(instructor, "/sandbox/create")
    post(instructor, "/sandbox/scenario/file-impact")
    post(instructor, "/sandbox/reset")

    # Scoped to this client's own session. The shared test database now holds
    # telemetry from every suite, so an unfiltered window of the *oldest* 500
    # rows would stop containing this flow as the suite grows -- the same
    # volume sensitivity the evaluation APIs were hardened against.
    with instructor.session_transaction() as sess:
        session_id = sess.get("session_id")
    events = instructor.get(
        "/sandbox/events?limit=500&session_id=%s" % session_id
    ).get_json()["events"]
    assert events, "expected telemetry from the flow above"
    assert [e["timestamp"] for e in events] == sorted(e["timestamp"] for e in events)

    types = [e["event_type"] for e in events]
    for expected in ("SANDBOX_CREATED", "SCENARIO_STARTED", "FILE_IMPACT",
                     "FILE_IMPACT_COMPLETED", "SANDBOX_RESET"):
        assert expected in types


def test_events_can_be_filtered_by_scenario(instructor):
    post(instructor, "/sandbox/create")
    result = post(instructor, "/sandbox/scenario/file-impact").get_json()
    scenario_id = result["result"]["scenario_id"]

    events = instructor.get(
        "/sandbox/events?scenario_id=" + scenario_id).get_json()["events"]
    assert events
    assert {e["scenario_id"] for e in events} == {scenario_id}


def test_dashboard_renders_the_sandbox_panel(instructor):
    page = instructor.get("/dashboard")
    assert page.status_code == 200
    assert b"Conference Sandbox" in page.data


def test_sessions_endpoint_lists_sandboxes(instructor):
    post(instructor, "/sandbox/create")
    body = instructor.get("/sandbox/sessions").get_json()
    assert body["ok"] is True
    assert body["count"] >= 1
    assert all(row["sandbox_id"].startswith("sess-") for row in body["sandboxes"])


def test_control_routes_reject_get(instructor):
    assert instructor.get("/sandbox/create").status_code == 405
    assert instructor.get("/sandbox/reset").status_code == 405
