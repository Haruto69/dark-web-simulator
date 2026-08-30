"""Milestone 4.1, section 3: internal failures never leak host detail.

``sandbox_routes`` used to return ``str(exc)`` in its instructor JSON bodies,
and ``FileImpactScenario`` used to persist ``str(exc)`` as SCENARIO_FAILED
telemetry. A backend exception can carry a Docker daemon message, a subprocess
argv, a chunk of container stderr or a host profile path -- all of which an
instructor then sees, exports and shares.

These tests raise deliberately ugly exceptions and prove none of it reaches an
HTTP response or the telemetry table.
"""

import pytest

from conftest import csrf_for
from sandbox.errors import SandboxError, SandboxNotReadyError
from sandbox.sanitize import (internal_diagnostic, public_message, scrub,
                              telemetry_detail)

#: Every fragment below must be absent from anything a caller can observe.
UGLY = (
    r"C:\Users\eng22\OneDrive\Desktop\dark-web-simulator\instance\secret.db",
    "/var/run/docker.sock",
    "/home/instructor/.docker/config.json",
    r"\\FILESERVER\share\classroom",
    "docker run --rm -v /etc/passwd:/mnt --privileged dws-sandbox:latest",
    "subprocess.CalledProcessError argv=['docker', 'exec', '-i', 'sess-abc']",
    "Traceback (most recent call last):",
)
UGLY_MESSAGE = "\n".join(UGLY)

#: Fragments that must not survive scrubbing even into the internal log line.
LEAKY_SUBSTRINGS = (
    r"C:\Users",
    "/var/run",
    "/home/instructor",
    r"\\FILESERVER",
    "--privileged",
    "/etc/passwd",
    "argv=",
)


def assert_clean(text):
    lowered = text.lower()
    for fragment in LEAKY_SUBSTRINGS:
        assert fragment.lower() not in lowered, fragment
    for fragment in UGLY:
        assert fragment.lower() not in lowered, fragment


# -- the sanitiser itself ----------------------------------------------------

def test_scrub_removes_paths_and_command_lines():
    assert_clean(scrub(UGLY_MESSAGE))


def test_scrub_collapses_multiline_stderr():
    assert "\n" not in scrub(UGLY_MESSAGE)


def test_the_internal_diagnostic_keeps_the_class_but_not_the_message():
    diagnostic = internal_diagnostic(SandboxError(UGLY_MESSAGE))
    assert diagnostic.startswith("SandboxError:")
    assert_clean(diagnostic)


def test_telemetry_detail_never_contains_the_message():
    detail = telemetry_detail(SandboxError(UGLY_MESSAGE), "err-1234abcd")
    assert detail == "SandboxError (ref=err-1234abcd)"
    assert_clean(detail)


def test_the_public_message_is_stable_across_causes():
    a = public_message("err-1111aaaa")
    b = public_message("err-2222bbbb")
    assert a.replace("err-1111aaaa", "X") == b.replace("err-2222bbbb", "X")


def test_the_sandbox_workspace_constant_is_not_scrubbed():
    """/workspace is a constant of the simulation, not a host path."""
    assert "/workspace/finance_report.txt" in scrub(
        "target /workspace/finance_report.txt was rejected")


# -- routes ------------------------------------------------------------------

def _manager(flask_app):
    """The app's single SandboxManager, wired to the real DB recorder."""
    import app as app_module
    import sandbox_routes

    return sandbox_routes.ensure_manager(
        flask_app, app_module.db, app_module.SecurityEvent,
        flask_app.config["SANDBOX_LOCAL_ROOT"])


@pytest.fixture
def exploding_manager(flask_app, monkeypatch):
    """Make every manager operation raise an exception with ugly text."""
    manager = _manager(flask_app)

    def boom(*args, **kwargs):
        raise SandboxError(UGLY_MESSAGE)

    for name in ("create", "reset", "reap_stale"):
        monkeypatch.setattr(manager, name, boom)
    monkeypatch.setattr(manager, "require_ready", boom)
    return manager


@pytest.mark.parametrize("path", ["/sandbox/create", "/sandbox/reset",
                                  "/sandbox/reap",
                                  "/sandbox/scenario/file-impact"])
def test_route_failures_return_a_sanitized_body(instructor, exploding_manager,
                                                path):
    response = instructor.post(path, headers={"Accept": "application/json",
                                              "X-CSRF-Token": csrf_for(instructor)})
    assert response.status_code == 500
    payload = response.get_json()
    assert payload["ok"] is False
    assert payload["error_ref"].startswith("err-")
    assert payload["error"] == public_message(payload["error_ref"])
    assert_clean(response.data.decode("utf-8"))


def test_a_not_ready_failure_is_also_sanitized(instructor, flask_app, monkeypatch):
    manager = _manager(flask_app)

    def boom(*args, **kwargs):
        raise SandboxNotReadyError(UGLY_MESSAGE)

    monkeypatch.setattr(manager, "require_ready", boom)
    response = instructor.post("/sandbox/scenario/file-impact",
                               headers={"Accept": "application/json",
                                        "X-CSRF-Token": csrf_for(instructor)})
    assert response.status_code == 409
    assert_clean(response.data.decode("utf-8"))


def test_the_html_flash_path_is_sanitized_too(instructor, exploding_manager):
    """A browser (non-JSON) caller gets the same generic message."""
    response = instructor.post("/sandbox/create",
                               data={"csrf_token": csrf_for(instructor)},
                               follow_redirects=True)
    assert_clean(response.data.decode("utf-8"))


# -- telemetry ---------------------------------------------------------------

def test_scenario_failed_telemetry_carries_no_host_detail(instructor, flask_app,
                                                          monkeypatch):
    import app as app_module
    manager = _manager(flask_app)

    def boom(*args, **kwargs):
        raise SandboxNotReadyError(UGLY_MESSAGE)

    monkeypatch.setattr(manager, "require_ready", boom)
    instructor.post("/sandbox/scenario/file-impact",
                    headers={"Accept": "application/json",
                             "X-CSRF-Token": csrf_for(instructor)})

    with app_module.app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(event_type="SCENARIO_FAILED").all())
    assert rows, "the failure should still be recorded"
    for row in rows:
        assert row.details.startswith("SandboxNotReadyError (ref=err-")
        assert_clean(row.details)
        assert_clean(row.target or "")


def test_the_instructor_event_feed_exposes_no_host_detail(instructor, flask_app,
                                                          monkeypatch):
    manager = _manager(flask_app)
    monkeypatch.setattr(manager, "require_ready",
                        lambda *a, **k: (_ for _ in ()).throw(
                            SandboxNotReadyError(UGLY_MESSAGE)))
    instructor.post("/sandbox/scenario/file-impact",
                    headers={"Accept": "application/json",
                             "X-CSRF-Token": csrf_for(instructor)})

    feed = instructor.get("/sandbox/events?limit=500")
    assert feed.status_code == 200
    assert_clean(feed.data.decode("utf-8"))

    logs = instructor.get("/api/logs?limit=500")
    assert logs.status_code == 200
    assert_clean(logs.data.decode("utf-8"))


def test_no_route_module_returns_a_raw_exception_string():
    """Guard the regression: ``str(exc)`` must not reach a response body."""
    import io
    import os

    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    source = io.open(os.path.join(root, "sandbox_routes.py"),
                     encoding="utf-8").read()
    # The docstring names the removed pattern, so only real code counts.
    code = source.replace("``str(exc)``", "")
    assert "str(exc)" not in code
    assert '"error": str(' not in code
