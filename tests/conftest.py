import os
import re
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import pytest

from sandbox import EventCollector, SandboxManager
from sandbox.backends.local import LocalBackend

#: Password used by every instructor-auth test. Set into the environment before
#: ``app`` is imported so the app never sees a real one.
INSTRUCTOR_PASSWORD = "test-instructor-pw"


@pytest.fixture
def collector():
    return EventCollector()


@pytest.fixture
def manager(tmp_path, collector):
    """A manager on the local backend, rooted in pytest's temp directory.

    Nothing outside tmp_path is ever touched, so tests cannot damage the
    developer machine.
    """
    return SandboxManager(LocalBackend(str(tmp_path / "sandboxes")),
                          recorder=collector)


@pytest.fixture(scope="session")
def flask_app(tmp_path_factory):
    """The real Flask app, on a throwaway DB and a throwaway sandbox root.

    CSRF stays *enabled* -- the tests supply real tokens, so the protection is
    exercised rather than switched off.
    """
    root = tmp_path_factory.mktemp("app")
    os.environ["SIMULATOR_DATABASE_URI"] = (
        "sqlite:///" + str(root / "test.db").replace("\\", "/"))
    os.environ["SANDBOX_LOCAL_ROOT"] = str(root / "sandboxes")
    # HTTP-level tests cover routing, auth and telemetry -- not containment.
    # Pin the local backend so they never create containers on the developer's
    # machine. Container behaviour is covered by tests/test_docker_*.py, which
    # manage and clean up their own containers.
    os.environ["SANDBOX_BACKEND"] = "local"
    os.environ["FLASK_SECRET_KEY"] = "test-only-key"
    os.environ["SYNTHETIC_IDENTITY_SECRET"] = "test-only-identity-secret"
    os.environ["INSTRUCTOR_PASSWORD"] = INSTRUCTOR_PASSWORD
    sys.modules.pop("app", None)

    import app as app_module
    app_module.app.config["TESTING"] = True
    return app_module.app


@pytest.fixture
def client(flask_app):
    return flask_app.test_client()


@pytest.fixture
def other_client(flask_app):
    """A second, independent browser session against the same app."""
    return flask_app.test_client()


CSRF_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')


def csrf_for(client, path="/instructor/login"):
    """Scrape a valid CSRF token for this client's session from a GET page."""
    page = client.get(path)
    match = CSRF_RE.search(page.data)
    assert match, "no CSRF token found on %s" % path
    return match.group(1).decode()


def login_instructor(client):
    token = csrf_for(client)
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "csrf_token": token})
    assert response.status_code in (302, 303), response.status_code
    return client


def ransomware_post(client, path):
    """POST a state-changing ransomware route with this client's CSRF token.

    Milestone 4.1 made these routes POST-only; a GET can no longer mutate.
    """
    return client.post(path, data={"csrf_token": csrf_for(client)})


@pytest.fixture
def instructor(client):
    return login_instructor(client)


@pytest.fixture
def json_headers(client):
    """Accept-JSON headers carrying a valid CSRF token for this client."""
    return {"Accept": "application/json", "X-CSRF-Token": csrf_for(client)}
