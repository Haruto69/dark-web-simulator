"""A, K. Per-session sandbox isolation."""

import pytest

from conftest import csrf_for, login_instructor
from sandbox import SandboxManager, sandbox_id_for_session
from sandbox.backends.base import validate_sandbox_id
from sandbox.backends.local import LocalBackend
from sandbox.errors import SandboxError

JSON = {"Accept": "application/json"}


def post(client, path):
    return client.post(path, headers=dict(JSON, **{"X-CSRF-Token": csrf_for(client)}))


# -- id derivation ----------------------------------------------------------

def test_derived_ids_are_stable_distinct_and_valid():
    a = sandbox_id_for_session("session-a")
    b = sandbox_id_for_session("session-b")
    assert a == sandbox_id_for_session("session-a")
    assert a != b
    assert validate_sandbox_id(a) == a
    assert a.startswith("sess-")


def test_derived_id_never_echoes_the_session_id():
    session_id = "1f2e3d4c-0000-4000-8000-abcdefabcdef"
    assert session_id not in sandbox_id_for_session(session_id)


@pytest.mark.parametrize("hostile", ["../../etc", "a b", "UPPER", "", None,
                                     "x" * 64, "a;rm -rf /"])
def test_hostile_sandbox_ids_are_refused(hostile):
    with pytest.raises(SandboxError):
        validate_sandbox_id(hostile)


# -- backend-level isolation ------------------------------------------------

def test_two_sandboxes_do_not_share_a_workspace(tmp_path):
    manager = SandboxManager(LocalBackend(str(tmp_path / "roots")),
                             default_sandbox_id=None)
    a = sandbox_id_for_session("learner-a")
    b = sandbox_id_for_session("learner-b")
    manager.create(a)
    manager.create(b)

    manager.backend.run_impact(a, ["finance_report.txt"])

    assert [f for f in manager.workspace_state(a)
            if f["name"] == "finance_report.txt"][0]["status"] == "impacted"
    assert [f for f in manager.workspace_state(b)
            if f["name"] == "finance_report.txt"][0]["status"] == "baseline"


def test_resetting_one_sandbox_leaves_the_other_alone(tmp_path):
    manager = SandboxManager(LocalBackend(str(tmp_path / "roots")),
                             default_sandbox_id=None)
    a = sandbox_id_for_session("learner-a")
    b = sandbox_id_for_session("learner-b")
    manager.create(a)
    manager.create(b)
    manager.backend.run_impact(a, ["finance_report.txt"])
    manager.backend.run_impact(b, ["finance_report.txt"])

    manager.reset(a)

    assert all(f["status"] == "baseline" for f in manager.workspace_state(a))
    assert any(f["status"] == "impacted" for f in manager.workspace_state(b))


def test_destroying_one_sandbox_leaves_the_other_running(tmp_path):
    manager = SandboxManager(LocalBackend(str(tmp_path / "roots")),
                             default_sandbox_id=None)
    a, b = sandbox_id_for_session("a"), sandbox_id_for_session("b")
    manager.create(a)
    manager.create(b)
    manager.destroy(a)
    assert manager.status(a)["ready"] is False
    assert manager.status(b)["ready"] is True


def test_manager_without_a_default_refuses_an_unscoped_call(tmp_path):
    manager = SandboxManager(LocalBackend(str(tmp_path / "roots")),
                             default_sandbox_id=None)
    with pytest.raises(SandboxError):
        manager.create()


# -- HTTP-level isolation ---------------------------------------------------

def test_two_http_sessions_get_two_sandboxes(client, other_client):
    a = login_instructor(client)
    b = login_instructor(other_client)

    post(a, "/sandbox/create")
    post(b, "/sandbox/create")

    id_a = a.get("/sandbox/status").get_json()["sandbox"]["sandbox_id"]
    id_b = b.get("/sandbox/status").get_json()["sandbox"]["sandbox_id"]
    assert id_a != id_b

    post(a, "/sandbox/scenario/file-impact")

    assert all(f["status"] == "impacted"
               for f in a.get("/sandbox/status").get_json()["files"])
    assert all(f["status"] == "baseline"
               for f in b.get("/sandbox/status").get_json()["files"])


def test_resetting_session_a_does_not_reset_session_b(client, other_client):
    a = login_instructor(client)
    b = login_instructor(other_client)
    post(a, "/sandbox/create")
    post(b, "/sandbox/create")
    post(a, "/sandbox/scenario/file-impact")
    post(b, "/sandbox/scenario/file-impact")

    post(a, "/sandbox/reset")

    assert all(f["status"] == "baseline"
               for f in a.get("/sandbox/status").get_json()["files"])
    assert all(f["status"] == "impacted"
               for f in b.get("/sandbox/status").get_json()["files"])


def test_a_client_cannot_name_another_sessions_sandbox(client, other_client):
    """Sandbox ids are derived, so request data cannot select a target."""
    a = login_instructor(client)
    b = login_instructor(other_client)
    post(b, "/sandbox/create")
    id_b = b.get("/sandbox/status").get_json()["sandbox"]["sandbox_id"]

    # Every shape a caller might try to smuggle an id through.
    a.post("/sandbox/create",
           headers=dict(JSON, **{"X-CSRF-Token": csrf_for(a)}),
           data={"sandbox_id": id_b, "id": id_b})
    id_a = a.get("/sandbox/status").get_json()["sandbox"]["sandbox_id"]
    assert id_a != id_b
