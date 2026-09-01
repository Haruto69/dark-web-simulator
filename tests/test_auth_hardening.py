"""Milestone 3, section 3: session rotation and login throttling."""

import pytest

from conftest import INSTRUCTOR_PASSWORD, csrf_for
from security import (CSRF_SESSION_KEY, INSTRUCTOR_SESSION_KEY, LoginThrottle,
                      login_throttle)


@pytest.fixture(autouse=True)
def clean_throttle():
    """Every test starts with an empty limiter and leaves one behind."""
    login_throttle.reset()
    yield
    login_throttle.reset()


# -- session rotation --------------------------------------------------------

def test_csrf_token_is_rotated_on_login(client):
    before = csrf_for(client)
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "csrf_token": before})
    assert response.status_code == 302
    after = csrf_for(client)
    assert after != before, "the pre-login CSRF token must not survive login"


def test_pre_login_csrf_token_is_rejected_afterwards(client):
    stale = csrf_for(client)
    client.post("/instructor/login",
                data={"password": INSTRUCTOR_PASSWORD, "csrf_token": stale})
    # The instructor is authenticated, but the old token is void.
    response = client.post("/sandbox/create",
                           headers={"Accept": "application/json",
                                    "X-CSRF-Token": stale})
    assert response.status_code == 400
    fresh = client.post("/sandbox/create",
                        headers={"Accept": "application/json",
                                 "X-CSRF-Token": csrf_for(client)})
    assert fresh.status_code == 200


def test_session_contents_are_cleared_on_login(client, flask_app):
    """Anything an attacker could have fixed pre-auth is gone after login."""
    client.get("/training/phishing")  # seeds scenario state in the session
    with client.session_transaction() as session:
        session["planted_by_attacker"] = "should-not-survive"
        old_csrf = session.get(CSRF_SESSION_KEY)

    client.post("/instructor/login",
                data={"password": INSTRUCTOR_PASSWORD,
                      "csrf_token": csrf_for(client)})

    with client.session_transaction() as session:
        assert "planted_by_attacker" not in session
        assert session.get(CSRF_SESSION_KEY) != old_csrf
        assert session.get(INSTRUCTOR_SESSION_KEY) is True


def test_session_id_is_preserved_so_the_sandbox_stays_continuous(client):
    """session_id correlates a workspace; it is not an authenticator."""
    client.get("/")
    with client.session_transaction() as session:
        before = session["session_id"]

    client.post("/instructor/login",
                data={"password": INSTRUCTOR_PASSWORD,
                      "csrf_token": csrf_for(client)})

    with client.session_transaction() as session:
        assert session["session_id"] == before


def test_logout_clears_the_whole_session(client):
    client.post("/instructor/login",
                data={"password": INSTRUCTOR_PASSWORD,
                      "csrf_token": csrf_for(client)})
    client.post("/instructor/logout", data={"csrf_token": csrf_for(client)})
    with client.session_transaction() as session:
        assert INSTRUCTOR_SESSION_KEY not in session


def test_a_failed_login_does_not_rotate_or_authenticate(client):
    before = csrf_for(client)
    client.post("/instructor/login",
                data={"password": "wrong", "csrf_token": before})
    assert csrf_for(client) == before
    with client.session_transaction() as session:
        assert INSTRUCTOR_SESSION_KEY not in session


# -- throttling: unit level --------------------------------------------------

def test_throttle_locks_after_the_configured_attempts():
    throttle = LoginThrottle(max_attempts=3, lockout_seconds=60)
    assert throttle.record_failure("k", now=100) == 0
    assert throttle.record_failure("k", now=101) == 0
    assert throttle.record_failure("k", now=102) > 0
    assert throttle.is_locked("k", now=102)


def test_throttle_is_per_key():
    throttle = LoginThrottle(max_attempts=2, lockout_seconds=60)
    throttle.record_failure("a", now=100)
    throttle.record_failure("a", now=100)
    assert throttle.is_locked("a", now=100)
    assert not throttle.is_locked("b", now=100)


def test_throttle_expires_after_the_window():
    throttle = LoginThrottle(max_attempts=2, lockout_seconds=60)
    throttle.record_failure("k", now=100)
    throttle.record_failure("k", now=100)
    assert throttle.is_locked("k", now=150)
    assert not throttle.is_locked("k", now=200)


def test_success_clears_the_bucket():
    throttle = LoginThrottle(max_attempts=3, lockout_seconds=60)
    throttle.record_failure("k", now=100)
    throttle.record_success("k")
    assert throttle.retry_after("k", now=100) == 0


def test_throttle_memory_is_bounded():
    """A flood of distinct keys must not grow memory without limit."""
    throttle = LoginThrottle(max_attempts=5, lockout_seconds=60, max_keys=8)
    for index in range(500):
        throttle.record_failure("key-%d" % index, now=100)
    assert len(throttle._buckets) <= 8


def test_retry_after_is_zero_for_an_unknown_key():
    assert LoginThrottle().retry_after("never-seen") == 0


# -- throttling: HTTP level --------------------------------------------------

def test_repeated_failures_lock_the_login_route(client, monkeypatch):
    monkeypatch.setattr(login_throttle, "max_attempts", 3)
    monkeypatch.setattr(login_throttle, "lockout_seconds", 60)

    for _ in range(3):
        response = client.post("/instructor/login",
                               data={"password": "wrong",
                                     "csrf_token": csrf_for(client)})
        assert response.status_code == 401

    locked = client.post("/instructor/login",
                         data={"password": "wrong",
                               "csrf_token": csrf_for(client)})
    assert locked.status_code == 429
    assert "Retry-After" in locked.headers


def test_a_locked_source_cannot_log_in_even_with_the_right_password(client, monkeypatch):
    monkeypatch.setattr(login_throttle, "max_attempts", 2)
    monkeypatch.setattr(login_throttle, "lockout_seconds", 60)

    for _ in range(2):
        client.post("/instructor/login",
                    data={"password": "wrong", "csrf_token": csrf_for(client)})

    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "csrf_token": csrf_for(client)})
    assert response.status_code == 429
    assert client.get("/dashboard").status_code == 302


def test_a_successful_login_resets_the_failure_count(client, monkeypatch):
    monkeypatch.setattr(login_throttle, "max_attempts", 3)
    monkeypatch.setattr(login_throttle, "lockout_seconds", 60)

    client.post("/instructor/login",
                data={"password": "wrong", "csrf_token": csrf_for(client)})
    client.post("/instructor/login",
                data={"password": INSTRUCTOR_PASSWORD,
                      "csrf_token": csrf_for(client)})
    assert client.get("/dashboard").status_code == 200
    assert login_throttle.retry_after("127.0.0.1") == 0


def test_failed_logins_are_recorded_as_telemetry_without_secrets(client, flask_app):
    import app as app_module
    from sandbox import EventType

    client.post("/instructor/login",
                data={"password": "some-guessed-value",
                      "csrf_token": csrf_for(client)})

    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(event_type=EventType.INSTRUCTOR_LOGIN_FAILED).all())
        assert rows
        for row in rows:
            blob = "%s %s %s" % (row.details or "", row.target or "", row.source or "")
            assert "some-guessed-value" not in blob
