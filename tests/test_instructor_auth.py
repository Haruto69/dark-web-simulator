"""B, C. Instructor login/logout and unauthorized route access."""

import pytest

from conftest import INSTRUCTOR_PASSWORD, csrf_for

INSTRUCTOR_ROUTES = ["/dashboard", "/deets", "/api/logs", "/sandbox/status",
                     "/sandbox/events", "/sandbox/sessions"]
INSTRUCTOR_POST_ROUTES = ["/sandbox/create", "/sandbox/reset",
                          "/sandbox/destroy", "/sandbox/scenario/file-impact",
                          "/ransomware/simulate", "/ransomware/restore"]


@pytest.mark.parametrize("path", INSTRUCTOR_ROUTES)
def test_get_routes_require_instructor(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/instructor/login" in response.headers["Location"]


@pytest.mark.parametrize("path", INSTRUCTOR_ROUTES)
def test_json_callers_get_403_not_a_redirect(client, path):
    response = client.get(path, headers={"Accept": "application/json"})
    assert response.status_code == 403
    assert response.get_json()["ok"] is False


@pytest.mark.parametrize("path", INSTRUCTOR_POST_ROUTES)
def test_post_routes_require_instructor(client, path):
    response = client.post(path, headers={"Accept": "application/json",
                                          "X-CSRF-Token": csrf_for(client)})
    assert response.status_code == 403


def test_login_with_wrong_password_is_rejected(client):
    response = client.post("/instructor/login",
                           data={"password": "not-the-password",
                                 "csrf_token": csrf_for(client)})
    assert response.status_code == 401
    assert client.get("/dashboard").status_code == 302


def test_login_does_not_echo_the_submitted_password(client):
    secret = "hunter2-should-never-appear"
    response = client.post("/instructor/login",
                           data={"password": secret,
                                 "csrf_token": csrf_for(client)})
    assert secret.encode() not in response.data


def test_login_then_logout(client):
    token = csrf_for(client)
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "csrf_token": token})
    assert response.status_code == 302
    assert client.get("/dashboard").status_code == 200

    assert client.post("/instructor/logout",
                       data={"csrf_token": token}).status_code == 302
    assert client.get("/dashboard").status_code == 302


def test_login_honours_a_relative_next_path(client):
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "next": "/deets",
                                 "csrf_token": csrf_for(client)})
    assert response.headers["Location"].endswith("/deets")


@pytest.mark.parametrize("evil", ["https://evil.example/x", "//evil.example",
                                  "http://evil.example", "evil.example"])
def test_login_refuses_an_offsite_next_path(client, evil):
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "next": evil,
                                 "csrf_token": csrf_for(client)})
    assert response.status_code == 302
    assert "evil.example" not in response.headers["Location"]


def test_instructor_session_does_not_leak_to_another_client(instructor, other_client):
    assert instructor.get("/dashboard").status_code == 200
    assert other_client.get("/dashboard").status_code == 302
