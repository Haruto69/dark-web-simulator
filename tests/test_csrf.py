"""D. CSRF enforcement on every state-changing route."""

import pytest

from conftest import INSTRUCTOR_PASSWORD, csrf_for

LEARNER_POSTS = ["/training/phishing/start"]
INSTRUCTOR_POSTS = ["/sandbox/create", "/sandbox/reset", "/sandbox/destroy",
                    "/sandbox/scenario/file-impact", "/instructor/logout"]


@pytest.mark.parametrize("path", LEARNER_POSTS)
def test_learner_posts_without_a_token_are_rejected(client, path):
    assert client.post(path, data={}).status_code == 400


@pytest.mark.parametrize("path", INSTRUCTOR_POSTS)
def test_instructor_posts_without_a_token_are_rejected(instructor, path):
    response = instructor.post(path, headers={"Accept": "application/json"})
    assert response.status_code == 400


@pytest.mark.parametrize("path", INSTRUCTOR_POSTS)
def test_a_wrong_token_is_rejected(instructor, path):
    response = instructor.post(path, headers={"Accept": "application/json",
                                              "X-CSRF-Token": "not-the-token"})
    assert response.status_code == 400


def test_login_without_a_token_is_rejected(client):
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD})
    assert response.status_code == 400
    assert client.get("/dashboard").status_code == 302


def test_another_sessions_token_does_not_work(client, other_client):
    """A token minted for one session must not authorise another."""
    stolen = csrf_for(other_client)
    response = client.post("/instructor/login",
                           data={"password": INSTRUCTOR_PASSWORD,
                                 "csrf_token": stolen})
    assert response.status_code == 400


def test_a_valid_token_is_accepted(instructor):
    response = instructor.post("/sandbox/create",
                               headers={"Accept": "application/json",
                                        "X-CSRF-Token": csrf_for(instructor)})
    assert response.status_code == 200


def test_get_routes_stay_readable_without_a_token(client):
    assert client.get("/").status_code == 200
    assert client.get("/instructor/login").status_code == 200
    assert client.get("/training/phishing").status_code == 200
