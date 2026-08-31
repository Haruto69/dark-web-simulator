"""Milestone 4.2, section 4: instructor HTML shows a pseudonym, not a session id.

The split being tested:

  * **stored and correlated**: the canonical ``session_id``. Nothing about the
    telemetry model changes, and the internal evaluation APIs still return it.
  * **displayed**: a deterministic one-way label. An instructor can still tell
    two learners apart and follow one across tables; a projected screen no
    longer carries a learner's session UUID.
"""

import re

import pytest

from conftest import login_instructor, ransomware_post
from sandbox.pseudonym import ABSENT, DEFAULT_LENGTH, session_label, short_id

SESSION_A = "9d5a3f1e-0b2c-4d6e-8f70-112233445566"
SESSION_B = "1a2b3c4d-5e6f-4708-9a0b-ffeeddccbbaa"


# -- the transformation itself ------------------------------------------------

def test_the_label_is_deterministic():
    assert short_id(SESSION_A) == short_id(SESSION_A)
    assert session_label(SESSION_A) == session_label(SESSION_A)


def test_different_sessions_get_different_labels():
    assert short_id(SESSION_A) != short_id(SESSION_B)


def test_the_label_does_not_contain_the_session_id_or_any_part_of_it():
    label = short_id(SESSION_A)
    assert SESSION_A not in label
    for chunk in SESSION_A.split("-"):
        assert chunk.lower() not in label.lower()


def test_the_label_is_short_uppercase_hex():
    label = short_id(SESSION_A)
    assert len(label) == DEFAULT_LENGTH
    assert re.fullmatch(r"[0-9A-F]+", label), label


def test_the_label_is_readable_for_an_instructor():
    assert session_label(SESSION_A) == "Session %s" % short_id(SESSION_A)


@pytest.mark.parametrize("empty", [None, ""])
def test_an_absent_session_is_visibly_absent_rather_than_pseudonymised(empty):
    assert short_id(empty) == ABSENT
    assert session_label(empty) == ABSENT


def test_the_length_is_adjustable_and_is_a_prefix_of_the_longer_label():
    assert short_id(SESSION_A, 4) == short_id(SESSION_A, 16)[:4]


def test_the_label_is_domain_separated_from_a_plain_digest():
    """It must not coincide with a digest derived elsewhere from the same id."""
    import hashlib
    assert short_id(SESSION_A) != hashlib.blake2s(
        SESSION_A.encode()).hexdigest()[:DEFAULT_LENGTH].upper()


# -- instructor HTML ----------------------------------------------------------

@pytest.fixture
def learner_with_history(flask_app):
    """A client that has produced telemetry, run state and an interaction row."""
    from test_phishing_scenario import run_full_scenario

    client = flask_app.test_client()
    client.get("/product/1")
    run_full_scenario(client)
    client.get("/marketplace/tools")
    ransomware_post(client, "/ransomware/activate")
    with client.session_transaction() as flask_session:
        return client, flask_session["session_id"]


@pytest.mark.parametrize("path", ["/deets", "/dashboard"])
def test_instructor_html_never_renders_a_raw_session_id(flask_app,
                                                        learner_with_history,
                                                        path):
    _learner, session_id = learner_with_history
    instructor = login_instructor(flask_app.test_client())

    page = instructor.get(path)
    assert page.status_code == 200
    body = page.data.decode("utf-8", "replace")
    assert session_id not in body
    # Not even a prefix of it: the old templates printed ``session_id[:8]``.
    assert session_id[:8] not in body


@pytest.mark.parametrize("path", ["/deets", "/dashboard"])
def test_instructor_html_shows_the_pseudonymous_label(flask_app,
                                                      learner_with_history,
                                                      path):
    _learner, session_id = learner_with_history
    instructor = login_instructor(flask_app.test_client())

    body = instructor.get(path).data.decode("utf-8", "replace")
    assert short_id(session_id) in body, (
        "%s must identify the learner by their stable label" % path)


def test_two_learners_stay_distinguishable_on_the_instructor_page(flask_app):
    clients = []
    for _ in range(2):
        client = flask_app.test_client()
        client.get("/marketplace/tools")
        ransomware_post(client, "/ransomware/activate")
        with client.session_transaction() as flask_session:
            clients.append(flask_session["session_id"])

    body = login_instructor(flask_app.test_client()).get("/deets").data.decode()
    labels = {short_id(session_id) for session_id in clients}
    assert len(labels) == 2
    for label in labels:
        assert label in body


def test_the_raw_session_id_is_absent_from_the_template_context(flask_app,
                                                               learner_with_history):
    """Hidden by the template is not enough; it must not be in the context."""
    import app as app_module

    _learner, session_id = learner_with_history
    with flask_app.app_context():
        run = app_module.RansomwareRunState.query.filter_by(
            session_id=session_id).first()
        assert run is not None
        display = run.display_dict()
        assert "session_id" not in display
        assert display["session_label"] == session_label(session_id)
        # The canonical form is unchanged and still carries the real id.
        assert run.to_dict()["session_id"] == session_id


# -- stored data and the internal evaluation APIs are unchanged ---------------

def test_the_stored_correlation_identifier_is_untouched(flask_app,
                                                        learner_with_history):
    import app as app_module

    _learner, session_id = learner_with_history
    with flask_app.app_context():
        assert app_module.SecurityEvent.query.filter_by(
            session_id=session_id).count() > 0
        assert app_module.CredentialInteraction.query.filter_by(
            session_id=session_id).count() > 0
        assert app_module.RansomwareRunState.query.filter_by(
            session_id=session_id).first() is not None


@pytest.mark.parametrize("path", ["/api/logs?limit=500",
                                  "/sandbox/events?limit=500"])
def test_the_internal_evaluation_apis_still_return_canonical_ids(
        flask_app, learner_with_history, path):
    """The formal harness joins runs on the real id; a one-way label cannot."""
    _learner, session_id = learner_with_history
    instructor = login_instructor(flask_app.test_client())

    payload = instructor.get(path).get_json()
    rows = payload["events"] if isinstance(payload, dict) else payload
    assert any(row["session_id"] == session_id for row in rows)


@pytest.mark.parametrize("path", ["/api/logs?limit=500",
                                  "/sandbox/events?limit=500"])
def test_the_internal_evaluation_apis_stay_instructor_only(flask_app, path):
    """Canonical ids are exposed to an authenticated instructor and nobody else."""
    response = flask_app.test_client().get(path)
    assert response.status_code in (302, 401, 403), response.status_code


def test_the_pseudonym_helper_is_not_used_as_a_lookup_key():
    """It is a printed nickname; nothing may join or authorise on it."""
    import os

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    for name in ("app.py", "sandbox_routes.py", "security.py"):
        source = open(os.path.join(repo_root, name), encoding="utf-8").read()
        for line in source.splitlines():
            if "session_label(" not in line or line.strip().startswith("#"):
                continue
            assert "filter" not in line and "query" not in line, line
