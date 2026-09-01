"""E-N. The multi-stage phishing scenario, credential privacy and consent."""

import pytest

from conftest import csrf_for, login_instructor
from sandbox import EventType, SyntheticIdentityStore
from sandbox.scenarios.phishing import SYNTHETIC_RESOURCES

#: A value that must never reach the database, an API, a template or a log.
SECRET = "REAL-PASSWORD-DO-NOT-KEEP-9f3a"


# -- helpers ----------------------------------------------------------------

def identities_for(client):
    """Read this session's issued identities off the consent page."""
    import re
    page = client.get("/phishing/consent")
    assert page.status_code == 200
    pairs = re.findall(
        rb'monospace;color:#0dcaf0;">([^<]+)</td>\s*'
        rb'<td style="padding:8px;font-family:monospace;color:#fd7e14;">([^<]+)</td>',
        page.data)
    assert pairs, "consent page did not issue any sandbox identities"
    return [(u.decode().strip(), p.decode().strip()) for u, p in pairs]


def consent(client):
    return client.post("/phishing/consent",
                       data={"consent": "yes", "csrf_token": csrf_for(client)},
                       follow_redirects=False)


def submit(client, username, password):
    client.get("/phishing/login")  # emits PHISHING_FORM_VIEWED
    return client.post("/phishing/login",
                       data={"username": username, "password": password,
                             "csrf_token": csrf_for(client)})


def run_full_scenario(client):
    username, password = identities_for(client)[0]
    consent(client)
    response = submit(client, username, password)
    assert response.status_code == 302, response.status_code
    assert client.get("/phishing/portal").status_code == 200
    assert client.get("/phishing/debrief").status_code == 200
    return username


def scenario_events(instructor_client, session_client=None):
    """This run's telemetry, read through the instructor API.

    Scoped to ``session_client``'s session when one is given. The shared test
    database accumulates every suite's telemetry, so an unfiltered window of
    the oldest 500 rows would eventually stop containing the run under test --
    the volume sensitivity the evaluation APIs were hardened against.
    """
    query = "limit=500"
    if session_client is not None:
        with session_client.session_transaction() as sess:
            query += "&session_id=%s" % sess.get("session_id")
    body = instructor_client.get("/sandbox/events?" + query).get_json()
    return body["events"]


# -- L. consent enforcement -------------------------------------------------

def test_login_form_requires_consent_first(client):
    response = client.get("/phishing/login")
    assert response.status_code == 302
    assert "/phishing/consent" in response.headers["Location"]


def test_credential_post_without_consent_is_refused(client):
    response = client.post("/phishing/login",
                           data={"username": "employee01@lab.local",
                                 "password": SECRET,
                                 "csrf_token": csrf_for(client)})
    assert response.status_code == 302
    assert "/phishing/consent" in response.headers["Location"]


def test_consent_without_the_checkbox_does_not_advance(client):
    client.get("/phishing/consent")
    response = client.post("/phishing/consent",
                           data={"csrf_token": csrf_for(client)})
    assert response.status_code == 302
    assert "/phishing/consent" in response.headers["Location"]
    assert "/phishing/consent" in client.get("/phishing/login").headers["Location"]


def test_later_stages_cannot_be_reached_directly(client):
    for path in ("/phishing/portal", "/phishing/debrief"):
        response = client.get(path)
        assert response.status_code == 302
        assert "/phishing/consent" in response.headers["Location"]


# -- G, H. synthetic credential validation ----------------------------------

def test_valid_sandbox_identity_advances_the_scenario(client):
    username, password = identities_for(client)[0]
    assert username.endswith("@lab.local")
    consent(client)
    response = submit(client, username, password)
    assert response.status_code == 302
    assert "/phishing/portal" in response.headers["Location"]


def test_invalid_credential_is_rejected_and_does_not_advance(client):
    consent(client)
    response = submit(client, "employee01@lab.local", "wrong-password")
    assert response.status_code == 401
    assert client.get("/phishing/portal").status_code == 302


def test_a_real_looking_address_is_never_retained(client, other_client, flask_app):
    """A learner who ignores the briefing must not have their address stored."""
    real_address = "student.name@university.example"
    consent(client)
    submit(client, real_address, SECRET)

    import app as app_module
    with flask_app.app_context():
        stored = {row.synthetic_username
                  for row in app_module.CredentialInteraction.query.all()}
        assert real_address not in stored
        targets = {e.target for e in app_module.SecurityEvent.query.all()}
        assert real_address not in targets

    instructor_client = login_instructor(other_client)
    for path in ("/api/logs", "/sandbox/events?limit=500", "/deets", "/dashboard"):
        assert real_address.encode() not in instructor_client.get(path).data


def test_unknown_identity_is_rejected(client):
    consent(client)
    response = submit(client, "ceo@example.com", SECRET)
    assert response.status_code == 401


def test_another_sessions_identity_does_not_validate(client, other_client):
    """K. Synthetic credentials are not reusable across sessions."""
    stolen_user, stolen_password = identities_for(other_client)[0]
    consent(client)
    response = submit(client, stolen_user, stolen_password)
    assert response.status_code == 401


def test_identity_store_is_deterministic_per_session():
    store = SyntheticIdentityStore("secret-key")
    assert store.identities("s1") == store.identities("s1")
    assert store.identities("s1") != store.identities("s2")
    user, password = (store.identities("s1")[0]["username"],
                      store.identities("s1")[0]["password"])
    assert store.validate("s1", user, password) == (True, "ok")
    assert store.validate("s2", user, password)[0] is False


# -- I, J. full scenario and event ordering ---------------------------------

EXPECTED_SEQUENCE = [
    EventType.SCENARIO_STARTED,
    EventType.PHISHING_EXPOSED,
    EventType.CONSENT_GRANTED,
    EventType.PHISHING_FORM_VIEWED,
    EventType.CREDENTIAL_SUBMITTED,
    EventType.CREDENTIAL_VALIDATED,
    EventType.SANDBOX_LOGIN_SUCCEEDED,
    EventType.SYNTHETIC_RESOURCE_ACCESSED,
    EventType.SCENARIO_COMPLETED,
]


def test_full_scenario_emits_the_expected_ordered_sequence(client, other_client):
    run_full_scenario(client)

    instructor_client = login_instructor(other_client)
    events = scenario_events(instructor_client, client)

    # Correlate on the scenario that contains the completion event.
    completed = [e for e in events
                 if e["event_type"] == EventType.SCENARIO_COMPLETED
                 and e["source"] == "scenario:credential_reuse_phishing"]
    assert completed
    scenario_id = completed[-1]["scenario_id"]

    mine = [e for e in events if e["scenario_id"] == scenario_id]
    assert [e["event_type"] for e in mine] == EXPECTED_SEQUENCE
    assert len({e["session_id"] for e in mine}) == 1
    assert [e["timestamp"] for e in mine] == sorted(e["timestamp"] for e in mine)


def test_failed_validation_emits_its_own_event(client, other_client):
    consent(client)
    submit(client, "employee01@lab.local", "definitely-wrong")

    instructor_client = login_instructor(other_client)
    types = [e["event_type"]
             for e in scenario_events(instructor_client, client)]
    assert EventType.CREDENTIAL_VALIDATION_FAILED in types


# -- E, F. the password is never persisted or returned ----------------------

def test_password_is_never_persisted_anywhere(client, other_client, flask_app):
    consent(client)
    submit(client, identities_for(client)[0][0], SECRET)

    import app as app_module
    with flask_app.app_context():
        rows = app_module.CredentialInteraction.query.all()
        assert rows, "the interaction should still be recorded"
        for row in rows:
            assert SECRET not in repr(row.to_dict())
        # There is no password column on the model at all.
        assert "password" not in {c.name for c in
                                  app_module.CredentialInteraction.__table__.columns}
        for event in app_module.SecurityEvent.query.all():
            blob = "%s %s %s" % (event.target or "", event.details or "",
                                 event.source or "")
            assert SECRET not in blob
            assert "password" not in blob.lower() or "not retained" in blob


def test_password_is_never_returned_by_an_api_or_page(client, other_client):
    consent(client)
    submit(client, identities_for(client)[0][0], SECRET)

    instructor_client = login_instructor(other_client)
    for path in ("/api/logs", "/sandbox/events?limit=500", "/deets", "/dashboard"):
        response = instructor_client.get(path)
        assert response.status_code == 200, path
        assert SECRET.encode() not in response.data, path


def test_legacy_credential_table_is_gone(flask_app):
    """M. The unsafe Milestone 1 table must not survive the migration."""
    import sqlalchemy

    import app as app_module
    with flask_app.app_context():
        inspector = sqlalchemy.inspect(app_module.db.engine)
        assert "simulated_credential" not in inspector.get_table_names()
    assert not hasattr(app_module, "SimulatedCredential")


def test_legacy_leakage_routes_are_closed_or_redirected(client, flask_app):
    """M. /deets and /api/logs no longer serve credentials to anyone."""
    assert client.get("/deets").status_code == 302
    assert client.get("/api/logs").status_code == 302
    assert "process_payment" not in {r.endpoint for r in flask_app.url_map.iter_rules()}


def test_payment_route_redirects_into_the_consented_flow(client):
    response = client.get("/payment/1")
    assert response.status_code == 302
    assert "/phishing/consent" in response.headers["Location"]


# -- reuse stage containment ------------------------------------------------

def test_reuse_stage_accepts_no_user_supplied_destination(client):
    run_full_scenario(client)
    # An unknown resource key falls back to the allow-listed default rather
    # than being fetched, and a URL is simply not a key.
    for hostile in ("https://evil.example", "../../etc/passwd", "unknown-key"):
        response = client.get("/phishing/portal?resource=" + hostile)
        assert response.status_code == 200
        assert b"evil.example" not in response.data


@pytest.mark.parametrize("key", sorted(SYNTHETIC_RESOURCES))
def test_each_allow_listed_resource_renders(client, key):
    run_full_scenario(client)
    assert client.get("/phishing/portal?resource=" + key).status_code == 200


# -- N. reset after the phishing scenario -----------------------------------

def test_sandbox_reset_after_the_scenario_restores_the_baseline(client):
    run_full_scenario(client)
    instructor_client = login_instructor(client)

    assert instructor_client.get("/sandbox/status").get_json()["sandbox"]["ready"] is True
    instructor_client.post("/sandbox/scenario/file-impact",
                           headers={"Accept": "application/json",
                                    "X-CSRF-Token": csrf_for(instructor_client)})
    instructor_client.post("/sandbox/reset",
                           headers={"Accept": "application/json",
                                    "X-CSRF-Token": csrf_for(instructor_client)})
    files = instructor_client.get("/sandbox/status").get_json()["files"]
    assert files and all(f["status"] == "baseline" for f in files)
