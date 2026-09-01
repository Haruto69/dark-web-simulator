"""Security invariants carried over from the removed ``test_phishing_scenario.py``
(the legacy conference-simulator phishing HTTP flow) that are not specific to
the pages that module drove and therefore still apply to current code paths.

Each test here proves its invariant against the *current* architecture
directly at the model/service layer -- the legacy routes
(``/phishing/consent``, ``/phishing/login``, ``/phishing/portal``,
``/phishing/debrief``, marketplace/product pages) are gone and are not
reconstructed here.
"""

import json

from conftest import login_instructor
from sandbox import SyntheticIdentityStore

SECRET = "REAL-PASSWORD-DO-NOT-KEEP-9f3a"


# -- A, B, C: SyntheticIdentityStore session semantics -----------------------

def test_identity_store_is_deterministic_for_one_session():
    store = SyntheticIdentityStore("secret-key")
    assert store.identities("session-a") == store.identities("session-a")


def test_identities_differ_across_sessions():
    store = SyntheticIdentityStore("secret-key")
    first = store.identities("session-a")[0]["password"]
    second = store.identities("session-b")[0]["password"]
    assert first != second


def test_one_sessions_identity_does_not_validate_in_another_session():
    store = SyntheticIdentityStore("secret-key")
    issued = store.identities("session-a")[0]
    valid, _ = store.validate("session-b", issued["username"], issued["password"])
    assert valid is False


# -- F, G: no plaintext credential is ever persisted --------------------------

def test_credential_interaction_has_no_password_column(flask_app):
    import app as app_module
    columns = {c.name for c in app_module.CredentialInteraction.__table__.columns}
    assert "password" not in columns
    assert "credential" not in columns


def test_credential_interaction_and_security_event_never_hold_the_secret(
        flask_app):
    """A secret written nowhere by the model layer stays absent end to end."""
    import app as app_module
    with flask_app.app_context():
        app_module.db.session.add(app_module.CredentialInteraction(
            session_id="legacy-invariant-session", scenario_id="phishing",
            synthetic_username="employee01@lab.local", credential_valid=True,
            event_type="CREDENTIAL_VALIDATED"))
        app_module.db.session.add(app_module.SecurityEvent(
            session_id="legacy-invariant-session", scenario_id="phishing",
            event_type="CREDENTIAL_VALIDATED", source="tests:legacy-invariants",
            target="employee01@lab.local", details="synthetic identity validated"))
        app_module.db.session.commit()

        for row in app_module.CredentialInteraction.query.filter_by(
                session_id="legacy-invariant-session").all():
            assert SECRET not in json.dumps(row.to_dict())
        for event in app_module.SecurityEvent.query.filter_by(
                session_id="legacy-invariant-session").all():
            assert SECRET not in json.dumps(event.to_dict())


# -- H: retained instructor surfaces never return a submitted secret ---------

def test_retained_instructor_surfaces_never_return_a_submitted_secret(
        flask_app):
    import app as app_module
    with flask_app.app_context():
        app_module.db.session.add(app_module.CredentialInteraction(
            session_id="legacy-invariant-session-2", scenario_id="phishing",
            synthetic_username="employee01@lab.local", credential_valid=False,
            event_type="CREDENTIAL_VALIDATION_FAILED"))
        app_module.db.session.add(app_module.SecurityEvent(
            session_id="legacy-invariant-session-2", scenario_id="phishing",
            event_type="CREDENTIAL_VALIDATION_FAILED",
            source="tests:legacy-invariants", target="employee01@lab.local"))
        app_module.db.session.commit()

    instructor = login_instructor(flask_app.test_client())
    for path in ("/dashboard", "/api/logs?limit=500", "/sandbox/events?limit=500"):
        response = instructor.get(path)
        assert response.status_code == 200, path
        assert SECRET.encode() not in response.data, path


# -- I: the legacy plaintext credential table is absent -----------------------

def test_legacy_credential_table_is_absent(flask_app):
    import sqlalchemy

    import app as app_module
    with flask_app.app_context():
        inspector = sqlalchemy.inspect(app_module.db.engine)
        assert "simulated_credential" not in inspector.get_table_names()
    assert not hasattr(app_module, "SimulatedCredential")


# -- J: the removed payment endpoint stays removed -----------------------------

def test_process_payment_endpoint_is_absent(flask_app):
    import app as app_module
    assert "process_payment" not in {
        r.endpoint for r in flask_app.url_map.iter_rules()}
    assert not hasattr(app_module, "process_payment")
