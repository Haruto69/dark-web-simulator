"""Research mode is off by default, fails closed, and is gated by a code.

The most important property in this file is the first one: a RewindSec
deployment that has not been configured for research has no study surface at
all, and an ordinary learner cannot become a research participant by accident.
"""

import pytest

from tests.conftest import csrf_for
from tests.study_helpers import (ADMIN, ENROLL, EXPORT, GATE, IMMEDIATE,
                                 RESUME, RETENTION, STUDY_ACCESS_CODE,
                                 TRAINING, enroll, post, research_mode)

STUDY_PATHS = (GATE, TRAINING, "/study/intervention", "/study/comparison",
               "/study/reflection", IMMEDIATE, "/study/immediate/complete",
               RETENTION, "/study/complete", RESUME, ADMIN, EXPORT)


class TestDisabledByDefault:
    def test_research_mode_is_off_unless_configured(self, flask_app):
        """The shipped default. Enabling is an explicit operator action."""
        import os
        assert not os.environ.get("REWINDSEC_STUDY_ENABLED")
        assert flask_app.config["STUDY_ENABLED"] is False

    @pytest.mark.parametrize("path", STUDY_PATHS)
    def test_every_study_route_404s_when_disabled(self, client, path):
        """404, not 403: with research mode off there is nothing to discover."""
        assert client.get(path).status_code == 404

    def test_no_enrollment_can_be_created_when_disabled(self, flask_app,
                                                        client):
        import app as app_module
        with flask_app.app_context():
            before = app_module.StudyEnrollment.query.count()
        # Global CSRF enforcement runs before the blueprint's gate, so an
        # unauthenticated POST is refused as 400 before it is refused as 404.
        # Either way nothing is written, which is what this asserts.
        assert client.post(ENROLL, data={"access_code": STUDY_ACCESS_CODE}
                           ).status_code in (400, 404)
        with flask_app.app_context():
            assert app_module.StudyEnrollment.query.count() == before

    def test_normal_training_still_works_when_disabled(self, client):
        """R1-R6 are untouched by the study layer being absent."""
        assert client.get("/training").status_code == 200
        assert client.get("/training/phishing").status_code == 200
        assert client.get("/training/mfa").status_code == 200


class TestFailsClosed:
    def test_enabled_without_an_allocation_secret_is_unavailable(
            self, flask_app, client):
        """503 rather than allocating under an empty or invented key."""
        with research_mode(flask_app, secret=""):
            response = client.get(GATE)
            assert response.status_code == 503
            assert b"not available" in response.data.lower()

    def test_enabled_without_an_access_code_is_unavailable(self, flask_app,
                                                           client):
        with research_mode(flask_app, access_code=""):
            assert client.get(GATE).status_code == 503

    def test_enabled_without_a_continuity_secret_is_unavailable(
            self, flask_app, client):
        """503 rather than storing return-code digests under an empty key."""
        with research_mode(flask_app, continuity_secret=""):
            response = client.get(GATE)
            assert response.status_code == 503
            assert b"not available" in response.data.lower()

    def test_no_enrollment_is_created_while_unconfigured(self, flask_app,
                                                         client):
        import app as app_module
        with research_mode(flask_app, secret=""):
            with flask_app.app_context():
                before = app_module.StudyEnrollment.query.count()
            client.post(ENROLL, data={"access_code": STUDY_ACCESS_CODE})
            with flask_app.app_context():
                assert app_module.StudyEnrollment.query.count() == before


class TestAccessCode:
    def test_the_gate_renders_when_configured(self, flask_app, client):
        with research_mode(flask_app):
            assert client.get(GATE).status_code == 200

    def test_a_wrong_code_is_refused_and_enrolls_nobody(self, flask_app,
                                                        client):
        import app as app_module
        with research_mode(flask_app):
            with flask_app.app_context():
                before = app_module.StudyEnrollment.query.count()
            response = enroll(client, access_code="not-the-code")
            assert response.status_code == 403
            with flask_app.app_context():
                assert app_module.StudyEnrollment.query.count() == before

    def test_an_empty_code_is_refused(self, flask_app, client):
        with research_mode(flask_app):
            assert enroll(client, access_code="").status_code == 403

    def test_the_access_code_is_never_rendered(self, flask_app, client):
        with research_mode(flask_app):
            page = client.get(GATE)
            assert STUDY_ACCESS_CODE.encode() not in page.data

    def test_the_access_code_is_not_stored_on_the_enrollment(self, flask_app,
                                                             client):
        with research_mode(flask_app):
            enroll(client)
        import app as app_module
        with flask_app.app_context():
            row = (app_module.StudyEnrollment.query
                   .order_by(app_module.StudyEnrollment.id.desc()).first())
            values = [str(v) for v in row.to_dict().values()]
        assert STUDY_ACCESS_CODE not in values


class TestCsrf:
    """Every study write is CSRF-protected. Enforcement is global (security.py);
    these assert the study routes are actually covered by it."""

    @pytest.mark.parametrize("path,fields", [
        (ENROLL, {"access_code": STUDY_ACCESS_CODE}),
        ("/study/training/decision", {"choice_id": "report_message",
                                      "confidence": "50"}),
        ("/study/intervention/continue", {}),
        ("/study/counterfactual", {"choice_id": "report_message",
                                   "confidence": "50"}),
        ("/study/reflection", {"explanation_id": "password_strength"}),
        (IMMEDIATE, {"choice_id": "report_qr_message", "confidence": "50"}),
        (RETENTION, {"choice_id": "open_official_service",
                     "confidence": "50"}),
        (RESUME, {"return_code": "x" * 32}),
    ])
    def test_post_without_a_token_is_refused(self, flask_app, client, path,
                                             fields):
        with research_mode(flask_app):
            response = client.post(path, data=fields)
            assert response.status_code == 400
            assert b"CSRF" in response.data


class TestInstructorOnly:
    def test_dashboard_requires_instructor_auth(self, flask_app, client):
        with research_mode(flask_app):
            response = client.get(ADMIN)
            assert response.status_code in (302, 303)
            assert "/instructor/login" in response.headers["Location"]

    def test_export_requires_instructor_auth(self, flask_app, client):
        with research_mode(flask_app):
            response = client.get(EXPORT)
            assert response.status_code in (302, 303)
            assert "/instructor/login" in response.headers["Location"]

    def test_a_participant_cannot_see_aggregate_research_data(self, flask_app,
                                                              client):
        """Enrolling grants no instructor privilege."""
        with research_mode(flask_app):
            enroll(client)
            assert client.get(ADMIN).status_code in (302, 303)
            assert client.get(EXPORT).status_code in (302, 303)

    def test_instructor_can_reach_both(self, flask_app, instructor):
        with research_mode(flask_app):
            assert instructor.get(ADMIN).status_code == 200
            assert instructor.get(EXPORT).status_code == 200
