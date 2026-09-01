"""What the study layer must never collect, store, show or emit.

Also the boundary in the other direction: enabling research mode must not change
the ordinary training and learning flows, and the study flow must not turn an
ordinary learner into a research participant.
"""

from datetime import timedelta

import pytest

import study
from tests.study_helpers import (ADMIN, EXPORT, GATE, answer_immediate,
                                 answer_retention, complete_intervention,
                                 enroll, enrollment_of, first_decision,
                                 intervention_of, research_mode, shift_window)

#: Column names that must not exist on any study table. Personal data the
#: protocol explicitly does not need, plus the browser fingerprinting a study
#: like this has no business collecting.
FORBIDDEN_COLUMNS = (
    "name", "full_name", "first_name", "last_name", "email", "student_id",
    "registration_number", "phone", "date_of_birth", "dob", "gender", "age",
    "demographics", "ip_address", "remote_addr", "user_agent", "geolocation",
    "device_id", "fingerprint", "access_code", "password", "credential",
)


@pytest.fixture
def study_mode(flask_app):
    with research_mode(flask_app) as configured:
        yield configured


def study_models():
    import app as app_module
    return (app_module.StudyEnrollment, app_module.StudyIntervention,
            app_module.StudyAssessmentAttempt)


class TestNoPersonalData:
    def test_no_study_table_has_a_personal_or_fingerprinting_column(self,
                                                                    flask_app):
        for model in study_models():
            columns = {column.name.lower()
                       for column in model.__table__.columns}
            for forbidden in FORBIDDEN_COLUMNS:
                assert forbidden not in columns, (
                    "%s.%s" % (model.__tablename__, forbidden))

    def test_no_study_table_has_a_free_text_column(self, flask_app):
        """Every stored value is an authored identifier or a number.

        A free-text column would be an unbounded channel for personal
        information in a research record; the two ``Text`` columns the study
        layer touches hold canonical JSON produced by the runtime's own
        serializer, never anything a participant typed.
        """
        allowed_text = {"study_intervention": {"factual_state_json"}}
        import sqlalchemy
        for model in study_models():
            for column in model.__table__.columns:
                if isinstance(column.type, sqlalchemy.Text):
                    assert column.name in allowed_text.get(
                        model.__tablename__, set())

    def test_no_form_in_the_study_flow_accepts_free_text(self, study_mode,
                                                          flask_app, client):
        """Only fixed identifiers, a slider, an access code and a return code."""
        import re
        allowed = {"csrf_token", "choice_id", "confidence", "explanation_id",
                   "access_code", "return_code"}
        enroll(client)
        pages = ["/study/training"]
        first_decision(client)
        pages.append("/study/intervention")
        for path in pages:
            body = client.get(path).data.decode()
            # Only submitted controls, not every element carrying a name
            # attribute (``<meta name="viewport">`` and friends).
            controls = re.findall(r"<(?:input|textarea|select)[^>]*>", body)
            for control in controls:
                field = re.search(r'name="([^"]+)"', control)
                assert field and field.group(1) in allowed, (
                    "%s on %s" % (control, path))
            assert "<textarea" not in body

    def test_the_participant_id_is_a_uuid4_derived_from_nothing(self,
                                                                study_mode,
                                                                flask_app,
                                                                client):
        import uuid
        enroll(client)
        row = enrollment_of(flask_app, client)
        parsed = uuid.UUID(row.participant_id)
        assert parsed.version == 4
        with client.session_transaction() as sess:
            session_id = sess["session_id"]
        assert row.participant_id != session_id
        # Two enrollments in adjacent slots share no derivable structure.
        assert row.participant_id != str(row.allocation_slot)
        assert row.return_code_digest not in row.participant_id


class TestTelemetry:
    def test_no_study_event_types_are_emitted(self, study_mode, flask_app,
                                              client):
        """R7 adds no ``STUDY_*`` event and no second event stream.

        ``SecurityEvent`` remains the general timeline. The study artifacts
        carry their own timestamps, which is all the study needs, so adding a
        dozen event types would have created a parallel analytics system --
        exactly what Milestone 3 removed once already.
        """
        import app as app_module
        enroll(client)
        first_decision(client, "follow_link_and_sign_in", 90)
        complete_intervention(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))
        answer_retention(client)
        with flask_app.app_context():
            types = {row.event_type for row
                     in app_module.SecurityEvent.query.all()}
        assert not [name for name in types if name.startswith("STUDY_")]

    def test_arm_c_still_emits_exactly_the_six_training_events(self,
                                                               study_mode,
                                                               flask_app,
                                                               client):
        """The study reuses R2's lifecycle; it does not extend or replace it."""
        from tests.learning_helpers import training_event_types
        from tests.test_study_flow import force_arm
        enroll(client)
        force_arm(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client)
        complete_intervention(flask_app, client)
        item = intervention_of(flask_app, client)
        events = training_event_types(flask_app, item.training_execution_id)
        assert len(events) == 6 == len(set(events))

    def test_arms_a_and_b_emit_no_training_events(self, study_mode, flask_app,
                                                  client):
        import app as app_module
        from tests.test_study_flow import force_arm
        for arm in (study.AWARENESS_DEBRIEF, study.FACTUAL_CONSEQUENCE):
            browser = flask_app.test_client()
            enroll(browser)
            force_arm(flask_app, browser, arm)
            with browser.session_transaction() as sess:
                session_id = sess["session_id"]
            first_decision(browser)
            complete_intervention(flask_app, browser)
            with flask_app.app_context():
                rows = (app_module.SecurityEvent.query
                        .filter_by(session_id=session_id).all())
            assert not [r for r in rows
                        if r.event_type.startswith("TRAINING_")]


class TestNormalModeIsUnaffected:
    def test_the_ordinary_flows_work_with_research_mode_on(self, study_mode,
                                                            flask_app, client):
        """Enabling research mode changes nothing about R1-R6."""
        from tests.learning_helpers import (complete_phishing,
                                            preferred_explanation_id,
                                            submit_reflection)
        execution_id = complete_phishing(flask_app, client)
        assert execution_id
        submit_reflection(client, "phishing",
                          preferred_explanation_id(study.SOURCE_SCENARIO_KEY))
        assert client.get("/training/learn/phishing/feedback"
                          ).status_code == 200
        assert client.get("/training/transfer/quishing").status_code == 200

    def test_the_ordinary_flow_creates_no_enrollment(self, study_mode,
                                                     flask_app, client):
        """An ordinary learner never becomes a research participant."""
        import app as app_module
        from tests.learning_helpers import complete_phishing
        with flask_app.app_context():
            before = app_module.StudyEnrollment.query.count()
        complete_phishing(flask_app, client)
        with flask_app.app_context():
            assert app_module.StudyEnrollment.query.count() == before

    def test_the_study_uses_its_own_session_keys(self, study_mode, flask_app,
                                                 client):
        """The two flows cannot disturb each other's server-side state."""
        from tests.learning_helpers import complete_phishing
        complete_phishing(flask_app, client)
        enroll(client)
        first_decision(client)
        with client.session_transaction() as sess:
            assert "rewindsec_training" in sess
            assert "rewindsec_study" in sess
            # The ordinary flow's completed execution is untouched.
            assert sess["rewindsec_training"]["execution_id"]
            assert set(sess["rewindsec_study"]) == {"participant_id"}

    def test_a_study_participant_does_not_gain_the_ordinary_flow_state(
            self, study_mode, flask_app, client):
        from tests.test_study_flow import force_arm
        enroll(client)
        force_arm(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client)
        complete_intervention(flask_app, client)
        with client.session_transaction() as sess:
            assert "rewindsec_training" not in sess


class TestNoArmLeakageToParticipants:
    def test_no_participant_page_names_an_arm(self, study_mode, flask_app,
                                              client):
        from tests.test_study_flow import force_arm
        enroll(client)
        force_arm(flask_app, client, study.COUNTERFACTUAL_REPLAY)
        first_decision(client)
        complete_intervention(flask_app, client)
        answer_immediate(client)
        shift_window(flask_app, client, -timedelta(days=10))

        paths = [GATE, "/study/training", "/study/intervention",
                 "/study/comparison", "/study/reflection", "/study/immediate",
                 "/study/immediate/complete", "/study/retention",
                 "/study/complete", "/study/resume"]
        banned = [b"awareness_debrief", b"factual_consequence",
                  b"counterfactual_replay", b"you are control",
                  b"you are experimental", b"arm a", b"arm b", b"arm c",
                  b"condition", b"randomis", b"randomiz"]
        for path in paths:
            body = client.get(path, follow_redirects=True).data.lower()
            for token in banned:
                assert token not in body, "%s on %s" % (token, path)

    def test_the_dashboard_does_name_arms(self, study_mode, flask_app, client,
                                          instructor):
        """The suppression is learner-facing only; an instructor needs them."""
        enroll(client)
        body = instructor.get(ADMIN).data
        assert b"awareness_debrief" in body
        assert b"counterfactual_replay" in body


class TestEthicsLanguage:
    def test_no_page_claims_approval_consent_or_registration(self, study_mode,
                                                              flask_app,
                                                              client,
                                                              instructor):
        claims = [b"irb approved", b"irb approval number", b"iec approval",
                  b"ethics approved", b"ethics approval number",
                  b"informed consent obtained", b"consent obtained",
                  b"study registration number", b"trial registration",
                  b"recruitment approved", b"approval no"]
        enroll(client)
        for browser, paths in ((client, [GATE, "/study/training"]),
                               (instructor, [ADMIN])):
            for path in paths:
                body = browser.get(path, follow_redirects=True).data.lower()
                for claim in claims:
                    assert claim not in body

    def test_the_dashboard_states_the_operational_disclaimer(self, study_mode,
                                                             instructor):
        body = instructor.get(ADMIN).data.decode().lower()
        assert "does not constitute ethics approval" in body

    def test_the_documentation_states_both_disclaimers(self):
        import io as _io
        import re as _re
        # Markdown wraps these across lines and sets them as bold block
        # quotes; compare on the prose with its markup and wrapping removed.
        raw = _io.open("docs/study-protocol.md", encoding="utf-8").read()
        text = _re.sub(r"\s+", " ", _re.sub(r"[>*]", "", raw))
        assert ("Enabling research mode is an operational setting and does not "
                "constitute ethics approval, consent, or study registration."
                in text)
        assert ("Research-mode enablement is not a substitute for institutional "
                "ethics review, participant consent, or study registration "
                "where those are required." in text)
        assert ("RewindSec does not claim efficacy from the existence of this "
                "infrastructure." in text)
        assert ("Learning-effect claims require data collected under an "
                "appropriate approved study protocol." in text)

    def test_no_approval_number_is_invented_anywhere(self):
        import io as _io
        import re
        text = _io.open("docs/study-protocol.md", encoding="utf-8").read()
        assert not re.search(r"(IRB|IEC|REC)[ -]?(No\.?|#|number)\s*\S", text,
                             re.I)
