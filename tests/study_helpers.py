"""Shared helpers for the R7 study suites.

Research mode is **off by default**, which is exactly the property
``test_study_gating.py`` asserts. These suites therefore turn it on through
``app.config`` rather than through the environment: the ``flask_app`` fixture is
session-scoped and imports the app once, and re-importing it per test to change
an environment variable would be slower and would not test the code path a
running deployment uses either. The routes read ``study_settings()`` on every
request, so flipping the config is the same switch an operator flips.

The clock is injectable in exactly one place -- ``StudyService.record_attempt``
and the retention-state checks take a ``now`` -- so the seven- and fourteen-day
boundaries are tested by moving the stored window, never by sleeping.
"""

import contextlib
from datetime import timedelta

from tests.conftest import csrf_for

#: The access code and allocation secret every study test runs under. Fixed, so
#: the allocation sequence in a test is reproducible and can be asserted
#: against ``study.allocation_sequence`` directly.
STUDY_ACCESS_CODE = "test-study-access"
STUDY_ASSIGNMENT_SECRET = "test-study-assignment-secret"
STUDY_CONTINUITY_SECRET = "test-study-continuity-secret"

GATE = "/study"
ENROLL = "/study/enroll"
TRAINING = "/study/training"
DECISION = "/study/training/decision"
INTERVENTION = "/study/intervention"
CONTINUE = "/study/intervention/continue"
COUNTERFACTUAL = "/study/counterfactual"
COMPARISON = "/study/comparison"
REFLECTION = "/study/reflection"
IMMEDIATE = "/study/immediate"
IMMEDIATE_DONE = "/study/immediate/complete"
RETENTION = "/study/retention"
COMPLETE = "/study/complete"
RESUME = "/study/resume"
ADMIN = "/study/admin"
EXPORT = "/study/admin/export.csv"


@contextlib.contextmanager
def research_mode(flask_app, enabled=True, secret=STUDY_ASSIGNMENT_SECRET,
                  access_code=STUDY_ACCESS_CODE,
                  continuity_secret=STUDY_CONTINUITY_SECRET):
    """Turn research mode on (or partly on) for the duration of a test.

    Restores the previous configuration afterwards, so a test that disables the
    access code cannot leak that state into the next one.
    """
    keys = ("STUDY_ENABLED", "STUDY_ASSIGNMENT_SECRET", "STUDY_ACCESS_CODE",
           "STUDY_CONTINUITY_SECRET")
    previous = {key: flask_app.config.get(key) for key in keys}
    flask_app.config["STUDY_ENABLED"] = enabled
    flask_app.config["STUDY_ASSIGNMENT_SECRET"] = secret
    flask_app.config["STUDY_ACCESS_CODE"] = access_code
    flask_app.config["STUDY_CONTINUITY_SECRET"] = continuity_secret
    # The service reads settings per request, but it is cached on the app; drop
    # it so a test that changes the wiring gets a service built against it.
    try:
        yield flask_app
    finally:
        for key, value in previous.items():
            flask_app.config[key] = value


#: A page that always renders a CSRF-bearing form for any session. The token is
#: per session, not per page, so this is a legitimate fallback -- and a
#: necessary one: the study flow deliberately redirects away from a page once
#: its step is done, which is exactly the behaviour the repeat-submission tests
#: need to POST against.
TOKEN_PAGE = "/instructor/login"


def token_for(client, form_page):
    """This session's CSRF token, preferring the page under test."""
    import re
    from tests.conftest import CSRF_RE
    page = client.get(form_page)
    match = CSRF_RE.search(page.data)
    if match:
        return match.group(1).decode()
    return csrf_for(client, TOKEN_PAGE)


def post(client, path, form_page, **fields):
    """POST with a CSRF token scraped from the page that renders the form."""
    fields.setdefault("csrf_token", token_for(client, form_page))
    return client.post(path, data=fields)


def enroll(client, access_code=STUDY_ACCESS_CODE):
    """Enrol one participant. Returns the response, which carries the code."""
    return post(client, ENROLL, GATE, access_code=access_code)


def return_code_from(response):
    """The raw return code, scraped from the one page that ever renders it."""
    import re
    match = re.search(rb"<code>([A-Za-z0-9_-]{16,64})</code>", response.data)
    assert match, "no return code rendered"
    return match.group(1).decode()


def enrollment_row(flask_app, participant_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.StudyEnrollment.query
                .filter_by(participant_id=participant_id).first())


def participant_id_of(client):
    with client.session_transaction() as sess:
        state = sess.get("rewindsec_study") or {}
    return state.get("participant_id")


def enrollment_of(flask_app, client):
    return enrollment_row(flask_app, participant_id_of(client))


def arm_of(flask_app, client):
    return enrollment_of(flask_app, client).arm_key


def intervention_of(flask_app, client):
    import app as app_module
    row = enrollment_of(flask_app, client)
    with flask_app.app_context():
        return (app_module.StudyIntervention.query
                .filter_by(enrollment_id=row.id).first())


def attempts_of(flask_app, client, phase=None):
    import app as app_module
    row = enrollment_of(flask_app, client)
    with flask_app.app_context():
        query = (app_module.StudyAssessmentAttempt.query
                 .filter_by(enrollment_id=row.id))
        if phase is not None:
            query = query.filter_by(phase=phase)
        return query.order_by(app_module.StudyAssessmentAttempt.id.asc()).all()


def executions_for_session(flask_app, session_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.TrainingExecution.query
                .filter_by(session_id=session_id)
                .order_by(app_module.TrainingExecution.id.asc()).all())


def reflections_for(flask_app, execution_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.LearningReflection.query
                .filter_by(execution_id=execution_id).all())


def session_id_of(client):
    with client.session_transaction() as sess:
        return sess.get("session_id")


# -- driving one participant through the flow -------------------------------
def first_decision(client, choice_id="follow_link_and_sign_in", confidence=90):
    """The pre-intervention decision. Identical for every arm."""
    client.get(TRAINING)
    return post(client, DECISION, TRAINING, choice_id=choice_id,
                confidence=str(confidence))


def complete_intervention(flask_app, client,
                          counterfactual="verify_independently",
                          explanation_id=None):
    """Finish whichever intervention this participant was allocated.

    The branch below is the only place a test needs to know about arms, and it
    reads the arm from the database -- exactly as the application does, and
    never from anything the client could influence.
    """
    import study
    arm = arm_of(flask_app, client)
    client.get(INTERVENTION)
    if not study.runs_counterfactual(arm):
        return post(client, CONTINUE, INTERVENTION)
    post(client, COUNTERFACTUAL, INTERVENTION, choice_id=counterfactual,
         confidence="60")
    client.get(COMPARISON)
    if explanation_id is None:
        import learning
        explanation_id = learning.reflection_for(
            study.SOURCE_SCENARIO_KEY).preferred.explanation_id
    return post(client, REFLECTION, REFLECTION, explanation_id=explanation_id)


def answer_immediate(client, choice_id="verify_via_official_portal",
                     confidence=70):
    client.get(IMMEDIATE)
    return post(client, IMMEDIATE, IMMEDIATE, choice_id=choice_id,
                confidence=str(confidence))


def open_retention_window(flask_app, client, days=8):
    """Move this participant's stored window back so it is open now.

    Rewriting the persisted timestamps -- rather than patching a clock the
    routes read -- exercises the real gate: the routes compare the current time
    against the stored window, and that comparison is what is under test.
    """
    import app as app_module
    row = enrollment_of(flask_app, client)
    with flask_app.app_context():
        stored = (app_module.StudyEnrollment.query
                  .filter_by(participant_id=row.participant_id).first())
        shift = timedelta(days=days)
        stored.immediate_transfer_completed_at -= shift
        stored.retention_open_at -= shift
        stored.retention_close_at -= shift
        app_module.db.session.commit()
        return stored.retention_open_at, stored.retention_close_at


def shift_window(flask_app, client, delta):
    """Move the stored retention window by ``delta`` (a ``timedelta``)."""
    import app as app_module
    row = enrollment_of(flask_app, client)
    with flask_app.app_context():
        stored = (app_module.StudyEnrollment.query
                  .filter_by(participant_id=row.participant_id).first())
        stored.retention_open_at += delta
        stored.retention_close_at += delta
        app_module.db.session.commit()
        return stored.retention_open_at, stored.retention_close_at


def answer_retention(client, choice_id="open_official_service", confidence=65):
    client.get(RETENTION)
    return post(client, RETENTION, RETENTION, choice_id=choice_id,
                confidence=str(confidence))


def run_participant(flask_app, client, choice_id="follow_link_and_sign_in",
                    confidence=90):
    """Enrol and run one participant as far as the immediate probe."""
    response = enroll(client)
    code = return_code_from(response)
    first_decision(client, choice_id=choice_id, confidence=confidence)
    complete_intervention(flask_app, client)
    answer_immediate(client)
    return code
