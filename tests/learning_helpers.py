"""Shared helpers for the R6 learning-layer suites.

Three of the four modules are driven through their real browser flow. The
ransomware module is not: its technical consequence environment is the
contained Docker sandbox, and the HTTP test suite deliberately pins the local
backend (see ``tests/conftest.py``), so the module reports itself unavailable
there.

:func:`complete_ransomware_execution` therefore produces a genuine completed
``TrainingExecution`` by running the **real** ``TrainingService`` over the real
ransomware scenario definition with a deterministic in-memory adapter, and then
plants the resulting ``execution_id`` in the same server-side session key the
ransomware flow uses. That is exactly the seam R6 consumes: the learning layer
reads a completed execution row and the module's session state, and nothing
else. It is also the point -- the learning layer, its reflection and its
transfer probe must work with no Docker daemon anywhere.
"""

from scenario_adapters.ransomware import (ACTION_FLAGS, ACTION_IMPACT_TOTAL,
                                          IMPACT_PROGRESSION,
                                          RANSOMWARE_DECISION_ID,
                                          RANSOMWARE_SCENARIO)
from tests.conftest import csrf_for
from training.adapters.memory import InMemoryConsequenceAdapter

PHISHING_SESSION_KEY = "rewindsec_training"
RANSOMWARE_SESSION_KEY = "rewindsec_training_ransomware"
MFA_SESSION_KEY = "rewindsec_training_mfa"
BEC_SESSION_KEY = "rewindsec_training_bec"

SESSION_KEYS = {
    "phishing": PHISHING_SESSION_KEY,
    "ransomware": RANSOMWARE_SESSION_KEY,
    "mfa": MFA_SESSION_KEY,
    "bec": BEC_SESSION_KEY,
}

REFLECTION = "/training/learn/%s/reflection"
FEEDBACK = "/training/learn/%s/feedback"


def post(client, path, form_page, **fields):
    """POST with a CSRF token scraped from the page that renders the form."""
    fields.setdefault("csrf_token", csrf_for(client, form_page))
    return client.post(path, data=fields)


def session_id_of(client):
    with client.session_transaction() as sess:
        return sess.get("session_id")


def flow_state(client, module):
    with client.session_transaction() as sess:
        return dict(sess.get(SESSION_KEYS[module]) or {})


def execution_id_of(client, module):
    return flow_state(client, module).get("execution_id")


# -- phishing ---------------------------------------------------------------
def complete_phishing(flask_app, client, factual="follow_link_and_sign_in",
                      counterfactual="verify_independently",
                      factual_confidence=90, counterfactual_confidence=60):
    """Drive the real R3 flow to a completed comparison."""
    import app as app_module

    post(client, "/training/phishing/start", "/training/phishing")
    client.get("/training/phishing/inbox")
    post(client, "/training/phishing/decision", "/training/phishing/inbox",
         choice_id=factual, confidence=str(factual_confidence))
    if factual == "follow_link_and_sign_in":
        _sign_in(app_module, client, "/training/phishing/signin")
    client.get("/training/phishing/outcome")
    post(client, "/training/phishing/rewind", "/training/phishing/outcome",
         choice_id=counterfactual, confidence=str(counterfactual_confidence))
    if counterfactual == "follow_link_and_sign_in":
        _sign_in(app_module, client, "/training/phishing/signin/counterfactual")
    assert client.get("/training/phishing/result").status_code == 200
    return execution_id_of(client, "phishing")


def _sign_in(app_module, client, path):
    identity = app_module.IDENTITIES.identities(session_id_of(client))[0]
    return post(client, path, path, username=identity["username"],
                password=identity["password"])


# -- the Docker-free synthetic modules --------------------------------------
def complete_synthetic(client, module, factual, counterfactual,
                       factual_confidence=88, counterfactual_confidence=70):
    """Drive an R5 module's real flow to a completed comparison."""
    prompt = {"mfa": "prompt", "bec": "inbox"}[module]
    base = "/training/" + module
    post(client, base + "/start", base)
    client.get("%s/%s" % (base, prompt))
    post(client, base + "/decision", "%s/%s" % (base, prompt),
         choice_id=factual, confidence=str(factual_confidence))
    client.get(base + "/outcome")
    post(client, base + "/rewind", base + "/outcome",
         choice_id=counterfactual, confidence=str(counterfactual_confidence))
    assert client.get(base + "/result").status_code == 200
    return execution_id_of(client, module)


# -- ransomware, without Docker ---------------------------------------------
def _ransomware_baseline():
    """The shape the ransomware adapter's captured state has, at S0."""
    return {
        "files": {
            "impacted": [IMPACT_PROGRESSION[0]],
            "available": list(IMPACT_PROGRESSION[1:]),
        },
        "workstation": {"isolated": False, "restarted": False},
        "incident": {"reported": False},
    }


def _ransomware_actions():
    """Pure mutators matching the scenario's authored impact model."""
    def make(action_key):
        total = ACTION_IMPACT_TOTAL[action_key]
        flags = ACTION_FLAGS[action_key]

        def mutate(state):
            impacted = list(IMPACT_PROGRESSION[:total])
            state["files"]["impacted"] = impacted
            state["files"]["available"] = [name for name in IMPACT_PROGRESSION
                                           if name not in impacted]
            state["workstation"]["isolated"] = flags["isolated"]
            state["workstation"]["restarted"] = flags["restarted"]
            state["incident"]["reported"] = flags["reported"]
        return mutate

    return {key: make(key) for key in ACTION_IMPACT_TOTAL}


def complete_ransomware_execution(flask_app, client,
                                  factual="continue_working",
                                  counterfactual="isolate_and_report",
                                  factual_confidence=85,
                                  counterfactual_confidence=70):
    """A genuine completed ransomware execution, produced without Docker.

    Runs the real ``TrainingService`` over the real scenario definition, then
    plants the ``execution_id`` in the ransomware module's server-side session
    key -- the same place the R4 flow writes it. The learning layer reads from
    exactly there, so this exercises the real seam.
    """
    import app as app_module

    # Establish the session before anything is written against it.
    client.get("/training")
    session_id = session_id_of(client)
    with flask_app.app_context():
        adapter = InMemoryConsequenceAdapter(_ransomware_baseline(),
                                             _ransomware_actions())
        execution_id, _pair = app_module.training_service().run_pair(
            RANSOMWARE_SCENARIO, adapter, RANSOMWARE_DECISION_ID,
            factual_choice_id=factual,
            counterfactual_choice_id=counterfactual,
            session_id=session_id,
            factual_confidence=factual_confidence,
            counterfactual_confidence=counterfactual_confidence)
    with client.session_transaction() as sess:
        sess[RANSOMWARE_SESSION_KEY] = {"execution_id": execution_id}
    return execution_id


# -- completing a learning sequence -----------------------------------------
#: A page that always renders a CSRF-bearing form for this session. The
#: reflection page redirects once an explanation is recorded, so scraping its
#: own token would break exactly the repeat-submission tests that matter.
TOKEN_PAGE = "/training/phishing"


def submit_reflection(client, module, explanation_id):
    return post(client, REFLECTION % module, TOKEN_PAGE,
                explanation_id=explanation_id)


def preferred_explanation_id(scenario_key):
    import learning
    return learning.reflection_for(scenario_key).preferred.explanation_id


# -- reading the persisted artifacts ----------------------------------------
def reflections(flask_app, execution_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.LearningReflection.query
                .filter_by(execution_id=execution_id).all())


def evidence(flask_app, execution_id, source=None):
    import app as app_module
    with flask_app.app_context():
        query = (app_module.ConceptEvidence.query
                 .filter_by(execution_id=execution_id))
        if source is not None:
            query = query.filter_by(evidence_source=source)
        return query.order_by(app_module.ConceptEvidence.id.asc()).all()


def attempts(flask_app, source_execution_id, probe_key=None):
    import app as app_module
    with flask_app.app_context():
        query = (app_module.TransferAttempt.query
                 .filter_by(source_execution_id=source_execution_id))
        if probe_key is not None:
            query = query.filter_by(probe_key=probe_key)
        return query.order_by(app_module.TransferAttempt.id.asc()).all()


def execution_row(flask_app, execution_id):
    import app as app_module
    with flask_app.app_context():
        return (app_module.TrainingExecution.query
                .filter_by(execution_id=execution_id).first())


def training_event_types(flask_app, execution_id):
    """The ``TRAINING_*`` events for one execution, in recorded order.

    ``scenario_id`` carries the ``execution_id`` for training lifecycle events
    (see ``training_service``), which is what makes this exact.
    """
    import app as app_module
    with flask_app.app_context():
        rows = (app_module.SecurityEvent.query
                .filter_by(scenario_id=execution_id)
                .order_by(app_module.SecurityEvent.timestamp.asc(),
                          app_module.SecurityEvent.id.asc()).all())
    return [row.event_type for row in rows
            if row.event_type.startswith("TRAINING_")]
