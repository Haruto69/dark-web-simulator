"""The RewindSec learner-facing training flow (milestone R3).

This blueprint is the first complete browser workflow through the counterfactual
loop:

    /training                      module home
    /training/phishing             safety briefing (+ this session's identities)
    /training/phishing/inbox       the message and the decision
    /training/phishing/signin      the synthetic sign-in, factual branch
    /training/phishing/signin/counterfactual
                                   the same sign-in, counterfactual branch
    /training/phishing/outcome     what the chosen path produced, then rewind
    /training/phishing/result      the executed side-by-side comparison

Design rules this module holds to:

**The runtime does the work.** The comparison is produced by
``training_service().run_pair(...)`` -- the real R1 runtime behind the R2
service. No route reconstructs a state, recomputes an outcome, or implements a
phishing-only comparison.

**The persisted execution is the source of truth.** The result page renders
from the stored ``TrainingExecution`` row, never from submitted form values, so
it can be refreshed without re-running anything.

**Factual means first.** ``factual_*`` always carries the choice the learner
actually made, and ``counterfactual_*`` the alternative they picked after the
rewind. They are never swapped so that a particular branch lands on the left.

**Nothing learner-typed is retained.** A submitted password is compared and
dropped inside :mod:`sandbox.identity`; a submitted username is only ever
compared against this session's issued identities and is never stored, echoed,
flashed, logged or sent to telemetry. Progress lives in the server-side session
as opaque stable ids.

**No new event types.** The flow emits the standard ``TRAINING_*`` lifecycle and
nothing else; the legacy ``PHISHING_*`` events belong to the legacy marketplace
routes and are not duplicated here.
"""

import time
import uuid

from flask import (Blueprint, abort, redirect, render_template, request,
                   session, url_for)

from sandbox.scenarios.phishing import SYNTHETIC_RESOURCES
from scenario_adapters import (CREDENTIAL_CHOICE_ID, PHISHING_DECISION_ID,
                               PHISHING_SCENARIO, PhishingConsequenceAdapter,
                               describe_difference, describe_state,
                               label_for_choice)
from scenario_adapters.phishing import PHISHING_CHOICE_IDS
from training_service import TrainingExecutionError, TrainingPersistenceError

import json

#: Server-side session key holding the current attempt. Everything the flow
#: needs is here; nothing addressable is put in a URL.
STATE_KEY = "rewindsec_training"

#: Upper bound on a measured decision latency (one hour). Latency is learner
#: *interaction metadata*, not a security control: it is measured server-side
#: from when the decision page was rendered, so there is no client-supplied
#: value to trust, and anything past the bound is recorded as "not measured"
#: rather than as an implausible number.
MAX_RESPONSE_MS = 60 * 60 * 1000

#: The fictional service the scenario is set in. Deliberately invented, with a
#: ``.lab`` domain that resolves nowhere: no real institution is impersonated
#: and no real login page is reproduced.
ORG = {
    "name": "Northgate Campus Services",
    "short": "Northgate",
    "real_domain": "northgate-services.lab",
    "display_sender": "Northgate Account Services",
    "lure_sender": "no-reply@northgate-secure-verify.lab",
    "lure_domain": "northgate-secure-verify.lab",
    "lure_host": "northgate-secure-verify.lab",
}

#: Deterministic, fixed evidence shown for each branch on the outcome page.
#: Authored content, not generated text, and not derived from anything the
#: learner typed.
BRANCH_EVIDENCE = {
    CREDENTIAL_CHOICE_ID: {
        "heading": "You signed in on the linked page",
        "lines": [
            "The page you signed in on was hosted at %s, not %s."
            % (ORG["lure_host"], ORG["real_domain"]),
            "The synthetic identity you entered was accepted and immediately "
            "used inside this lab.",
            "A synthetic internal resource opened with that identity.",
        ],
    },
    "inspect_sender": {
        "heading": "You inspected the sender details",
        "lines": [
            "Display name: %s" % ORG["display_sender"],
            "Actual sending address: %s" % ORG["lure_sender"],
            "%s sends from %s. The sending domain does not match."
            % (ORG["short"], ORG["real_domain"]),
        ],
    },
    "verify_independently": {
        "heading": "You checked through a trusted channel",
        "lines": [
            "You used the service desk number already stored in your contacts, "
            "not one from the message.",
            "The service desk has no record of an access expiry for your "
            "account.",
            "The request was confirmed as not legitimate.",
        ],
    },
    "report_message": {
        "heading": "You reported the message",
        "lines": [
            "The message was forwarded to the %s security team." % ORG["short"],
            "A synthetic incident record was raised in this lab.",
            "The message was left in place and not interacted with further.",
        ],
    },
}


# -- session-scoped attempt state -------------------------------------------
def _blank_state():
    return {
        # Opaque, server-issued. Never appears in a URL and is not an
        # authenticator -- it exists so a restart is distinguishable from a
        # resubmission of the same attempt.
        "attempt_id": uuid.uuid4().hex,
        "factual_choice": None,
        "factual_confidence": None,
        "factual_response_ms": None,
        "credential_validated": False,
        "counterfactual_choice": None,
        "counterfactual_confidence": None,
        "counterfactual_response_ms": None,
        "counterfactual_credential_validated": False,
        "decision_shown_ms": None,
        "rewind_shown_ms": None,
        "execution_id": None,
    }


def _state():
    state = session.get(STATE_KEY)
    return state if isinstance(state, dict) else None


def _save(state):
    session[STATE_KEY] = state
    session.modified = True
    return state


def _now_ms():
    return int(time.time() * 1000)


def _elapsed_ms(started_ms):
    """Server-measured latency in whole milliseconds, or ``None``.

    ``None`` when the start was never recorded or the gap is implausible, so a
    stale session cannot write a meaningless figure into the research record.
    """
    if not isinstance(started_ms, int):
        return None
    elapsed = _now_ms() - started_ms
    if elapsed < 0 or elapsed > MAX_RESPONSE_MS:
        return None
    return elapsed


def _parse_confidence(raw):
    """Strict 0..100 integer, or ``None`` when malformed.

    The slider submits an integer; anything else is a malformed submission and
    is refused server-side rather than coerced.
    """
    if raw is None:
        return None
    raw = str(raw)
    # ASCII digits only, and no surrounding whitespace. ``str.isdigit`` alone
    # would accept other Unicode digit forms that ``int()`` happily parses;
    # a range slider never submits one, so anything else is malformed input
    # rather than something to normalise.
    if not raw or len(raw) > 3 or any(c not in "0123456789" for c in raw):
        return None
    value = int(raw)
    return value if 0 <= value <= 100 else None


def _choices():
    decision = PHISHING_SCENARIO.decision(PHISHING_DECISION_ID)
    return decision.choices


def create_training_blueprint(db, TrainingExecution, identities, service):
    """Build the learner blueprint.

    Dependencies are injected exactly as ``sandbox_routes`` does, so ``app.py``
    stays the only module that knows how the database, the model, the synthetic
    identity store and the training service are wired together.
    """
    bp = Blueprint("training", __name__, url_prefix="/training")

    def _session_id():
        return session.get("session_id")

    def _execution_for_session():
        """This session's current execution row, or ``None``.

        Ownership is enforced two ways: the ``execution_id`` is read from the
        server-side session (it is never accepted from a URL or a form), and
        the loaded row's ``session_id`` must still match. One learner therefore
        has no address with which to name another learner's result.
        """
        state = _state()
        if not state or not state.get("execution_id"):
            return None
        row = (TrainingExecution.query
               .filter_by(execution_id=state["execution_id"]).first())
        if row is None or row.session_id != _session_id():
            return None
        return row

    # -- home ---------------------------------------------------------------
    @bp.route("")
    @bp.route("/")
    def home():
        return render_template("training_home.html")

    # -- briefing -----------------------------------------------------------
    @bp.route("/phishing")
    def phishing_brief():
        return render_template(
            "training_phishing_brief.html",
            identities=identities.identities(_session_id()),
            lab_domain=identities.domain,
            started=bool(_state()))

    @bp.route("/phishing/start", methods=["POST"])
    def phishing_start():
        """Begin (or deliberately restart) an attempt.

        A restart is an explicit POST and intentionally creates a new attempt,
        which may later produce a second ``TrainingExecution``. Nothing passive
        -- no GET, no refresh, no prefetch -- can reach this.
        """
        _save(_blank_state())
        return redirect(url_for("training.phishing_inbox"))

    # -- the decision -------------------------------------------------------
    @bp.route("/phishing/inbox")
    def phishing_inbox():
        state = _state()
        if state is None:
            return redirect(url_for("training.phishing_brief"))
        # Server-side start of the latency measurement, refreshed each time the
        # decision is actually displayed.
        state["decision_shown_ms"] = _now_ms()
        _save(state)
        return render_template("training_phishing_inbox.html", org=ORG,
                               choices=_choices(), error=None)

    @bp.route("/phishing/decision", methods=["POST"])
    def phishing_decision():
        state = _state()
        if state is None:
            return redirect(url_for("training.phishing_brief"))

        choice_id = (request.form.get("choice_id") or "").strip()
        confidence = _parse_confidence(request.form.get("confidence"))
        if choice_id not in PHISHING_CHOICE_IDS or confidence is None:
            # Server-side validation, not a disabled button: an unsupported
            # choice or a malformed confidence never reaches the runtime.
            return render_template(
                "training_phishing_inbox.html", org=ORG, choices=_choices(),
                error="Choose one option and set a confidence between 0 and "
                      "100."), 400

        state["factual_choice"] = choice_id
        state["factual_confidence"] = confidence
        state["factual_response_ms"] = _elapsed_ms(
            state.get("decision_shown_ms"))
        state["credential_validated"] = False
        _save(state)

        if choice_id == CREDENTIAL_CHOICE_ID:
            return redirect(url_for("training.phishing_signin"))
        return redirect(url_for("training.phishing_outcome"))

    # -- executing the pair -------------------------------------------------
    def _outcome_error(state, message, status):
        factual = state["factual_choice"]
        return render_template(
            "training_phishing_outcome.html", org=ORG,
            evidence=BRANCH_EVIDENCE[factual],
            factual_label=label_for_choice(factual),
            alternatives=[c for c in _choices() if c.choice_id != factual],
            error=message), status

    def _execute_pair(state):
        """Run the stored pair and redirect to its persisted result.

        Called once both branches are prerequisites-complete: straight from the
        rewind for a branch that needs no credential, and only after a
        successful counterfactual sign-in otherwise. The runtime still receives
        exactly ``factual_choice_id`` and ``counterfactual_choice_id`` in the
        learner's own order; nothing here swaps them.
        """
        try:
            execution_id, _pair = service().run_pair(
                PHISHING_SCENARIO, PhishingConsequenceAdapter(),
                PHISHING_DECISION_ID,
                factual_choice_id=state["factual_choice"],
                counterfactual_choice_id=state["counterfactual_choice"],
                session_id=_session_id(),
                factual_confidence=state.get("factual_confidence"),
                counterfactual_confidence=state.get(
                    "counterfactual_confidence"),
                factual_response_ms=state.get("factual_response_ms"),
                counterfactual_response_ms=state.get(
                    "counterfactual_response_ms"))
        except (TrainingExecutionError, TrainingPersistenceError):
            # Both carry only a class name and an opaque reference; neither the
            # message nor a traceback reaches the learner.
            return _outcome_error(
                state, "The comparison could not be executed. Start the "
                       "scenario again.", 500)

        state["execution_id"] = execution_id
        _save(state)
        # POST -> Redirect -> GET: the result page is a plain GET, so a refresh
        # re-reads a stored row instead of resubmitting anything.
        return redirect(url_for("training.phishing_result"))

    # -- the credential-submission sign-in, either branch ------------------
    #
    # One implementation, parameterised by which branch role is submitting the
    # credential. ``follow_link_and_sign_in`` means the same thing whichever
    # side of the comparison it is on, so it has the same prerequisite and the
    # same validation on both: the learner must actually complete the synthetic
    # sign-in before that branch counts as experienced.
    FACTUAL, COUNTERFACTUAL = "factual", "counterfactual"

    def _signin_ready(state, role):
        """``None`` when this role may sign in, otherwise a redirect target.

        Both roles are gated the same way: the role must actually have chosen
        the credential-submission action, and must not have validated already.
        """
        if state is None:
            return url_for("training.phishing_brief")
        if role == COUNTERFACTUAL:
            if state.get("execution_id"):
                return url_for("training.phishing_result")
            if state.get("counterfactual_choice") != CREDENTIAL_CHOICE_ID:
                return url_for("training.phishing_outcome")
            if state.get("counterfactual_credential_validated"):
                return url_for("training.phishing_result")
            return None
        if state.get("factual_choice") != CREDENTIAL_CHOICE_ID:
            return url_for("training.phishing_brief")
        if state.get("credential_validated"):
            return url_for("training.phishing_outcome")
        return None

    def _signin(role):
        """The single credential-validation implementation.

        Whatever the branch role, the submitted password exists only as an
        argument to the HMAC comparison in ``sandbox.identity`` and is dropped
        there. The submitted username is compared and discarded: whether or not
        it matched, it is not stored, echoed back, flashed, logged or written to
        telemetry.
        """
        state = _state()
        elsewhere = _signin_ready(state, role)
        if elsewhere is not None:
            return redirect(elsewhere)

        action = url_for("training.phishing_signin_counterfactual"
                         if role == COUNTERFACTUAL
                         else "training.phishing_signin")
        if request.method == "GET":
            return render_template("training_phishing_signin.html", org=ORG,
                                   role=role, action=action, error=None)

        valid, _reason = identities.validate(
            _session_id(), request.form.get("username", ""),
            request.form.get("password", ""))
        if not valid:
            return render_template(
                "training_phishing_signin.html", org=ORG, role=role,
                action=action,
                error="Those details do not match a lab identity issued to "
                      "this session. Use one of the identities from the "
                      "briefing -- never a real account."), 401

        if role == COUNTERFACTUAL:
            state["counterfactual_credential_validated"] = True
            _save(state)
            # The counterfactual branch is only now experienced, so this is
            # the first moment the paired comparison may run.
            return _execute_pair(state)

        state["credential_validated"] = True
        _save(state)
        return redirect(url_for("training.phishing_outcome"))

    @bp.route("/phishing/signin", methods=["GET", "POST"])
    def phishing_signin():
        return _signin(FACTUAL)

    @bp.route("/phishing/signin/counterfactual", methods=["GET", "POST"])
    def phishing_signin_counterfactual():
        return _signin(COUNTERFACTUAL)

    # -- what the chosen path produced, and the rewind ----------------------
    @bp.route("/phishing/outcome")
    def phishing_outcome():
        state = _state()
        if state is None or not state.get("factual_choice"):
            return redirect(url_for("training.phishing_brief"))
        choice_id = state["factual_choice"]
        if choice_id == CREDENTIAL_CHOICE_ID and not state.get(
                "credential_validated"):
            # The factual branch is not ready for execution until the sign-in
            # actually happened.
            return redirect(url_for("training.phishing_signin"))
        if state.get("execution_id"):
            return redirect(url_for("training.phishing_result"))

        state["rewind_shown_ms"] = _now_ms()
        _save(state)
        alternatives = [c for c in _choices() if c.choice_id != choice_id]
        return render_template(
            "training_phishing_outcome.html", org=ORG,
            evidence=BRANCH_EVIDENCE[choice_id],
            factual_label=label_for_choice(choice_id),
            alternatives=alternatives, error=None)

    @bp.route("/phishing/rewind", methods=["POST"])
    def phishing_rewind():
        state = _state()
        if state is None or not state.get("factual_choice"):
            return redirect(url_for("training.phishing_brief"))
        # Idempotency, enforced server-side: once this attempt has an
        # execution, a resubmission redirects to it rather than running a
        # second experiment.
        if state.get("execution_id"):
            return redirect(url_for("training.phishing_result"))

        factual = state["factual_choice"]
        if factual == CREDENTIAL_CHOICE_ID and not state.get(
                "credential_validated"):
            return redirect(url_for("training.phishing_signin"))

        alternative = (request.form.get("choice_id") or "").strip()
        confidence = _parse_confidence(request.form.get("confidence"))
        if (alternative not in PHISHING_CHOICE_IDS or alternative == factual
                or confidence is None):
            return _outcome_error(
                state, "Pick a different decision from the one you made, and "
                       "set a confidence between 0 and 100.", 400)

        state["counterfactual_choice"] = alternative
        state["counterfactual_confidence"] = confidence
        # The counterfactual decision latency ends here, at the moment the
        # alternative was submitted. Any time spent afterwards typing the
        # synthetic credential is sign-in time, not decision time, and is
        # deliberately excluded.
        state["counterfactual_response_ms"] = _elapsed_ms(
            state.get("rewind_shown_ms"))
        state["counterfactual_credential_validated"] = False
        _save(state)

        if alternative == CREDENTIAL_CHOICE_ID:
            # Symmetric with the factual path: this branch is not experienced,
            # and the pair does not run, until the learner completes the
            # synthetic sign-in on it.
            return redirect(url_for("training.phishing_signin_counterfactual"))

        return _execute_pair(state)

    # -- the comparison -----------------------------------------------------
    @bp.route("/phishing/result")
    def phishing_result():
        row = _execution_for_session()
        if row is None:
            return redirect(url_for("training.phishing_brief"))
        if row.status != TrainingExecution.STATUS_COMPLETED:
            abort(409)

        # Rendered entirely from the persisted execution. Nothing here consults
        # the submitted form values, so the page is a view of the stored
        # result rather than a recomputation of it.
        factual_state = json.loads(row.factual_state_json or "{}")
        counterfactual_state = json.loads(row.counterfactual_state_json or "{}")
        difference = json.loads(row.difference_json or "{}")
        return render_template(
            "training_phishing_result.html",
            row=row,
            factual_label=label_for_choice(row.factual_choice_id),
            counterfactual_label=label_for_choice(
                row.counterfactual_choice_id),
            factual_lines=describe_state(factual_state, SYNTHETIC_RESOURCES),
            counterfactual_lines=describe_state(counterfactual_state,
                                                SYNTHETIC_RESOURCES),
            difference_lines=describe_difference(difference,
                                                 SYNTHETIC_RESOURCES))

    return bp
