"""The RewindSec research-study flow (milestone R7).

A blueprint mounted at ``/study``, entirely separate from the ordinary training
and learning flows:

    GET  /study                       gate: access code, or resume where you are
    POST /study/enroll                allocate, and show the return code once
    GET  /study/training              the phishing message and the first decision
    POST /study/training/decision     the pre-intervention behavioural measure
    GET  /study/intervention          the assigned intervention
    POST /study/intervention/continue arms A and B finish here
    POST /study/counterfactual        arm C: rewind and run the pair
    GET  /study/comparison            arm C: the executed side-by-side result
    GET/POST /study/reflection        arm C: the structured self-explanation
    GET/POST /study/immediate         the immediate transfer probe
    GET  /study/immediate/complete    "Response recorded." Nothing else.
    GET/POST /study/retention         the delayed transfer probe
    GET  /study/complete              the end of the participant's involvement
    GET/POST /study/resume            return-code continuity
    GET  /study/admin                 instructor-only descriptive dashboard
    GET  /study/admin/export.csv      instructor-only research export

Rules this module holds to
--------------------------
**Research mode is off unless a deployment turns it on.** Every route in this
blueprint 404s when it is off, so a normal RewindSec deployment has no study
surface at all and an ordinary learner cannot wander into a research protocol.

**The phase is server-authoritative.** Progress is read from the enrollment row
and advanced only through :meth:`StudyService.advance`. There is no phase field
in any form, no phase in any URL, and typing a later route reaches
:class:`StudyStateError` and a redirect to wherever the participant actually is.

**The arm is never accepted from the browser.** It is allocated once at
enrollment and read only from the row. No form field, query string, header or
cookie value named ``arm`` is consulted anywhere in this file, and the
learner-facing pages never name an arm, a condition, a group, or "control" and
"experimental".

**The first decision is identical in all three arms.** One template, one
message fixture, one choice list in one order, one confidence control -- and the
arm is not resolved until after the decision is recorded.

**No feedback after a probe.** The immediate probe's completion page says only
that the response was recorded. Revealing the quality would make the
measurement a further intervention and contaminate the retention probe.

**POST -> Redirect -> GET, everywhere except the return code.** That one page is
rendered directly from its POST because the raw code exists for exactly one
response and is deliberately not stored anywhere -- not in the database, not in
the session, not in a log -- so there is nothing for a redirected GET to read.

**No free text.** Every form submits a fixed authored identifier and, where
applicable, a confidence slider.
"""

import csv
import io
import time

from flask import (Blueprint, Response, abort, redirect, render_template,
                   request, session, url_for)

import learning
import study
from learning.errors import LearningError
from scenario_adapters.presentation import (describe_difference, describe_state,
                                            label_for_choice, vocabulary_for)
from scenario_adapters.phishing import (PHISHING_CHOICE_IDS, PHISHING_DECISION_ID,
                                        PHISHING_SCENARIO, PHISHING_SCENARIO_KEY)
from security import require_instructor
from study.errors import (PhaseTransitionError, RetentionWindowError,
                          StudyConfigurationError, StudyError)
from study_service import (EnrollmentNotFoundError, StudyLayerError,
                           StudyStateError)
from training_service import TrainingExecutionError, TrainingPersistenceError

#: Server-side session key holding this browser's study binding. It carries the
#: ``participant_id`` and nothing else -- no arm, no phase, no return code.
STUDY_SESSION_KEY = "rewindsec_study"

#: Per-page server-side latency timers, one key per measured page so two pages
#: in one session cannot overwrite each other's start.
TIMER_KEY = "rewindsec_study_shown"

#: Upper bound on a measured response latency (one hour), matching the training
#: and R6 probe flows. Beyond it the latency is recorded as "not measured".
MAX_RESPONSE_MS = 60 * 60 * 1000

#: The fictional organisation the study's phishing message is set in. Imported
#: from nowhere and duplicated deliberately: the study fixture must be frozen
#: for the life of the protocol, and it must not silently change if the
#: demonstration module's wording is ever revised.
STUDY_ORG = {
    "name": "Northgate Campus Services",
    "short": "Northgate",
    "real_domain": "northgate-services.lab",
    "display_sender": "Northgate Account Services",
    "lure_sender": "no-reply@northgate-secure-verify.lab",
    "lure_host": "northgate-secure-verify.lab",
}

#: Arm A's whole intervention: a concise conventional awareness debrief.
#:
#: Deliberately what a conventional awareness module gives you -- the principles,
#: stated plainly, with no branch state, no simulated account access, no rewind,
#: no alternative decision, no state diff and no structured reflection. Making it
#: weaker than a real awareness debrief would flatter the other two arms; making
#: it interactive would stop it being the conventional condition.
AWARENESS_DEBRIEF = {
    "heading": "Checking a request like this one",
    "lead": ("Messages of this kind rely on urgency and on a route they supply "
             "themselves. Three habits deal with almost all of them."),
    "points": (
        ("Inspect the request before acting on it.",
         "A display name is not a sending address. Urgency and a deadline in a "
         "message about your own account are a reason to slow down, not to "
         "hurry."),
        ("Verify through a channel you already trust.",
         "Use a number, address or portal you already had -- from your "
         "contacts or your browser's bookmarks -- rather than the route the "
         "message offers you."),
        ("Never present credentials to an unverified request.",
         "If a request cannot be confirmed through a channel you already "
         "trust, it does not get your account details. Report it and leave it "
         "alone."),
    ),
}


def now_ms():
    return int(time.time() * 1000)


def elapsed_ms(started_ms):
    """Server-measured latency in whole milliseconds, or ``None``.

    Measured from when the page was actually rendered, server-side, so there is
    no client-supplied duration to trust; an implausible gap is recorded as
    "not measured" rather than as a number.
    """
    if not isinstance(started_ms, int):
        return None
    elapsed = now_ms() - started_ms
    if elapsed < 0 or elapsed > MAX_RESPONSE_MS:
        return None
    return elapsed


def parse_confidence(raw):
    """Strict 0..100 integer, or ``None`` when malformed.

    ASCII digits only. The same rule the training and R6 flows apply, repeated
    rather than imported so the study flow depends on neither.
    """
    if raw is None:
        return None
    raw = str(raw)
    if not raw or len(raw) > 3 or any(c not in "0123456789" for c in raw):
        return None
    value = int(raw)
    return value if 0 <= value <= 100 else None


def study_choices():
    """The phishing decision's choices, in the one authored order.

    Read from the scenario definition itself, so all three arms are guaranteed
    the same options in the same order by construction rather than by three
    templates agreeing.
    """
    return PHISHING_SCENARIO.decision(PHISHING_DECISION_ID).choices


def create_study_blueprint(service, session_id, settings):
    """Build the study blueprint.

    ``service`` is a zero-argument callable returning the configured
    :class:`~study_service.StudyService`; ``session_id`` a zero-argument
    callable returning the canonical server-side Flask session id; ``settings``
    a zero-argument callable returning the live research-mode configuration.
    None of the three is ever read from a request.
    """
    bp = Blueprint("study", __name__, url_prefix="/study")

    # ======================================================================
    # Research-mode gating
    # ======================================================================
    @bp.before_request
    def _gate():
        """404 unless research mode is on; 503 when it is on but unconfigured.

        A 404 rather than a 403: with research mode off there is no study
        surface to discover, and a normal deployment should not advertise that
        one could exist.

        The 503 is the fail-closed case required by the protocol. Research mode
        with no allocation secret would make the allocation either public or
        irreproducible, and with no access code would let ordinary learners
        wander into a research protocol; neither is a state to serve pages in.
        """
        config = settings() or {}
        if not config.get("enabled"):
            abort(404)
        if (not config.get("assignment_secret") or not config.get("access_code")
                or not config.get("continuity_secret")):
            return render_template("study_unavailable.html"), 503
        return None

    # ======================================================================
    # Resolving the participant, server-side only
    # ======================================================================
    def participant_id():
        state = session.get(STUDY_SESSION_KEY)
        return state.get("participant_id") if isinstance(state, dict) else None

    def bind(enrollment):
        """Point this browser session at an enrollment.

        The session carries the ``participant_id`` and nothing else: no arm, no
        phase, no return code. Everything that decides what the participant
        sees is re-read from the row on every request.
        """
        session[STUDY_SESSION_KEY] = {
            "participant_id": enrollment.participant_id}
        session.modified = True
        return enrollment

    def enrollment():
        """The enrollment this session owns, or :class:`EnrollmentNotFoundError`."""
        return service().enrollment_for_session(participant_id(), session_id())

    def timer_start(key):
        timers = dict(session.get(TIMER_KEY) or {})
        timers[key] = now_ms()
        session[TIMER_KEY] = timers
        session.modified = True

    def timer_read(key):
        return elapsed_ms((session.get(TIMER_KEY) or {}).get(key))

    # -- where a participant belongs right now -----------------------------
    #: Phase -> the one route that phase is served by. A participant who asks
    #: for anything else is sent here, so "you cannot skip ahead" and "you
    #: cannot go back and redo a measurement" are the same single rule.
    PHASE_ENDPOINTS = {
        study.ENROLLED: "study.training",
        study.SOURCE_DECISION_RECORDED: "study.intervention",
        study.FACTUAL_PREVIEW: "study.intervention",
        study.COUNTERFACTUAL_COMPLETED: "study.comparison",
        study.REFLECTION_COMPLETED: "study.immediate_probe",
        study.INTERVENTION_COMPLETED: "study.immediate_probe",
        study.IMMEDIATE_TRANSFER_COMPLETED: "study.immediate_complete",
        study.RETENTION_WAITING: "study.retention_probe",
        study.RETENTION_COMPLETED: "study.complete",
    }

    def where(row):
        return redirect(url_for(PHASE_ENDPOINTS[row.phase]))

    def lost():
        """No enrollment for this browser: back to the gate."""
        return redirect(url_for("study.gate"))

    # ======================================================================
    # The gate and enrollment
    # ======================================================================
    @bp.route("", methods=["GET"])
    @bp.route("/", methods=["GET"])
    def gate():
        try:
            return where(enrollment())
        except EnrollmentNotFoundError:
            pass
        return render_template("study_gate.html",
                               post_url=url_for("study.enroll"),
                               resume_url=url_for("study.resume"),
                               error=None)

    def gate_error(message, status=400):
        return render_template("study_gate.html",
                               post_url=url_for("study.enroll"),
                               resume_url=url_for("study.resume"),
                               error=message), status

    @bp.route("/enroll", methods=["POST"])
    def enroll():
        """Allocate this participant, and show their return code once.

        The access code is an access gate and nothing more: it is compared in
        constant time, it is never written to the enrollment row, never
        rendered, and never logged.

        This response renders the return code directly rather than redirecting.
        The raw code exists for exactly this one response -- only its keyed
        digest is stored -- so there is nothing a redirected GET could read, and
        stashing it in the session to survive a redirect would be storing it.
        """
        try:
            return where(enrollment())
        except EnrollmentNotFoundError:
            pass

        import hmac
        expected = (settings() or {}).get("access_code") or ""
        supplied = request.form.get("access_code") or ""
        if not hmac.compare_digest(str(expected), str(supplied)):
            return gate_error("That access code was not recognised.", 403)

        try:
            row, code = service().enroll(session_id())
        except (StudyConfigurationError, StudyLayerError):
            return render_template("study_unavailable.html"), 503
        bind(row)
        return render_template("study_return_code.html", return_code=code,
                               continue_url=url_for("study.training"))

    # ======================================================================
    # Return-code continuity
    # ======================================================================
    @bp.route("/resume", methods=["GET"])
    def resume():
        return render_template("study_resume.html",
                               post_url=url_for("study.resume"), error=None)

    @bp.route("/resume", methods=["POST"])
    def resume_submit():
        """Re-bind this browser to an existing enrollment.

        The code is read from the POST body -- never a query string, so it
        cannot end up in a browser history, a proxy log or a ``Referer``
        header. It is not logged, not echoed back into the page, and not
        written to the session.

        What changes is which browser session owns the enrollment. The
        participant id, the allocated arm and every recorded response are
        untouched.
        """
        submitted = (request.form.get("return_code") or "").strip()
        try:
            row = service().resume(submitted, session_id())
        except (EnrollmentNotFoundError, StudyConfigurationError):
            # One answer for a malformed code, an unknown code and a
            # misconfigured deployment, so the form cannot be used to test
            # which codes exist.
            return render_template(
                "study_resume.html", post_url=url_for("study.resume"),
                error="That return code was not recognised."), 400
        bind(row)
        return where(row)

    # ======================================================================
    # The first decision -- identical in all three arms
    # ======================================================================
    def training_context(error=None):
        return {
            "org": STUDY_ORG,
            "choices": study_choices(),
            "post_url": url_for("study.training_decision"),
            "error": error,
        }

    @bp.route("/training", methods=["GET"])
    def training():
        """The phishing message and the decision. One page for every arm.

        Nothing on this page, and nothing in the context above, depends on the
        enrollment's arm: the organisation, the message, the choices, their
        order, the confidence control and the visual treatment are the same
        fixture whichever arm the participant was allocated to, and no arm-
        specific feedback exists yet. That is what makes the response recorded
        here a usable pre-intervention baseline.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if row.phase != study.ENROLLED:
            return where(row)
        # Server-side start of the latency measurement, refreshed each time the
        # decision is actually displayed.
        timer_start("source_decision")
        return render_template("study_training.html", **training_context())

    @bp.route("/training/decision", methods=["POST"])
    def training_decision():
        """Record the pre-intervention behavioural measure, then branch.

        The order matters and is deliberate: the decision is persisted *before*
        the arm is consulted for anything. A participant who abandons the study
        immediately after this POST has still contributed a clean baseline.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if row.phase != study.ENROLLED:
            return where(row)

        choice_id = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if choice_id not in PHISHING_CHOICE_IDS or confidence is None:
            # Server-side validation, not a disabled button.
            return render_template("study_training.html", **training_context(
                "Choose one response and set a confidence between 0 and "
                "100.")), 400

        try:
            service().record_source_decision(
                row, choice_id, confidence,
                response_time_ms=timer_read("source_decision"))
        except (LearningError, StudyError):
            abort(400)
        return redirect(url_for("study.intervention"))

    # ======================================================================
    # The assigned intervention
    # ======================================================================
    @bp.route("/intervention", methods=["GET"])
    def intervention():
        """Dispatch to the assigned intervention. The arm is read from the row.

        The three branches below are the whole experimental manipulation. Each
        renders its own template and nothing else; no page names an arm, and no
        page tells a participant that other participants saw something
        different.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.at_least(row.arm_key, row.phase,
                              study.SOURCE_DECISION_RECORDED):
            return where(row)
        if study.at_least(row.arm_key, row.phase, study.INTERVENTION_COMPLETED):
            return where(row)

        item = service().intervention_for(row)
        if item is None:
            return where(row)

        # -- Arm A: the conventional awareness debrief ---------------------
        # No adapter is constructed, no consequence is applied, no branch state
        # is shown, no rewind is offered and no reflection is asked for.
        if not study.executes_consequence(row.arm_key):
            return render_template(
                "study_debrief.html", debrief=AWARENESS_DEBRIEF,
                post_url=url_for("study.intervention_continue"))

        # -- Arms B and C: the real deterministic factual consequence -------
        if row.phase == study.SOURCE_DECISION_RECORDED:
            try:
                service().apply_factual_consequence(row, item)
            except StudyError:
                abort(409)
        if row.phase == study.COUNTERFACTUAL_COMPLETED:
            return where(row)

        state_lines = describe_state(
            service().factual_state(item),
            vocabulary=vocabulary_for(PHISHING_SCENARIO_KEY))
        factual_label = label_for_choice(PHISHING_SCENARIO_KEY,
                                         item.factual_choice_id)

        if study.runs_counterfactual(row.arm_key):
            # Arm C: the same factual consequence, followed by the rewind.
            timer_start("counterfactual")
            return render_template(
                "study_factual.html", state_lines=state_lines,
                factual_label=factual_label,
                alternatives=[c for c in study_choices()
                              if c.choice_id != item.factual_choice_id],
                post_url=url_for("study.counterfactual"), error=None)

        # Arm B: the factual consequence, and a concise authored debrief. No
        # rewind, no alternative, no pair, no state diff, no reflection.
        return render_template(
            "study_factual_only.html", state_lines=state_lines,
            factual_label=factual_label, debrief=AWARENESS_DEBRIEF,
            post_url=url_for("study.intervention_continue"))

    @bp.route("/intervention/continue", methods=["POST"])
    def intervention_continue():
        """Arms A and B finish their intervention here.

        Arm C does not use this route: its intervention is complete when the
        structured reflection is recorded, and reaching this would let it skip
        the reflection.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if study.runs_counterfactual(row.arm_key):
            return where(row)
        item = service().intervention_for(row)
        if item is None:
            return where(row)
        try:
            service().complete_intervention(row, item)
        except StudyError:
            return where(row)
        return redirect(url_for("study.immediate_probe"))

    # ======================================================================
    # Arm C: the verified paired replay
    # ======================================================================
    @bp.route("/counterfactual", methods=["POST"])
    def counterfactual():
        """Rewind, run the pair, and go to the comparison. Arm C only.

        The pair is produced by the real R2 service over the real R1 runtime.
        Nothing here reimplements the rewind, the digest verification or the
        state diff.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.runs_counterfactual(row.arm_key):
            abort(404)
        if row.phase != study.FACTUAL_PREVIEW:
            return where(row)
        item = service().intervention_for(row)
        if item is None:
            return where(row)

        alternative = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if (alternative not in PHISHING_CHOICE_IDS
                or alternative == item.factual_choice_id
                or confidence is None):
            return render_template(
                "study_factual.html",
                state_lines=describe_state(
                    service().factual_state(item),
                    vocabulary=vocabulary_for(PHISHING_SCENARIO_KEY)),
                factual_label=label_for_choice(PHISHING_SCENARIO_KEY,
                                               item.factual_choice_id),
                alternatives=[c for c in study_choices()
                              if c.choice_id != item.factual_choice_id],
                post_url=url_for("study.counterfactual"),
                error="Pick a different response from the one you made, and "
                      "set a confidence between 0 and 100."), 400

        try:
            service().run_counterfactual(
                row, item, alternative, confidence,
                response_time_ms=timer_read("counterfactual"))
        except (TrainingExecutionError, TrainingPersistenceError, StudyError):
            # Carries only a class name and an opaque reference; neither a
            # message nor a traceback reaches the participant.
            abort(500)
        return redirect(url_for("study.comparison"))

    @bp.route("/comparison", methods=["GET"])
    def comparison():
        """The executed side-by-side comparison. Rendered from the stored row."""
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.runs_counterfactual(row.arm_key):
            abort(404)
        if row.phase != study.COUNTERFACTUAL_COMPLETED:
            return where(row)
        item = service().intervention_for(row)
        execution = service().execution_for(item) if item else None
        if execution is None:
            return where(row)
        if execution.status != "completed":
            abort(409)

        import json as _json
        vocabulary = vocabulary_for(execution.scenario_key)
        return render_template(
            "study_comparison.html", row=execution,
            factual_label=label_for_choice(execution.scenario_key,
                                           execution.factual_choice_id),
            counterfactual_label=label_for_choice(
                execution.scenario_key, execution.counterfactual_choice_id),
            factual_lines=describe_state(
                _json.loads(execution.factual_state_json or "{}"),
                vocabulary=vocabulary),
            counterfactual_lines=describe_state(
                _json.loads(execution.counterfactual_state_json or "{}"),
                vocabulary=vocabulary),
            difference_lines=describe_difference(
                _json.loads(execution.difference_json or "{}"),
                vocabulary=vocabulary),
            reflection_url=url_for("study.reflection"))

    # ======================================================================
    # Arm C: the structured self-explanation
    # ======================================================================
    def reflection_context(item, definition, error=None):
        return {
            "prompt": definition.prompt,
            # Only the authored options, in authored order. The template has no
            # other source of options.
            "options": definition.options,
            "factual_label": label_for_choice(PHISHING_SCENARIO_KEY,
                                              item.factual_choice_id),
            "post_url": url_for("study.reflection"),
            "error": error,
        }

    @bp.route("/reflection", methods=["GET"])
    def reflection():
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.requires_reflection(row.arm_key):
            abort(404)
        if row.phase != study.COUNTERFACTUAL_COMPLETED:
            return where(row)
        item = service().intervention_for(row)
        if item is None:
            return where(row)
        definition = learning.reflection_for(PHISHING_SCENARIO_KEY)
        return render_template("study_reflection.html",
                               **reflection_context(item, definition))

    @bp.route("/reflection", methods=["POST"])
    def reflection_submit():
        """Record the structured self-explanation, completing Arm C.

        Delegates to the R6 learning service, so the persisted
        ``LearningReflection`` and the derived ``ConceptEvidence`` are exactly
        what the ordinary flow produces.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.requires_reflection(row.arm_key):
            abort(404)
        if row.phase != study.COUNTERFACTUAL_COMPLETED:
            return where(row)
        item = service().intervention_for(row)
        if item is None:
            return where(row)

        definition = learning.reflection_for(PHISHING_SCENARIO_KEY)
        selected = (request.form.get("explanation_id") or "").strip()
        if selected not in definition.explanation_ids:
            return render_template("study_reflection.html",
                                   **reflection_context(
                                       item, definition,
                                       "Choose the explanation that best "
                                       "accounts for the difference.")), 400
        try:
            service().record_reflection(row, item, selected)
        except (LearningError, StudyError):
            abort(400)
        return redirect(url_for("study.immediate_probe"))

    # ======================================================================
    # The two transfer probes
    # ======================================================================
    def probe_context(probe, post_url, error=None):
        return {
            "probe": probe,
            "choices": probe.choices,
            "qr_cells": (_inert_qr_cells()
                         if probe.probe_key == study.IMMEDIATE_PROBE_KEY
                         else None),
            "post_url": post_url,
            "error": error,
        }

    @bp.route("/immediate", methods=["GET"])
    def immediate_probe():
        """The immediate transfer probe. Identical for all three arms."""
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.at_least(row.arm_key, row.phase,
                              study.INTERVENTION_COMPLETED):
            return where(row)
        if row.phase != study.INTERVENTION_COMPLETED:
            return where(row)
        timer_start(study.IMMEDIATE_TRANSFER)
        return render_template(
            "study_probe.html",
            **probe_context(study.probe_for_phase(study.IMMEDIATE_TRANSFER),
                            url_for("study.immediate_probe_submit")))

    @bp.route("/immediate", methods=["POST"])
    def immediate_probe_submit():
        return _submit_probe(study.IMMEDIATE_TRANSFER,
                             url_for("study.immediate_probe_submit"),
                             "study.immediate_complete")

    @bp.route("/immediate/complete", methods=["GET"])
    def immediate_complete():
        """"Response recorded." Deliberately nothing else.

        No response quality, no correct or preferred answer, no security
        principle. The retention probe measures what the participant retained
        from the *intervention*; telling them here which answer was protective
        would make this page a further intervention and would contaminate the
        very measurement it precedes. The ordinary non-study R6 probe keeps its
        full feedback -- this suppression exists only in study mode.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if not study.at_least(row.arm_key, row.phase,
                              study.IMMEDIATE_TRANSFER_COMPLETED):
            return where(row)
        return render_template("study_recorded.html",
                               open_at=row.retention_open_at,
                               close_at=row.retention_close_at)

    @bp.route("/retention", methods=["GET"])
    def retention_probe():
        """The delayed transfer probe, gated by the authored window."""
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if row.phase == study.RETENTION_COMPLETED:
            return redirect(url_for("study.complete"))
        if row.phase != study.RETENTION_WAITING:
            return where(row)

        state = service().retention_state(row)
        if state != study.RETENTION_OPEN:
            return render_template("study_retention_closed.html", state=state,
                                   open_at=row.retention_open_at,
                                   close_at=row.retention_close_at)
        timer_start(study.RETENTION_TRANSFER)
        return render_template(
            "study_probe.html",
            **probe_context(study.probe_for_phase(study.RETENTION_TRANSFER),
                            url_for("study.retention_probe_submit")))

    @bp.route("/retention", methods=["POST"])
    def retention_probe_submit():
        return _submit_probe(study.RETENTION_TRANSFER,
                             url_for("study.retention_probe_submit"),
                             "study.complete")

    def _submit_probe(phase, post_url, done_endpoint):
        """One submission path for both probes.

        Written once because the two must behave identically: same validation,
        same server-side latency measurement, same first-response-wins rule,
        and the same complete absence of feedback.
        """
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        probe = study.probe_for_phase(phase)

        if phase == study.IMMEDIATE_TRANSFER:
            if row.phase != study.INTERVENTION_COMPLETED:
                return where(row)
        else:
            if row.phase != study.RETENTION_WAITING:
                return where(row)
            try:
                service().require_retention_open(row)
            except RetentionWindowError:
                return render_template(
                    "study_retention_closed.html",
                    state=service().retention_state(row),
                    open_at=row.retention_open_at,
                    close_at=row.retention_close_at), 403

        choice_id = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if choice_id not in probe.choice_ids or confidence is None:
            return render_template(
                "study_probe.html",
                **probe_context(probe, post_url,
                                "Choose one response and set a confidence "
                                "between 0 and 100.")), 400
        try:
            service().record_attempt(row, phase, choice_id, confidence,
                                     response_time_ms=timer_read(phase))
        except (LearningError, StudyError):
            abort(400)
        return redirect(url_for(done_endpoint))

    @bp.route("/complete", methods=["GET"])
    def complete():
        try:
            row = enrollment()
        except EnrollmentNotFoundError:
            return lost()
        if row.phase != study.RETENTION_COMPLETED:
            return where(row)
        return render_template("study_complete.html")

    # ======================================================================
    # Instructor-only research views
    # ======================================================================
    @bp.route("/admin", methods=["GET"])
    @require_instructor
    def admin():
        """Descriptive operational counts. No inferential statistics.

        Everything on this page is a count of rows. There is no significance
        test, no p-value, no effect size, no confidence interval and no
        statement that one arm did better than another -- because none of those
        could be justified by the existence of this infrastructure, and the
        software must not imply otherwise.
        """
        return render_template("study_admin.html", report=service().dashboard(),
                               rows=[row.display_dict()
                                     for row in service().enrollments()],
                               export_url=url_for("study.admin_export"))

    @bp.route("/admin/export.csv", methods=["GET"])
    @require_instructor
    def admin_export():
        """One row per enrollment, in a fixed column order.

        Absent by design: the Flask ``session_id``, the return-code digest, the
        access code, IP addresses, user agents, credentials and any learner-
        authored text. The internal evaluation APIs may return a canonical
        ``session_id`` because the formal harness joins on it; a research export
        has no such need, and ``participant_id`` is the correlation identifier.
        """
        columns = service().EXPORT_COLUMNS
        buffer = io.StringIO()
        # ``csv`` handles quoting and escaping; nothing here formats a row by
        # hand, so a value containing a comma or a quote cannot break the file.
        writer = csv.DictWriter(buffer, fieldnames=list(columns),
                                extrasaction="raise", lineterminator="\n")
        writer.writeheader()
        for row in service().export_rows():
            writer.writerow(row)
        return Response(
            buffer.getvalue(), mimetype="text/csv",
            headers={"Content-Disposition":
                     "attachment; filename=rewindsec-study-export.csv",
                     "X-Robots-Tag": "noindex"})

    return bp


#: A decorative code figure for the immediate probe, identical in construction
#: to the one the R6 probe page draws: a fixed arithmetic rule over the cell
#: coordinates. It encodes nothing, there is no URL anywhere in this module for
#: it to have encoded, and nothing can be decoded from it.
QR_SIZE = 15


def _inert_qr_cells(size=QR_SIZE):
    cells = []
    for y in range(size):
        for x in range(size):
            corner = ((x < 4 and y < 4) or (x >= size - 4 and y < 4)
                      or (x < 4 and y >= size - 4))
            if corner:
                cx = x if x < 4 else size - 1 - x
                cy = y if y < 4 else size - 1 - y
                filled = cx in (0, 3) or cy in (0, 3) or (cx == 2 and cy == 2)
            else:
                filled = ((x * 7 + y * 11 + x * y * 3) % 5) < 2
            if filled:
                cells.append((x, y))
    return tuple(cells)
