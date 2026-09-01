"""The RewindSec learning-review flow (milestone R6).

Registered as its own blueprint rather than appended to ``training_routes``,
which is already a thousand lines carrying four technical flows. The split is
along the same line the packages are split on: ``training_routes`` runs paired
executions, this module consumes completed ones.

    GET/POST /training/learn/<module>/reflection   structured self-explanation
    GET      /training/learn/<module>/feedback     deterministic learning review
    GET/POST /training/transfer/<probe>            an unseen probe
    GET      /training/transfer/<probe>/feedback   the probe's authored review

Rules this module holds to
--------------------------
**``<module>`` and ``<probe>`` are allow-lists.** Both resolve through a fixed
table to a scenario key and a server-side session key. No scenario definition,
adapter, template or import path is ever named by a URL.

**The execution is resolved from the session, never from the request.** There is
no route, form field or query string anywhere here through which a learner
could name an execution -- theirs or anybody else's. The resolved row's
``session_id`` is then checked again in :class:`LearningService`.

**Nothing technical is re-run.** No adapter is constructed, no
``CounterfactualRuntime`` runs, no sandbox is touched, no ``TrainingExecution``
row is written and no ``TRAINING_*`` event is emitted. A completed pair is
read-only from here.

**POST -> Redirect -> GET, everywhere.** Refreshing a reflection, a feedback
page or a probe result re-reads stored rows and writes nothing.

**No free text.** Every form on every page submits a fixed authored identifier
and a confidence slider. There is no text input in the R6 flow at all.
"""

import time

from flask import (Blueprint, abort, redirect, render_template, request,
                   session, url_for)

import learning
from learning.errors import LearningError
from learning.transfer import MAX_RESPONSE_MS
from learning_service import (ExecutionNotEligibleError,
                              NoProbeForScenarioError, ReflectionRequiredError)
from scenario_adapters.bec import BEC_SCENARIO_KEY
from scenario_adapters.mfa import MFA_SCENARIO_KEY
from scenario_adapters.phishing import PHISHING_SCENARIO_KEY
from scenario_adapters.presentation import label_for_choice
from scenario_adapters.ransomware import RANSOMWARE_SCENARIO_KEY


class LearningModule:
    """One training module's fixed learning-review wiring.

    ``session_key`` is the server-side key ``training_routes`` /
    ``training_flow`` already store that module's attempt state under. Reading
    the execution id from there is what makes the whole flow unaddressable: the
    learner's browser never holds one.
    """

    def __init__(self, name, scenario_key, session_key, result_endpoint,
                 title):
        self.name = name
        self.scenario_key = scenario_key
        self.session_key = session_key
        self.result_endpoint = result_endpoint
        self.title = title


#: The complete allow-list of learning modules. A ``<module>`` outside it is a
#: 404 before anything is looked up.
LEARNING_MODULES = {
    m.name: m for m in (
        LearningModule("phishing", PHISHING_SCENARIO_KEY,
                       "rewindsec_training", "training.phishing_result",
                       "Phishing & Credential Compromise"),
        LearningModule("ransomware", RANSOMWARE_SCENARIO_KEY,
                       "rewindsec_training_ransomware",
                       "training.ransomware_result",
                       "Ransomware Incident Response"),
        LearningModule("mfa", MFA_SCENARIO_KEY, "rewindsec_training_mfa",
                       "training.mfa_result", "MFA Fatigue"),
        LearningModule("bec", BEC_SCENARIO_KEY, "rewindsec_training_bec",
                       "training.bec_result", "Business Email Compromise"),
    )
}

#: URL slug -> authored probe key. An allow-list for the same reason: the probe
#: definition is chosen by this table, never by the path.
PROBE_SLUGS = {
    "quishing": "quishing_portal_qr",
    "update-attachment": "unexpected_update_attachment",
}

#: The reverse mapping, so a feedback page can link to its own probe.
PROBE_KEY_SLUGS = {key: slug for slug, key in PROBE_SLUGS.items()}

#: The module whose session state holds a probe's source execution. Derived
#: from the probe's authored source scenario, so the two cannot drift.
SOURCE_MODULE_FOR_SCENARIO = {m.scenario_key: m
                              for m in LEARNING_MODULES.values()}

#: Session key holding the moment a probe was last rendered, for the
#: server-side latency measurement. One key per probe, so two probes in one
#: browser session do not overwrite each other's timer.
PROBE_TIMER_KEY = "rewindsec_probe_shown"


def now_ms():
    return int(time.time() * 1000)


def elapsed_ms(started_ms):
    """Server-measured latency in whole milliseconds, or ``None``.

    Identical in shape and bound to the training flow's measurement: the start
    is recorded server-side when the page is rendered, so there is no
    client-supplied duration to trust, and an implausible gap is recorded as
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

    ASCII digits only. The same rule the training flow applies, repeated rather
    than imported so this blueprint does not depend on the technical flow.
    """
    if raw is None:
        return None
    raw = str(raw)
    if not raw or len(raw) > 3 or any(c not in "0123456789" for c in raw):
        return None
    value = int(raw)
    return value if 0 <= value <= 100 else None


#: A decorative code figure. Fifteen rows of fifteen cells, plus the three
#: corner squares a scanner would look for.
#:
#: It is **inert by construction**: the pattern comes from a fixed arithmetic
#: rule over the cell coordinates, encodes nothing, and there is no URL, host,
#: path or payload anywhere in this module for it to have encoded. Nothing can
#: be decoded from it, and the page asks the learner to reason about the
#: request rather than to scan anything.
QR_SIZE = 15


def inert_qr_cells(size=QR_SIZE):
    """The filled cells, as a flat tuple of ``(x, y)`` pairs.

    Flat rather than nested so the template is a single loop emitting squares:
    the figure is drawn, not decoded, and there is nothing for a reader of the
    markup to reconstruct.
    """
    cells = []
    for y in range(size):
        for x in range(size):
            corner = ((x < 4 and y < 4) or (x >= size - 4 and y < 4)
                      or (x < 4 and y >= size - 4))
            if corner:
                # A finder-square outline: filled border, hollow centre.
                cx = x if x < 4 else size - 1 - x
                cy = y if y < 4 else size - 1 - y
                filled = cx in (0, 3) or cy in (0, 3) or (cx == 2 and cy == 2)
            else:
                filled = ((x * 7 + y * 11 + x * y * 3) % 5) < 2
            if filled:
                cells.append((x, y))
    return tuple(cells)


def create_learning_blueprint(TrainingExecution, service, session_id):
    """Build the learning blueprint.

    ``service`` is a zero-argument callable returning the configured
    :class:`~learning_service.LearningService`; ``session_id`` a zero-argument
    callable returning the canonical server-side session id. Neither is ever
    read from a request, and no pseudonymous label is used for authorisation.
    """
    bp = Blueprint("learning", __name__, url_prefix="/training")

    # -- resolving the execution, server-side only -------------------------
    def execution_for(module):
        """The completed execution this session holds for ``module``.

        The id is read from the module's own server-side session state -- the
        same state the technical flow wrote -- and the loaded row must match
        both this session and this module's scenario. A row from another
        scenario stored under the wrong key is refused rather than reviewed
        with the wrong scenario's authored wording.
        """
        state = session.get(module.session_key)
        if not isinstance(state, dict) or not state.get("execution_id"):
            raise ExecutionNotEligibleError("no completed execution available")
        row = service().completed_execution(state["execution_id"],
                                            session_id())
        if row.scenario_key != module.scenario_key:
            raise ExecutionNotEligibleError("no completed execution available")
        return row

    def module_or_404(name):
        module = LEARNING_MODULES.get(name)
        if module is None:
            abort(404)
        return module

    def probe_or_404(slug):
        key = PROBE_SLUGS.get(slug)
        if key is None:
            abort(404)
        return learning.probe_for_key(key)

    # ======================================================================
    # Structured self-explanation
    # ======================================================================
    def reflection_context(module, execution, definition, error=None):
        return {
            "module": module,
            "row": execution,
            "prompt": definition.prompt,
            # Only the authored options, in authored order. The template
            # renders exactly this list and has no other source of options.
            "options": definition.options,
            "factual_label": label_for_choice(execution.scenario_key,
                                              execution.factual_choice_id),
            "counterfactual_label": label_for_choice(
                execution.scenario_key, execution.counterfactual_choice_id),
            "result_url": url_for(module.result_endpoint),
            "post_url": url_for("learning.reflection", module=module.name),
            "error": error,
        }

    @bp.route("/learn/<module>/reflection", methods=["GET"])
    def reflection_page(module):
        mod = module_or_404(module)
        try:
            execution = execution_for(mod)
        except ExecutionNotEligibleError:
            # No completed comparison for this session: back to the module,
            # with no hint about whether some other session has one.
            return redirect(url_for("training.home"))
        # Already explained: the recorded first response stands, and the
        # learner is shown the review rather than the prompt again.
        if service().reflection_for_execution(execution.execution_id,
                                              execution.session_id):
            return redirect(url_for("learning.feedback", module=mod.name))
        definition = learning.reflection_for(execution.scenario_key)
        return render_template("training_reflection.html",
                               **reflection_context(mod, execution, definition))

    @bp.route("/learn/<module>/reflection", methods=["POST"])
    def reflection(module):
        mod = module_or_404(module)
        try:
            execution = execution_for(mod)
        except ExecutionNotEligibleError:
            return redirect(url_for("training.home"))

        definition = learning.reflection_for(execution.scenario_key)
        selected = (request.form.get("explanation_id") or "").strip()
        if selected not in definition.explanation_ids:
            # Server-side validation against this scenario's own options. An
            # id from another scenario is as invalid as an invented one.
            return render_template("training_reflection.html",
                                   **reflection_context(
                                       mod, execution, definition,
                                       "Choose the explanation that best "
                                       "accounts for the difference.")), 400
        try:
            service().record_reflection(execution, selected)
        except LearningError:
            abort(400)
        # POST -> Redirect -> GET. A repeat POST reaches ``record_reflection``,
        # which returns the stored first explanation without overwriting it.
        return redirect(url_for("learning.feedback", module=mod.name))

    # ======================================================================
    # Learning feedback
    # ======================================================================
    @bp.route("/learn/<module>/feedback")
    def feedback(module):
        mod = module_or_404(module)
        try:
            execution = execution_for(mod)
        except ExecutionNotEligibleError:
            return redirect(url_for("training.home"))
        reflection_row = service().reflection_for_execution(
            execution.execution_id, execution.session_id)
        if reflection_row is None:
            return redirect(url_for("learning.reflection_page",
                                    module=mod.name))

        # Every value here is recomputed server-side from the persisted
        # execution, the persisted reflection and the authored definitions.
        context = service().feedback_context(execution, reflection_row)
        probe = context.pop("probe")
        return render_template(
            "training_learning_feedback.html",
            module=mod, reflection=reflection_row,
            factual_label=label_for_choice(execution.scenario_key,
                                           execution.factual_choice_id),
            result_url=url_for(mod.result_endpoint),
            probe=probe,
            probe_url=(url_for("learning.probe_page",
                               probe=PROBE_KEY_SLUGS[probe.probe_key])
                       if probe is not None else None),
            **context)

    # ======================================================================
    # Unseen transfer probes
    # ======================================================================
    def probe_source(probe):
        """The completed, reflected-on execution that unlocks ``probe``.

        Resolved entirely server-side: the probe names its source *scenario*,
        the table maps that to a module, and the module's session state holds
        the execution id. There is no request-supplied ``source_execution_id``
        anywhere in this blueprint.
        """
        module = SOURCE_MODULE_FOR_SCENARIO[probe.source_scenario_key]
        execution = execution_for(module)
        service().require_unlocked(execution)
        return module, execution

    def probe_locked(probe):
        """Where to send a learner who has not unlocked this probe yet."""
        module = SOURCE_MODULE_FOR_SCENARIO.get(probe.source_scenario_key)
        if module is None:
            return redirect(url_for("training.home"))
        return redirect(url_for("learning.reflection_page",
                                module=module.name))

    def probe_context(probe, slug, error=None):
        return {
            "probe": probe,
            "slug": slug,
            "choices": probe.choices,
            "qr_cells": inert_qr_cells() if probe.probe_key
            == "quishing_portal_qr" else None,
            "post_url": url_for("learning.probe", probe=slug),
            "error": error,
        }

    @bp.route("/transfer/<probe>", methods=["GET"])
    def probe_page(probe):
        slug, definition = probe, probe_or_404(probe)
        try:
            _module, execution = probe_source(definition)
        except (ExecutionNotEligibleError, ReflectionRequiredError,
                NoProbeForScenarioError):
            return probe_locked(definition)
        # Already answered: the first response stands and the review is shown.
        if service().attempt_for(execution.execution_id, definition.probe_key,
                                 execution.session_id):
            return redirect(url_for("learning.probe_feedback", probe=slug))
        # The latency measurement starts server-side, here, each time the probe
        # is actually displayed.
        timers = dict(session.get(PROBE_TIMER_KEY) or {})
        timers[definition.probe_key] = now_ms()
        session[PROBE_TIMER_KEY] = timers
        session.modified = True
        return render_template("training_transfer_probe.html",
                               **probe_context(definition, slug))

    @bp.route("/transfer/<probe>", methods=["POST"])
    def probe(probe):
        slug, definition = probe, probe_or_404(probe)
        try:
            _module, execution = probe_source(definition)
        except (ExecutionNotEligibleError, ReflectionRequiredError,
                NoProbeForScenarioError):
            return probe_locked(definition)

        choice_id = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if choice_id not in definition.choice_ids or confidence is None:
            return render_template("training_transfer_probe.html",
                                   **probe_context(
                                       definition, slug,
                                       "Choose one response and set a "
                                       "confidence between 0 and 100.")), 400

        timers = session.get(PROBE_TIMER_KEY) or {}
        response_ms = elapsed_ms(timers.get(definition.probe_key))
        try:
            # Idempotent: an existing attempt is returned unchanged, so a
            # resubmission or a Back-button repost cannot revise the recorded
            # first response.
            service().record_transfer_attempt(
                execution, definition, choice_id, confidence=confidence,
                response_time_ms=response_ms)
        except LearningError:
            abort(400)
        return redirect(url_for("learning.probe_feedback", probe=slug))

    @bp.route("/transfer/<probe>/feedback")
    def probe_feedback(probe):
        slug, definition = probe, probe_or_404(probe)
        try:
            module, execution = probe_source(definition)
        except (ExecutionNotEligibleError, ReflectionRequiredError,
                NoProbeForScenarioError):
            return probe_locked(definition)
        attempt = service().attempt_for(execution.execution_id,
                                        definition.probe_key,
                                        execution.session_id)
        # Feedback exists only after a response is recorded. There is no path
        # to the authored principle before the first response is taken.
        if attempt is None:
            return redirect(url_for("learning.probe_page", probe=slug))
        context = service().transfer_feedback_context(definition, attempt)
        return render_template("training_transfer_feedback.html",
                               module=module, slug=slug, **context)

    return bp
