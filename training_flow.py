"""Shared learner-flow wiring for the Docker-free training modules (R5).

Milestone R5 adds two scenarios -- MFA Fatigue and Business Email Compromise --
whose consequence environment is a deterministic in-memory state machine rather
than the contained sandbox. Their browser flows are structurally identical:

    GET  /training/<module>            briefing
    POST /training/<module>/start      begin (or deliberately restart)
    GET  /training/<module>/<prompt>   the situation and the decision
    POST /training/<module>/decision   factual choice + confidence, then the
                                       factual preview
    GET  /training/<module>/outcome    what the factual response produced
    POST /training/<module>/rewind     the alternative, then the paired run
    GET  /training/<module>/result     the executed side-by-side comparison

Rather than write that twice, :func:`register_synthetic_module` registers one
copy of it on the training blueprint, parameterised by a
:class:`SyntheticModule` description. This is deliberately **not** a general
scenario framework: it does not abstract the runtime, the adapter contract, the
service or the comparison. It is application-side route plumbing for the shape
both R5 modules happen to share, and the R3 phishing and R4 ransomware flows
are left exactly as they were -- phishing has an extra credential-submission
step and ransomware has containment gating, so neither fits this shape and
neither was rewritten to.

Every property the R4 flow established is preserved here:

* the factual preview runs the *same* adapter and action key the authoritative
  paired execution will, from a re-established and digest-verified baseline;
* ``run_pair`` is given ``expected_baseline_digest`` and
  ``expected_factual_digest``, so a mismatch fails closed inside the service and
  leaves a ``failed`` execution rather than a completed comparison;
* POST -> Redirect -> GET everywhere, so refreshing an outcome or a result
  re-reads stored state and never re-executes anything;
* the branch order is the learner's own: ``factual`` is always the choice they
  made first, whichever it was.
"""

import json
import time
import uuid

from flask import (abort, redirect, render_template, request, session,
                   url_for)

from scenario_adapters.presentation import (describe_difference, describe_state,
                                            label_for_choice, vocabulary_for)
from training.snapshots import StateSnapshot
from training_service import TrainingExecutionError, TrainingPersistenceError

#: Upper bound on a measured decision latency (one hour). Latency is learner
#: interaction metadata measured server-side; anything past the bound is
#: recorded as "not measured" rather than as an implausible number.
MAX_RESPONSE_MS = 60 * 60 * 1000


def now_ms():
    return int(time.time() * 1000)


def elapsed_ms(started_ms):
    """Server-measured latency in whole milliseconds, or ``None``."""
    if not isinstance(started_ms, int):
        return None
    elapsed = now_ms() - started_ms
    if elapsed < 0 or elapsed > MAX_RESPONSE_MS:
        return None
    return elapsed


def parse_confidence(raw):
    """Strict 0..100 integer, or ``None`` when malformed.

    ASCII digits only, no whitespace: a range slider never submits anything
    else, so anything else is a malformed submission and is refused rather than
    coerced.
    """
    if raw is None:
        return None
    raw = str(raw)
    if not raw or len(raw) > 3 or any(c not in "0123456789" for c in raw):
        return None
    value = int(raw)
    return value if 0 <= value <= 100 else None


class SyntheticModule:
    """One Docker-free learner module's fixed description.

    ``name``            url and endpoint prefix (``mfa``, ``bec``).
    ``scenario``        the :class:`~training.ScenarioDefinition`.
    ``decision_id``     the decision this module runs.
    ``adapter_factory`` zero-argument callable returning a fresh adapter.
    ``prompt_route``    the path segment of the decision page (``prompt``,
                        ``inbox``).
    ``templates``       ``{"brief","prompt","outcome","result"}``.
    ``context``         fixed authored template context (the fictional
                        organisation, message or request). Never learner data.
    """

    def __init__(self, name, scenario, decision_id, adapter_factory,
                 prompt_route, templates, context=None):
        self.name = name
        self.scenario = scenario
        self.decision_id = decision_id
        self.adapter_factory = adapter_factory
        self.prompt_route = prompt_route
        self.templates = dict(templates)
        self.context = dict(context or {})
        self.decision = scenario.decision(decision_id)
        self.choice_ids = self.decision.choice_ids
        self.vocabulary = vocabulary_for(scenario.scenario_key)
        #: A separate session key per module, so a learner may have an attempt
        #: in progress in each without either disturbing the other.
        self.session_key = "rewindsec_training_" + name

    def endpoint(self, suffix):
        return "training.%s_%s" % (self.name, suffix)

    def url(self, suffix):
        return url_for(self.endpoint(suffix))

    def choices(self):
        return self.decision.choices

    def choice(self, choice_id):
        return self.decision.choice(choice_id)


def register_synthetic_module(bp, module, TrainingExecution, service,
                              session_id):
    """Register one module's seven routes on the training blueprint.

    ``session_id`` is a zero-argument callable returning the current server-side
    session id. It is never read from a form or a URL.
    """
    name = module.name

    # -- session-scoped attempt state --------------------------------------
    def blank_state():
        return {
            # Opaque and server-issued. Never appears in a URL and is not an
            # authenticator; it exists so a deliberate restart is
            # distinguishable from a resubmission of the same attempt.
            "attempt_id": uuid.uuid4().hex,
            "baseline_digest": None,
            "baseline_state_json": None,
            "factual_choice": None,
            "factual_confidence": None,
            "factual_response_ms": None,
            "preview_digest": None,
            "preview_state_json": None,
            "decision_shown_ms": None,
            "rewind_shown_ms": None,
            "execution_id": None,
        }

    def get_state():
        state = session.get(module.session_key)
        return state if isinstance(state, dict) else None

    def save(state):
        session[module.session_key] = state
        session.modified = True
        return state

    def capture(adapter, label):
        return StateSnapshot.capture(adapter.capture_state(), label=label)

    def execution_for_session():
        """This attempt's execution row, or ``None``.

        Ownership is enforced twice: the ``execution_id`` comes from the
        server-side session (never from a URL or a form), and the loaded row's
        ``session_id`` must still match this session.
        """
        state = get_state()
        if not isinstance(state, dict) or not state.get("execution_id"):
            return None
        row = (TrainingExecution.query
               .filter_by(execution_id=state["execution_id"]).first())
        if row is None or row.session_id != session_id():
            return None
        return row

    def render(kind, **extra):
        context = dict(module.context)
        context.update(extra)
        return render_template(module.templates[kind], **context)

    # -- briefing ----------------------------------------------------------
    def brief():
        return render("brief", started=bool(get_state()))

    def start():
        """Establish the baseline and begin (or deliberately restart).

        A restart is an explicit POST and intentionally creates a new attempt,
        which may later produce a second ``TrainingExecution``. Nothing passive
        -- no GET, no refresh, no prefetch -- reaches this.
        """
        adapter = module.adapter_factory()
        adapter.prepare()
        baseline = capture(adapter, "baseline")
        state = blank_state()
        state["baseline_digest"] = baseline.digest
        state["baseline_state_json"] = baseline.canonical_json
        save(state)
        return redirect(module.url(module.prompt_route))

    # -- the situation and the decision ------------------------------------
    def prompt_context(state, error=None):
        baseline = json.loads(state.get("baseline_state_json") or "{}")
        return {
            "choices": module.choices(),
            "state_lines": describe_state(baseline,
                                          vocabulary=module.vocabulary),
            "error": error,
        }

    def prompt():
        state = get_state()
        if state is None or not state.get("baseline_digest"):
            return redirect(module.url("brief"))
        if state.get("execution_id"):
            return redirect(module.url("result"))
        if state.get("factual_choice"):
            return redirect(module.url("outcome"))
        # Server-side start of the latency measurement, refreshed each time the
        # decision is actually displayed.
        state["decision_shown_ms"] = now_ms()
        save(state)
        return render("prompt", **prompt_context(state))

    def decision():
        state = get_state()
        if state is None or not state.get("baseline_digest"):
            return redirect(module.url("brief"))
        if state.get("execution_id"):
            return redirect(module.url("result"))
        if state.get("factual_choice"):
            # Already decided: a resubmission shows the outcome that was
            # produced rather than applying a second consequence.
            return redirect(module.url("outcome"))

        choice_id = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if choice_id not in module.choice_ids or confidence is None:
            # Server-side validation, not a disabled button: an unsupported
            # choice or a malformed confidence never reaches the runtime.
            return render("prompt", **prompt_context(
                state, "Choose one response and set a confidence between 0 "
                       "and 100.")), 400

        # The decision latency ends here, before any consequence work.
        response_ms = elapsed_ms(state.get("decision_shown_ms"))

        # The factual preview: the same adapter class, the same action key and
        # the same baseline the authoritative run will use. The baseline is
        # re-established and its digest proved first, so the response is
        # applied to the state the learner was actually shown.
        adapter = module.adapter_factory()
        adapter.prepare()
        baseline = capture(adapter, "baseline")
        if baseline.digest != state["baseline_digest"]:
            return render("prompt", **prompt_context(
                state, "This exercise could not be returned to the state it "
                       "started from. Start the scenario again.")), 409
        adapter.apply(module.choice(choice_id).action_key)
        preview = capture(adapter, "factual")

        state["factual_choice"] = choice_id
        state["factual_confidence"] = confidence
        state["factual_response_ms"] = response_ms
        state["preview_digest"] = preview.digest
        state["preview_state_json"] = preview.canonical_json
        save(state)
        return redirect(module.url("outcome"))

    # -- the factual consequence, and the rewind ---------------------------
    def outcome_context(state, error=None):
        preview = json.loads(state.get("preview_state_json") or "{}")
        factual = state["factual_choice"]
        return {
            "state_lines": describe_state(preview,
                                          vocabulary=module.vocabulary),
            "factual_label": label_for_choice(module.scenario.scenario_key,
                                              factual),
            "alternatives": [c for c in module.choices()
                             if c.choice_id != factual],
            "error": error,
        }

    def outcome():
        state = get_state()
        if state is None or not state.get("factual_choice"):
            return redirect(module.url("brief"))
        if state.get("execution_id"):
            return redirect(module.url("result"))
        # Rendered from the stored preview snapshot. Nothing is executed here,
        # so a refresh re-reads a captured state.
        state["rewind_shown_ms"] = now_ms()
        save(state)
        return render("outcome", **outcome_context(state))

    def rewind():
        state = get_state()
        if state is None or not state.get("factual_choice"):
            return redirect(module.url("brief"))
        # Idempotency, enforced server-side: once this attempt has an
        # execution, a resubmission goes to it rather than running a second
        # experiment.
        if state.get("execution_id"):
            return redirect(module.url("result"))

        factual = state["factual_choice"]
        alternative = (request.form.get("choice_id") or "").strip()
        confidence = parse_confidence(request.form.get("confidence"))
        if (alternative not in module.choice_ids or alternative == factual
                or confidence is None):
            return render("outcome", **outcome_context(
                state, "Pick a different response from the one you made, and "
                       "set a confidence between 0 and 100.")), 400

        try:
            execution_id, _pair = service().run_pair(
                module.scenario, module.adapter_factory(), module.decision_id,
                factual_choice_id=factual,
                counterfactual_choice_id=alternative,
                session_id=session_id(),
                factual_confidence=state.get("factual_confidence"),
                counterfactual_confidence=confidence,
                factual_response_ms=state.get("factual_response_ms"),
                counterfactual_response_ms=elapsed_ms(
                    state.get("rewind_shown_ms")),
                # Fails closed inside the service: the recorded comparison may
                # not claim the learner experienced a factual outcome different
                # from the authoritative one.
                expected_baseline_digest=state.get("baseline_digest"),
                expected_factual_digest=state.get("preview_digest"))
        except (TrainingExecutionError, TrainingPersistenceError):
            # Both carry only a class name and an opaque reference; neither the
            # message nor a traceback reaches the learner.
            return render("outcome", **outcome_context(
                state, "The comparison could not be executed. Start the "
                       "scenario again.")), 500

        state["execution_id"] = execution_id
        save(state)
        # POST -> Redirect -> GET: the result page is a plain GET, so a refresh
        # re-reads a stored row instead of resubmitting anything.
        return redirect(module.url("result"))

    # -- the comparison ----------------------------------------------------
    def result():
        row = execution_for_session()
        if row is None:
            return redirect(module.url("brief"))
        if row.status != TrainingExecution.STATUS_COMPLETED:
            abort(409)

        # Rendered entirely from the persisted execution, and always through
        # *that row's own* scenario vocabulary -- never this module's, so a row
        # from another scenario could not be rendered with these words.
        vocabulary = vocabulary_for(row.scenario_key)
        factual_state = json.loads(row.factual_state_json or "{}")
        counterfactual_state = json.loads(row.counterfactual_state_json or "{}")
        difference = json.loads(row.difference_json or "{}")
        return render(
            "result", row=row,
            factual_label=label_for_choice(row.scenario_key,
                                           row.factual_choice_id),
            counterfactual_label=label_for_choice(
                row.scenario_key, row.counterfactual_choice_id),
            factual_lines=describe_state(factual_state, vocabulary=vocabulary),
            counterfactual_lines=describe_state(counterfactual_state,
                                                vocabulary=vocabulary),
            difference_lines=describe_difference(difference,
                                                 vocabulary=vocabulary))

    routes = (
        ("", brief, ["GET"], "brief"),
        ("/start", start, ["POST"], "start"),
        ("/" + module.prompt_route, prompt, ["GET"], module.prompt_route),
        ("/decision", decision, ["POST"], "decision"),
        ("/outcome", outcome, ["GET"], "outcome"),
        ("/rewind", rewind, ["POST"], "rewind"),
        ("/result", result, ["GET"], "result"),
    )
    for suffix, view, methods, endpoint in routes:
        bp.add_url_rule("/%s%s" % (name, suffix),
                        endpoint="%s_%s" % (name, endpoint),
                        view_func=view, methods=methods)
    return module
