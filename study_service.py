"""Application integration for the RewindSec research-study layer (R7).

The seam between the pure protocol and the database, mirroring the one
``training_service`` opened for R2 and ``learning_service`` for R6:

    study/            the pure protocol: arms, phases, allocation, probes. It
                      does not know what a row, a session or a request is.
    this module       Flask/SQLAlchemy aware. Claims allocation slots under a
                      uniqueness constraint, mints artifact identity, enforces
                      the phase machine, runs each arm's intervention, and
                      persists measurements idempotently.
    training/, R1-R2  the counterfactual runtime and the paired-execution
                      service, reused unchanged by the third arm.
    learning/, R6     the authored pedagogy and the structured self-explanation,
                      reused unchanged by the third arm.

What this module does not do
----------------------------
It does not reimplement ``CounterfactualRuntime``, does not add a second paired
execution path, does not modify ``TrainingExecution``'s meaning, and does not
alter the normal non-study training or transfer flows in any way.

It computes no statistic. No significance test, no effect size, no p-value, no
improvement score and no causal claim is produced anywhere in this file or the
dashboard built on it. It stores and counts observations.

Idempotency is a constraint, not a convention
---------------------------------------------
Every research datum -- the allocation, the first decision, the immediate
response, the retention response -- is written under a unique constraint, and
every write path catches the integrity error and re-reads rather than trusting a
prior ``SELECT``. Two concurrent submissions therefore still leave exactly one
first response.
"""

import json
import uuid

from sqlalchemy import func
from sqlalchemy.exc import IntegrityError

import learning
import study
from learning.assessment import validate_confidence
from sandbox.timeutil import utcnow
from scenario_adapters.phishing import (PHISHING_DECISION_ID, PHISHING_SCENARIO,
                                        PHISHING_SCENARIO_KEY,
                                        PhishingConsequenceAdapter)
from study.errors import (PhaseTransitionError, RetentionWindowError,
                          StudyConfigurationError, StudyError)
from training.snapshots import StateSnapshot

#: Bounded retry budget for claiming an allocation slot. Each retry follows a
#: real collision with a concurrent enrollment, so the loop terminates as soon
#: as this process wins a slot; the bound exists so a pathological environment
#: fails loudly instead of spinning.
MAX_SLOT_ATTEMPTS = 25


class StudyLayerError(RuntimeError):
    """A study artifact could not be created or read for this request."""


class EnrollmentNotFoundError(StudyLayerError):
    """No enrollment is available for this browser session.

    Deliberately one error for "never enrolled", "belongs to another session"
    and "does not exist", so the flow cannot be used to discover which
    participant ids exist.
    """


class StudyStateError(StudyLayerError):
    """The request does not match this enrollment's server-side phase."""


def new_participant_id():
    return str(uuid.uuid4())


def new_intervention_id():
    return "sint-" + uuid.uuid4().hex


def new_study_attempt_id():
    return "satt-" + uuid.uuid4().hex


class StudyService:
    """Owns study allocation, phase enforcement, intervention and measurement.

    Dependencies are injected rather than imported from ``app``, exactly as the
    other two services do it. ``training_service`` and ``learning_service`` are
    passed in as zero-argument callables: the third arm delegates its paired
    execution and its structured reflection to them unchanged, and this class
    deliberately holds no second implementation of either.
    """

    def __init__(self, db, StudyEnrollment, StudyIntervention,
                 StudyAssessmentAttempt, TrainingExecution, LearningReflection,
                 training_service, learning_service, settings, logger=None):
        self.db = db
        self.StudyEnrollment = StudyEnrollment
        self.StudyIntervention = StudyIntervention
        self.StudyAssessmentAttempt = StudyAssessmentAttempt
        self.TrainingExecution = TrainingExecution
        self.LearningReflection = LearningReflection
        self.training_service = training_service
        self.learning_service = learning_service
        #: Zero-argument callable returning the live research-mode settings.
        #: Read per request rather than captured at construction, so a
        #: deployment's configuration is never frozen into the object graph.
        self.settings = settings
        self.logger = logger

    # -- configuration, read fresh and failing closed ----------------------
    def _config(self):
        return self.settings()

    def assignment_secret(self):
        """The configured allocation secret, or a hard failure.

        Fails closed. Research mode without an allocation secret would either
        publish the allocation sequence (unkeyed) or make it irreproducible
        (random fallback), and both are disqualifying for a pilot that has to be
        auditable. Flask's ``secret_key`` is deliberately not consulted.
        """
        secret = (self._config() or {}).get("assignment_secret")
        if not secret:
            raise StudyConfigurationError(
                "research mode requires a study assignment secret; set {0}"
                .format(study.SECRET_ENV_VAR))
        return secret

    def continuity_secret(self):
        """The configured return-code secret, or a hard failure.

        Fails closed, independently of :meth:`assignment_secret`. Allocation
        randomisation and return-code continuity are separate security
        domains -- one derives which arm a slot gets, the other authenticates
        a credential a participant holds -- and are kept under independent
        key material so a compromise of one purpose does not compromise the
        other.
        """
        secret = (self._config() or {}).get("continuity_secret")
        if not secret:
            raise StudyConfigurationError(
                "research mode requires a study continuity secret; set {0}"
                .format(study.CONTINUITY_SECRET_ENV_VAR))
        return secret

    # ======================================================================
    # Enrollment and allocation
    # ======================================================================
    def enrollment_for_session(self, participant_id, session_id):
        """The enrollment this browser session owns, or a hard failure.

        Two things must agree: the ``participant_id`` held in the signed Flask
        session, and the ``session_id`` currently bound to the enrollment row.
        A participant id alone is not sufficient, so a leaked or copied
        identifier does not grant access to the enrollment.
        """
        if not participant_id or not session_id:
            raise EnrollmentNotFoundError("no study enrollment for this session")
        row = (self.StudyEnrollment.query
               .filter_by(participant_id=participant_id).first())
        if row is None or row.session_id != session_id:
            raise EnrollmentNotFoundError("no study enrollment for this session")
        return row

    def _next_slot(self):
        highest = (self.db.session.query(
            func.max(self.StudyEnrollment.allocation_slot))
            .filter(self.StudyEnrollment.protocol_key == study.PROTOCOL_KEY,
                    self.StudyEnrollment.protocol_version
                    == study.PROTOCOL_VERSION).scalar())
        return (highest or 0) + 1

    def enroll(self, session_id):
        """Allocate one participant. Returns ``(enrollment, raw_return_code)``.

        **The raw return code is returned to the caller once and never stored.**
        Only its keyed digest reaches the database, and the caller renders it a
        single time; it is not written to the Flask session, a log line, a URL
        or an export.

        Concurrency: the allocation slot is *claimed by insertion*, not chosen
        after a count. Two simultaneous enrollments that compute the same next
        slot collide on the unique constraint; the loser rolls back, recomputes
        and retries. A count-then-choose scheme without the constraint would
        hand both participants the same slot -- and therefore the same arm --
        and quietly unbalance the block.
        """
        secret = self.assignment_secret()
        continuity_secret = self.continuity_secret()

        for _attempt in range(MAX_SLOT_ATTEMPTS):
            slot = self._next_slot()
            arm = study.arm_for_slot(secret, slot)
            code = study.new_return_code()
            row = self.StudyEnrollment(
                participant_id=new_participant_id(),
                session_id=session_id,
                protocol_key=study.PROTOCOL_KEY,
                protocol_version=study.PROTOCOL_VERSION,
                arm_key=arm,
                allocation_slot=slot,
                return_code_digest=study.code_digest(continuity_secret, code),
                status=self.StudyEnrollment.STATUS_ACTIVE,
                phase=study.ENROLLED,
                created_at=utcnow())
            self.db.session.add(row)
            try:
                self.db.session.commit()
            except IntegrityError:
                # Another enrollment took this slot. Recompute and try again;
                # the arm is a function of the slot, so retrying is what keeps
                # the block balanced rather than merely unique.
                self.db.session.rollback()
                continue
            return row, code

        raise StudyLayerError("could not claim a study allocation slot")

    def resume(self, submitted_code, session_id):
        """Re-bind the current browser session to an existing enrollment.

        Looks the code up **by its keyed digest**, which is why the lookup is a
        single indexed equality rather than a scan-and-compare over every row.

        What changes: ``session_id``. What does not: ``participant_id``, the
        allocated arm, the allocation slot, the recorded first decision, the
        intervention, and every recorded attempt. Resuming is a change of
        browser, not a change of participant.

        The raw code is never logged and is not written to the session.
        """
        secret = self.continuity_secret()
        if not study.looks_like_code(submitted_code):
            raise EnrollmentNotFoundError("no enrollment for that return code")
        digest = study.code_digest(secret, submitted_code)
        row = (self.StudyEnrollment.query
               .filter_by(return_code_digest=digest).first())
        # Compared again in constant time. The indexed lookup is what finds the
        # row; this is what decides it matched.
        if row is None or not study.digests_match(row.return_code_digest,
                                                  digest):
            raise EnrollmentNotFoundError("no enrollment for that return code")
        row.session_id = session_id
        self.db.session.commit()
        return row

    # ======================================================================
    # The server-authoritative phase machine
    # ======================================================================
    def require_phase(self, enrollment, *allowed):
        """Assert the enrollment is in one of ``allowed``, or fail.

        Every study route calls this before rendering or writing anything. A
        participant who types a later URL is refused here; there is no hidden
        phase field for them to edit, because the phase is only ever read from
        this row.
        """
        if enrollment.phase not in allowed:
            raise StudyStateError(
                "enrollment is at {0!r}, not {1}".format(
                    enrollment.phase, " or ".join(repr(p) for p in allowed)))
        return enrollment.phase

    def advance(self, enrollment, *targets):
        """Move the enrollment forward one authored step at a time.

        Each step is validated by :func:`study.check_transition` against *this
        arm's* progression, so a phase another arm has cannot be reached even by
        a bug in a route. Several steps may be given where one request
        legitimately completes two authored phases (recording the immediate
        response both completes it and opens the retention window).
        """
        for target in targets:
            study.check_transition(enrollment.arm_key, enrollment.phase, target)
            enrollment.phase = target
        return enrollment.phase

    # ======================================================================
    # The source decision -- identical across all three arms
    # ======================================================================
    def intervention_for(self, enrollment):
        """This enrollment's intervention row, or ``None``."""
        return (self.StudyIntervention.query
                .filter_by(enrollment_id=enrollment.id).first())

    def record_source_decision(self, enrollment, choice_id, confidence,
                               response_time_ms=None):
        """Record the pre-intervention behavioural measure. Exactly once, ever.

        Returns ``(intervention, created)``.

        This is **the** baseline behaviour of the study: the learner's first
        response to a phishing message they have been shown identically
        whatever arm they are in, taken before any arm-specific feedback
        exists. Nothing later -- not the counterfactual choice, not the
        reflection, not a transfer response -- may overwrite it, and the unique
        constraint on ``enrollment_id`` is what makes that true rather than
        merely intended.

        The response quality is *derived server-side* from the authored
        learning tables. It is never accepted from a form.
        """
        confidence = validate_confidence(confidence)
        # Validates against the phishing scenario's own choice table, and
        # raises rather than recording an unclassifiable datum.
        quality = learning.response_quality(PHISHING_SCENARIO_KEY, choice_id)

        existing = self.intervention_for(enrollment)
        if existing is not None:
            return existing, False

        row = self.StudyIntervention(
            intervention_id=new_intervention_id(),
            enrollment_id=enrollment.id,
            participant_id=enrollment.participant_id,
            scenario_key=PHISHING_SCENARIO_KEY,
            arm_key=enrollment.arm_key,
            factual_choice_id=choice_id,
            factual_response_quality=quality,
            factual_confidence=confidence,
            factual_response_time_ms=response_time_ms,
            created_at=utcnow())
        self.db.session.add(row)
        enrollment.intervention_started_at = utcnow()
        self.advance(enrollment, study.SOURCE_DECISION_RECORDED)
        try:
            self.db.session.commit()
        except IntegrityError:
            # Another request won the race; its answer is the first response.
            self.db.session.rollback()
            existing = self.intervention_for(enrollment)
            if existing is None:
                raise
            return existing, False
        return row, True

    # ======================================================================
    # Arm B and Arm C: the factual consequence
    # ======================================================================
    def apply_factual_consequence(self, enrollment, intervention):
        """Execute the learner's own response in the real phishing environment.

        The genuine ``PhishingConsequenceAdapter``, from a verified S0:

            prepare -> capture baseline -> apply the learner's action ->
            capture the factual result

        Idempotent: once ``factual_result_digest`` is set, a refresh re-reads
        the stored state rather than applying a second consequence. That
        matters more here than in the ordinary flow -- a second application
        would make the participant's recorded factual state disagree with what
        they were shown.

        Never reached by ``awareness_debrief``: that arm's whole definition is
        that no consequence is executed for it.
        """
        if not study.executes_consequence(enrollment.arm_key):
            raise StudyStateError("this arm does not execute a consequence")
        if intervention.factual_result_digest:
            return intervention, False

        adapter = PhishingConsequenceAdapter()
        adapter.prepare()
        baseline = StateSnapshot.capture(adapter.capture_state(),
                                         label="baseline")
        action_key = (PHISHING_SCENARIO.decision(PHISHING_DECISION_ID)
                      .choice(intervention.factual_choice_id).action_key)
        adapter.apply(action_key)
        factual = StateSnapshot.capture(adapter.capture_state(),
                                        label="factual")

        intervention.baseline_digest = baseline.digest
        intervention.factual_result_digest = factual.digest
        intervention.factual_state_json = factual.canonical_json
        self.advance(enrollment, study.FACTUAL_PREVIEW)
        self.db.session.commit()
        return intervention, True

    def factual_state(self, intervention):
        """The stored factual state as a mapping, or ``{}``."""
        return json.loads(intervention.factual_state_json or "{}")

    # ======================================================================
    # Arm C only: the verified paired replay
    # ======================================================================
    def run_counterfactual(self, enrollment, intervention,
                           counterfactual_choice_id, confidence,
                           response_time_ms=None):
        """Rewind and run the paired execution. **Arm C only, exactly once.**

        Delegates wholly to the R2 ``TrainingService``, which drives the R1
        ``CounterfactualRuntime``. Nothing about the pair is reimplemented here:
        the same six ``TRAINING_*`` lifecycle events are emitted, the same
        ``TrainingExecution`` row is written, the same digests are proved.

        The two staged digests are passed through, so the service fails closed
        if the authoritative run does not reproduce exactly the baseline the
        participant started from and exactly the factual outcome they were
        shown. A mismatch leaves a ``failed`` execution rather than a completed
        comparison claiming something the participant never saw.
        """
        if not study.runs_counterfactual(enrollment.arm_key):
            raise StudyStateError("this arm does not run a counterfactual")
        if intervention.training_execution_id:
            return intervention, False
        if counterfactual_choice_id == intervention.factual_choice_id:
            raise StudyStateError("the alternative must differ")
        confidence = validate_confidence(confidence)

        execution_id, _pair = self.training_service().run_pair(
            PHISHING_SCENARIO, PhishingConsequenceAdapter(),
            PHISHING_DECISION_ID,
            factual_choice_id=intervention.factual_choice_id,
            counterfactual_choice_id=counterfactual_choice_id,
            session_id=enrollment.session_id,
            factual_confidence=intervention.factual_confidence,
            counterfactual_confidence=confidence,
            factual_response_ms=intervention.factual_response_time_ms,
            counterfactual_response_ms=response_time_ms,
            expected_baseline_digest=intervention.baseline_digest,
            expected_factual_digest=intervention.factual_result_digest)

        intervention.training_execution_id = execution_id
        self.advance(enrollment, study.COUNTERFACTUAL_COMPLETED)
        self.db.session.commit()
        return intervention, True

    def execution_for(self, intervention):
        """The paired execution this intervention produced, or ``None``.

        Authorised through the *enrollment*, not through the Flask session:
        the caller has already proved it owns the enrollment, and the
        enrollment owns the intervention that names this execution. That
        indirection is what lets Arm C survive a return-code resume, which
        changes the browser session but changes nothing about who the
        participant is.
        """
        if not intervention.training_execution_id:
            return None
        return (self.TrainingExecution.query
                .filter_by(execution_id=intervention.training_execution_id)
                .first())

    def record_reflection(self, enrollment, intervention, explanation_id):
        """The structured self-explanation. **Arm C only, exactly once.**

        Delegates to the R6 ``LearningService``, so the reflection, the
        ``LearningReflection`` row and the derived ``ConceptEvidence`` are
        exactly what the ordinary flow produces. R7 adds no second reflection
        model and no free-text field.

        Completing the reflection completes the intervention: the two authored
        phases are advanced together because a participant who has explained the
        comparison has, by this protocol's definition, finished Arm C.
        """
        if not study.requires_reflection(enrollment.arm_key):
            raise StudyStateError("this arm has no structured reflection")
        execution = self.execution_for(intervention)
        if execution is None:
            raise StudyStateError("no completed comparison to reflect on")

        reflection, _created = self.learning_service().record_reflection(
            execution, explanation_id)
        intervention.reflection_id = reflection.reflection_id
        if enrollment.phase == study.COUNTERFACTUAL_COMPLETED:
            self.advance(enrollment, study.REFLECTION_COMPLETED)
            self.complete_intervention(enrollment, intervention)
        self.db.session.commit()
        return reflection

    def reflection_for(self, intervention):
        if not intervention.reflection_id:
            return None
        return (self.LearningReflection.query
                .filter_by(reflection_id=intervention.reflection_id).first())

    # ======================================================================
    # Completing the intervention
    # ======================================================================
    def complete_intervention(self, enrollment, intervention):
        """Mark the assigned intervention finished and unlock the immediate probe.

        Idempotent: a repeated POST on an already-completed intervention is a
        no-op rather than a second timestamp.
        """
        if enrollment.phase == study.INTERVENTION_COMPLETED:
            return enrollment, False
        self.advance(enrollment, study.INTERVENTION_COMPLETED)
        now = utcnow()
        enrollment.intervention_completed_at = now
        intervention.completed_at = now
        self.db.session.commit()
        return enrollment, True

    # ======================================================================
    # Measurement: the two transfer probes
    # ======================================================================
    def attempt_for(self, enrollment, phase):
        """The recorded attempt for one enrollment and phase, or ``None``."""
        probe = study.probe_for_phase(phase)
        return (self.StudyAssessmentAttempt.query
                .filter_by(enrollment_id=enrollment.id, phase=phase,
                           probe_key=probe.probe_key).first())

    def record_attempt(self, enrollment, phase, choice_id, confidence,
                       response_time_ms=None, now=None):
        """Record a **first** probe response. Exactly once, per phase.

        Returns ``(attempt, created)``. An existing attempt is returned
        unchanged: the first response is the measurement, and no resubmission,
        refresh or Back-button repost may replace it.

        Recording the immediate response also schedules the retention window,
        because the window is defined relative to that exact moment and
        computing it anywhere else would let the two drift apart.

        **No feedback is derived or returned here.** The response quality is
        stored for later analysis and is deliberately not shown to the
        participant until the study is over -- revealing it would turn the
        measurement into a further training intervention and contaminate the
        retention probe it precedes.
        """
        probe = study.probe_for_phase(phase)
        # Validates against *this probe's* option list; a choice id from the
        # other probe, or an invented one, is refused before anything is
        # written.
        option = study.classify(phase, choice_id)
        confidence = validate_confidence(confidence)
        now = now or utcnow()

        existing = self.attempt_for(enrollment, phase)
        if existing is not None:
            return existing, False

        row = self.StudyAssessmentAttempt(
            attempt_id=new_study_attempt_id(),
            enrollment_id=enrollment.id,
            participant_id=enrollment.participant_id,
            phase=phase,
            probe_key=probe.probe_key,
            probe_version=probe.version,
            choice_id=option.choice_id,
            response_quality=option.response_quality,
            confidence=confidence,
            response_time_ms=response_time_ms,
            created_at=now)
        self.db.session.add(row)

        if phase == study.IMMEDIATE_TRANSFER:
            enrollment.immediate_transfer_completed_at = now
            open_at, close_at = study.retention_window(now)
            enrollment.retention_open_at = open_at
            enrollment.retention_close_at = close_at
            self.advance(enrollment, study.IMMEDIATE_TRANSFER_COMPLETED,
                         study.RETENTION_WAITING)
        else:
            enrollment.retention_completed_at = now
            enrollment.status = self.StudyEnrollment.STATUS_COMPLETED
            self.advance(enrollment, study.RETENTION_COMPLETED)

        try:
            self.db.session.commit()
        except IntegrityError:
            self.db.session.rollback()
            existing = self.attempt_for(enrollment, phase)
            if existing is None:
                raise
            return existing, False
        return row, True

    # -- the retention window ---------------------------------------------
    def retention_state(self, enrollment, now=None):
        """Where ``now`` falls relative to this participant's window.

        ``now`` is injectable so the seven-day boundary can be tested at the
        instant it opens and the instant after it closes, rather than by
        waiting a week.
        """
        return study.retention_state(now or utcnow(),
                                     enrollment.retention_open_at,
                                     enrollment.retention_close_at)

    def require_retention_open(self, enrollment, now=None):
        """Refuse a retention submission outside the authored window."""
        state = self.retention_state(enrollment, now=now)
        if state != study.RETENTION_OPEN:
            raise RetentionWindowError(
                "retention window is {0!r}".format(state))
        return state

    # ======================================================================
    # Descriptive reporting -- counts only, never statistics
    # ======================================================================
    def enrollments(self):
        """Every enrollment in this protocol, in allocation order."""
        return (self.StudyEnrollment.query
                .filter_by(protocol_key=study.PROTOCOL_KEY,
                           protocol_version=study.PROTOCOL_VERSION)
                .order_by(self.StudyEnrollment.allocation_slot.asc()).all())

    def _blank_counts(self):
        return {arm: 0 for arm in study.ARMS}

    def _quality_counts(self):
        return {arm: {quality: 0 for quality in learning.RESPONSE_QUALITIES}
                for arm in study.ARMS}

    def dashboard(self, now=None):
        """Descriptive operational counts, per arm.

        **Counts only.** No significance test, no effect size, no p-value, no
        improvement label and no comparison between arms is computed here or
        anywhere downstream of it. An instructor reading this page learns how
        many participants reached each step and how their responses were
        classified -- nothing about whether an arm worked.

        Missing data is represented rather than imputed: a participant who
        never returned appears under "not reached" or "window closed", never as
        a risky response.
        """
        now = now or utcnow()
        rows = self.enrollments()
        by_id = {row.id: row for row in rows}

        interventions = {}
        attempts = {}
        if by_id:
            ids = list(by_id)
            for row in (self.StudyIntervention.query
                        .filter(self.StudyIntervention.enrollment_id.in_(ids))
                        .all()):
                interventions[row.enrollment_id] = row
            for row in (self.StudyAssessmentAttempt.query
                        .filter(self.StudyAssessmentAttempt.enrollment_id
                                .in_(ids)).all()):
                attempts[(row.enrollment_id, row.phase)] = row

        assigned = self._blank_counts()
        intervention_completed = self._blank_counts()
        immediate_completed = self._blank_counts()
        retention_due = self._blank_counts()
        retention_completed = self._blank_counts()
        retention_expired = self._blank_counts()
        baseline_quality = self._quality_counts()
        immediate_quality = self._quality_counts()
        retention_quality = self._quality_counts()
        high_confidence_risky = {
            "baseline": self._blank_counts(),
            study.IMMEDIATE_TRANSFER: self._blank_counts(),
            study.RETENTION_TRANSFER: self._blank_counts(),
        }

        for row in rows:
            arm = row.arm_key
            if arm not in assigned:
                # An arm outside the protocol cannot be produced by allocation;
                # skipping rather than crashing keeps the dashboard readable if
                # a database is ever inspected from a different protocol.
                continue
            assigned[arm] += 1

            intervention = interventions.get(row.id)
            if intervention is not None and intervention.factual_choice_id:
                quality = intervention.factual_response_quality
                if quality in baseline_quality[arm]:
                    baseline_quality[arm][quality] += 1
                if study.high_confidence_risky(quality,
                                               intervention.factual_confidence):
                    high_confidence_risky["baseline"][arm] += 1
            if row.intervention_completed_at is not None:
                intervention_completed[arm] += 1

            immediate = attempts.get((row.id, study.IMMEDIATE_TRANSFER))
            if immediate is not None:
                immediate_completed[arm] += 1
                if immediate.response_quality in immediate_quality[arm]:
                    immediate_quality[arm][immediate.response_quality] += 1
                if study.high_confidence_risky(immediate.response_quality,
                                               immediate.confidence):
                    high_confidence_risky[study.IMMEDIATE_TRANSFER][arm] += 1

            retention = attempts.get((row.id, study.RETENTION_TRANSFER))
            state = self.retention_state(row, now=now)
            if retention is not None:
                retention_completed[arm] += 1
                if retention.response_quality in retention_quality[arm]:
                    retention_quality[arm][retention.response_quality] += 1
                if study.high_confidence_risky(retention.response_quality,
                                               retention.confidence):
                    high_confidence_risky[study.RETENTION_TRANSFER][arm] += 1
            elif state == study.RETENTION_OPEN:
                retention_due[arm] += 1
            elif state == study.RETENTION_EXPIRED:
                retention_expired[arm] += 1

        # Eligible-for-retention counts every participant whose window has been
        # scheduled at all, so the flow table reconciles: eligible = completed +
        # still due + expired + still waiting.
        eligible = self._blank_counts()
        for row in rows:
            if row.arm_key in eligible and row.retention_open_at is not None:
                eligible[row.arm_key] += 1

        return {
            "generated_at": now,
            "protocol_key": study.PROTOCOL_KEY,
            "protocol_version": study.PROTOCOL_VERSION,
            "arms": study.ARMS,
            "arm_descriptions": study.ARM_DESCRIPTIONS,
            "qualities": learning.RESPONSE_QUALITIES,
            "total": len(rows),
            "assigned": assigned,
            "intervention_completed": intervention_completed,
            "immediate_completed": immediate_completed,
            "retention_eligible": eligible,
            "retention_due": retention_due,
            "retention_completed": retention_completed,
            "retention_expired": retention_expired,
            "baseline_quality": baseline_quality,
            "immediate_quality": immediate_quality,
            "retention_quality": retention_quality,
            "high_confidence_risky": high_confidence_risky,
        }

    # ======================================================================
    # Research export
    # ======================================================================
    #: Stable column order. Changing it changes every downstream analysis
    #: script, so it is declared once, here, and asserted by test.
    #:
    #: Absent by design: the Flask ``session_id``, the return-code digest, the
    #: access code, any IP address, any user agent, any credential and any
    #: learner-authored text. ``participant_id`` is the research correlation
    #: identifier; the dashboard's ``P-XXXXXX`` label is a display artifact and
    #: is deliberately **not** a join key.
    EXPORT_COLUMNS = (
        "participant_id",
        "protocol_key",
        "protocol_version",
        "arm_key",
        "allocation_slot",

        "baseline_choice_id",
        "baseline_response_quality",
        "baseline_confidence",
        "baseline_response_time_ms",

        "intervention_completed",
        "training_execution_id",
        "pair_id",
        "baseline_verified",
        "reflection_selected_preferred",

        "immediate_probe_key",
        "immediate_choice_id",
        "immediate_response_quality",
        "immediate_confidence",
        "immediate_response_time_ms",

        "retention_probe_key",
        "retention_choice_id",
        "retention_response_quality",
        "retention_confidence",
        "retention_response_time_ms",

        "retention_open_at",
        "retention_close_at",
        "retention_completed_at",
    )

    def export_rows(self):
        """One mapping per enrollment, in stable column order.

        Missing values are empty, never zero and never a quality: a participant
        who did not answer the retention probe has an empty
        ``retention_response_quality``, which an analysis can treat as missing.
        Writing ``RISKY`` there would have fabricated the study's own outcome.
        """
        rows = self.enrollments()
        interventions = {}
        attempts = {}
        executions = {}
        reflections = {}
        if rows:
            ids = [row.id for row in rows]
            for item in (self.StudyIntervention.query
                         .filter(self.StudyIntervention.enrollment_id.in_(ids))
                         .all()):
                interventions[item.enrollment_id] = item
            for item in (self.StudyAssessmentAttempt.query
                         .filter(self.StudyAssessmentAttempt.enrollment_id
                                 .in_(ids)).all()):
                attempts[(item.enrollment_id, item.phase)] = item

            execution_ids = [i.training_execution_id
                             for i in interventions.values()
                             if i.training_execution_id]
            if execution_ids:
                for item in (self.TrainingExecution.query
                             .filter(self.TrainingExecution.execution_id
                                     .in_(execution_ids)).all()):
                    executions[item.execution_id] = item
            reflection_ids = [i.reflection_id for i in interventions.values()
                              if i.reflection_id]
            if reflection_ids:
                for item in (self.LearningReflection.query
                             .filter(self.LearningReflection.reflection_id
                                     .in_(reflection_ids)).all()):
                    reflections[item.reflection_id] = item

        exported = []
        for row in rows:
            intervention = interventions.get(row.id)
            immediate = attempts.get((row.id, study.IMMEDIATE_TRANSFER))
            retention = attempts.get((row.id, study.RETENTION_TRANSFER))
            execution = (executions.get(intervention.training_execution_id)
                         if intervention else None)
            reflection = (reflections.get(intervention.reflection_id)
                          if intervention else None)

            exported.append({
                "participant_id": row.participant_id,
                "protocol_key": row.protocol_key,
                "protocol_version": row.protocol_version,
                "arm_key": row.arm_key,
                "allocation_slot": row.allocation_slot,

                "baseline_choice_id": _value(
                    intervention, "factual_choice_id"),
                "baseline_response_quality": _value(
                    intervention, "factual_response_quality"),
                "baseline_confidence": _value(
                    intervention, "factual_confidence"),
                "baseline_response_time_ms": _value(
                    intervention, "factual_response_time_ms"),

                "intervention_completed": _flag(
                    row.intervention_completed_at is not None),
                "training_execution_id": _value(
                    intervention, "training_execution_id"),
                "pair_id": _value(execution, "pair_id"),
                "baseline_verified": ("" if execution is None
                                      else _flag(execution.baseline_verified)),
                "reflection_selected_preferred": (
                    "" if reflection is None
                    else _flag(bool(reflection.preferred_explanation))),

                "immediate_probe_key": _value(immediate, "probe_key"),
                "immediate_choice_id": _value(immediate, "choice_id"),
                "immediate_response_quality": _value(
                    immediate, "response_quality"),
                "immediate_confidence": _value(immediate, "confidence"),
                "immediate_response_time_ms": _value(
                    immediate, "response_time_ms"),

                "retention_probe_key": _value(retention, "probe_key"),
                "retention_choice_id": _value(retention, "choice_id"),
                "retention_response_quality": _value(
                    retention, "response_quality"),
                "retention_confidence": _value(retention, "confidence"),
                "retention_response_time_ms": _value(
                    retention, "response_time_ms"),

                "retention_open_at": _timestamp(row.retention_open_at),
                "retention_close_at": _timestamp(row.retention_close_at),
                "retention_completed_at": _timestamp(row.retention_completed_at),
            })
        return exported


def _value(row, attribute):
    """One exported cell: the attribute, or ``""`` when the row is absent.

    Empty means *not observed*. It is never a zero and never a response
    quality, so a missing measurement stays visibly missing in the CSV.
    """
    if row is None:
        return ""
    value = getattr(row, attribute, None)
    return "" if value is None else value


def _flag(value):
    return "true" if value else "false"


def _timestamp(value):
    return value.isoformat() if value else ""


__all__ = [
    "StudyService", "StudyLayerError", "EnrollmentNotFoundError",
    "StudyStateError", "StudyError", "StudyConfigurationError",
    "PhaseTransitionError", "RetentionWindowError",
    "new_participant_id", "new_intervention_id", "new_study_attempt_id",
    "MAX_SLOT_ATTEMPTS",
]
