"""Application integration for the RewindSec learning layer (milestone R6).

The seam between three layers, mirroring the one ``training_service`` opened
for R2:

    learning/         pure authored pedagogy. No Flask, no SQLAlchemy, no
                      ``app``, no sandbox. It does not know what an
                      ``execution_id`` or a database session is.
    this module       Flask/SQLAlchemy aware. Validates ownership, mints
                      artifact identity, and persists reflections, concept
                      evidence and transfer attempts idempotently.
    training/, R2     the completed technical execution this layer consumes.

R6 consumes the technical result. It does not alter it
------------------------------------------------------
Nothing in this module writes to ``TrainingExecution``, runs
``CounterfactualRuntime``, prepares an adapter, touches the sandbox or emits a
``TRAINING_*`` event. A completed pair's ``pair_id``, digests and stored states
are read-only here, and the six lifecycle events of a successful execution stay
six.

Idempotency is a constraint, not a convention
---------------------------------------------
Both artifacts carry unique constraints, and both write paths catch the
integrity error and re-read rather than trusting a prior ``SELECT``. Two
concurrent submissions therefore still leave exactly one first response, which
a check-then-insert alone would not guarantee.

Ownership
---------
Every entry point takes the canonical ``session_id`` and refuses to touch a row
belonging to another one. Authorisation is never by pseudonymous label -- a
label is a display artifact, and treating one as an authenticator would make
the pseudonymisation itself load-bearing for access control.
"""

import uuid

from sqlalchemy.exc import IntegrityError

import learning
from learning import assessment as A
from learning import feedback as F
from learning.errors import (LearningError, UnknownChoiceError,
                             UnknownExplanationError, UnknownProbeError,
                             UnknownScenarioError)
from sandbox.timeutil import utcnow


class LearningLayerError(RuntimeError):
    """A learning artifact could not be created for this request."""


class ExecutionNotEligibleError(LearningLayerError):
    """The referenced execution is missing, unowned, or not completed.

    Deliberately one error for all three: a learner asking about somebody
    else's execution and a learner asking about a nonexistent one get the same
    answer, so the API cannot be used to discover which ids exist.
    """


class ReflectionRequiredError(LearningLayerError):
    """A transfer probe was reached before its source reflection was recorded."""


class NoProbeForScenarioError(LearningLayerError):
    """This training scenario has no authored transfer probe in R6."""


def new_reflection_id():
    return "refl-" + uuid.uuid4().hex


def new_attempt_id():
    return "xfer-" + uuid.uuid4().hex


class LearningService:
    """Owns learning-artifact identity, validation and idempotent persistence.

    Dependencies are injected rather than imported from ``app``, exactly as
    ``TrainingService`` does it: the service needs a SQLAlchemy session holder
    and the four model classes it reads and writes. ``app.py`` stays the only
    module that knows how they are wired together.
    """

    def __init__(self, db, TrainingExecution, LearningReflection,
                 ConceptEvidence, TransferAttempt, logger=None):
        self.db = db
        self.TrainingExecution = TrainingExecution
        self.LearningReflection = LearningReflection
        self.ConceptEvidence = ConceptEvidence
        self.TransferAttempt = TransferAttempt
        self.logger = logger

    # -- ownership ---------------------------------------------------------
    def completed_execution(self, execution_id, session_id):
        """A completed execution this session owns, or a hard failure.

        Ownership is checked on the loaded row rather than folded into the
        query, so the two failure modes are indistinguishable to a caller and a
        missing ``session_id`` (never authenticated) can never match a row whose
        ``session_id`` is also null.
        """
        if not execution_id or not session_id:
            raise ExecutionNotEligibleError("no completed execution available")
        row = (self.TrainingExecution.query
               .filter_by(execution_id=execution_id).first())
        if (row is None or row.session_id != session_id
                or row.status != self.TrainingExecution.STATUS_COMPLETED):
            raise ExecutionNotEligibleError("no completed execution available")
        return row

    # -- assessment --------------------------------------------------------
    def assess_execution(self, row):
        """The authored reading of this execution's **factual** decision.

        Recomputed from the persisted ``scenario_key``, ``factual_choice_id``
        and ``factual_confidence`` every time it is needed. No response
        quality, "correct" flag, confidence band or concept classification is
        ever accepted from a form, a hidden field or a URL.

        The counterfactual branch is deliberately not assessed here. It is the
        alternative the learner explored *after* seeing the consequence -- part
        of the intervention, not a sample of unassisted behaviour -- and
        scoring it as though it were would misdescribe what was measured.
        """
        return learning.assess_decision(row.scenario_key,
                                        row.factual_choice_id,
                                        row.factual_confidence)

    # -- concept evidence --------------------------------------------------
    def _add_evidence(self, session_id, execution_id, scenario_key,
                      concept_tag, evidence_source, evidence_signal,
                      response_quality, confidence=None):
        """Insert one evidence row, or leave the existing one alone.

        The unique constraint is the authority. A pre-check would still race
        two concurrent requests; catching the integrity error cannot.
        """
        existing = (self.ConceptEvidence.query
                    .filter_by(execution_id=execution_id,
                               evidence_source=evidence_source,
                               concept_tag=concept_tag).first())
        if existing is not None:
            return existing
        row = self.ConceptEvidence(
            session_id=session_id,
            execution_id=execution_id,
            scenario_key=scenario_key,
            concept_tag=concept_tag,
            evidence_source=evidence_source,
            evidence_signal=evidence_signal,
            response_quality=response_quality,
            confidence=confidence,
            created_at=utcnow())
        self.db.session.add(row)
        try:
            self.db.session.flush()
        except IntegrityError:
            self.db.session.rollback()
            return (self.ConceptEvidence.query
                    .filter_by(execution_id=execution_id,
                               evidence_source=evidence_source,
                               concept_tag=concept_tag).first())
        return row

    def record_decision_evidence(self, row, assessment=None):
        """Derive and persist the factual decision's concept evidence.

        One row per concept the factual choice is authored to be evidence
        about -- never one per scenario concept, and never a row per learner
        trait. Safe to call repeatedly: the second call writes nothing.
        """
        assessment = assessment or self.assess_execution(row)
        stored = []
        for tag in assessment.concept_tags:
            stored.append(self._add_evidence(
                row.session_id, row.execution_id, row.scenario_key, tag,
                self.ConceptEvidence.SOURCE_FACTUAL_DECISION,
                assessment.evidence_signal, assessment.response_quality,
                assessment.confidence))
        self.db.session.commit()
        return stored

    def _record_reflection_evidence(self, row, option):
        """Concept evidence from the structured explanation the learner chose.

        The signal is authored from whether the selected explanation was the
        preferred account, and carries no confidence: the reflection step does
        not ask for one, and inventing a reading would be worse than a null.
        """
        signal = (A.SUPPORTING_EVIDENCE if option.preferred
                  else A.NEEDS_REINFORCEMENT)
        stored = []
        for tag in option.concept_tags:
            stored.append(self._add_evidence(
                row.session_id, row.execution_id, row.scenario_key, tag,
                self.ConceptEvidence.SOURCE_STRUCTURED_REFLECTION,
                signal, None, None))
        return stored

    def evidence_for_execution(self, execution_id, session_id):
        """This session's evidence rows for one execution, in stable order."""
        return (self.ConceptEvidence.query
                .filter_by(execution_id=execution_id, session_id=session_id)
                .order_by(self.ConceptEvidence.evidence_source.asc(),
                          self.ConceptEvidence.concept_tag.asc(),
                          self.ConceptEvidence.id.asc()).all())

    # -- structured self-explanation ---------------------------------------
    def reflection_for_execution(self, execution_id, session_id):
        """The recorded reflection for one owned execution, or ``None``."""
        row = (self.LearningReflection.query
               .filter_by(execution_id=execution_id).first())
        if row is None or row.session_id != session_id:
            return None
        return row

    def record_reflection(self, execution, selected_explanation_id):
        """Record the structured self-explanation. Exactly once, ever.

        Returns ``(reflection_row, created)``. When a reflection already
        exists, the stored one is returned unchanged and ``created`` is
        ``False``: the first explanation is the research datum, and a repeated
        POST must not be able to revise it after the learner has seen which
        account was preferred.
        """
        definition = learning.reflection_for(execution.scenario_key)
        # Validates against *this scenario's* option list, and raises rather
        # than recording a "not preferred" datum for an id nobody authored.
        option = definition.option(selected_explanation_id)

        existing = self.reflection_for_execution(execution.execution_id,
                                                 execution.session_id)
        if existing is not None:
            # Evidence derivation stays idempotent, so a repeat POST converges
            # on the same rows rather than doing nothing at all if a previous
            # request died between the two writes.
            self.record_decision_evidence(execution)
            self._record_reflection_evidence(
                execution, definition.option(existing.selected_explanation_id))
            self.db.session.commit()
            return existing, False

        row = self.LearningReflection(
            reflection_id=new_reflection_id(),
            execution_id=execution.execution_id,
            session_id=execution.session_id,
            scenario_key=execution.scenario_key,
            prompt_key=definition.prompt_key,
            selected_explanation_id=option.explanation_id,
            preferred_explanation=bool(option.preferred),
            created_at=utcnow())
        self.db.session.add(row)
        try:
            self.db.session.flush()
        except IntegrityError:
            # Another request won the race. Its answer is the first response.
            self.db.session.rollback()
            existing = self.reflection_for_execution(execution.execution_id,
                                                     execution.session_id)
            if existing is None:
                raise
            return existing, False

        self.record_decision_evidence(execution)
        self._record_reflection_evidence(execution, option)
        self.db.session.commit()
        return row, True

    # -- learner feedback --------------------------------------------------
    def feedback_context(self, execution, reflection):
        """Everything the feedback page renders, derived server-side.

        The three sources of truth are the completed ``TrainingExecution``, the
        persisted ``LearningReflection`` and the authored definitions in
        ``learning/``. Nothing is read from a hidden field, a query string or a
        submitted form, so a learner cannot present themselves with a different
        response quality by editing a page.
        """
        assessment = self.assess_execution(execution)
        definition = learning.reflection_for(execution.scenario_key)
        selected = definition.option(reflection.selected_explanation_id)
        return {
            "row": execution,
            "assessment": assessment,
            "quality_label": F.quality_label(assessment.response_quality),
            "quality_summary": F.quality_summary(assessment.response_quality),
            "confidence_statement": F.confidence_statement(assessment),
            "confidence_sentence": F.confidence_sentence(assessment),
            "prompt": definition.prompt,
            "preferred_explanation": definition.preferred,
            "selected_explanation": selected,
            "selection_matched_preferred": bool(selected.preferred),
            "signal_heading": F.signal_heading(assessment.evidence_signal),
            "signal_note": F.signal_note(assessment.evidence_signal),
            "carry_forward": F.carry_forward(execution.scenario_key,
                                             assessment.concept_tags),
            "probe": learning.probe_for_scenario(execution.scenario_key),
        }

    # -- unseen transfer probes --------------------------------------------
    def probe_for_execution(self, execution):
        """The probe this completed scenario unlocks, or a hard failure."""
        probe = learning.probe_for_scenario(execution.scenario_key)
        if probe is None:
            raise NoProbeForScenarioError(
                "scenario has no authored transfer probe")
        return probe

    def attempt_for(self, source_execution_id, probe_key, session_id):
        """The recorded attempt for this source/probe pair, or ``None``."""
        row = (self.TransferAttempt.query
               .filter_by(source_execution_id=source_execution_id,
                          probe_key=probe_key).first())
        if row is None or row.session_id != session_id:
            return None
        return row

    def require_unlocked(self, execution):
        """Refuse a probe until its source learning sequence is complete.

        Both gates matter. The completed execution means the learner really
        saw the technical comparison; the recorded reflection means they went
        through the structured self-explanation. A probe reached before either
        would not be measuring what happened after the intervention.
        """
        probe = self.probe_for_execution(execution)
        reflection = self.reflection_for_execution(execution.execution_id,
                                                   execution.session_id)
        if reflection is None:
            raise ReflectionRequiredError(
                "the structured reflection for this execution has not been "
                "recorded")
        return probe, reflection

    def record_transfer_attempt(self, execution, probe, choice_id,
                                confidence=None, response_time_ms=None):
        """Record the learner's **first** response to a probe. Exactly once.

        Returns ``(attempt_row, created)``. When an attempt already exists it
        is returned unchanged: the recorded first response is the measurement,
        and no resubmission, refresh or Back-button repost may replace it.

        ``source_execution_id`` comes from ``execution``, which the caller
        resolved from server-side session state. It is never read from a form.
        """
        # Validates against *this probe's* option list; an id from the other
        # probe, or an invented one, is refused before anything is written.
        option = probe.choice(choice_id)
        confidence = A.validate_confidence(confidence)

        existing = self.attempt_for(execution.execution_id, probe.probe_key,
                                    execution.session_id)
        if existing is not None:
            return existing, False

        row = self.TransferAttempt(
            attempt_id=new_attempt_id(),
            session_id=execution.session_id,
            source_execution_id=execution.execution_id,
            source_scenario_key=execution.scenario_key,
            probe_key=probe.probe_key,
            probe_version=probe.version,
            choice_id=option.choice_id,
            response_quality=option.response_quality,
            confidence=confidence,
            response_time_ms=response_time_ms,
            created_at=utcnow())
        self.db.session.add(row)
        try:
            self.db.session.commit()
        except IntegrityError:
            self.db.session.rollback()
            existing = self.attempt_for(execution.execution_id,
                                        probe.probe_key,
                                        execution.session_id)
            if existing is None:
                raise
            return existing, False
        return row, True

    def transfer_feedback_context(self, probe, attempt):
        """The deterministic feedback shown after a probe is recorded."""
        option = probe.choice(attempt.choice_id)
        return {
            "probe": probe,
            "attempt": attempt,
            "choice": option,
            "quality_label": F.quality_label(option.response_quality),
            "quality_summary": F.quality_summary(option.response_quality),
            "confidence_statement": (
                "You chose this response with {0}% confidence."
                .format(attempt.confidence)
                if attempt.confidence is not None else None),
            "principle": probe.principle,
        }


__all__ = [
    "LearningService", "LearningLayerError", "ExecutionNotEligibleError",
    "ReflectionRequiredError", "NoProbeForScenarioError",
    "LearningError", "UnknownChoiceError", "UnknownExplanationError",
    "UnknownProbeError", "UnknownScenarioError",
    "new_reflection_id", "new_attempt_id",
]
