"""Deterministic assessment of one completed learner decision.

What this module does
---------------------
Given ``(scenario_key, choice_id, confidence)`` it returns an immutable
:class:`DecisionAssessment`: the authored response quality, the raw confidence,
an authored confidence band, the concepts the choice is evidence about, and a
single ``evidence_signal``.

What this module deliberately does not do
-----------------------------------------
It does not grade, score, rank or diagnose. There is no mastery percentage and
no averaging of signals -- an evidence signal describes *one authored exercise
response*, not a person.

Confidence
----------
The raw 0..100 reading stays authoritative and is carried through unchanged, so
a later statistical analysis works from the measurement rather than from a
bucket. :data:`HIGH_CONFIDENCE_THRESHOLD` exists only to select a sentence of
learner feedback.

    **The threshold is an authored feedback rule, not a validated psychometric
    cutoff.** It was chosen for pedagogical legibility, has not been calibrated
    against any instrument, and no claim about a learner's metacognition should
    be derived from which side of it a reading falls.

Language
--------
The signal ``misconception_candidate`` names a property of a *response*: an
authored risky choice made with high stated confidence is the pattern most
worth reinforcing. It is not a finding about the learner, and the learner-facing
wording in :mod:`learning.feedback` never uses the word.
"""

from dataclasses import dataclass
from typing import Optional, Tuple

from .concepts import concepts_for_choice
from .errors import LearningConfidenceError
from .quality import PARTIAL, PROTECTIVE, RISKY, response_quality

CONFIDENCE_MIN = 0
CONFIDENCE_MAX = 100

#: Authored feedback rule. See the module docstring: not a psychometric cutoff.
HIGH_CONFIDENCE_THRESHOLD = 70

# -- confidence bands (feedback only) ---------------------------------------
BAND_HIGH = "high"
BAND_LOW = "low"
BAND_UNSTATED = "unstated"

# -- the authored interpretation of quality x confidence --------------------
CONFIDENT_PROTECTIVE = "confident_protective"
FRAGILE_PROTECTIVE = "fragile_protective"
HIGH_CONFIDENCE_RISK = "high_confidence_risk"
RECOGNIZED_UNCERTAINTY = "recognized_uncertainty"
PARTIAL_RESPONSE = "partial_response"

CONFIDENCE_INTERPRETATIONS = (CONFIDENT_PROTECTIVE, FRAGILE_PROTECTIVE,
                              HIGH_CONFIDENCE_RISK, RECOGNIZED_UNCERTAINTY,
                              PARTIAL_RESPONSE)

# -- evidence signals -------------------------------------------------------
# Concept-evidence terminology, not diagnosis. Each names what the *response*
# suggests about a concept, and each is authored, fixed and machine-readable.
SUPPORTING_EVIDENCE = "supporting_evidence"
FRAGILE_UNDERSTANDING = "fragile_understanding"
PARTIAL_UNDERSTANDING = "partial_understanding"
NEEDS_REINFORCEMENT = "needs_reinforcement"
MISCONCEPTION_CANDIDATE = "misconception_candidate"

EVIDENCE_SIGNALS = (SUPPORTING_EVIDENCE, FRAGILE_UNDERSTANDING,
                    PARTIAL_UNDERSTANDING, NEEDS_REINFORCEMENT,
                    MISCONCEPTION_CANDIDATE)

#: ``interpretation -> evidence signal``. A total mapping over the five
#: interpretations, so no combination can fall through to a default.
INTERPRETATION_SIGNALS = {
    CONFIDENT_PROTECTIVE: SUPPORTING_EVIDENCE,
    FRAGILE_PROTECTIVE: FRAGILE_UNDERSTANDING,
    PARTIAL_RESPONSE: PARTIAL_UNDERSTANDING,
    RECOGNIZED_UNCERTAINTY: NEEDS_REINFORCEMENT,
    HIGH_CONFIDENCE_RISK: MISCONCEPTION_CANDIDATE,
}


def validate_confidence(value):
    """Strict integer in 0..100, or ``None`` when the reading was not taken.

    Bools, floats, numeric strings and out-of-range values are rejected rather
    than coerced: a stored reading must never leave a later analysis guessing
    what it meant. Mirrors ``training.definitions.validate_confidence``, which
    this package cannot import without depending on the runtime.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise LearningConfidenceError(
            "confidence must be an integer in {0}..{1} or None, got {2!r}"
            .format(CONFIDENCE_MIN, CONFIDENCE_MAX, value))
    if not CONFIDENCE_MIN <= value <= CONFIDENCE_MAX:
        raise LearningConfidenceError(
            "confidence {0} is outside {1}..{2}".format(
                value, CONFIDENCE_MIN, CONFIDENCE_MAX))
    return value


def confidence_band(confidence):
    """``high`` at or above the authored threshold, ``low`` below it."""
    if confidence is None:
        return BAND_UNSTATED
    return BAND_HIGH if confidence >= HIGH_CONFIDENCE_THRESHOLD else BAND_LOW


def interpret(quality, confidence):
    """The authored interpretation of one quality/confidence combination.

    ``PARTIAL`` is interpreted the same way whatever the confidence: the
    response left the decisive risk unaddressed, and how sure the learner felt
    about it does not change what the exercise can claim.

    A confidence that was never stated is treated as the cautious reading --
    ``fragile_protective`` rather than ``confident_protective``, and
    ``recognized_uncertainty`` rather than ``high_confidence_risk`` -- so an
    absent measurement can never manufacture the strongest signal.
    """
    high = confidence_band(confidence) == BAND_HIGH
    if quality == PARTIAL:
        return PARTIAL_RESPONSE
    if quality == PROTECTIVE:
        return CONFIDENT_PROTECTIVE if high else FRAGILE_PROTECTIVE
    if quality == RISKY:
        return HIGH_CONFIDENCE_RISK if high else RECOGNIZED_UNCERTAINTY
    raise ValueError("unclassifiable response quality {0!r}".format(quality))


@dataclass(frozen=True)
class DecisionAssessment:
    """The complete authored reading of one decision. Immutable by design.

    Every field is either copied from the decision or derived from the authored
    tables above; nothing here is generated, sampled or inferred. Two
    assessments of the same input are equal.
    """

    scenario_key: str
    choice_id: str
    response_quality: str
    confidence: Optional[int]
    confidence_band: str
    confidence_interpretation: str
    concept_tags: Tuple[str, ...]
    evidence_signal: str

    @property
    def confidence_stated(self) -> bool:
        return self.confidence is not None

    def as_dict(self):
        """A JSON-safe mapping, for tests and diagnostics.

        Nothing in it identifies a learner: it is the authored reading of a
        choice, not a record about a person.
        """
        return {
            "scenario_key": self.scenario_key,
            "choice_id": self.choice_id,
            "response_quality": self.response_quality,
            "confidence": self.confidence,
            "confidence_band": self.confidence_band,
            "confidence_interpretation": self.confidence_interpretation,
            "concept_tags": list(self.concept_tags),
            "evidence_signal": self.evidence_signal,
        }


def assess_decision(scenario_key, choice_id, confidence=None):
    """Assess one completed decision. Pure, total and deterministic.

    Raises :class:`~learning.errors.UnknownScenarioError`,
    :class:`~learning.errors.UnknownChoiceError` or
    :class:`~learning.errors.LearningConfidenceError` rather than returning a
    degraded assessment: an unclassifiable input must never become a row of
    research evidence.
    """
    quality = response_quality(scenario_key, choice_id)
    confidence = validate_confidence(confidence)
    interpretation = interpret(quality, confidence)
    return DecisionAssessment(
        scenario_key=scenario_key,
        choice_id=choice_id,
        response_quality=quality,
        confidence=confidence,
        confidence_band=confidence_band(confidence),
        confidence_interpretation=interpretation,
        concept_tags=concepts_for_choice(scenario_key, choice_id),
        evidence_signal=INTERPRETATION_SIGNALS[interpretation])
