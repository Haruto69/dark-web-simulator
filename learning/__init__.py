"""RewindSec learning domain -- authored pedagogy, deterministically applied.

Milestone R6 adds the layer that sits *after* the technical comparison. Where
``training/`` executes a counterfactual pair and reports what changed, this
package interprets a completed learner decision against authored pedagogical
definitions:

    training/   executes deterministic counterfactual technical consequences.
    learning/   interprets completed learner choices using authored
                pedagogical definitions.

The two are kept apart on purpose. ``CounterfactualRuntime`` knows nothing
about response quality, confidence bands, concept evidence or reflection, and
must not learn: a runtime that scored its own output could no longer be said to
be measuring anything.

Framework independence
----------------------
Like ``training/``, this package imports nothing but the standard library. No
Flask, no SQLAlchemy, no ``app``, no ``sandbox``, no Docker, no HTTP, no
templates -- and no ``training`` either, which keeps the dependency edge in one
direction only. The scenario keys it classifies are declared here as literals
and tied back to the shipped scenarios by test, not by import.

Determinism
-----------
No language model, at import time or at runtime. Every classification,
explanation, concept statement and probe is written by hand and fixed at import
time. Two identical inputs always produce two equal outputs.

What this package does not claim
--------------------------------
Concept evidence is an authored training signal. It is not a psychological
diagnosis, a permanent learner trait, a validated mastery score, or a clinical
or educational assessment. R6 computes no global score and averages nothing.
"""

from .assessment import (BAND_HIGH, BAND_LOW, BAND_UNSTATED,
                         CONFIDENCE_INTERPRETATIONS, CONFIDENCE_MAX,
                         CONFIDENCE_MIN, CONFIDENT_PROTECTIVE,
                         EVIDENCE_SIGNALS, FRAGILE_PROTECTIVE,
                         FRAGILE_UNDERSTANDING, HIGH_CONFIDENCE_RISK,
                         HIGH_CONFIDENCE_THRESHOLD, INTERPRETATION_SIGNALS,
                         MISCONCEPTION_CANDIDATE, NEEDS_REINFORCEMENT,
                         PARTIAL_RESPONSE, PARTIAL_UNDERSTANDING,
                         RECOGNIZED_UNCERTAINTY, SUPPORTING_EVIDENCE,
                         DecisionAssessment, assess_decision, confidence_band,
                         interpret, validate_confidence)
from .concepts import (CHOICE_CONCEPTS, SCENARIO_CONCEPTS, concepts_for_choice,
                       scenario_concepts)
from .errors import (LearningConfidenceError, LearningError,
                     UnknownChoiceError, UnknownExplanationError,
                     UnknownProbeError, UnknownScenarioError)
from .quality import (BEC, LEARNING_SCENARIOS, MFA, PARTIAL, PHISHING,
                      PROTECTIVE, RANSOMWARE, RESPONSE_QUALITIES,
                      RESPONSE_QUALITY, RISKY, known_scenario,
                      response_quality, scenario_choice_ids)
from .reflection import (REFLECTIONS, ExplanationOption, ReflectionDefinition,
                         explanation_for, reflection_for)
from .transfer import (PROBE_FOR_SCENARIO, TRANSFER_PROBES, ProbeChoice,
                       TransferProbe, classify_probe_choice, probe_for_key,
                       probe_for_scenario)

#: Evidence sources. What kind of learner act produced a piece of evidence.
#:
#: The distinction matters for the paper: the factual decision is the learner's
#: behaviour *before* the intervention, while the structured reflection is
#: their explanation *after* seeing it. The counterfactual branch is neither --
#: it is part of the intervention, and is never recorded as behavioural
#: evidence.
FACTUAL_DECISION = "factual_decision"
STRUCTURED_REFLECTION = "structured_reflection"
TRANSFER_PROBE = "transfer_probe"

EVIDENCE_SOURCES = (FACTUAL_DECISION, STRUCTURED_REFLECTION, TRANSFER_PROBE)

__all__ = [
    # scenarios and quality
    "PHISHING", "RANSOMWARE", "MFA", "BEC", "LEARNING_SCENARIOS",
    "PROTECTIVE", "PARTIAL", "RISKY", "RESPONSE_QUALITIES",
    "RESPONSE_QUALITY", "known_scenario", "response_quality",
    "scenario_choice_ids",
    # concepts
    "CHOICE_CONCEPTS", "SCENARIO_CONCEPTS", "concepts_for_choice",
    "scenario_concepts",
    # assessment
    "CONFIDENCE_MIN", "CONFIDENCE_MAX", "HIGH_CONFIDENCE_THRESHOLD",
    "BAND_HIGH", "BAND_LOW", "BAND_UNSTATED", "CONFIDENCE_INTERPRETATIONS",
    "CONFIDENT_PROTECTIVE", "FRAGILE_PROTECTIVE", "HIGH_CONFIDENCE_RISK",
    "RECOGNIZED_UNCERTAINTY", "PARTIAL_RESPONSE", "EVIDENCE_SIGNALS",
    "SUPPORTING_EVIDENCE", "FRAGILE_UNDERSTANDING", "PARTIAL_UNDERSTANDING",
    "NEEDS_REINFORCEMENT", "MISCONCEPTION_CANDIDATE",
    "INTERPRETATION_SIGNALS", "DecisionAssessment", "assess_decision",
    "confidence_band", "interpret", "validate_confidence",
    # reflection
    "REFLECTIONS", "ExplanationOption", "ReflectionDefinition",
    "explanation_for", "reflection_for",
    # transfer
    "TRANSFER_PROBES", "PROBE_FOR_SCENARIO", "ProbeChoice", "TransferProbe",
    "classify_probe_choice", "probe_for_key", "probe_for_scenario",
    # evidence sources
    "FACTUAL_DECISION", "STRUCTURED_REFLECTION", "TRANSFER_PROBE",
    "EVIDENCE_SOURCES",
    # errors
    "LearningError", "LearningConfidenceError", "UnknownScenarioError",
    "UnknownChoiceError", "UnknownExplanationError", "UnknownProbeError",
]
