"""RewindSec study domain -- the research protocol, applied deterministically.

Milestone R7 adds the layer that makes a randomised pilot possible without
contaminating the ordinary training experience:

    training/   executes deterministic counterfactual technical consequences.
    learning/   interprets completed learner choices using authored
                pedagogical definitions.
    study/      defines one randomised research protocol: its arms, its phase
                progression, its allocation rule and its measurements.

What this package establishes, and what it does not
---------------------------------------------------
It establishes the *infrastructure* to test one question:

    Does deterministic counterfactual replay plus structured self-explanation
    improve protective transfer behaviour compared with a conventional debrief
    and with factual-consequence simulation?

**RewindSec does not claim that it does.** Nothing in this package, and nothing
in the application built on it, computes a p-value, an effect size, a
significance test or a "learning improvement" label. The software stores and
describes observations; analysis belongs in the paper workflow, after real data
collected under an appropriate approved study protocol exists.

Defining the protocol here is likewise not evidence that a study has been
approved, registered or recruited for. Enabling research mode in a deployment
is an operational setting and is not a substitute for institutional ethics
review, participant consent, or study registration where those are required.

Framework independence
----------------------
Like ``training/`` and ``learning/``, this package imports no Flask, no
SQLAlchemy, no ``app``, no ``sandbox``, no Docker, no ``requests`` and no
``subprocess``. It holds no persistence and no HTTP logic; those live in
``study_service.py`` and ``study_routes.py``.

The one non-stdlib import is ``learning`` -- itself pure, and depended on in one
direction only, so the immediate transfer probe used by the study is literally
the instrument the normal flow uses rather than a copy that could drift.

Privacy
-------
No name, email, student id, phone number, registration number, date of birth,
gender or demographic field appears anywhere in this package or in the tables
built from it. A participant is a UUID4 and an allocation slot.
"""

from .assessment import (ASSESSMENT_PHASES, IMMEDIATE_TRANSFER,
                         INTERVENTION_INCOMPLETE, MISSINGNESS_LABELS,
                         MISSINGNESS_STATES, NOT_REACHED, OBSERVED,
                         PROBES_BY_PHASE, RETENTION_PROBE, RETENTION_TRANSFER,
                         WINDOW_EXPIRED, WINDOW_NOT_OPEN, classify,
                         high_confidence_risky, known_phase, probe_for_phase)
from .assignment import (BLOCK_SIZE, PER_ARM_PER_BLOCK, SECRET_ENV_VAR,
                         allocation_sequence, arm_for_slot, block_index,
                         block_permutation, block_position, require_secret)
from .continuity import (RETURN_CODE_BYTES, RETURN_CODE_LENGTH,
                         SECRET_ENV_VAR as CONTINUITY_SECRET_ENV_VAR,
                         code_digest, digests_match, looks_like_code,
                         new_return_code,
                         require_secret as require_continuity_secret)
from .errors import (PhaseTransitionError, RetentionWindowError,
                     StudyConfigurationError, StudyError, UnknownArmError,
                     UnknownPhaseError, UnknownStudyProbeError)
from .protocol import (ARM_DESCRIPTIONS, ARM_PHASES, ARMS, AWARENESS_DEBRIEF,
                       COUNTERFACTUAL_COMPLETED, COUNTERFACTUAL_REPLAY,
                       ENROLLED, FACTUAL_CONSEQUENCE, FACTUAL_PREVIEW,
                       IMMEDIATE_PROBE_KEY, IMMEDIATE_TRANSFER_COMPLETED,
                       INTERVENTION_COMPLETED, PHASES, PROTOCOL_KEY,
                       PROTOCOL_VERSION, REFLECTION_COMPLETED,
                       RETENTION_CLOSE_DAYS, RETENTION_COMPLETED,
                       RETENTION_EXPIRED, RETENTION_OPEN, RETENTION_OPEN_DAYS,
                       RETENTION_PENDING, RETENTION_PROBE_KEY,
                       RETENTION_UNSCHEDULED, RETENTION_WAITING,
                       SOURCE_DECISION_ID, SOURCE_DECISION_RECORDED,
                       SOURCE_SCENARIO_KEY, arm_phases, at_least,
                       check_transition, executes_consequence, has_phase,
                       known_arm, next_phase, phase_index, require_arm,
                       requires_reflection, retention_state, retention_window,
                       runs_counterfactual)

__all__ = [
    # protocol
    "PROTOCOL_KEY", "PROTOCOL_VERSION", "SOURCE_SCENARIO_KEY",
    "SOURCE_DECISION_ID", "IMMEDIATE_PROBE_KEY", "RETENTION_PROBE_KEY",
    "AWARENESS_DEBRIEF", "FACTUAL_CONSEQUENCE", "COUNTERFACTUAL_REPLAY",
    "ARMS", "ARM_DESCRIPTIONS", "known_arm", "require_arm",
    "executes_consequence", "runs_counterfactual", "requires_reflection",
    # phases
    "ENROLLED", "SOURCE_DECISION_RECORDED", "FACTUAL_PREVIEW",
    "COUNTERFACTUAL_COMPLETED", "REFLECTION_COMPLETED",
    "INTERVENTION_COMPLETED", "IMMEDIATE_TRANSFER_COMPLETED",
    "RETENTION_WAITING", "RETENTION_COMPLETED", "PHASES", "ARM_PHASES",
    "arm_phases", "phase_index", "has_phase", "at_least", "next_phase",
    "check_transition",
    # retention window
    "RETENTION_OPEN_DAYS", "RETENTION_CLOSE_DAYS", "retention_window",
    "retention_state", "RETENTION_PENDING", "RETENTION_OPEN",
    "RETENTION_EXPIRED", "RETENTION_UNSCHEDULED",
    # allocation
    "PER_ARM_PER_BLOCK", "BLOCK_SIZE", "SECRET_ENV_VAR", "require_secret",
    "block_index", "block_position", "block_permutation", "arm_for_slot",
    "allocation_sequence",
    # continuity
    "CONTINUITY_SECRET_ENV_VAR", "require_continuity_secret",
    "RETURN_CODE_BYTES", "RETURN_CODE_LENGTH", "new_return_code",
    "looks_like_code", "code_digest", "digests_match",
    # measurement
    "IMMEDIATE_TRANSFER", "RETENTION_TRANSFER", "ASSESSMENT_PHASES",
    "RETENTION_PROBE", "PROBES_BY_PHASE", "known_phase", "probe_for_phase",
    "classify", "high_confidence_risky",
    "OBSERVED", "NOT_REACHED", "WINDOW_NOT_OPEN", "WINDOW_EXPIRED",
    "INTERVENTION_INCOMPLETE", "MISSINGNESS_STATES", "MISSINGNESS_LABELS",
    # errors
    "StudyError", "StudyConfigurationError", "UnknownArmError",
    "UnknownPhaseError", "PhaseTransitionError", "RetentionWindowError",
    "UnknownStudyProbeError",
]
