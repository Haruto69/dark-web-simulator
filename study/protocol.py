"""The authored study protocol: arms, phases and the retention window.

What this module is
-------------------
A **protocol definition**. It fixes the names, the ordering and the timing of
one randomised pilot so that the application, the tests and the paper all read
the same authored constants rather than three copies of a convention.

What this module is not
-----------------------
It is not evidence that a study has been approved, registered, recruited for or
completed. Defining ``rewindsec_phishing_pilot`` here says only that the
software can run that shape of pilot. Enabling research mode in a deployment is
an operational setting and is **not** a substitute for institutional ethics
review, participant consent, or study registration where those are required.

Scope
-----
The first pilot uses **one** source scenario, ``phishing_credential_compromise``,
because all three intervention arms can be built on it without Docker, every
participant can be shown an identical first decision, and the immediate
transfer probe already exists. Ransomware, MFA and BEC remain full RewindSec
demonstration modules and are deliberately **not** part of this protocol; no
human-study claim may be made about them.

The data model is keyed by ``(protocol_key, protocol_version)`` throughout, so a
second source scenario can be added later as a second protocol without
rewriting a table or a route.
"""

from datetime import timedelta
from types import MappingProxyType

from .errors import PhaseTransitionError, UnknownArmError, UnknownPhaseError

# -- protocol identity ------------------------------------------------------
PROTOCOL_KEY = "rewindsec_phishing_pilot"
PROTOCOL_VERSION = 1

#: The single source training scenario of this protocol. Repeated as a literal
#: rather than imported from ``scenario_adapters`` (which pulls in the sandbox);
#: ``tests/test_study_protocol.py`` asserts it is the shipped phishing key.
SOURCE_SCENARIO_KEY = "phishing_credential_compromise"
SOURCE_DECISION_ID = "respond_to_message"

#: The probe every arm answers immediately after its intervention, and the
#: study-only probe answered after the retention interval.
IMMEDIATE_PROBE_KEY = "quishing_portal_qr"
RETENTION_PROBE_KEY = "smishing_account_notice"

# -- the three arms ---------------------------------------------------------
# Stable keys, deliberately descriptive of *what the arm does*. Never
# "control"/"experimental": those words carry an expectation, and no
# learner-facing surface in this build names an arm at all.
AWARENESS_DEBRIEF = "awareness_debrief"
FACTUAL_CONSEQUENCE = "factual_consequence"
COUNTERFACTUAL_REPLAY = "counterfactual_replay"

#: Declaration order is allocation-block order and export order. It is not a
#: ranking and implies nothing about an expected outcome.
ARMS = (AWARENESS_DEBRIEF, FACTUAL_CONSEQUENCE, COUNTERFACTUAL_REPLAY)

#: Instructor-facing arm descriptions. Never rendered on a learner page.
ARM_DESCRIPTIONS = MappingProxyType({
    AWARENESS_DEBRIEF: ("Concise conventional awareness debrief. No "
                        "consequence is executed."),
    FACTUAL_CONSEQUENCE: ("The learner's own response is executed in the "
                          "deterministic consequence environment and shown. "
                          "No rewind."),
    COUNTERFACTUAL_REPLAY: ("Factual consequence, verified rewind, learner-"
                            "chosen alternative, paired comparison and "
                            "structured self-explanation."),
})


def known_arm(arm_key):
    return arm_key in ARMS


def require_arm(arm_key):
    if not known_arm(arm_key):
        raise UnknownArmError("unknown study arm {0!r}".format(arm_key))
    return arm_key


# -- what each arm is authored to do ----------------------------------------
#: Whether the arm applies the real consequence adapter to the learner's own
#: factual response. Arm A deliberately does not: showing it the technical
#: branch state would make it an interactive simulation rather than the
#: conventional debrief it is there to represent.
ARM_EXECUTES_CONSEQUENCE = MappingProxyType({
    AWARENESS_DEBRIEF: False,
    FACTUAL_CONSEQUENCE: True,
    COUNTERFACTUAL_REPLAY: True,
})

#: Whether the arm rewinds and runs a paired counterfactual execution. Only the
#: third arm does, and it is therefore the only arm that ever produces a
#: ``TrainingExecution`` row.
ARM_RUNS_COUNTERFACTUAL = MappingProxyType({
    AWARENESS_DEBRIEF: False,
    FACTUAL_CONSEQUENCE: False,
    COUNTERFACTUAL_REPLAY: True,
})

#: Whether the arm asks for the structured self-explanation.
ARM_REQUIRES_REFLECTION = MappingProxyType({
    AWARENESS_DEBRIEF: False,
    FACTUAL_CONSEQUENCE: False,
    COUNTERFACTUAL_REPLAY: True,
})


def executes_consequence(arm_key):
    return ARM_EXECUTES_CONSEQUENCE[require_arm(arm_key)]


def runs_counterfactual(arm_key):
    return ARM_RUNS_COUNTERFACTUAL[require_arm(arm_key)]


def requires_reflection(arm_key):
    return ARM_REQUIRES_REFLECTION[require_arm(arm_key)]


# -- phases -----------------------------------------------------------------
# The server-authoritative progression. A participant's phase is stored on the
# enrollment and advanced only by this module's rules; nothing a browser submits
# names a phase, and there is no hidden phase field anywhere in the flow.
ENROLLED = "enrolled"
SOURCE_DECISION_RECORDED = "source_decision_recorded"
FACTUAL_PREVIEW = "factual_preview"
COUNTERFACTUAL_COMPLETED = "counterfactual_completed"
REFLECTION_COMPLETED = "reflection_completed"
INTERVENTION_COMPLETED = "intervention_completed"
IMMEDIATE_TRANSFER_COMPLETED = "immediate_transfer_completed"
RETENTION_WAITING = "retention_waiting"
RETENTION_COMPLETED = "retention_completed"

#: Every phase key, for validation and for stable dashboard ordering.
PHASES = (ENROLLED, SOURCE_DECISION_RECORDED, FACTUAL_PREVIEW,
          COUNTERFACTUAL_COMPLETED, REFLECTION_COMPLETED,
          INTERVENTION_COMPLETED, IMMEDIATE_TRANSFER_COMPLETED,
          RETENTION_WAITING, RETENTION_COMPLETED)

#: **The** progression, per arm. A phase an arm does not list is not reachable
#: for that arm at all, which is what makes cross-arm contamination a phase
#: error rather than a template accident: an Arm A participant asking for the
#: comparison page is asking for a phase Arm A has never had.
ARM_PHASES = MappingProxyType({
    AWARENESS_DEBRIEF: (
        ENROLLED, SOURCE_DECISION_RECORDED, INTERVENTION_COMPLETED,
        IMMEDIATE_TRANSFER_COMPLETED, RETENTION_WAITING, RETENTION_COMPLETED),
    FACTUAL_CONSEQUENCE: (
        ENROLLED, SOURCE_DECISION_RECORDED, FACTUAL_PREVIEW,
        INTERVENTION_COMPLETED, IMMEDIATE_TRANSFER_COMPLETED,
        RETENTION_WAITING, RETENTION_COMPLETED),
    COUNTERFACTUAL_REPLAY: (
        ENROLLED, SOURCE_DECISION_RECORDED, FACTUAL_PREVIEW,
        COUNTERFACTUAL_COMPLETED, REFLECTION_COMPLETED, INTERVENTION_COMPLETED,
        IMMEDIATE_TRANSFER_COMPLETED, RETENTION_WAITING, RETENTION_COMPLETED),
})


def arm_phases(arm_key):
    """This arm's authored phase progression, in order."""
    return ARM_PHASES[require_arm(arm_key)]


def phase_index(arm_key, phase):
    """Position of ``phase`` in this arm's progression.

    Raises rather than returning ``-1``: a phase outside the arm's progression
    is a routing error, and a silent negative would compare as "earliest".
    """
    try:
        return arm_phases(arm_key).index(phase)
    except ValueError:
        raise UnknownPhaseError(
            "arm {0!r} has no phase {1!r}".format(arm_key, phase)) from None


def has_phase(arm_key, phase):
    return phase in arm_phases(arm_key)


def at_least(arm_key, current, required):
    """True when ``current`` is at or past ``required`` for this arm."""
    return phase_index(arm_key, current) >= phase_index(arm_key, required)


def next_phase(arm_key, current):
    """The one phase that may legally follow ``current``, ``None`` at the end."""
    order = arm_phases(arm_key)
    index = phase_index(arm_key, current)
    return order[index + 1] if index + 1 < len(order) else None


def check_transition(arm_key, current, target):
    """Validate one forward step. Raises :class:`PhaseTransitionError`.

    Only the *immediate* successor is legal. A participant cannot skip ahead by
    typing a URL, and a repeated POST that would move the same enrollment
    forward twice is refused here rather than in a template.
    """
    expected = next_phase(arm_key, current)
    if target != expected:
        raise PhaseTransitionError(
            "arm {0!r} cannot move from {1!r} to {2!r}".format(
                arm_key, current, target))
    return target


# -- the retention window ---------------------------------------------------
#: **An authored study-protocol choice, not evidence that this interval is
#: optimal.** Seven days is a conventional short-retention interval and
#: fourteen bounds the window, so a "retention" measurement cannot silently
#: become a two-month one. Neither figure is calibrated against anything, and
#: no claim in this repository depends on the interval being correct.
RETENTION_OPEN_DAYS = 7
RETENTION_CLOSE_DAYS = 14


def retention_window(immediate_completed_at):
    """``(open_at, close_at)`` for one participant, or ``(None, None)``.

    ``immediate_completed_at`` is a naive UTC datetime, matching the project's
    single clock (``sandbox.timeutil.utcnow``). The arithmetic lives here so the
    two offsets exist in exactly one place.
    """
    if immediate_completed_at is None:
        return (None, None)
    return (immediate_completed_at + timedelta(days=RETENTION_OPEN_DAYS),
            immediate_completed_at + timedelta(days=RETENTION_CLOSE_DAYS))


#: Retention access states. Boundary rule: the window is inclusive at both
#: ends -- ``now >= open_at`` opens it, ``now > close_at`` closes it -- so a
#: participant arriving at the exact opening instant is admitted rather than
#: turned away by a strict inequality.
RETENTION_PENDING = "pending"
RETENTION_OPEN = "open"
RETENTION_EXPIRED = "expired"
RETENTION_UNSCHEDULED = "unscheduled"


def retention_state(now, open_at, close_at):
    """Where ``now`` falls relative to one participant's window."""
    if open_at is None or close_at is None:
        return RETENTION_UNSCHEDULED
    if now < open_at:
        return RETENTION_PENDING
    if now > close_at:
        return RETENTION_EXPIRED
    return RETENTION_OPEN


__all__ = [
    "PROTOCOL_KEY", "PROTOCOL_VERSION", "SOURCE_SCENARIO_KEY",
    "SOURCE_DECISION_ID", "IMMEDIATE_PROBE_KEY", "RETENTION_PROBE_KEY",
    "AWARENESS_DEBRIEF", "FACTUAL_CONSEQUENCE", "COUNTERFACTUAL_REPLAY",
    "ARMS", "ARM_DESCRIPTIONS", "known_arm", "require_arm",
    "ARM_EXECUTES_CONSEQUENCE", "ARM_RUNS_COUNTERFACTUAL",
    "ARM_REQUIRES_REFLECTION", "executes_consequence", "runs_counterfactual",
    "requires_reflection",
    "ENROLLED", "SOURCE_DECISION_RECORDED", "FACTUAL_PREVIEW",
    "COUNTERFACTUAL_COMPLETED", "REFLECTION_COMPLETED",
    "INTERVENTION_COMPLETED", "IMMEDIATE_TRANSFER_COMPLETED",
    "RETENTION_WAITING", "RETENTION_COMPLETED", "PHASES", "ARM_PHASES",
    "arm_phases", "phase_index", "has_phase", "at_least", "next_phase",
    "check_transition",
    "RETENTION_OPEN_DAYS", "RETENTION_CLOSE_DAYS", "retention_window",
    "RETENTION_PENDING", "RETENTION_OPEN", "RETENTION_EXPIRED",
    "RETENTION_UNSCHEDULED", "retention_state",
]
