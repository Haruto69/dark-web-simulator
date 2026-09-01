"""The two study measurement phases, and the study-only retention probe.

Two probes, two phases
----------------------
``immediate_transfer``  the existing authored ``quishing_portal_qr`` probe,
                        answered by **all three arms** immediately after their
                        intervention. Reused verbatim from ``learning.transfer``
                        rather than copied, so the immediate measurement is
                        literally the same instrument in every arm and in the
                        normal non-study flow.

``retention_transfer``  ``smishing_account_notice``, defined here because it
                        exists only for this protocol. It is not registered in
                        ``learning.TRANSFER_PROBES`` and is unreachable from the
                        normal R6 transfer routes.

Why a third surface
-------------------
The retention probe tests the same underlying principle -- verify a request
through a channel you already trust before presenting an identity -- on a
surface the participant has met neither in the training scenario (an email with
a link) nor in the immediate probe (a printed QR code). A mobile-message
notification is a third medium with a third pretext.

This is called a **retention transfer probe**, never "far transfer". Whether
two surfaces are near or far is a judgement about the surfaces, and nothing in
this repository is entitled to make it.

Safety
------
Everything here is authored static text. There is no SMS, no real or fictional
external URL, no clickable destination, no login form, no credential field and
no network call anywhere in the retention page. The message is rendered as
inert prose and the participant reasons about it.

No statistics
-------------
This module classifies one response against an authored table and names the
ways a measurement can be *missing*. It computes no significance, no effect
size, no improvement and no score. Those belong in the analysis workflow, after
data collected under an appropriate approved protocol exists.
"""

from types import MappingProxyType

import learning
from learning import concepts as C
from learning.assessment import HIGH_CONFIDENCE_THRESHOLD
from learning.quality import PARTIAL, PHISHING, PROTECTIVE, RISKY
from learning.transfer import ProbeChoice, TransferProbe

from .errors import UnknownStudyProbeError
from .protocol import IMMEDIATE_PROBE_KEY, RETENTION_PROBE_KEY

# -- measurement phases -----------------------------------------------------
IMMEDIATE_TRANSFER = "immediate_transfer"
RETENTION_TRANSFER = "retention_transfer"

ASSESSMENT_PHASES = (IMMEDIATE_TRANSFER, RETENTION_TRANSFER)

# -- the study-only retention probe -----------------------------------------
# A fictional mobile-message notification. The fictional service, the pretext
# and the medium all differ from the training email and from the QR notice.
#
# There is deliberately no address, host, short link or destination of any kind
# in the situation text: a "route supplied by the message" is described, never
# rendered, so there is nothing on the page that could be visited even by
# accident.
RETENTION_PROBE = TransferProbe(
    probe_key=RETENTION_PROBE_KEY,
    version=1,
    source_scenario_key=PHISHING,
    title="A message about your account",
    prompt=("A message has arrived on your phone. What is your first "
            "response?"),
    situation=(
        "The message says it is from Halbrook Union Services and that a "
        "sign-in from a new device is waiting to be confirmed.",
        "It says the account will be locked within the hour unless the "
        "sign-in is confirmed now.",
        "It asks you to sign in using the route supplied in the message.",
        "The sender is a number you do not recognise, and you were not "
        "expecting any account notice.",
    ),
    choices=(
        ProbeChoice("follow_message_and_sign_in",
                    "Use the message route and sign in", RISKY,
                    (C.CREDENTIAL_EXPOSURE, C.CHANNEL_SWITCHING)),
        ProbeChoice("inspect_message_details",
                    "Inspect the message details first", PARTIAL,
                    (C.CHANNEL_SWITCHING,)),
        ProbeChoice("open_official_service",
                    "Open the known official service independently",
                    PROTECTIVE,
                    (C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE)),
        ProbeChoice("report_suspicious_message",
                    "Report the suspicious message", PROTECTIVE,
                    (C.INDEPENDENT_VERIFICATION, C.CHANNEL_SWITCHING)),
    ),
    concept_tags=(C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE,
                  C.CHANNEL_SWITCHING),
    principle=(
        "The medium changed again -- an email, then a printed code, now a "
        "message on a phone -- and the request did not. Urgency and a "
        "convenient route are still the whole of the pressure, and the answer "
        "is still to reach the service the way you already know how."),
)

#: ``phase -> probe``. The immediate probe is *resolved from*
#: ``learning.TRANSFER_PROBES`` rather than redefined, so it cannot drift from
#: the instrument the normal flow uses.
PROBES_BY_PHASE = MappingProxyType({
    IMMEDIATE_TRANSFER: learning.probe_for_key(IMMEDIATE_PROBE_KEY),
    RETENTION_TRANSFER: RETENTION_PROBE,
})


def known_phase(phase):
    return phase in ASSESSMENT_PHASES


def probe_for_phase(phase):
    """The authored probe for one measurement phase, or a hard failure."""
    try:
        return PROBES_BY_PHASE[phase]
    except KeyError:
        raise UnknownStudyProbeError(
            "no study probe for phase {0!r}".format(phase)) from None


def classify(phase, choice_id):
    """The authored classification of one probe response.

    Scoped by ``(phase, choice_id)``, so a choice id belonging to the other
    probe is refused rather than silently classified against the wrong table.
    """
    return probe_for_phase(phase).choice(choice_id)


def high_confidence_risky(response_quality, confidence):
    """Whether one response is a risky answer given with high stated confidence.

    A **descriptive** flag over a single response, reusing the learning layer's
    authored threshold so the study and the training feedback cannot disagree
    about what "high confidence" means. It is not a diagnosis, not a trait, and
    is counted -- never averaged -- on the dashboard.
    """
    return (response_quality == RISKY and confidence is not None
            and confidence >= HIGH_CONFIDENCE_THRESHOLD)


# -- missing data -----------------------------------------------------------
# Missingness is represented, never imputed. A participant who never returned
# for the retention probe did not answer it riskily; they did not answer it.
# Collapsing the two would manufacture the study's own outcome variable.
OBSERVED = "observed"
NOT_REACHED = "not_reached"
WINDOW_NOT_OPEN = "window_not_open"
WINDOW_EXPIRED = "window_expired"
INTERVENTION_INCOMPLETE = "intervention_incomplete"

MISSINGNESS_STATES = (OBSERVED, NOT_REACHED, WINDOW_NOT_OPEN, WINDOW_EXPIRED,
                      INTERVENTION_INCOMPLETE)

#: Instructor-facing wording. Each says what is *not known*, and none implies a
#: response quality.
MISSINGNESS_LABELS = MappingProxyType({
    OBSERVED: "Recorded",
    NOT_REACHED: "Not reached",
    WINDOW_NOT_OPEN: "Window not open yet",
    WINDOW_EXPIRED: "Window closed without a response",
    INTERVENTION_INCOMPLETE: "Intervention not completed",
})


__all__ = [
    "IMMEDIATE_TRANSFER", "RETENTION_TRANSFER", "ASSESSMENT_PHASES",
    "RETENTION_PROBE", "PROBES_BY_PHASE", "known_phase", "probe_for_phase",
    "classify", "high_confidence_risky",
    "OBSERVED", "NOT_REACHED", "WINDOW_NOT_OPEN", "WINDOW_EXPIRED",
    "INTERVENTION_INCOMPLETE", "MISSINGNESS_STATES", "MISSINGNESS_LABELS",
]
