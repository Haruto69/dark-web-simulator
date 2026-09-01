"""Authored **unseen transfer probes**.

What a transfer probe is here
-----------------------------
A probe presents a security situation on a *different surface* from the
training scenario the learner has just completed, and records their **first
response** -- before any feedback, any comparison and any rewind. It is the one
measurement in RewindSec that is taken after the intervention and without it.

What a transfer probe is not
----------------------------
*  It is **not** a counterfactual training module. There is no paired
   execution, no baseline fingerprint, no rewind, and no
   ``TrainingExecution`` row. ``CounterfactualRuntime`` is never involved.
*  It is **not** labelled near or far transfer. The literature's distinction
   depends on how the surfaces are judged to differ, which is a study-design
   question this milestone deliberately leaves open. These are recorded as
   *unseen transfer probes*, and nothing downstream hard-codes a stronger
   claim.

Safety
------
Everything a probe presents is authored static text held in this module. A
probe carries no URL, no external host, no destination of any kind, no
attachment, and no downloadable payload. The QR figure the quishing probe
renders is a locally drawn decorative pattern that encodes nothing; there is no
code to scan and nothing to decode. Nothing here opens a socket, spawns a
process, touches a filesystem or calls a model.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Tuple

from . import concepts as C
from .errors import UnknownChoiceError, UnknownProbeError
from .quality import PARTIAL, PHISHING, PROTECTIVE, RANSOMWARE, RISKY

#: Upper bound on a recorded probe response time (one hour), matching the
#: training flow's bound. Beyond it the latency is recorded as "not measured"
#: rather than as an implausible number.
MAX_RESPONSE_MS = 60 * 60 * 1000


@dataclass(frozen=True)
class ProbeChoice:
    """One fixed option, with its authored quality and concept evidence."""

    choice_id: str
    label: str
    response_quality: str
    concept_tags: Tuple[str, ...] = ()

    def __post_init__(self):
        if self.response_quality not in (PROTECTIVE, PARTIAL, RISKY):
            raise ValueError(
                "probe choice {0!r} has an unauthored quality {1!r}".format(
                    self.choice_id, self.response_quality))
        object.__setattr__(self, "concept_tags", tuple(self.concept_tags))


@dataclass(frozen=True)
class TransferProbe:
    """One authored unseen probe: its surface, its options and its principle.

    ``source_scenario_key`` is the training scenario whose completed learning
    sequence unlocks this probe. It is a *pedagogical* link, and the routing
    layer resolves the actual source execution from server-side session state
    -- never from anything a browser submits.
    """

    probe_key: str
    version: int
    source_scenario_key: str
    title: str
    prompt: str
    situation: Tuple[str, ...]
    choices: Tuple[ProbeChoice, ...]
    concept_tags: Tuple[str, ...]
    principle: str

    def __post_init__(self):
        object.__setattr__(self, "situation", tuple(self.situation))
        object.__setattr__(self, "choices", tuple(self.choices))
        object.__setattr__(self, "concept_tags", tuple(self.concept_tags))
        ids = [c.choice_id for c in self.choices]
        if len(set(ids)) != len(ids):
            raise ValueError(
                "probe {0!r} has duplicate choice ids".format(self.probe_key))
        if len(self.choices) != 4:
            raise ValueError(
                "probe {0!r} must offer exactly four choices, got {1}".format(
                    self.probe_key, len(self.choices)))

    @property
    def choice_ids(self) -> Tuple[str, ...]:
        return tuple(c.choice_id for c in self.choices)

    def choice(self, choice_id) -> ProbeChoice:
        for candidate in self.choices:
            if candidate.choice_id == choice_id:
                return candidate
        raise UnknownChoiceError(
            "probe {0!r} does not offer choice {1!r}".format(
                self.probe_key, choice_id))


# -- A. Quishing / QR phishing ----------------------------------------------
# Source: phishing_credential_compromise. Different surface (a printed/pasted
# code rather than a link in an email), same underlying principle: verify the
# request through a channel you already trust before presenting an identity.
#
# The wording deliberately shares nothing with the R3 phishing message: a
# different fictional service, a different pretext (event registration rather
# than account expiry), and a different medium.
QUISHING_PROBE = TransferProbe(
    probe_key="quishing_portal_qr",
    version=1,
    source_scenario_key=PHISHING,
    title="A QR code on a registration notice",
    prompt=("A notice has been pinned in the shared staff area at Riverbend "
            "Polytechnic. What is your first response?"),
    situation=(
        "The notice is headed \"Riverbend Polytechnic — Staff Development "
        "Week registration\".",
        "It says places are being confirmed this week and asks staff to scan "
        "the printed code to confirm their place and their access.",
        "The code is printed on a sticker that has been applied over part of "
        "the original notice.",
        "No contact name, extension or office is given anywhere on the page.",
    ),
    choices=(
        ProbeChoice("scan_and_sign_in", "Scan the code and sign in", RISKY,
                    (C.CREDENTIAL_EXPOSURE, C.CHANNEL_SWITCHING)),
        ProbeChoice("inspect_qr_request",
                    "Inspect the request and destination details first",
                    PARTIAL, (C.CHANNEL_SWITCHING,)),
        ProbeChoice("verify_via_official_portal",
                    "Open the known official portal independently", PROTECTIVE,
                    (C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE)),
        ProbeChoice("report_qr_message", "Report the QR-code message",
                    PROTECTIVE,
                    (C.INDEPENDENT_VERIFICATION, C.CHANNEL_SWITCHING)),
    ),
    concept_tags=(C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE,
                  C.CHANNEL_SWITCHING),
    principle=(
        "A QR code is a link you cannot read. Moving the request from a screen "
        "onto a printed sticker removes the one check an email at least "
        "allowed -- seeing where it goes -- while the principle is unchanged: "
        "reach the service through a route you already trust, and never "
        "present an identity to a destination the request itself chose for "
        "you."),
)

# -- B. Malicious update / attachment ---------------------------------------
# Source: ransomware_incident_response. Different surface (a pushed "update"
# arriving in a chat message rather than files already being impacted), and it
# probes the step *before* impact: where software is allowed to come from.
#
# There is no attachment. The file name below is inert display text; no file of
# that name exists in this repository, no route serves one, and nothing in the
# probe can be opened, downloaded or executed.
UPDATE_ATTACHMENT_PROBE = TransferProbe(
    probe_key="unexpected_update_attachment",
    version=1,
    source_scenario_key=RANSOMWARE,
    title="An unexpected update package",
    prompt=("A message has arrived in your workplace chat. What is your first "
            "response?"),
    situation=(
        "The message reads: \"Critical security update required immediately.\"",
        "It claims to come from the Riverbend Polytechnic desktop team and "
        "says every workstation must be patched before the end of the day.",
        "An update package is referenced in the message, named "
        "\"riverbend-endpoint-patch\".",
        "The sender is not in your contacts, and no maintenance window was "
        "announced.",
    ),
    choices=(
        ProbeChoice("run_attached_update", "Open the attached update", RISKY,
                    (C.TRUSTED_SOFTWARE_SOURCE,)),
        ProbeChoice("restart_then_try_update",
                    "Restart the workstation, then try the attachment again",
                    RISKY,
                    (C.TRUSTED_SOFTWARE_SOURCE, C.ENDPOINT_ISOLATION)),
        ProbeChoice("verify_update_through_it",
                    "Verify the update through the known IT/software channel",
                    PROTECTIVE, (C.TRUSTED_SOFTWARE_SOURCE,)),
        ProbeChoice("isolate_and_report_attachment",
                    "Isolate the workstation and report the suspicious "
                    "attachment",
                    PROTECTIVE, (C.ENDPOINT_ISOLATION, C.INCIDENT_REPORTING)),
    ),
    concept_tags=(C.TRUSTED_SOFTWARE_SOURCE, C.ENDPOINT_ISOLATION,
                  C.INCIDENT_REPORTING),
    principle=(
        "Urgency is the oldest way to get software run. Updates arrive through "
        "a channel your organisation already operates; a package that arrives "
        "with the message asking you to run it has chosen its own route. "
        "Confirm through that known channel, and if something already looks "
        "wrong, contain the machine before doing anything that might make "
        "matters worse."),
)

#: Every authored probe, addressed by probe key.
TRANSFER_PROBES = MappingProxyType({
    QUISHING_PROBE.probe_key: QUISHING_PROBE,
    UPDATE_ATTACHMENT_PROBE.probe_key: UPDATE_ATTACHMENT_PROBE,
})

#: ``source scenario key -> probe key``. Exactly two scenarios have a probe in
#: R6; MFA and BEC deliberately have none.
PROBE_FOR_SCENARIO = MappingProxyType({
    PHISHING: QUISHING_PROBE.probe_key,
    RANSOMWARE: UPDATE_ATTACHMENT_PROBE.probe_key,
})


def probe_for_key(probe_key) -> TransferProbe:
    """The authored probe with this key, or a hard failure."""
    try:
        return TRANSFER_PROBES[probe_key]
    except KeyError:
        raise UnknownProbeError(
            "no transfer probe {0!r}".format(probe_key)) from None


def probe_for_scenario(scenario_key):
    """The probe unlocked by one training scenario, or ``None``.

    ``None`` is a legitimate answer, not an error: MFA and BEC complete at the
    learning feedback page in R6 and no probe is invented for them.
    """
    key = PROBE_FOR_SCENARIO.get(scenario_key)
    return TRANSFER_PROBES[key] if key else None


def classify_probe_choice(probe_key, choice_id) -> ProbeChoice:
    """The authored classification of one probe response.

    Scenario-scoped in the same way training classifications are: the lookup is
    always ``(probe_key, choice_id)`` and never a global choice-id table.
    """
    return probe_for_key(probe_key).choice(choice_id)
