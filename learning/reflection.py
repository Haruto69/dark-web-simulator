"""Authored **structured self-explanation** definitions.

What this is
------------
After a learner has seen the executed technical comparison, they are asked to
select the security principle that best accounts for what the comparison shows.
That is a self-explanation intervention, and it is deliberately a **structured**
one: the learner chooses from a fixed set of authored explanations rather than
writing prose.

Prompts are scenario-level, and deliberately so
-----------------------------------------------
A prompt must be valid for *every* allowed pair of distinct choices in its
scenario, so it may not presuppose that a particular high-level outcome
differed between the two branches. Several legitimate comparisons -- phishing
``inspect_sender`` against ``report_message``, MFA ``deny_and_report`` against
``verify_through_known_channel``, BEC ``verify_via_known_contact`` against
``escalate_to_finance_security`` -- are two protective responses whose
technical states differ while the major security outcome does not. Asking "why
did account access differ?" would have been false there.

So each prompt asks which **security principle** the comparison demonstrates,
and each preferred explanation states that principle rather than narrating one
branch against the other. This also keeps reflection correctness independent of
which choice happened to be factual: the reflection tests understanding of the
scenario's principle, not recall of which branch the learner picked first.

The technical state diff on the result page is unchanged, and still shows the
actual differences truthfully.

Why structured rather than free-form
------------------------------------
Four reasons, all of them constraints of this project rather than preferences:

*  **Privacy.** Free text is an unbounded channel for personal information. A
   selected identifier is not.
*  **Determinism.** The whole system is reproducible and LLM-free. Grading
   prose would require either a model at runtime or a human rater, and both
   would break that property.
*  **Reproducibility.** ``explanation_id`` is stable across runs and across
   sessions, so two learners who reason the same way produce the same datum.
*  **No free-text grading.** R6 explicitly ships no rater, automated or
   otherwise.

The documentation, the UI and the paper must all call this *structured
self-explanation*. Describing it as unrestricted free-form explanation would
misstate the intervention.

Authoring rules enforced by construction
----------------------------------------
Exactly one preferred explanation per prompt; explanation ids unique within a
scenario; three or four options; and no callables, format strings or generated
content anywhere in the table. A distractor must be *plausible but not
deceptive*: each names a real security-adjacent idea that is simply not the
principle this scenario turns on. Like the preferred explanation, a distractor
is stated as a general claim, so no option presupposes a particular pair of
branches.
"""

from dataclasses import dataclass
from types import MappingProxyType
from typing import Tuple

from . import concepts as C
from .errors import UnknownExplanationError, UnknownScenarioError
from .quality import BEC, MFA, PHISHING, RANSOMWARE, known_scenario


@dataclass(frozen=True)
class ExplanationOption:
    """One selectable account of the principle a comparison demonstrates.

    ``text`` is authored prose, fixed at import time. ``concept_tags`` are the
    concepts *choosing this option* is evidence about -- which is why a
    distractor still carries tags: selecting it is informative.
    """

    explanation_id: str
    text: str
    concept_tags: Tuple[str, ...] = ()
    preferred: bool = False

    def __post_init__(self):
        if not isinstance(self.explanation_id, str) or not self.explanation_id:
            raise ValueError("explanation id must be a non-empty string")
        if not isinstance(self.text, str) or not self.text.strip():
            raise ValueError("explanation text must be non-empty prose")
        object.__setattr__(self, "concept_tags", tuple(self.concept_tags))


@dataclass(frozen=True)
class ReflectionDefinition:
    """One scenario's structured self-explanation prompt and its options."""

    scenario_key: str
    prompt_key: str
    prompt: str
    options: Tuple[ExplanationOption, ...]

    def __post_init__(self):
        object.__setattr__(self, "options", tuple(self.options))
        if not 3 <= len(self.options) <= 4:
            raise ValueError(
                "reflection {0!r} needs three or four explanations, got {1}"
                .format(self.prompt_key, len(self.options)))
        ids = [option.explanation_id for option in self.options]
        if len(set(ids)) != len(ids):
            raise ValueError(
                "reflection {0!r} has duplicate explanation ids".format(
                    self.prompt_key))
        preferred = [o for o in self.options if o.preferred]
        if len(preferred) != 1:
            raise ValueError(
                "reflection {0!r} must have exactly one preferred "
                "explanation, got {1}".format(self.prompt_key, len(preferred)))

    @property
    def explanation_ids(self) -> Tuple[str, ...]:
        return tuple(o.explanation_id for o in self.options)

    @property
    def preferred(self) -> ExplanationOption:
        """The authored best account. Exactly one exists, by construction."""
        return next(o for o in self.options if o.preferred)

    def option(self, explanation_id) -> ExplanationOption:
        for candidate in self.options:
            if candidate.explanation_id == explanation_id:
                return candidate
        raise UnknownExplanationError(
            "reflection {0!r} does not offer explanation {1!r}".format(
                self.prompt_key, explanation_id))

    def is_preferred(self, explanation_id) -> bool:
        """True when this id is the authored preferred explanation.

        Validates first: an unknown id raises rather than quietly answering
        ``False``, so a malformed submission never becomes a recorded
        "not preferred" datum.
        """
        return self.option(explanation_id).preferred


# -- Phishing & Credential Compromise ---------------------------------------
PHISHING_REFLECTION = ReflectionDefinition(
    scenario_key=PHISHING,
    prompt_key="phishing_verification_principle",
    prompt=("Which security principle best explains the significance of the "
            "two responses you compared?"),
    options=(
        ExplanationOption(
            "chain_broken_before_disclosure",
            "Verifying or rejecting a suspicious request before disclosing "
            "credentials breaks the path from the request to credential "
            "exposure and unauthorised synthetic account access.",
            concept_tags=(C.INDEPENDENT_VERIFICATION, C.CREDENTIAL_EXPOSURE),
            preferred=True),
        ExplanationOption(
            "password_strength",
            "A sufficiently strong password is what protects the account, so "
            "the strength of the credentials is the decisive factor.",
            concept_tags=(C.CREDENTIAL_EXPOSURE,)),
        ExplanationOption(
            "page_reloaded",
            "Reloading the page in the browser clears a sign-in attempt, so a "
            "credential disclosure can be undone afterwards.",
            concept_tags=()),
        ExplanationOption(
            "message_volume",
            "The number of messages received in the inbox is what determines "
            "how much risk a request carries.",
            concept_tags=()),
    ))

# -- Ransomware Incident Response -------------------------------------------
RANSOMWARE_REFLECTION = ReflectionDefinition(
    scenario_key=RANSOMWARE,
    prompt_key="ransomware_containment_principle",
    prompt=("Which incident-response principle best explains the consequences "
            "shown in this comparison?"),
    options=(
        ExplanationOption(
            "isolation_stopped_progression",
            "Early endpoint isolation limits further authored file-impact "
            "progression; reporting or recovery actions without containment "
            "do not provide the same containment effect.",
            concept_tags=(C.ENDPOINT_ISOLATION, C.INCIDENT_REPORTING),
            preferred=True),
        ExplanationOption(
            "restart_cleans_machine",
            "Restarting a workstation clears affected files, so recovery by "
            "restart is itself the containment step.",
            concept_tags=(C.RECOVERY_SEQUENCE,)),
        ExplanationOption(
            "reporting_alone_stops_impact",
            "Reporting an incident is what stops file impact, so containment "
            "adds nothing once a report has been made.",
            concept_tags=(C.INCIDENT_REPORTING,)),
        ExplanationOption(
            "file_size_ordering",
            "File size determines which documents are affected, so the "
            "consequences follow from the files rather than the response.",
            concept_tags=()),
    ))

# -- MFA Fatigue -------------------------------------------------------------
MFA_REFLECTION = ReflectionDefinition(
    scenario_key=MFA,
    prompt_key="mfa_prompt_response_principle",
    prompt=("Which authentication principle best explains the security "
            "significance of the responses you compared?"),
    options=(
        ExplanationOption(
            "approval_authorized_signin",
            "An unexpected MFA request should be denied or independently "
            "verified rather than approved, because approval authorises the "
            "synthetic sign-in.",
            concept_tags=(C.MFA_PROMPT_VERIFICATION,
                          C.UNEXPECTED_AUTHENTICATION),
            preferred=True),
        ExplanationOption(
            "prompt_expires_anyway",
            "An unanswered prompt expires by itself, so how a prompt is "
            "answered does not affect whether a sign-in succeeds.",
            concept_tags=(C.UNEXPECTED_AUTHENTICATION,)),
        ExplanationOption(
            "second_factor_always_blocks",
            "A second factor blocks an attacker whatever the response is, so "
            "responding to the prompt is not the security-relevant step.",
            concept_tags=(C.MFA_PROMPT_VERIFICATION,)),
        ExplanationOption(
            "prompt_count",
            "The number of prompts that arrive is what determines the risk.",
            concept_tags=()),
    ))

# -- Business Email Compromise ----------------------------------------------
BEC_REFLECTION = ReflectionDefinition(
    scenario_key=BEC,
    prompt_key="bec_channel_verification_principle",
    prompt=("Which verification principle best explains the security "
            "significance of the responses you compared?"),
    options=(
        ExplanationOption(
            "compromised_thread_cannot_self_verify",
            "A payment-change request should be verified through a known "
            "independent channel, because replying within a potentially "
            "compromised email thread does not independently establish "
            "authenticity.",
            concept_tags=(C.SECONDARY_CHANNEL_VERIFICATION,
                          C.PAYMENT_CHANGE_VERIFICATION),
            preferred=True),
        ExplanationOption(
            "reply_is_slower",
            "Replying within the thread is simply slower, so the choice of "
            "channel is a question of timing rather than of verification.",
            concept_tags=()),
        ExplanationOption(
            "phone_is_inherently_secure",
            "A phone call is an inherently secure medium, so any information "
            "confirmed by phone can be trusted.",
            concept_tags=(C.SECONDARY_CHANNEL_VERIFICATION,)),
        ExplanationOption(
            "invoice_amount_threshold",
            "The size of the invoice is what decides whether a payment change "
            "needs checking at all.",
            concept_tags=(C.PAYMENT_CHANGE_VERIFICATION,)),
    ))

#: Every authored reflection, addressed by scenario key.
REFLECTIONS = MappingProxyType({
    PHISHING: PHISHING_REFLECTION,
    RANSOMWARE: RANSOMWARE_REFLECTION,
    MFA: MFA_REFLECTION,
    BEC: BEC_REFLECTION,
})


def reflection_for(scenario_key) -> ReflectionDefinition:
    """The structured self-explanation prompt for one scenario."""
    if not known_scenario(scenario_key) or scenario_key not in REFLECTIONS:
        raise UnknownScenarioError(
            "no reflection definition for scenario {0!r}".format(scenario_key))
    return REFLECTIONS[scenario_key]


def explanation_for(scenario_key, explanation_id) -> ExplanationOption:
    """One scenario's explanation option. Never searches another scenario."""
    return reflection_for(scenario_key).option(explanation_id)
