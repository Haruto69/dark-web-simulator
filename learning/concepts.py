"""The authored concept map: which security concept a response is evidence about.

A concept tag is a stable, machine-readable identifier for one security idea
the exercise teaches. It exists so that later analysis can ask "which concepts
does this cohort's evidence cluster around?" without anybody having to parse
prose.

Two authoring rules are enforced here rather than left to good intentions:

*  A choice is mapped only to the concepts it **genuinely provides evidence
   about**. Tagging every response with every scenario concept would make the
   evidence meaningless, so ``tests/test_learning_definitions.py`` asserts that
   no scenario maps every choice to its full tag set.
*  Concept tags are scenario-scoped in exactly the way response qualities are:
   the lookup key is always ``(scenario_key, choice_id)``.

``incident_reporting`` and ``endpoint_isolation`` deliberately appear in more
than one scenario. That is the point of a concept map -- the same idea recurs
across surfaces -- and it is why a *tag* is shared while a *classification*
never is.
"""

from types import MappingProxyType

from .errors import UnknownChoiceError, UnknownScenarioError
from .quality import BEC, MFA, PHISHING, RANSOMWARE, known_scenario

# -- phishing ---------------------------------------------------------------
SENDER_VERIFICATION = "sender_verification"
INDEPENDENT_VERIFICATION = "independent_verification"
CREDENTIAL_EXPOSURE = "credential_exposure"

# -- ransomware -------------------------------------------------------------
ENDPOINT_ISOLATION = "endpoint_isolation"
INCIDENT_REPORTING = "incident_reporting"
RECOVERY_SEQUENCE = "recovery_sequence"

# -- MFA --------------------------------------------------------------------
MFA_PROMPT_VERIFICATION = "mfa_prompt_verification"
UNEXPECTED_AUTHENTICATION = "unexpected_authentication"

# -- BEC --------------------------------------------------------------------
SECONDARY_CHANNEL_VERIFICATION = "secondary_channel_verification"
PAYMENT_CHANGE_VERIFICATION = "payment_change_verification"
INCIDENT_ESCALATION = "incident_escalation"

# -- transfer probes only ---------------------------------------------------
CHANNEL_SWITCHING = "channel_switching"
TRUSTED_SOFTWARE_SOURCE = "trusted_software_source"

#: The concepts each training scenario is authored to teach.
SCENARIO_CONCEPTS = MappingProxyType({
    PHISHING: (SENDER_VERIFICATION, INDEPENDENT_VERIFICATION,
               CREDENTIAL_EXPOSURE),
    RANSOMWARE: (ENDPOINT_ISOLATION, INCIDENT_REPORTING, RECOVERY_SEQUENCE),
    MFA: (MFA_PROMPT_VERIFICATION, UNEXPECTED_AUTHENTICATION,
          INCIDENT_REPORTING),
    BEC: (SECONDARY_CHANNEL_VERIFICATION, PAYMENT_CHANGE_VERIFICATION,
          INCIDENT_ESCALATION),
})

#: ``(scenario_key, choice_id) -> the concepts that choice is evidence about``.
_CHOICE_CONCEPTS = {
    (PHISHING, "follow_link_and_sign_in"): (CREDENTIAL_EXPOSURE,
                                            INDEPENDENT_VERIFICATION),
    (PHISHING, "inspect_sender"): (SENDER_VERIFICATION,),
    (PHISHING, "verify_independently"): (INDEPENDENT_VERIFICATION,
                                         CREDENTIAL_EXPOSURE),
    (PHISHING, "report_message"): (CREDENTIAL_EXPOSURE,),

    (RANSOMWARE, "isolate_and_report"): (ENDPOINT_ISOLATION,
                                         INCIDENT_REPORTING),
    (RANSOMWARE, "report_without_isolating"): (INCIDENT_REPORTING,
                                               ENDPOINT_ISOLATION),
    (RANSOMWARE, "restart_workstation"): (RECOVERY_SEQUENCE,
                                          ENDPOINT_ISOLATION),
    (RANSOMWARE, "continue_working"): (ENDPOINT_ISOLATION,
                                       INCIDENT_REPORTING),

    (MFA, "approve_request"): (MFA_PROMPT_VERIFICATION,
                               UNEXPECTED_AUTHENTICATION),
    (MFA, "deny_and_report"): (UNEXPECTED_AUTHENTICATION, INCIDENT_REPORTING),
    (MFA, "review_signin_details"): (MFA_PROMPT_VERIFICATION,),
    (MFA, "verify_through_known_channel"): (MFA_PROMPT_VERIFICATION,
                                            UNEXPECTED_AUTHENTICATION),

    (BEC, "authorize_payment"): (PAYMENT_CHANGE_VERIFICATION,
                                 SECONDARY_CHANNEL_VERIFICATION),
    (BEC, "reply_to_request"): (SECONDARY_CHANNEL_VERIFICATION,),
    (BEC, "verify_via_known_contact"): (SECONDARY_CHANNEL_VERIFICATION,
                                        PAYMENT_CHANGE_VERIFICATION),
    (BEC, "escalate_to_finance_security"): (INCIDENT_ESCALATION,
                                            PAYMENT_CHANGE_VERIFICATION),
}

CHOICE_CONCEPTS = MappingProxyType(dict(_CHOICE_CONCEPTS))


def scenario_concepts(scenario_key):
    """Every concept tag one scenario teaches."""
    if not known_scenario(scenario_key):
        raise UnknownScenarioError(
            "no learning definitions for scenario {0!r}".format(scenario_key))
    return SCENARIO_CONCEPTS[scenario_key]


def concepts_for_choice(scenario_key, choice_id):
    """The concepts ``choice_id`` provides evidence about, in authored order."""
    if not known_scenario(scenario_key):
        raise UnknownScenarioError(
            "no learning definitions for scenario {0!r}".format(scenario_key))
    try:
        return CHOICE_CONCEPTS[(scenario_key, choice_id)]
    except KeyError:
        raise UnknownChoiceError(
            "scenario {0!r} has no concept map for choice {1!r}".format(
                scenario_key, choice_id)) from None
