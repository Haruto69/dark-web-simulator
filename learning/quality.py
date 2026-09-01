"""Authored response-quality classification.

A learner's choice is **not** globally "correct" or "incorrect". RewindSec
classifies a response at three levels, and always *within a scenario*:

``PROTECTIVE``  the response breaks the attack chain or contains the incident.
``PARTIAL``     the response does something useful but leaves the decisive risk
                unaddressed.
``RISKY``       the response advances the attack chain or the impact.

These are **authored training classifications**, written by the people who
designed the exercise. They are not measurements, not grades, and not claims
about a learner.

Two properties matter enough to be enforced by construction:

*  A classification is only ever addressable as ``(scenario_key, choice_id)``.
   There is no global ``choice_id -> quality`` table anywhere in this package,
   because ``report_without_isolating`` means something only inside the
   ransomware scenario and ``endpoint_isolation`` evidence from one scenario is
   not interchangeable with another's.
*  The table is a plain immutable mapping of strings. No callables, no
   generated prose, no runtime model.
"""

from types import MappingProxyType

from .errors import UnknownChoiceError, UnknownScenarioError

#: The three authored levels. Plain strings, so they survive persistence,
#: canonical JSON and a template round-trip unchanged.
PROTECTIVE = "PROTECTIVE"
PARTIAL = "PARTIAL"
RISKY = "RISKY"

#: Declaration order is severity order, most protective first. Used for stable
#: presentation, never for arithmetic -- these levels are not a scale and are
#: never averaged into a score.
RESPONSE_QUALITIES = (PROTECTIVE, PARTIAL, RISKY)

# -- scenario keys ----------------------------------------------------------
# Repeated here as literals rather than imported from ``scenario_adapters``:
# that package pulls in the sandbox, and this one must stay importable with
# nothing but the standard library. ``tests/test_learning_definitions.py``
# asserts these are exactly the shipped scenario keys, so the duplication
# cannot silently drift.
PHISHING = "phishing_credential_compromise"
RANSOMWARE = "ransomware_incident_response"
MFA = "mfa_fatigue_response"
BEC = "business_email_compromise"

#: Every scenario the learning layer has authored definitions for.
LEARNING_SCENARIOS = (PHISHING, RANSOMWARE, MFA, BEC)

#: ``(scenario_key, choice_id) -> response quality``.
_RESPONSE_QUALITY = {
    # -- Phishing & Credential Compromise -------------------------------
    (PHISHING, "follow_link_and_sign_in"): RISKY,
    (PHISHING, "inspect_sender"): PROTECTIVE,
    (PHISHING, "verify_independently"): PROTECTIVE,
    (PHISHING, "report_message"): PROTECTIVE,

    # -- Ransomware Incident Response -----------------------------------
    (RANSOMWARE, "isolate_and_report"): PROTECTIVE,
    (RANSOMWARE, "report_without_isolating"): PARTIAL,
    (RANSOMWARE, "restart_workstation"): RISKY,
    (RANSOMWARE, "continue_working"): RISKY,

    # -- MFA Fatigue ----------------------------------------------------
    (MFA, "approve_request"): RISKY,
    (MFA, "deny_and_report"): PROTECTIVE,
    (MFA, "review_signin_details"): PARTIAL,
    (MFA, "verify_through_known_channel"): PROTECTIVE,

    # -- Business Email Compromise --------------------------------------
    (BEC, "authorize_payment"): RISKY,
    (BEC, "reply_to_request"): PARTIAL,
    (BEC, "verify_via_known_contact"): PROTECTIVE,
    (BEC, "escalate_to_finance_security"): PROTECTIVE,
}

RESPONSE_QUALITY = MappingProxyType(dict(_RESPONSE_QUALITY))


def known_scenario(scenario_key):
    """True when this scenario has authored learning definitions."""
    return scenario_key in LEARNING_SCENARIOS


def scenario_choice_ids(scenario_key):
    """Every classified choice id for one scenario, in sorted order."""
    if not known_scenario(scenario_key):
        raise UnknownScenarioError(
            "no learning definitions for scenario {0!r}".format(scenario_key))
    return tuple(sorted(choice for scenario, choice in RESPONSE_QUALITY
                        if scenario == scenario_key))


def response_quality(scenario_key, choice_id):
    """The authored quality of ``choice_id`` **within** ``scenario_key``.

    Fails closed twice, and distinguishes the two failures: an unknown scenario
    is a wiring mistake, an unknown choice is a malformed submission. Neither
    ever falls back to another scenario's table.
    """
    if not known_scenario(scenario_key):
        raise UnknownScenarioError(
            "no learning definitions for scenario {0!r}".format(scenario_key))
    try:
        return RESPONSE_QUALITY[(scenario_key, choice_id)]
    except KeyError:
        raise UnknownChoiceError(
            "scenario {0!r} does not classify choice {1!r}".format(
                scenario_key, choice_id)) from None
