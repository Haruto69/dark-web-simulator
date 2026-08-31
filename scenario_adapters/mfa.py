"""The ``mfa_fatigue_response`` scenario (RewindSec milestone R5).

An unexpected multi-factor push arrives, with an urgent message insisting it be
approved. The learner decides how to respond, sees what that response actually
produced, then rewinds and takes a different response from a verified identical
baseline.

Where the consequence lives
---------------------------
Unlike the R4 ransomware module, the security consequence here is *account and
session state*, not filesystem impact, so the consequence environment is a
small deterministic in-memory state machine -- exactly like the R3 phishing
adapter. This module never needs Docker, and must not be routed through
``SandboxManager``: there is no container to contain, because there is nothing
to contain.

SAFETY BOUNDARY
---------------
Nothing here contacts an identity provider, issues a real MFA request, opens a
socket, spawns a process or touches the filesystem. Every transition is a pure
function of an opaque action key. The captured state contains no username, no
password, no real IP address, no device identifier, no push token and no
external IdP response -- only the security-relevant facts a comparison needs.

AUTHORED TRAINING MODEL
-----------------------
The outcomes below are authored teaching outcomes chosen so that four responses
can be compared under identical conditions. They are not a claim that every
real MFA incident behaves this way.
"""

import copy

from training import (Choice, ConsequenceSpec, DecisionPoint,
                      ScenarioDefinition)
from training.adapters.base import ConsequenceAdapter
from training.errors import AdapterProtocolError

MFA_SCENARIO_KEY = "mfa_fatigue_response"
MFA_SCENARIO_VERSION = 1
MFA_DECISION_ID = "respond_to_unexpected_mfa_prompt"
MFA_PROMPT_KEY = "unexpected_push_approval_request"

# -- action vocabulary -------------------------------------------------------
# Closed and symbolic. The adapter is the only component that resolves these.
ACTION_APPROVED = "mfa_request_approved"
ACTION_DENIED_AND_REPORTED = "mfa_request_denied_and_reported"
ACTION_DETAILS_REVIEWED = "mfa_signin_details_reviewed"
ACTION_VERIFIED_OUT_OF_BAND = "mfa_request_verified_out_of_band"

MFA_ACTIONS = frozenset({
    ACTION_APPROVED,
    ACTION_DENIED_AND_REPORTED,
    ACTION_DETAILS_REVIEWED,
    ACTION_VERIFIED_OUT_OF_BAND,
})

#: Deterministic outcome token for the out-of-band verification branch. A fixed
#: symbol, never generated text.
VERIFICATION_OUTCOME = "request_not_recognised"

#: The canonical starting state both branches are executed from.
#:
#: Small, JSON-safe, free of secrets. Deliberately absent: any account name,
#: any password, any real address, any device id, any push token.
MFA_BASELINE_STATE = {
    "mfa": {
        "request_pending": True,
        "approved": False,
        "denied": False,
    },
    "evidence": {
        "details_reviewed": False,
        "unexpected_device_visible": False,
        "verified_out_of_band": False,
        "verification_outcome": None,
    },
    "account": {"synthetic_session_created": False},
    "resource": {"accessed": False},
    "incident": {"reported": False},
}


def mfa_choices():
    """The decision's choices, in the order the learner sees them."""
    return (
        Choice("approve_request",
               "Approve the sign-in request",
               ConsequenceSpec(ACTION_APPROVED),
               description="Tap approve so the prompts stop and whoever is "
                           "signing in can get on with it."),
        Choice("deny_and_report",
               "Deny the request and report it",
               ConsequenceSpec(ACTION_DENIED_AND_REPORTED),
               description="Reject the request, then tell the security team "
                           "that it arrived unexpectedly."),
        Choice("review_signin_details",
               "Review the sign-in details",
               ConsequenceSpec(ACTION_DETAILS_REVIEWED),
               description="Open the request and read the device and location "
                           "it claims to come from before doing anything."),
        Choice("verify_through_known_channel",
               "Verify the request through a known support channel",
               ConsequenceSpec(ACTION_VERIFIED_OUT_OF_BAND),
               description="Contact the service desk using a number you "
                           "already had, not one from the message."),
    )


MFA_SCENARIO = ScenarioDefinition(
    scenario_key=MFA_SCENARIO_KEY,
    version=MFA_SCENARIO_VERSION,
    title="MFA Fatigue",
    competency_tags=("mfa_security", "authentication_verification",
                     "incident_reporting"),
    decision_points=(DecisionPoint(MFA_DECISION_ID, MFA_PROMPT_KEY,
                                   mfa_choices()),))

#: Stable choice ids, for server-side validation of a submitted choice.
MFA_CHOICE_IDS = MFA_SCENARIO.decision(MFA_DECISION_ID).choice_ids


def mfa_choice_labels():
    """``choice_id -> display label``, derived from the definition itself."""
    decision = MFA_SCENARIO.decision(MFA_DECISION_ID)
    return {choice.choice_id: choice.label for choice in decision.choices}


# -- the deterministic consequences ------------------------------------------
def _approve(state):
    """The unsafe path: the push is approved and the session is used.

    "Used" means a state transition inside this process. No authentication
    request leaves the machine.
    """
    state["mfa"]["approved"] = True
    state["mfa"]["request_pending"] = False
    state["account"]["synthetic_session_created"] = True
    state["resource"]["accessed"] = True


def _deny_and_report(state):
    state["mfa"]["denied"] = True
    state["mfa"]["request_pending"] = False
    state["incident"]["reported"] = True


def _review_details(state):
    # Reviewing is an observation: the request is still pending afterwards.
    state["evidence"]["details_reviewed"] = True
    state["evidence"]["unexpected_device_visible"] = True


def _verify_out_of_band(state):
    state["evidence"]["verified_out_of_band"] = True
    state["evidence"]["verification_outcome"] = VERIFICATION_OUTCOME
    state["incident"]["reported"] = True


_TRANSITIONS = {
    ACTION_APPROVED: _approve,
    ACTION_DENIED_AND_REPORTED: _deny_and_report,
    ACTION_DETAILS_REVIEWED: _review_details,
    ACTION_VERIFIED_OUT_OF_BAND: _verify_out_of_band,
}


class MfaConsequenceAdapter(ConsequenceAdapter):
    """Deterministic consequence environment for the MFA fatigue scenario.

    Satisfies the R1 adapter contract. ``rewind`` restores a deep copy of the
    canonical baseline, so the runtime's independent fingerprint check is a real
    test; the adapter never self-reports a successful rewind.

    One action per branch: a second ``apply`` before a ``rewind`` is refused,
    because two stacked responses would make the branch uncomparable.

    No randomness, no clock, no network, no subprocess, no filesystem, no LLM.
    """

    supported_actions = MFA_ACTIONS
    environment_kind = "synthetic_authentication_state"

    def __init__(self, baseline=None):
        # A deep copy at construction, so a caller cannot alias -- and later
        # mutate -- the module-level canonical baseline.
        self._baseline = copy.deepcopy(
            baseline if baseline is not None else MFA_BASELINE_STATE)
        self._state = copy.deepcopy(self._baseline)
        self._applied = None

    @property
    def applied_action(self):
        """The one action applied on this branch, or ``None``."""
        return self._applied

    def prepare(self):
        self._state = copy.deepcopy(self._baseline)
        self._applied = None

    def capture_state(self):
        # A copy: capturing must be a pure observation, so a caller holding the
        # result cannot mutate the environment through it.
        return copy.deepcopy(self._state)

    def apply(self, action_key):
        self.require_supported(action_key)
        if self._applied is not None:
            raise AdapterProtocolError(
                "a response has already been applied on this branch; rewind "
                "before applying another")
        _TRANSITIONS[action_key](self._state)
        self._applied = action_key

    def rewind(self):
        self._state = copy.deepcopy(self._baseline)
        self._applied = None
