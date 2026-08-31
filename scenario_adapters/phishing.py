"""The ``phishing_credential_compromise`` scenario (RewindSec milestone R3).

The first complete learner-facing RewindSec scenario:

    realistic inbox
      -> learner decision (+ confidence)
      -> controlled technical consequence
      -> rewind
      -> alternative decision
      -> verified identical baseline
      -> alternative consequence
      -> side-by-side comparison

Two things are kept strictly apart here.

**The scenario definition** names *what* may happen. Every choice carries an
opaque ``ConsequenceSpec`` action key; the definition contains no URL, no path,
no command and no callable, and ``training.definitions`` rejects those by
construction.

**The adapter** is the only trusted component that turns an action key into a
state transition. Its vocabulary is fixed and closed: an action outside
:data:`PHISHING_ACTIONS` is refused by the runtime before the environment is
touched.

The consequence environment is a small deterministic synthetic state held in
memory. It contains no credential, no learner-typed text, no email address, no
URL and no host path -- only the security-relevant facts a comparison needs.
Nothing in this module opens a socket, spawns a process, reads the filesystem
or calls a language model; every transition is a pure function of the action
key.
"""

import copy

from sandbox.scenarios.phishing import DEFAULT_RESOURCE, SYNTHETIC_RESOURCES
from training import (Choice, ConsequenceSpec, DecisionPoint,
                      ScenarioDefinition)
from training.adapters.base import ConsequenceAdapter

PHISHING_SCENARIO_KEY = "phishing_credential_compromise"
PHISHING_SCENARIO_VERSION = 1
PHISHING_DECISION_ID = "respond_to_message"
PHISHING_PROMPT_KEY = "urgent_account_verification_message"

#: The one choice whose consequence requires the learner to actually go through
#: the synthetic sign-in step before the factual branch may be executed.
CREDENTIAL_CHOICE_ID = "follow_link_and_sign_in"

# -- action vocabulary -------------------------------------------------------
# The complete, closed set of consequences this scenario can enact. Symbolic
# tokens only: the adapter resolves them, nothing else may.
ACTION_CREDENTIAL_SUBMITTED = "credential_submitted_to_lookalike"
ACTION_SENDER_INSPECTED = "sender_details_inspected"
ACTION_VERIFIED_OUT_OF_BAND = "request_verified_out_of_band"
ACTION_MESSAGE_REPORTED = "message_reported_to_security"

PHISHING_ACTIONS = frozenset({
    ACTION_CREDENTIAL_SUBMITTED,
    ACTION_SENDER_INSPECTED,
    ACTION_VERIFIED_OUT_OF_BAND,
    ACTION_MESSAGE_REPORTED,
})

#: The synthetic internal resource the exposed identity reaches. An
#: allow-listed *key* from the existing sandbox scenario -- never a URL, host,
#: port or path, and never taken from a request.
EXPOSED_RESOURCE_KEY = DEFAULT_RESOURCE

#: Deterministic outcome label for the out-of-band verification branch. A fixed
#: token, not generated text.
VERIFICATION_OUTCOME = "request_not_legitimate"

#: The canonical starting state both branches are executed from.
#:
#: Small, JSON-safe, free of secrets, and understandable in the comparison UI.
#: Deliberately absent: any password, any submitted email address, any learner
#: free text, any URL, any host path.
PHISHING_BASELINE_STATE = {
    "message": {
        "sender_inspected": False,
        "verified_independently": False,
        "reported": False,
    },
    # Named ``identity`` rather than ``credential``: ``training.snapshots``
    # rejects credential-shaped state keys outright, and that guard is worth
    # keeping sharp. Only the *fact* of exposure is recorded either way.
    "identity": {"exposed": False},
    "account": {"synthetic_access": False},
    "resource": {"accessed": False, "key": None},
    "incident": {"created": False},
    "evidence": {
        "sender_mismatch_visible": False,
        "verification_outcome": None,
    },
}


def phishing_choices():
    """The decision's choices, in the order the learner sees them."""
    return (
        Choice(CREDENTIAL_CHOICE_ID,
               "Follow the link and sign in",
               ConsequenceSpec(ACTION_CREDENTIAL_SUBMITTED),
               description="Open the verification page from the message and "
                           "enter your account details."),
        Choice("inspect_sender",
               "Inspect the sender details",
               ConsequenceSpec(ACTION_SENDER_INSPECTED),
               description="Expand the full sender address and message "
                           "headers before doing anything else."),
        Choice("verify_independently",
               "Verify through a trusted channel",
               ConsequenceSpec(ACTION_VERIFIED_OUT_OF_BAND),
               description="Contact the service using a number or address you "
                           "already had, not one from the message."),
        Choice("report_message",
               "Report the message",
               ConsequenceSpec(ACTION_MESSAGE_REPORTED),
               description="Send the message to the security team and leave "
                           "it alone."),
    )


PHISHING_SCENARIO = ScenarioDefinition(
    scenario_key=PHISHING_SCENARIO_KEY,
    version=PHISHING_SCENARIO_VERSION,
    title="Phishing & Credential Compromise",
    competency_tags=("phishing", "credential_hygiene", "reporting"),
    decision_points=(DecisionPoint(PHISHING_DECISION_ID, PHISHING_PROMPT_KEY,
                                   phishing_choices()),))

#: Stable choice ids, for server-side validation of a submitted choice.
PHISHING_CHOICE_IDS = PHISHING_SCENARIO.decision(
    PHISHING_DECISION_ID).choice_ids


def choice_labels():
    """``choice_id -> display label``, derived from the definition itself."""
    decision = PHISHING_SCENARIO.decision(PHISHING_DECISION_ID)
    return {choice.choice_id: choice.label for choice in decision.choices}


# -- the consequence adapter -------------------------------------------------
def _submit_credential(state):
    """The unsafe path: the identity is captured and immediately used.

    "Used" means a state transition inside this process. No authentication
    request leaves the machine, and the credential itself is not represented in
    the state at all -- only the fact of exposure.
    """
    state["identity"]["exposed"] = True
    state["account"]["synthetic_access"] = True
    state["resource"]["accessed"] = True
    state["resource"]["key"] = EXPOSED_RESOURCE_KEY


def _inspect_sender(state):
    state["message"]["sender_inspected"] = True
    state["evidence"]["sender_mismatch_visible"] = True


def _verify_out_of_band(state):
    state["message"]["verified_independently"] = True
    state["evidence"]["verification_outcome"] = VERIFICATION_OUTCOME


def _report_message(state):
    state["message"]["reported"] = True
    state["incident"]["created"] = True


_TRANSITIONS = {
    ACTION_CREDENTIAL_SUBMITTED: _submit_credential,
    ACTION_SENDER_INSPECTED: _inspect_sender,
    ACTION_VERIFIED_OUT_OF_BAND: _verify_out_of_band,
    ACTION_MESSAGE_REPORTED: _report_message,
}


class PhishingConsequenceAdapter(ConsequenceAdapter):
    """Deterministic consequence environment for the phishing scenario.

    Satisfies the R1 adapter contract: ``prepare`` / ``capture_state`` /
    ``apply`` / ``rewind``. ``rewind`` restores a deep copy of the canonical
    baseline, so the runtime's independent fingerprint check passes exactly --
    the adapter is never trusted to self-report that, and does not try to.

    No randomness, no clock, no network, no LLM, no filesystem: two runs of the
    same action sequence produce byte-identical canonical state.
    """

    supported_actions = PHISHING_ACTIONS
    environment_kind = "synthetic_phishing_state"

    def __init__(self, baseline=None):
        # A deep copy at construction, so a caller cannot alias -- and later
        # mutate -- the module-level canonical baseline.
        self._baseline = copy.deepcopy(
            baseline if baseline is not None else PHISHING_BASELINE_STATE)
        self._state = copy.deepcopy(self._baseline)

    def prepare(self):
        self._state = copy.deepcopy(self._baseline)

    def capture_state(self):
        # A copy: capturing must be a pure observation, so a caller holding the
        # result cannot mutate the environment through it.
        return copy.deepcopy(self._state)

    def apply(self, action_key):
        self.require_supported(action_key)
        _TRANSITIONS[action_key](self._state)

    def rewind(self):
        self._state = copy.deepcopy(self._baseline)

    def describe(self):
        info = dict(super().describe())
        info["resource_allow_list"] = sorted(SYNTHETIC_RESOURCES)
        return info
