"""The ``business_email_compromise`` scenario (RewindSec milestone R5).

A supplier's invoice thread asks for the bank details on an outstanding invoice
to be changed, and for payment to be made urgently. The learner decides how to
respond, sees what that response actually produced, then rewinds and takes a
different response from a verified identical baseline.

Where the consequence lives
---------------------------
The security consequence here is *payment workflow state*, not filesystem
impact, so the consequence environment is a small deterministic in-memory state
machine. This module never needs Docker and is not routed through
``SandboxManager``.

SAFETY BOUNDARY
---------------
There is no payment API, no banking API, no network, no subprocess and no
ledger. The invoice, its amount and the supplier are authored synthetic
fixtures declared in this module. The amount and the destination can never come
from a request: nothing in the scenario reads either from HTTP input, and the
captured state carries no account number, no routing number, no recipient and
no payment credential.

The payment and loss values are synthetic scenario state. RewindSec does not
initiate or simulate a networked financial transaction.
"""

import copy

from training import (Choice, ConsequenceSpec, DecisionPoint,
                      ScenarioDefinition)
from training.adapters.base import ConsequenceAdapter
from training.errors import AdapterProtocolError

BEC_SCENARIO_KEY = "business_email_compromise"
BEC_SCENARIO_VERSION = 1
BEC_DECISION_ID = "respond_to_payment_change_request"
BEC_PROMPT_KEY = "supplier_payment_detail_change_request"

# -- action vocabulary -------------------------------------------------------
ACTION_PAYMENT_AUTHORIZED = "payment_authorized_to_changed_details"
ACTION_THREAD_REPLIED = "unverified_thread_replied_to"
ACTION_SUPPLIER_VERIFIED = "supplier_verified_via_known_channel"
ACTION_ESCALATED = "payment_request_escalated"

BEC_ACTIONS = frozenset({
    ACTION_PAYMENT_AUTHORIZED,
    ACTION_THREAD_REPLIED,
    ACTION_SUPPLIER_VERIFIED,
    ACTION_ESCALATED,
})

# -- the one fixed synthetic invoice -----------------------------------------
#: Authored fixtures. Fictional supplier, fictional reference, fixed amount.
#: None of these is ever read from a form, a query string or a session value.
SYNTHETIC_INVOICE_ID = "INV-DEMO-1042"
SYNTHETIC_INVOICE_AMOUNT = 18450
SYNTHETIC_CURRENCY = "GBP"
SUPPLIER_NAME = "Asterline Office Supplies"
ORG_NAME = "Northgate Operations"

#: Deterministic outcome token for the known-contact verification branch.
CHANGE_DISPROVED = False

#: The canonical starting state both branches are executed from.
#:
#: Deliberately absent: any bank account number, sort code, routing number,
#: payment link, recipient address, learner free text or email address.
BEC_BASELINE_STATE = {
    "message": {
        "request_received": True,
        "replied_to_unverified_thread": False,
    },
    "verification": {
        "known_contact_used": False,
        "change_confirmed": None,
    },
    "payment": {
        "authorized": False,
        "synthetic_loss": 0,
    },
    "incident": {
        "finance_escalated": False,
        "security_reported": False,
    },
}


def bec_choices():
    """The decision's choices, in the order the learner sees them."""
    return (
        Choice("authorize_payment",
               "Approve the payment using the new details",
               ConsequenceSpec(ACTION_PAYMENT_AUTHORIZED),
               description="Update the payment record to the account given in "
                           "the message and release the invoice."),
        Choice("reply_to_request",
               "Reply to the email for confirmation",
               ConsequenceSpec(ACTION_THREAD_REPLIED),
               description="Answer in the same thread and ask the sender to "
                           "confirm the change."),
        Choice("verify_via_known_contact",
               "Call the supplier using the saved contact details",
               ConsequenceSpec(ACTION_SUPPLIER_VERIFIED),
               description="Use the number already held for the supplier in "
                           "your own records, not one from the message."),
        Choice("escalate_to_finance_security",
               "Escalate the request to Finance and Security",
               ConsequenceSpec(ACTION_ESCALATED),
               description="Hold the payment and hand the request to the "
                           "people whose job it is to check it."),
    )


BEC_SCENARIO = ScenarioDefinition(
    scenario_key=BEC_SCENARIO_KEY,
    version=BEC_SCENARIO_VERSION,
    title="Business Email Compromise",
    competency_tags=("business_email_compromise", "payment_verification",
                     "secondary_channel_verification", "incident_reporting"),
    decision_points=(DecisionPoint(BEC_DECISION_ID, BEC_PROMPT_KEY,
                                   bec_choices()),))

#: Stable choice ids, for server-side validation of a submitted choice.
BEC_CHOICE_IDS = BEC_SCENARIO.decision(BEC_DECISION_ID).choice_ids


def bec_choice_labels():
    """``choice_id -> display label``, derived from the definition itself."""
    decision = BEC_SCENARIO.decision(BEC_DECISION_ID)
    return {choice.choice_id: choice.label for choice in decision.choices}


# -- the deterministic consequences ------------------------------------------
def _authorize_payment(state):
    """The unsafe path: the invoice is released to the changed details.

    The loss is the module-level fixture, never an amount taken from input.
    """
    state["payment"]["authorized"] = True
    state["payment"]["synthetic_loss"] = SYNTHETIC_INVOICE_AMOUNT


def _reply_to_request(state):
    # Replying in the same thread is not a secondary channel: in this authored
    # scenario the conversation the learner trusts is the one under attacker
    # control, so nothing is verified and the payment stays pending.
    state["message"]["replied_to_unverified_thread"] = True


def _verify_via_known_contact(state):
    state["verification"]["known_contact_used"] = True
    state["verification"]["change_confirmed"] = CHANGE_DISPROVED


def _escalate(state):
    state["incident"]["finance_escalated"] = True
    state["incident"]["security_reported"] = True


_TRANSITIONS = {
    ACTION_PAYMENT_AUTHORIZED: _authorize_payment,
    ACTION_THREAD_REPLIED: _reply_to_request,
    ACTION_SUPPLIER_VERIFIED: _verify_via_known_contact,
    ACTION_ESCALATED: _escalate,
}


class BecConsequenceAdapter(ConsequenceAdapter):
    """Deterministic consequence environment for the BEC scenario.

    Satisfies the R1 adapter contract. One action per branch; a second
    ``apply`` before a ``rewind`` is refused. ``rewind`` restores a deep copy of
    the canonical baseline so the runtime's independent fingerprint check is a
    real test.

    No network, no payment execution, no ledger, no arbitrary amount, no
    external address, no randomness, no clock.
    """

    supported_actions = BEC_ACTIONS
    environment_kind = "synthetic_payment_workflow_state"

    def __init__(self, baseline=None):
        self._baseline = copy.deepcopy(
            baseline if baseline is not None else BEC_BASELINE_STATE)
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

    def describe(self):
        info = dict(super().describe())
        info["synthetic_invoice"] = SYNTHETIC_INVOICE_ID
        info["synthetic_amount"] = SYNTHETIC_INVOICE_AMOUNT
        return info
