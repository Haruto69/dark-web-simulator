"""The business email compromise scenario and its consequence adapter (R5).

Covers the adapter contract, the four authored outcomes, exact rewind, and the
safety properties the module claims: no payment execution, no network, no
subprocess, no bank data, and no amount or destination reachable from input.
"""

import ast
import inspect

import pytest

from scenario_adapters import bec
from scenario_adapters.bec import (ACTION_ESCALATED, ACTION_PAYMENT_AUTHORIZED,
                                   ACTION_SUPPLIER_VERIFIED,
                                   ACTION_THREAD_REPLIED, BEC_ACTIONS,
                                   BEC_BASELINE_STATE, BEC_CHOICE_IDS,
                                   BEC_DECISION_ID, BEC_SCENARIO,
                                   BEC_SCENARIO_KEY, BEC_SCENARIO_VERSION,
                                   SYNTHETIC_INVOICE_AMOUNT,
                                   SYNTHETIC_INVOICE_ID, BecConsequenceAdapter)
from training.errors import AdapterProtocolError, UnknownActionError
from training.snapshots import fingerprint

EXPECTED_CHOICES = ("authorize_payment", "reply_to_request",
                    "verify_via_known_contact", "escalate_to_finance_security")


@pytest.fixture
def adapter():
    a = BecConsequenceAdapter()
    a.prepare()
    return a


def apply_once(action_key):
    a = BecConsequenceAdapter()
    a.prepare()
    a.apply(action_key)
    return a.capture_state()


# -- N. the scenario definition ---------------------------------------------
def test_scenario_definition_is_valid_and_identified():
    assert BEC_SCENARIO.scenario_key == BEC_SCENARIO_KEY
    assert BEC_SCENARIO_KEY == "business_email_compromise"
    assert BEC_SCENARIO.version == BEC_SCENARIO_VERSION == 1
    assert BEC_SCENARIO.identity == "business_email_compromise@1"
    assert BEC_SCENARIO.decision(
        BEC_DECISION_ID).decision_id == "respond_to_payment_change_request"
    assert set(BEC_SCENARIO.competency_tags) == {
        "business_email_compromise", "payment_verification",
        "secondary_channel_verification", "incident_reporting"}


def test_choices_are_the_four_stable_ids_with_their_action_keys():
    decision = BEC_SCENARIO.decision(BEC_DECISION_ID)
    assert decision.choice_ids == EXPECTED_CHOICES == BEC_CHOICE_IDS
    assert {c.choice_id: c.action_key for c in decision.choices} == {
        "authorize_payment": ACTION_PAYMENT_AUTHORIZED,
        "reply_to_request": ACTION_THREAD_REPLIED,
        "verify_via_known_contact": ACTION_SUPPLIER_VERIFIED,
        "escalate_to_finance_security": ACTION_ESCALATED,
    }
    assert {c.choice_id: c.label for c in decision.choices} == {
        "authorize_payment": "Approve the payment using the new details",
        "reply_to_request": "Reply to the email for confirmation",
        "verify_via_known_contact":
            "Call the supplier using the saved contact details",
        "escalate_to_finance_security":
            "Escalate the request to Finance and Security",
    }


# -- O. exactly four supported actions --------------------------------------
def test_adapter_supports_exactly_the_four_scenario_actions():
    assert BecConsequenceAdapter.supported_actions == BEC_ACTIONS
    assert len(BEC_ACTIONS) == 4
    assert set(BEC_SCENARIO.action_keys) == set(BEC_ACTIONS)


# -- P. the fixed baseline ---------------------------------------------------
def test_prepare_returns_the_fixed_request_baseline(adapter):
    state = adapter.capture_state()
    assert state == BEC_BASELINE_STATE
    assert state["message"]["request_received"] is True
    assert state["payment"] == {"authorized": False, "synthetic_loss": 0}
    assert state["verification"]["change_confirmed"] is None
    assert adapter.applied_action is None


def test_the_same_baseline_produces_the_same_digest():
    first, second = BecConsequenceAdapter(), BecConsequenceAdapter()
    first.prepare()
    second.prepare()
    assert fingerprint(first.capture_state()) == fingerprint(
        second.capture_state())


def test_capture_state_is_a_pure_observation(adapter):
    before = fingerprint(adapter.capture_state())
    adapter.capture_state()["payment"]["authorized"] = True
    assert fingerprint(adapter.capture_state()) == before


# -- Q..U. the four authored outcomes ---------------------------------------
def test_authorizing_records_the_fixed_synthetic_loss():
    state = apply_once(ACTION_PAYMENT_AUTHORIZED)
    assert state["payment"] == {"authorized": True,
                                "synthetic_loss": SYNTHETIC_INVOICE_AMOUNT}
    assert state["verification"]["known_contact_used"] is False
    assert state["verification"]["change_confirmed"] is None


def test_the_loss_figure_is_the_authored_fixture_not_an_input():
    """R. There is no path by which an amount or destination can be supplied.

    ``apply`` takes one symbolic action key and nothing else, and the loss
    comes from a module constant.
    """
    signature = inspect.signature(BecConsequenceAdapter.apply)
    assert list(signature.parameters) == ["self", "action_key"]
    assert isinstance(SYNTHETIC_INVOICE_AMOUNT, int)
    assert apply_once(ACTION_PAYMENT_AUTHORIZED)["payment"][
        "synthetic_loss"] == SYNTHETIC_INVOICE_AMOUNT
    # Constructing with a tampered baseline still cannot introduce a new
    # destination: the state schema has no destination at all.
    assert "account" not in BEC_BASELINE_STATE
    assert "destination" not in str(BEC_BASELINE_STATE)


def test_replying_performs_no_secondary_channel_verification():
    state = apply_once(ACTION_THREAD_REPLIED)
    assert state["message"]["replied_to_unverified_thread"] is True
    assert state["verification"]["known_contact_used"] is False
    assert state["verification"]["change_confirmed"] is None
    assert state["payment"]["authorized"] is False
    assert state["payment"]["synthetic_loss"] == 0


def test_verifying_via_the_known_contact_disproves_the_change():
    state = apply_once(ACTION_SUPPLIER_VERIFIED)
    assert state["verification"]["known_contact_used"] is True
    assert state["verification"]["change_confirmed"] is False
    assert state["payment"]["authorized"] is False
    assert state["payment"]["synthetic_loss"] == 0


def test_escalation_holds_the_payment_and_records_both_escalations():
    state = apply_once(ACTION_ESCALATED)
    assert state["incident"] == {"finance_escalated": True,
                                 "security_reported": True}
    assert state["payment"]["authorized"] is False
    assert state["payment"]["synthetic_loss"] == 0


@pytest.mark.parametrize("action", sorted(BEC_ACTIONS))
def test_every_action_is_deterministic(action):
    assert fingerprint(apply_once(action)) == fingerprint(apply_once(action))


def test_the_four_actions_produce_four_distinct_states():
    assert len({fingerprint(apply_once(a)) for a in BEC_ACTIONS}) == 4


def test_only_authorizing_records_a_loss():
    for action in BEC_ACTIONS:
        loss = apply_once(action)["payment"]["synthetic_loss"]
        assert loss == (SYNTHETIC_INVOICE_AMOUNT
                        if action == ACTION_PAYMENT_AUTHORIZED else 0)


# -- V/W/X. the adapter contract --------------------------------------------
def test_a_second_apply_before_rewind_is_refused(adapter):
    adapter.apply(ACTION_PAYMENT_AUTHORIZED)
    with pytest.raises(AdapterProtocolError):
        adapter.apply(ACTION_ESCALATED)


def test_rewind_reproduces_the_exact_baseline(adapter):
    baseline = fingerprint(adapter.capture_state())
    adapter.apply(ACTION_PAYMENT_AUTHORIZED)
    assert fingerprint(adapter.capture_state()) != baseline
    adapter.rewind()
    assert adapter.capture_state() == BEC_BASELINE_STATE
    assert fingerprint(adapter.capture_state()) == baseline
    adapter.apply(ACTION_SUPPLIER_VERIFIED)


@pytest.mark.parametrize("action", [
    "", "pay_someone", "payment_authorized", "mfa_request_approved", None, 3])
def test_an_unsupported_action_is_refused(adapter, action):
    with pytest.raises(UnknownActionError):
        adapter.apply(action)
    assert adapter.capture_state() == BEC_BASELINE_STATE


# -- Y/Z. the safety claims --------------------------------------------------
def _imported_modules(module):
    """Top-level module names this module actually imports (not mentions)."""
    tree = ast.parse(inspect.getsource(module))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


FORBIDDEN_IMPORTS = ("socket", "requests", "urllib", "subprocess", "http",
                     "docker", "random")


def test_no_network_payment_or_subprocess_dependency():
    imported = _imported_modules(bec)
    assert not imported & set(FORBIDDEN_IMPORTS), imported
    # And nothing here reaches the sandbox subsystem: the module
    # runs with no Docker daemon and no container.
    assert not any(name.startswith("sandbox") for name in imported)


FINANCIAL_WORDS = ("iban", "sort_code", "sortcode", "routing", "account_number",
                   "bank", "card", "swift", "password", "secret", "token",
                   "credential", "recipient")


def _pointers(state, prefix=""):
    for key, value in state.items():
        path = prefix + key
        if isinstance(value, dict):
            for item in _pointers(value, path + "."):
                yield item
        else:
            yield path, value


@pytest.mark.parametrize("action", sorted(BEC_ACTIONS) + [None])
def test_no_sensitive_financial_data_in_captured_state(action):
    state = apply_once(action) if action else BEC_BASELINE_STATE
    for pointer, value in _pointers(state):
        lowered = pointer.lower()
        for word in FINANCIAL_WORDS:
            assert word not in lowered, pointer
        # Booleans, ``None`` or the one authored integer amount. No strings at
        # all, so no address, reference or free text can be carried.
        assert isinstance(value, bool) or value is None or isinstance(
            value, int)
    assert SYNTHETIC_INVOICE_ID not in str(state)
