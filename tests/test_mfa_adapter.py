"""The MFA fatigue scenario definition and its consequence adapter (R5).

Covers the adapter contract, the four authored outcomes, exact rewind, and the
safety properties the module claims: no network, no subprocess, no secrets.
"""

import ast
import inspect

import pytest

from scenario_adapters import mfa
from scenario_adapters.mfa import (ACTION_APPROVED, ACTION_DENIED_AND_REPORTED,
                                   ACTION_DETAILS_REVIEWED,
                                   ACTION_VERIFIED_OUT_OF_BAND, MFA_ACTIONS,
                                   MFA_BASELINE_STATE, MFA_CHOICE_IDS,
                                   MFA_DECISION_ID, MFA_SCENARIO,
                                   MFA_SCENARIO_KEY, MFA_SCENARIO_VERSION,
                                   VERIFICATION_OUTCOME, MfaConsequenceAdapter)
from training.errors import AdapterProtocolError, UnknownActionError
from training.snapshots import fingerprint

EXPECTED_CHOICES = ("approve_request", "deny_and_report",
                    "review_signin_details", "verify_through_known_channel")


@pytest.fixture
def adapter():
    a = MfaConsequenceAdapter()
    a.prepare()
    return a


def apply_once(action_key):
    a = MfaConsequenceAdapter()
    a.prepare()
    a.apply(action_key)
    return a.capture_state()


# -- A. the scenario definition ---------------------------------------------
def test_scenario_definition_is_valid_and_identified():
    assert MFA_SCENARIO.scenario_key == MFA_SCENARIO_KEY == "mfa_fatigue_response"
    assert MFA_SCENARIO.version == MFA_SCENARIO_VERSION == 1
    assert MFA_SCENARIO.identity == "mfa_fatigue_response@1"
    decision = MFA_SCENARIO.decision(MFA_DECISION_ID)
    assert decision.decision_id == "respond_to_unexpected_mfa_prompt"
    assert set(MFA_SCENARIO.competency_tags) == {
        "mfa_security", "authentication_verification", "incident_reporting"}


def test_choices_are_the_four_stable_ids_with_their_action_keys():
    decision = MFA_SCENARIO.decision(MFA_DECISION_ID)
    assert decision.choice_ids == EXPECTED_CHOICES == MFA_CHOICE_IDS
    assert {c.choice_id: c.action_key for c in decision.choices} == {
        "approve_request": ACTION_APPROVED,
        "deny_and_report": ACTION_DENIED_AND_REPORTED,
        "review_signin_details": ACTION_DETAILS_REVIEWED,
        "verify_through_known_channel": ACTION_VERIFIED_OUT_OF_BAND,
    }
    assert {c.choice_id: c.label for c in decision.choices} == {
        "approve_request": "Approve the sign-in request",
        "deny_and_report": "Deny the request and report it",
        "review_signin_details": "Review the sign-in details",
        "verify_through_known_channel":
            "Verify the request through a known support channel",
    }


# -- B. exactly four supported actions --------------------------------------
def test_adapter_supports_exactly_the_four_scenario_actions():
    assert MfaConsequenceAdapter.supported_actions == MFA_ACTIONS
    assert len(MFA_ACTIONS) == 4
    assert set(MFA_SCENARIO.action_keys) == set(MFA_ACTIONS)


# -- C/D. the fixed baseline and its digest ---------------------------------
def test_prepare_returns_the_fixed_baseline(adapter):
    assert adapter.capture_state() == MFA_BASELINE_STATE
    assert adapter.applied_action is None


def test_the_same_baseline_produces_the_same_digest():
    first, second = MfaConsequenceAdapter(), MfaConsequenceAdapter()
    first.prepare()
    second.prepare()
    assert fingerprint(first.capture_state()) == fingerprint(
        second.capture_state())


def test_capture_state_is_a_pure_observation(adapter):
    before = fingerprint(adapter.capture_state())
    captured = adapter.capture_state()
    captured["mfa"]["approved"] = True
    assert fingerprint(adapter.capture_state()) == before


def test_a_caller_cannot_mutate_the_module_baseline_through_the_adapter():
    a = MfaConsequenceAdapter()
    a.prepare()
    a.apply(ACTION_APPROVED)
    assert MFA_BASELINE_STATE["mfa"]["approved"] is False


# -- E..H. the four authored outcomes ---------------------------------------
def test_approving_creates_a_synthetic_session_and_resource_access():
    state = apply_once(ACTION_APPROVED)
    assert state["mfa"] == {"request_pending": False, "approved": True,
                            "denied": False}
    assert state["account"]["synthetic_session_created"] is True
    assert state["resource"]["accessed"] is True
    assert state["incident"]["reported"] is False


def test_denying_and_reporting_blocks_access_and_raises_the_incident():
    state = apply_once(ACTION_DENIED_AND_REPORTED)
    assert state["mfa"] == {"request_pending": False, "approved": False,
                            "denied": True}
    assert state["account"]["synthetic_session_created"] is False
    assert state["resource"]["accessed"] is False
    assert state["incident"]["reported"] is True


def test_reviewing_details_exposes_fixed_evidence_without_access():
    state = apply_once(ACTION_DETAILS_REVIEWED)
    assert state["evidence"]["details_reviewed"] is True
    assert state["evidence"]["unexpected_device_visible"] is True
    assert state["account"]["synthetic_session_created"] is False
    assert state["resource"]["accessed"] is False
    # Reviewing is an observation, so the request is still waiting afterwards.
    assert state["mfa"]["request_pending"] is True


def test_out_of_band_verification_blocks_access_and_records_the_check():
    state = apply_once(ACTION_VERIFIED_OUT_OF_BAND)
    assert state["evidence"]["verified_out_of_band"] is True
    assert state["evidence"]["verification_outcome"] == VERIFICATION_OUTCOME
    assert state["incident"]["reported"] is True
    assert state["account"]["synthetic_session_created"] is False
    assert state["resource"]["accessed"] is False


@pytest.mark.parametrize("action", sorted(MFA_ACTIONS))
def test_every_action_is_deterministic(action):
    assert fingerprint(apply_once(action)) == fingerprint(apply_once(action))


@pytest.mark.parametrize("action", sorted(MFA_ACTIONS))
def test_every_action_changes_the_state(action):
    assert fingerprint(apply_once(action)) != fingerprint(MFA_BASELINE_STATE)


def test_the_four_actions_produce_four_distinct_states():
    digests = {fingerprint(apply_once(a)) for a in MFA_ACTIONS}
    assert len(digests) == 4


# -- I/J/K. the adapter contract --------------------------------------------
def test_a_second_apply_before_rewind_is_refused(adapter):
    adapter.apply(ACTION_APPROVED)
    with pytest.raises(AdapterProtocolError):
        adapter.apply(ACTION_DENIED_AND_REPORTED)


def test_rewind_reproduces_the_exact_baseline_digest(adapter):
    baseline = fingerprint(adapter.capture_state())
    adapter.apply(ACTION_APPROVED)
    assert fingerprint(adapter.capture_state()) != baseline
    adapter.rewind()
    assert fingerprint(adapter.capture_state()) == baseline
    assert adapter.applied_action is None
    # And the branch is usable again after the rewind.
    adapter.apply(ACTION_DENIED_AND_REPORTED)


@pytest.mark.parametrize("action", [
    "", "unknown_action", "mfa_request_approved_twice",
    "workstation_isolated_and_reported", None, 7])
def test_an_unsupported_action_is_refused(adapter, action):
    with pytest.raises(UnknownActionError):
        adapter.apply(action)
    assert adapter.capture_state() == MFA_BASELINE_STATE


def test_check_protocol_passes(adapter):
    adapter.check_protocol()


# -- L/M. the safety claims --------------------------------------------------
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
                     "os.system", "docker", "random")


def test_the_module_has_no_network_or_subprocess_dependency():
    imported = _imported_modules(mfa)
    assert not imported & set(FORBIDDEN_IMPORTS), imported
    # And nothing here reaches the sandbox subsystem: the module
    # runs with no Docker daemon and no container.
    assert not any(name.startswith("sandbox") for name in imported)


SECRET_WORDS = ("password", "passwd", "secret", "token", "credential",
                "api_key", "ip_address", "device_id", "username")


def _pointers(state, prefix=""):
    for key, value in state.items():
        path = prefix + key
        if isinstance(value, dict):
            for item in _pointers(value, path + "."):
                yield item
        else:
            yield path, value


@pytest.mark.parametrize("action", sorted(MFA_ACTIONS) + [None])
def test_no_secret_like_or_identifying_state_keys(action):
    state = apply_once(action) if action else MFA_BASELINE_STATE
    for pointer, value in _pointers(state):
        lowered = pointer.lower()
        for word in SECRET_WORDS:
            assert word not in lowered, pointer
        # Values are booleans or one fixed symbolic token -- never free text.
        assert isinstance(value, bool) or value in (None, VERIFICATION_OUTCOME)
