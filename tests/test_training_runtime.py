"""Unit tests for the RewindSec counterfactual training runtime (milestone R1).

Everything here runs without Flask, without Docker and without a database. The
subject is the *semantics* of decision -> consequence -> rewind -> verified
baseline -> alternative consequence -> comparison.
"""

import pytest

from training import (BaselineVerificationError, Choice, ConfidenceValueError,
                      ConsequenceSpec, CounterfactualRuntime, DecisionPoint,
                      ScenarioDefinition, ScenarioDefinitionError,
                      SnapshotError, StateSnapshot, UnknownActionError,
                      diff_states, fingerprint)
from training.adapters import DriftingRewindAdapter, InMemoryConsequenceAdapter
from training.comparison import ADDED, CHANGED, REMOVED

# --------------------------------------------------------------------------
# A small deterministic world: an endpoint that may or may not be isolated.
# --------------------------------------------------------------------------

BASELINE_STATE = {
    "account": {"compromised": False, "sessions": 1},
    "files": {"impacted": 0, "total": 5},
    "endpoint": {"isolated": False},
}


def _credential_reuse(state):
    state["account"]["compromised"] = True
    state["account"]["sessions"] = 3
    state["files"]["impacted"] = 5
    state["notified"] = False


def _isolate_endpoint(state):
    state["endpoint"]["isolated"] = True
    state["files"]["impacted"] = 1
    state["notified"] = True


def _noop(state):
    return None


ACTIONS = {
    "credentials_reused": _credential_reuse,
    "endpoint_isolated": _isolate_endpoint,
    "nothing_happens": _noop,
}


def make_adapter(cls=InMemoryConsequenceAdapter):
    return cls(BASELINE_STATE, ACTIONS)


def make_scenario():
    return ScenarioDefinition(
        scenario_key="credential_prompt",
        version=1,
        title="Unexpected credential prompt",
        competency_tags=("phishing", "incident_response"),
        decision_points=(
            DecisionPoint(
                decision_id="respond_to_prompt",
                prompt_key="unexpected_login_prompt",
                choices=(
                    Choice("reuse_password", "Enter the usual password",
                           ConsequenceSpec("credentials_reused")),
                    Choice("isolate_endpoint", "Disconnect and report",
                           ConsequenceSpec("endpoint_isolated")),
                    Choice("ignore_prompt", "Close the tab and move on",
                           ConsequenceSpec("nothing_happens")),
                ),
            ),
        ),
    )


@pytest.fixture
def runtime():
    return CounterfactualRuntime(make_scenario(), make_adapter())


# --------------------------------------------------------------------------
# A. / B. / C.  Snapshot digests
# --------------------------------------------------------------------------

def test_identical_logical_states_produce_identical_digests():
    first = StateSnapshot.capture({"a": 1, "b": {"c": [1, 2]}})
    second = StateSnapshot.capture({"a": 1, "b": {"c": [1, 2]}})
    assert first.digest == second.digest
    assert first.matches(second)


def test_dictionary_insertion_order_does_not_affect_the_digest():
    ordered = {"alpha": 1, "beta": {"x": True, "y": None}}
    shuffled = {"beta": {"y": None, "x": True}, "alpha": 1}
    assert fingerprint(ordered) == fingerprint(shuffled)
    # ...and the labels are descriptive only, never part of the fingerprint.
    assert (StateSnapshot.capture(ordered, "baseline").digest
            == StateSnapshot.capture(shuffled, "rewound").digest)


def test_different_states_produce_different_digests():
    assert (fingerprint({"files": {"impacted": 5}})
            != fingerprint({"files": {"impacted": 1}}))


def test_digest_is_stable_sha256_of_canonical_json_not_python_hash():
    import hashlib
    snapshot = StateSnapshot.capture({"b": 2, "a": 1})
    assert snapshot.canonical_json == '{"a":1,"b":2}'
    assert snapshot.digest == hashlib.sha256(b'{"a":1,"b":2}').hexdigest()


def test_snapshot_state_is_a_defensive_copy():
    snapshot = StateSnapshot.capture({"files": {"impacted": 0}})
    borrowed = snapshot.state
    borrowed["files"]["impacted"] = 99
    assert snapshot.state["files"]["impacted"] == 0


def test_snapshots_reject_secret_bearing_keys():
    with pytest.raises(SnapshotError):
        StateSnapshot.capture({"account": {"password": "hunter2"}})
    with pytest.raises(SnapshotError):
        StateSnapshot.capture({"api_key": "abc"})


def test_snapshots_reject_non_deterministic_and_non_json_values():
    with pytest.raises(SnapshotError):
        StateSnapshot.capture({"drift": float("nan")})
    with pytest.raises(SnapshotError):
        StateSnapshot.capture({"callable": len})


# --------------------------------------------------------------------------
# D. / E.  Consequence and rewind
# --------------------------------------------------------------------------

def test_factual_choice_changes_state_as_expected(runtime):
    baseline = runtime.establish_baseline()
    assert baseline.state["account"]["compromised"] is False

    scenario = runtime.scenario
    choice = scenario.decision("respond_to_prompt").choice("reuse_password")
    factual = runtime.apply_choice(choice, "factual")

    assert factual.state["account"]["compromised"] is True
    assert factual.state["files"]["impacted"] == 5
    assert factual.digest != baseline.digest


def test_rewind_restores_the_original_state(runtime):
    baseline = runtime.establish_baseline()
    choice = runtime.scenario.decision("respond_to_prompt").choice(
        "reuse_password")
    runtime.apply_choice(choice, "factual")

    rewound = runtime.rewind_and_verify(baseline)

    assert rewound.digest == baseline.digest
    assert rewound.state == baseline.state


# --------------------------------------------------------------------------
# 14.  The named research invariant
# --------------------------------------------------------------------------

def test_counterfactual_branch_runs_from_verified_identical_baseline(runtime):
    """The scientific invariant of RewindSec.

    The alternative decision is executed only after the environment has been
    rewound and its canonical fingerprint proven equal to the baseline captured
    before the factual decision. The intended changed variable is the learner's
    decision, not uncontrolled environmental drift.
    """
    pair = runtime.run_decision_pair(
        "respond_to_prompt",
        factual_choice_id="reuse_password",
        counterfactual_choice_id="isolate_endpoint")

    # The evidence, retained on the result itself:
    assert pair.rewound_snapshot.digest == pair.baseline_snapshot.digest
    assert pair.as_dict()["baseline_verified"] is True

    # Both branches genuinely ran, from that one baseline.
    assert runtime.adapter.applied == ["credentials_reused",
                                       "endpoint_isolated"]
    assert runtime.adapter.rewind_count == 1
    assert pair.branches_diverged


def test_counterfactual_branch_refuses_mismatched_rewind_baseline():
    """The negative case: a rewind that does not restore baseline fails closed.

    A comparison drawn across two different starting states would not support a
    counterfactual claim, so the runtime refuses to produce one.
    """
    adapter = make_adapter(DriftingRewindAdapter)
    runtime = CounterfactualRuntime(make_scenario(), adapter)

    with pytest.raises(BaselineVerificationError) as raised:
        runtime.run_decision_pair(
            "respond_to_prompt",
            factual_choice_id="reuse_password",
            counterfactual_choice_id="isolate_endpoint")

    assert raised.value.expected_digest != raised.value.observed_digest

    # H. The alternative consequence was never applied.
    assert adapter.applied == ["credentials_reused"]
    assert "endpoint_isolated" not in adapter.applied


def test_a_pair_cannot_be_constructed_around_an_unverified_rewind():
    """Even bypassing the runtime, the result type refuses to misrepresent."""
    from training.results import BranchOutcome, CounterfactualPair
    from training.comparison import StateDiff

    baseline = StateSnapshot.capture({"x": 0}, "baseline")
    drifted = StateSnapshot.capture({"x": 1}, "rewound")
    outcome = BranchOutcome("factual", "reuse_password", "credentials_reused",
                            baseline)

    with pytest.raises(BaselineVerificationError):
        CounterfactualPair(
            pair_id="p", scenario_key="s", scenario_version=1,
            decision_id="d", baseline_snapshot=baseline,
            rewound_snapshot=drifted, factual=outcome, counterfactual=outcome,
            difference=StateDiff(()))


# --------------------------------------------------------------------------
# F.  Ordering of the experiment
# --------------------------------------------------------------------------

def test_alternative_executes_only_after_the_rewind(runtime):
    calls = []
    adapter = runtime.adapter
    original_rewind = adapter.rewind
    original_apply = adapter.apply

    def traced_rewind():
        calls.append("rewind")
        original_rewind()

    def traced_apply(action_key):
        calls.append("apply:" + action_key)
        original_apply(action_key)

    adapter.rewind = traced_rewind
    adapter.apply = traced_apply

    runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                              "isolate_endpoint")

    assert calls == ["apply:credentials_reused", "rewind",
                     "apply:endpoint_isolated"]


# --------------------------------------------------------------------------
# I.  Paired result contents
# --------------------------------------------------------------------------

def test_paired_result_preserves_the_full_provenance_of_the_comparison(runtime):
    pair = runtime.run_decision_pair(
        "respond_to_prompt", "reuse_password", "isolate_endpoint",
        factual_confidence=80, counterfactual_confidence=35,
        factual_response_ms=4200, session_ref="pseudonym-1")

    assert pair.scenario_key == "credential_prompt"
    assert pair.scenario_version == 1
    assert pair.scenario_identity == "credential_prompt@1"
    assert pair.decision_id == "respond_to_prompt"

    assert pair.factual.choice_id == "reuse_password"
    assert pair.factual.action_key == "credentials_reused"
    assert pair.factual.confidence == 80
    assert pair.factual.response_time_ms == 4200

    assert pair.counterfactual.choice_id == "isolate_endpoint"
    assert pair.counterfactual.action_key == "endpoint_isolated"
    assert pair.counterfactual.confidence == 35
    assert pair.counterfactual.response_time_ms is None

    assert pair.baseline_digest == pair.baseline_snapshot.digest
    assert pair.factual.digest != pair.counterfactual.digest
    assert pair.factual.digest == fingerprint(pair.factual.resulting_snapshot.state)

    assert pair.pair_id and len(pair.pair_id) == 32
    assert pair.session_ref == "pseudonym-1"
    assert pair.adapter_info["environment_kind"] == "in_memory"

    # The structured form carries the same facts, ready for telemetry later.
    record = pair.as_dict()
    assert record["baseline_digest"] == pair.baseline_digest
    assert record["factual"]["state_digest"] == pair.factual.digest
    assert record["counterfactual"]["state_digest"] == pair.counterfactual.digest


def test_pair_id_is_content_derived_and_free_of_timestamps():
    first = CounterfactualRuntime(make_scenario(), make_adapter()).run_decision_pair(
        "respond_to_prompt", "reuse_password", "isolate_endpoint")
    second = CounterfactualRuntime(make_scenario(), make_adapter()).run_decision_pair(
        "respond_to_prompt", "reuse_password", "isolate_endpoint")
    assert first.pair_id == second.pair_id

    other_session = CounterfactualRuntime(
        make_scenario(), make_adapter()).run_decision_pair(
            "respond_to_prompt", "reuse_password", "isolate_endpoint",
            session_ref="pseudonym-2")
    assert other_session.pair_id != first.pair_id


# --------------------------------------------------------------------------
# J.  State comparison
# --------------------------------------------------------------------------

def test_state_diff_reports_added_removed_and_changed_values():
    before = {"account": {"compromised": True}, "files": {"impacted": 5},
              "notified": False}
    after = {"account": {"compromised": False}, "files": {"impacted": 1},
             "endpoint": {"isolated": True}}

    diff = diff_states(before, after)
    by_pointer = {change.pointer: change for change in diff.changes}

    assert by_pointer["account.compromised"].change == CHANGED
    assert by_pointer["account.compromised"].before is True
    assert by_pointer["account.compromised"].after is False

    assert by_pointer["files.impacted"].change == CHANGED
    assert (by_pointer["files.impacted"].before,
            by_pointer["files.impacted"].after) == (5, 1)

    assert by_pointer["endpoint.isolated"].change == ADDED
    assert by_pointer["endpoint.isolated"].after is True

    assert by_pointer["notified"].change == REMOVED
    assert by_pointer["notified"].before is False


def test_state_diff_is_deterministically_ordered_and_empty_when_equal():
    left = {"b": 1, "a": 2}
    right = {"a": 3, "b": 4}
    assert diff_states(left, right).pointers() == ("a", "b")
    assert diff_states(left, dict(left)).is_empty


def test_state_diff_of_a_pair_describes_the_two_branch_outcomes(runtime):
    pair = runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                     "isolate_endpoint")
    by_pointer = {change.pointer: change for change in pair.difference.changes}

    assert by_pointer["account.compromised"].before is True
    assert by_pointer["account.compromised"].after is False
    assert by_pointer["files.impacted"].before == 5
    assert by_pointer["files.impacted"].after == 1
    assert pair.difference.as_dict()["counts"][CHANGED] >= 2


def test_identical_choices_on_both_branches_produce_an_empty_delta(runtime):
    """A null control: same decision twice must show no environmental drift."""
    pair = runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                     "reuse_password")
    assert pair.difference.is_empty
    assert not pair.branches_diverged


# --------------------------------------------------------------------------
# K.  Reproducibility
# --------------------------------------------------------------------------

def test_repeated_identical_experiments_produce_equivalent_outcomes():
    results = []
    for _ in range(3):
        runtime = CounterfactualRuntime(make_scenario(), make_adapter())
        results.append(runtime.run_decision_pair(
            "respond_to_prompt", "reuse_password", "isolate_endpoint"))

    first = results[0]
    for repeat in results[1:]:
        assert repeat.baseline_digest == first.baseline_digest
        assert repeat.factual.digest == first.factual.digest
        assert repeat.counterfactual.digest == first.counterfactual.digest
        assert repeat.difference.as_dict() == first.difference.as_dict()


# --------------------------------------------------------------------------
# L. / M.  Confidence
# --------------------------------------------------------------------------

@pytest.mark.parametrize("value", [-1, 101, 1000, "80", "high", 50.5, 50.0,
                                   float("nan"), True, False, [80]])
def test_invalid_confidence_values_are_rejected(runtime, value):
    with pytest.raises(ConfidenceValueError):
        runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                  "isolate_endpoint",
                                  factual_confidence=value)


@pytest.mark.parametrize("value", [0, 100, 50])
def test_valid_confidence_boundaries_are_accepted(runtime, value):
    pair = runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                     "isolate_endpoint",
                                     factual_confidence=value)
    assert pair.factual.confidence == value


def test_confidence_is_optional(runtime):
    pair = runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                     "isolate_endpoint")
    assert pair.factual.confidence is None
    assert pair.counterfactual.confidence is None


def test_invalid_confidence_is_rejected_before_the_environment_is_touched(runtime):
    with pytest.raises(ConfidenceValueError):
        runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                  "isolate_endpoint", factual_confidence=101)
    assert runtime.adapter.applied == []
    assert runtime.adapter.prepare_count == 0


# --------------------------------------------------------------------------
# N. / O.  The consequence safety boundary
# --------------------------------------------------------------------------

def test_unknown_consequence_action_keys_fail_before_any_execution():
    scenario = ScenarioDefinition(
        scenario_key="unresolvable", version=1, title="Unresolvable",
        decision_points=(DecisionPoint(
            "d", "p", (Choice("a", "A", ConsequenceSpec("no_such_action")),
                       Choice("b", "B", ConsequenceSpec("endpoint_isolated")))),))
    adapter = make_adapter()

    with pytest.raises(UnknownActionError):
        CounterfactualRuntime(scenario, adapter)

    assert adapter.applied == []
    assert adapter.prepare_count == 0


def test_adapter_refuses_an_action_outside_its_declared_vocabulary():
    adapter = make_adapter()
    with pytest.raises(UnknownActionError):
        adapter.apply("endpoint_detonated")
    assert adapter.applied == []


@pytest.mark.parametrize("hostile_key", [
    "docker exec -it sandbox sh",
    "sandbox.backends.docker:DockerBackend",
    "https://example.invalid/payload",
    "../../etc/passwd",
    "C:\\Windows\\System32\\cmd.exe",
    "rm -rf /",
    "__import__",
    "os_system",
    "eval_this",
    "",
])
def test_a_consequence_cannot_reference_an_arbitrary_executable(hostile_key):
    """A scenario may name an action; it may never describe how to run one."""
    with pytest.raises(ScenarioDefinitionError):
        ConsequenceSpec(hostile_key)


def test_a_choice_cannot_carry_a_callable_instead_of_a_consequence_spec():
    with pytest.raises(ScenarioDefinitionError):
        Choice("danger", "Run it", _credential_reuse)
    with pytest.raises(ScenarioDefinitionError):
        Choice("danger", "Run it", "credentials_reused")


# --------------------------------------------------------------------------
# Definition integrity
# --------------------------------------------------------------------------

def test_a_decision_needs_at_least_two_choices_to_be_comparable():
    with pytest.raises(ScenarioDefinitionError):
        DecisionPoint("d", "p", (Choice("only", "Only",
                                        ConsequenceSpec("nothing_happens")),))


def test_duplicate_choice_and_decision_ids_are_rejected():
    duplicate = Choice("same", "One", ConsequenceSpec("nothing_happens"))
    with pytest.raises(ScenarioDefinitionError):
        DecisionPoint("d", "p", (duplicate, duplicate))

    point = make_scenario().decision_points[0]
    with pytest.raises(ScenarioDefinitionError):
        ScenarioDefinition("dupes", 1, "Dupes", (point, point))


def test_unknown_decision_and_choice_lookups_raise(runtime):
    with pytest.raises(ScenarioDefinitionError):
        runtime.run_decision_pair("no_such_decision", "reuse_password",
                                  "isolate_endpoint")
    with pytest.raises(ScenarioDefinitionError):
        runtime.run_decision_pair("respond_to_prompt", "reuse_password",
                                  "no_such_choice")


def test_scenario_version_is_part_of_its_identity():
    assert make_scenario().identity == "credential_prompt@1"
    with pytest.raises(ScenarioDefinitionError):
        ScenarioDefinition("k", 0, "T", make_scenario().decision_points)


def test_the_training_package_stays_independent_of_flask_and_the_sandbox():
    """R1 is a standalone core. It is driven by the app, never the reverse."""
    import pathlib
    import re

    root = pathlib.Path(__file__).resolve().parent.parent / "training"
    forbidden = re.compile(
        r"^\s*(?:from|import)\s+(flask|sqlalchemy|app|sandbox|telemetry_ledger)\b",
        re.MULTILINE | re.IGNORECASE)
    for module in root.rglob("*.py"):
        assert not forbidden.search(module.read_text(encoding="utf-8")), \
            "{0} imports an application-layer dependency".format(module)
