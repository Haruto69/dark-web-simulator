"""Unit tests for the R4 ransomware consequence adapter and its safe boundary.

No Docker is required here: the adapter is exercised against the real
``SandboxManager`` on the local backend, rooted in pytest's temp directory, so
the file operations are genuine but nothing outside ``tmp_path`` is touched.
Container behaviour is covered separately in
``tests/test_docker_ransomware_scenario.py``.
"""

import ast
import inspect
import json

import pytest

import scenario_adapters.ransomware as ransomware_module
from sandbox.backends.local import LocalBackend
from sandbox.dataset import BASELINE_FILENAMES
from sandbox.errors import SandboxError, UnsafePathError
from sandbox.manager import SandboxManager
from scenario_adapters.ransomware import (ACTION_ISOLATED_AND_REPORTED,
                                          ACTION_REPORTED_ONLY,
                                          ACTION_RESTARTED,
                                          ACTION_WORK_CONTINUED,
                                          IMPACT_PROGRESSION, INITIAL_IMPACT,
                                          RANSOMWARE_ACTIONS,
                                          RANSOMWARE_DECISION_ID,
                                          RANSOMWARE_SCENARIO,
                                          RansomwareConsequenceAdapter,
                                          WorkspaceIntegrityError,
                                          additional_targets,
                                          read_file_condition)
from training.adapters.base import ConsequenceAdapter
from training.errors import AdapterProtocolError
from training.runtime import CounterfactualRuntime
from training.snapshots import StateSnapshot

SANDBOX_ID = "r4-unit"


@pytest.fixture
def rw_manager(tmp_path, collector):
    return SandboxManager(LocalBackend(str(tmp_path / "sandboxes")),
                          recorder=collector, default_sandbox_id=None)


@pytest.fixture
def adapter(rw_manager):
    return RansomwareConsequenceAdapter(rw_manager, SANDBOX_ID)


def counts(state):
    return state["files"]["impacted_count"], state["files"]["available_count"]


# -- A/B: the one-impact baseline -------------------------------------------
def test_prepare_creates_the_exact_one_impact_baseline(adapter):
    """A: the learner starts after exactly one file is already impacted."""
    adapter.prepare()
    state = adapter.capture_state()
    assert counts(state) == (1, len(BASELINE_FILENAMES) - 1)
    assert state["files"]["impacted"] == [INITIAL_IMPACT]
    # ...and no response has been taken yet.
    assert state["endpoint"] == {"isolated": False, "restarted": False}
    assert state["incident"] == {"reported": False}


def test_baseline_uses_only_fixed_known_synthetic_files(adapter):
    """B: every filename in the baseline comes from the fixed dataset."""
    adapter.prepare()
    files = adapter.capture_state()["files"]
    for name in files["impacted"] + files["available"]:
        assert name in BASELINE_FILENAMES
    assert sorted(files["impacted"] + files["available"]) == sorted(
        BASELINE_FILENAMES)


def test_initial_impact_is_a_single_predetermined_allow_listed_file():
    assert INITIAL_IMPACT in BASELINE_FILENAMES
    assert IMPACT_PROGRESSION == tuple(BASELINE_FILENAMES)


# -- C/D: what capture_state may contain ------------------------------------
def test_capture_state_carries_no_contents_or_host_paths(adapter, tmp_path):
    """C: no file contents, no host path, no container id, no backend text."""
    adapter.prepare()
    adapter.apply(ACTION_WORK_CONTINUED)
    blob = json.dumps(adapter.capture_state())
    assert str(tmp_path) not in blob
    assert "/workspace" not in blob and "\\\\" not in blob
    assert ".demo_locked" not in blob
    assert "DWS-DEMO-STATE" not in blob
    assert "SIMULATED" not in blob
    # No slice of any baseline file's content appears in the state.
    from sandbox.dataset import SYNTHETIC_FILES
    for content in SYNTHETIC_FILES.values():
        assert content.strip().splitlines()[0] not in blob


def test_state_ordering_is_deterministic(rw_manager):
    """D: the same condition always fingerprints identically."""
    first = RansomwareConsequenceAdapter(rw_manager, SANDBOX_ID)
    first.prepare()
    digest_a = StateSnapshot.capture(first.capture_state()).digest
    second = RansomwareConsequenceAdapter(rw_manager, SANDBOX_ID)
    second.prepare()
    digest_b = StateSnapshot.capture(second.capture_state()).digest
    assert digest_a == digest_b
    # Ordering follows the fixed progression, not the backend's report order.
    assert first.capture_state()["files"]["available"] == list(
        IMPACT_PROGRESSION[1:])


# -- E-H: the authored progression ------------------------------------------
@pytest.mark.parametrize("action,expected", [
    (ACTION_ISOLATED_AND_REPORTED, 1),
    (ACTION_REPORTED_ONLY, 2),
    (ACTION_RESTARTED, 3),
    (ACTION_WORK_CONTINUED, 5),
])
def test_each_response_reaches_its_authored_impact_total(adapter, action,
                                                         expected):
    """E/F/G/H: the authored deterministic progression, end to end."""
    adapter.prepare()
    adapter.apply(action)
    state = adapter.capture_state()
    assert counts(state) == (expected, len(BASELINE_FILENAMES) - expected)
    assert state["files"]["impacted"] == list(IMPACT_PROGRESSION[:expected])


def test_authored_response_flags(adapter):
    expectations = {
        ACTION_ISOLATED_AND_REPORTED: (True, False, True),
        ACTION_REPORTED_ONLY: (False, False, True),
        ACTION_RESTARTED: (False, True, False),
        ACTION_WORK_CONTINUED: (False, False, False),
    }
    for action, (isolated, restarted, reported) in expectations.items():
        adapter.prepare()
        adapter.apply(action)
        state = adapter.capture_state()
        assert state["endpoint"]["isolated"] is isolated
        assert state["endpoint"]["restarted"] is restarted
        assert state["incident"]["reported"] is reported


# -- I/J: targets are never learner-controlled ------------------------------
def test_every_impact_target_comes_from_baseline_filenames():
    """I: the whole progression is a subset of the fixed dataset."""
    for action in RANSOMWARE_ACTIONS:
        for name in additional_targets(action):
            assert name in BASELINE_FILENAMES
        assert INITIAL_IMPACT not in additional_targets(action)


def test_learner_cannot_specify_impact_targets(adapter):
    """J: ``apply`` takes an action key and nothing else."""
    parameters = list(inspect.signature(adapter.apply).parameters)
    assert parameters == ["action_key"]
    # An action key outside the closed vocabulary is refused before any work.
    with pytest.raises(Exception):
        adapter.apply("employee_records.csv")
    with pytest.raises(Exception):
        adapter.apply("../../etc/passwd")


def test_manager_impact_delegation_refuses_targets_outside_the_allow_list(
        rw_manager):
    rw_manager.create(SANDBOX_ID)
    for bad in ("../../etc/passwd", "/workspace/../secret", "notes.txt",
                "employee_records.csv.demo_locked", "sub/dir/file.txt"):
        with pytest.raises(UnsafePathError):
            rw_manager.apply_synthetic_impact([bad], sandbox_id=SANDBOX_ID)
    # An empty selection is not "impact everything".
    for empty in ([], None, ""):
        with pytest.raises(SandboxError):
            rw_manager.apply_synthetic_impact(empty, sandbox_id=SANDBOX_ID)
    state = {row["name"]: row["status"]
             for row in rw_manager.workspace_state(SANDBOX_ID)}
    assert set(state.values()) == {"baseline"}


# -- K/L: one action per branch, and an exact rewind ------------------------
def test_second_apply_before_rewind_is_rejected(adapter):
    """K: responses are never stacked."""
    adapter.prepare()
    adapter.apply(ACTION_RESTARTED)
    with pytest.raises(AdapterProtocolError):
        adapter.apply(ACTION_WORK_CONTINUED)
    # ...and the refusal changed nothing.
    assert counts(adapter.capture_state()) == (3, 2)


def test_rewind_reproduces_the_exact_one_impact_baseline_digest(adapter):
    """L: the research invariant, at adapter level."""
    adapter.prepare()
    baseline = StateSnapshot.capture(adapter.capture_state())
    adapter.apply(ACTION_WORK_CONTINUED)
    assert counts(adapter.capture_state()) == (5, 0)
    adapter.rewind()
    rewound = StateSnapshot.capture(adapter.capture_state())
    assert rewound.digest == baseline.digest
    assert counts(rewound.state) == (1, 4)
    # The logical action state is reset too, so the alternative can be applied.
    assert adapter.applied_action is None
    adapter.apply(ACTION_ISOLATED_AND_REPORTED)
    assert counts(adapter.capture_state()) == (1, 4)


def test_runtime_pair_runs_both_branches_from_one_verified_baseline(
        rw_manager):
    adapter = RansomwareConsequenceAdapter(rw_manager, SANDBOX_ID)
    pair = CounterfactualRuntime(RANSOMWARE_SCENARIO, adapter).run_decision_pair(
        RANSOMWARE_DECISION_ID,
        factual_choice_id="isolate_and_report",
        counterfactual_choice_id="continue_working")
    assert pair.baseline_digest == pair.rewound_snapshot.digest
    assert counts(pair.baseline_snapshot.state) == (1, 4)
    assert counts(pair.factual.resulting_snapshot.state) == (1, 4)
    assert counts(pair.counterfactual.resulting_snapshot.state) == (5, 0)
    # Branch order is the learner's, not the severity order.
    assert pair.factual.choice_id == "isolate_and_report"
    assert pair.counterfactual.choice_id == "continue_working"


# -- M: unexpected workspace entries fail closed ----------------------------
class StubManager:
    """A manager stand-in that reports whatever workspace rows it is given."""

    def __init__(self, rows):
        self.rows = rows

    def reset(self, sandbox_id, session_id=None):
        return {"sandbox_id": sandbox_id, "state": "running"}

    def apply_synthetic_impact(self, targets, sandbox_id=None, session_id=None):
        return [{"target": name, "status": "impacted"} for name in targets]

    def workspace_state(self, sandbox_id=None):
        return self.rows


@pytest.mark.parametrize("rows", [
    # An entry outside the fixed synthetic universe.
    [{"name": "ransom_note.txt", "status": "impacted"}],
    # A known file reported missing rather than present or impacted.
    [{"name": name, "status": "missing"} for name in BASELINE_FILENAMES],
    # An unexpected status token.
    [{"name": name, "status": "encrypted"} for name in BASELINE_FILENAMES],
    # An incomplete workspace.
    [{"name": BASELINE_FILENAMES[0], "status": "baseline"}],
    # Not a sequence of mappings at all.
    ["employee_records.csv"],
])
def test_unexpected_workspace_entries_fail_closed(rows):
    """M: an unrecognised workspace is refused, never persisted."""
    adapter = RansomwareConsequenceAdapter(StubManager(rows), SANDBOX_ID)
    with pytest.raises(WorkspaceIntegrityError):
        adapter.capture_state()


def test_a_recognised_workspace_still_reads_normally():
    rows = [{"name": name, "status": "baseline"} for name in BASELINE_FILENAMES]
    rows[0]["status"] = "impacted"
    impacted, available = read_file_condition(rows)
    assert impacted == [BASELINE_FILENAMES[0]]
    assert available == list(BASELINE_FILENAMES[1:])


# -- N/O: the safety and layering boundaries --------------------------------
def _imported_modules(tree):
    """Every module name imported by a parsed source tree."""
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module.split(".")[0])
    return names


def test_adapter_contains_no_raw_docker_or_subprocess_execution():
    """N: the adapter delegates; it never executes anything itself.

    Checked against the parsed syntax tree rather than the raw text, so the
    module's own prose about *not* running subprocesses cannot satisfy -- or
    trip -- the assertion.
    """
    tree = ast.parse(inspect.getsource(ransomware_module))
    assert _imported_modules(tree) <= {"copy", "sandbox", "training"}

    called = set()
    attributes = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            target = node.func
            called.add(target.attr if isinstance(target, ast.Attribute)
                       else getattr(target, "id", ""))
        if isinstance(node, ast.Attribute):
            attributes.add(node.attr)
    for forbidden in ("run", "Popen", "call", "check_output", "system",
                      "popen", "open", "remove", "rename", "replace",
                      "walk", "listdir", "glob", "rmtree", "encrypt",
                      "eval", "exec", "__import__"):
        assert forbidden not in called, forbidden
    # Never reaches past the manager into a backend, and never names a
    # container, a path or a command.
    assert "backend" not in attributes


def test_adapter_module_declares_no_paths_commands_or_cryptography():
    source = inspect.getsource(ransomware_module)
    for forbidden in ("/workspace", "docker run", "docker exec", "--network",
                      "cipher", "Fernet", "AES", "ransom note", "bitcoin",
                      "decrypt", "payment"):
        assert forbidden not in source, forbidden


def test_training_package_remains_framework_independent():
    """O: R4 must not have pulled Flask/SQLAlchemy/sandbox into training/."""
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1] / "training"
    forbidden = {"flask", "flask_wtf", "sqlalchemy", "flask_sqlalchemy",
                 "sandbox", "subprocess", "docker", "requests", "socket"}
    for path in root.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        leaked = _imported_modules(tree) & forbidden
        assert not leaked, "%s imports %s" % (path, sorted(leaked))


def test_adapter_implements_the_shared_contract(adapter):
    assert isinstance(adapter, ConsequenceAdapter)
    adapter.check_protocol()
    assert adapter.supported_actions == RANSOMWARE_ACTIONS
    described = adapter.describe()
    assert described["environment_kind"] == "contained_synthetic_workstation"
    assert described["synthetic_file_allow_list"] == sorted(BASELINE_FILENAMES)


def test_scenario_definition_names_only_symbolic_actions():
    decision = RANSOMWARE_SCENARIO.decision(RANSOMWARE_DECISION_ID)
    assert len(decision.choices) == 4
    for choice in decision.choices:
        key = choice.action_key
        assert key in RANSOMWARE_ACTIONS
        for forbidden in ("/", "\\", ".", ":", " ", "-"):
            assert forbidden not in key
    assert RANSOMWARE_SCENARIO.competency_tags == (
        "endpoint_containment", "incident_reporting", "ransomware_response")
    assert RANSOMWARE_SCENARIO.version == 1


def test_no_sandbox_id_is_accepted_from_a_caller_supplied_source(rw_manager):
    with pytest.raises(AdapterProtocolError):
        RansomwareConsequenceAdapter(rw_manager, None)
    with pytest.raises(AdapterProtocolError):
        RansomwareConsequenceAdapter(None, SANDBOX_ID)
