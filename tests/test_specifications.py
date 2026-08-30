"""Milestone 4, section 1: the evaluation oracle is independent and strict.

Two things are proved here:

1. ``evaluation/specifications.py`` does not depend on the production
   progression definitions, so an experiment cannot grade the implementation
   against itself.
2. The oracle actually *catches* each defect class the experiments claim to
   detect: a missing event, an unexpected event, a wrong order, a wrong
   ``scenario_id`` and a wrong ``session_id``.
"""

import ast
import datetime
import os
import sys

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from evaluation import specifications as spec_module
from evaluation.specifications import (SPECIFICATIONS, evaluate,
                                       specification_manifest)

SPEC_PATH = os.path.join(os.path.dirname(os.path.abspath(spec_module.__file__)),
                         "specifications.py")

BASE_TIME = datetime.datetime(2026, 8, 30, 12, 0, 0)


def event(event_type, offset=0, scenario_id="scn-1", session_id="sess-1"):
    return {
        "event_type": event_type,
        "scenario_id": scenario_id,
        "session_id": session_id,
        "timestamp": BASE_TIME + datetime.timedelta(seconds=offset),
        "source": "test",
        "target": None,
        "details": None,
    }


def sequence(types, **kwargs):
    return [event(t, offset=i, **kwargs) for i, t in enumerate(types)]


def good(scenario, **kwargs):
    return sequence(SPECIFICATIONS[scenario].required, **kwargs)


ALL_SCENARIOS = sorted(SPECIFICATIONS)


# -- independence ------------------------------------------------------------

def test_the_specification_module_imports_nothing_from_the_implementation():
    """The oracle must not be able to inherit the implementation's mistakes."""
    tree = ast.parse(open(SPEC_PATH, encoding="utf-8").read())
    imported = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    assert not [name for name in imported
                if name.split(".")[0] in ("sandbox", "app", "sandbox_routes")], \
        "specifications.py must stay independent of the production code: %s" % imported


def test_the_specification_module_is_self_contained_at_runtime():
    assert not [name for name in sys.modules
                if name.startswith("evaluation.specifications.")]
    # Every declared event type is a plain literal string, not an attribute
    # borrowed from EventType.
    for spec in SPECIFICATIONS.values():
        for name in tuple(spec.required) + tuple(spec.optional) + tuple(spec.forbidden):
            assert isinstance(name, str) and name.isupper()


def test_specifications_cover_the_evaluated_scenarios():
    assert set(SPECIFICATIONS) == {"file_impact", "credential_reuse_phishing",
                                   "ransomware_awareness"}


def test_the_manifest_is_serialisable_and_versioned():
    manifest = specification_manifest()
    assert manifest["specification_version"]
    assert set(manifest["scenarios"]) == set(SPECIFICATIONS)
    import json
    json.loads(json.dumps(manifest))


# -- the oracle accepts a correct run ----------------------------------------

@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_a_correct_sequence_passes(scenario):
    verdict = evaluate(good(scenario), scenario,
                       scenario_id="scn-1", session_id="sess-1")
    assert verdict.ok, verdict.as_dict()
    assert verdict.completeness == 1.0
    assert verdict.missing == []
    assert verdict.unexpected == []


def test_a_declared_repeatable_event_may_fire_more_than_once():
    events = sequence(["SCENARIO_STARTED", "FILE_IMPACT_STARTED", "FILE_IMPACT",
                       "FILE_IMPACT", "FILE_IMPACT", "FILE_IMPACT_COMPLETED",
                       "SCENARIO_COMPLETED"])
    assert evaluate(events, "file_impact").ok


def test_a_declared_optional_event_is_tolerated():
    events = sequence(["SCENARIO_STARTED", "FILE_IMPACT_STARTED", "FILE_IMPACT",
                       "FILE_IMPACT_REJECTED", "FILE_IMPACT_COMPLETED",
                       "SCENARIO_COMPLETED"])
    verdict = evaluate(events, "file_impact")
    assert verdict.ok, verdict.as_dict()
    assert verdict.unexpected == []


# -- the oracle catches each defect class ------------------------------------

@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
@pytest.mark.parametrize("drop", [0, 1, -1])
def test_a_missing_expected_event_is_caught(scenario, drop):
    required = list(SPECIFICATIONS[scenario].required)
    dropped = required.pop(drop)
    verdict = evaluate(sequence(required), scenario)
    assert not verdict.ok
    assert verdict.missing == [dropped]
    assert verdict.completeness < 1.0


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_an_unexpected_event_is_caught(scenario):
    events = good(scenario) + [event("TOTALLY_UNDECLARED_EVENT", offset=99)]
    verdict = evaluate(events, scenario)
    assert not verdict.ok
    assert verdict.unexpected == ["TOTALLY_UNDECLARED_EVENT"]
    # An extra event must not be excused by full completeness.
    assert verdict.completeness == 1.0


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_an_event_from_another_scenario_is_unexpected_here(scenario):
    foreign = next(t for name, s in SPECIFICATIONS.items() if name != scenario
                   for t in s.required
                   if t not in SPECIFICATIONS[scenario].permitted)
    verdict = evaluate(good(scenario) + [event(foreign, offset=99)], scenario)
    assert not verdict.ok
    assert foreign in verdict.unexpected


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_an_incorrect_order_is_caught(scenario):
    required = list(SPECIFICATIONS[scenario].required)
    swapped = required[:]
    swapped[0], swapped[1] = swapped[1], swapped[0]
    verdict = evaluate(sequence(swapped), scenario)
    assert not verdict.ok
    assert verdict.order_correct is False
    # Every event is present -- only the order is wrong, which is exactly the
    # defect a set-based completeness score would miss.
    assert verdict.missing == []
    assert verdict.completeness == 1.0


def test_a_reversed_sequence_is_caught():
    verdict = evaluate(sequence(list(SPECIFICATIONS["file_impact"].required)[::-1]),
                       "file_impact")
    assert verdict.order_correct is False and not verdict.ok


def test_a_duplicated_non_repeatable_event_breaks_the_order():
    events = sequence(["SCENARIO_STARTED", "SCENARIO_STARTED",
                       "FILE_IMPACT_STARTED", "FILE_IMPACT",
                       "FILE_IMPACT_COMPLETED", "SCENARIO_COMPLETED"])
    verdict = evaluate(events, "file_impact")
    assert verdict.order_correct is False and not verdict.ok


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_an_incorrect_scenario_id_is_caught(scenario):
    verdict = evaluate(good(scenario), scenario, scenario_id="the-other-run")
    assert not verdict.ok
    assert verdict.scenario_id_correct is False


def test_a_mixed_scenario_id_is_caught_even_without_an_expected_value():
    events = good("file_impact")
    events[2]["scenario_id"] = "a-different-run"
    verdict = evaluate(events, "file_impact")
    assert not verdict.ok
    assert verdict.scenario_id_correct is False


def test_a_missing_scenario_id_is_caught():
    events = good("file_impact")
    events[1]["scenario_id"] = None
    verdict = evaluate(events, "file_impact")
    assert not verdict.ok
    assert verdict.scenario_id_correct is False
    assert verdict.fields_complete is False


@pytest.mark.parametrize("scenario", ALL_SCENARIOS)
def test_an_incorrect_session_id_is_caught(scenario):
    verdict = evaluate(good(scenario), scenario, session_id="another-learner")
    assert not verdict.ok
    assert verdict.session_id_correct is False


def test_an_event_leaking_from_another_session_is_caught():
    events = good("credential_reuse_phishing")
    events[3]["session_id"] = "another-learner"
    verdict = evaluate(events, "credential_reuse_phishing",
                       session_id="sess-1")
    assert not verdict.ok
    assert verdict.session_id_correct is False


# -- remaining invariants ----------------------------------------------------

def test_a_forbidden_event_invalidates_the_run():
    verdict = evaluate(good("file_impact") + [event("SCENARIO_FAILED", offset=99)],
                       "file_impact")
    assert not verdict.ok
    assert verdict.forbidden_seen == ["SCENARIO_FAILED"]


def test_out_of_order_timestamps_are_caught():
    events = good("file_impact")
    events[2]["timestamp"] = BASE_TIME - datetime.timedelta(seconds=60)
    verdict = evaluate(events, "file_impact")
    assert not verdict.ok
    assert verdict.timestamps_ordered is False


def test_equal_timestamps_are_accepted():
    events = good("file_impact")
    for item in events:
        item["timestamp"] = BASE_TIME
    assert evaluate(events, "file_impact").ok


def test_an_empty_sequence_is_never_ok():
    verdict = evaluate([], "file_impact")
    assert not verdict.ok
    assert verdict.completeness == 0.0


def test_an_unknown_scenario_is_refused_rather_than_scored():
    with pytest.raises(KeyError):
        evaluate(good("file_impact"), "no_such_scenario")


def test_the_oracle_reads_object_rows_as_well_as_dicts():
    class Row:
        def __init__(self, data):
            self.__dict__.update(data)

    rows = [Row(e) for e in good("file_impact")]
    assert evaluate(rows, "file_impact", scenario_id="scn-1").ok
