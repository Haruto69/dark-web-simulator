"""Milestone 4.2, section 1: the progression / interaction event model.

These tests pin the *classification* itself. The refresh behaviour it produces
is covered by ``tests/test_refresh_resilience.py``; what matters here is that
every declared event type has exactly one class, and that the classes mean what
the rest of the system assumes they mean.
"""

import pytest

from sandbox.events import ALL_EVENT_TYPES, EventType
from sandbox.progression import PHISHING_FUNNEL, RANSOMWARE_FUNNEL
from sandbox.telemetry import (INTERACTION_EVENTS, PROGRESSION_EVENTS,
                               SCORING_NOISE, drop_scoring_noise,
                               is_interaction, is_progression, milestone_key)


# -- the classification partitions the declared universe ----------------------

def test_every_declared_event_type_has_exactly_one_class():
    unclassified = sorted(set(ALL_EVENT_TYPES)
                          - PROGRESSION_EVENTS - INTERACTION_EVENTS)
    assert unclassified == [], (
        "a new event type must be declared a progression milestone or raw "
        "interaction telemetry: %s" % unclassified)


def test_the_two_classes_are_disjoint():
    assert PROGRESSION_EVENTS.isdisjoint(INTERACTION_EVENTS)


def test_the_classes_declare_nothing_that_is_not_an_event_type():
    known = set(ALL_EVENT_TYPES)
    assert PROGRESSION_EVENTS <= known
    assert INTERACTION_EVENTS <= known


# -- what each class means ----------------------------------------------------

@pytest.mark.parametrize("funnel", [PHISHING_FUNNEL, RANSOMWARE_FUNNEL])
def test_every_funnel_stage_is_a_progression_milestone(funnel):
    """A funnel stage that was repeatable would be a request counter."""
    for stage, event_type in funnel:
        assert is_progression(event_type), stage


def test_page_view_is_raw_interaction_telemetry():
    assert is_interaction(EventType.PAGE_VIEW)
    assert not is_progression(EventType.PAGE_VIEW)


def test_a_retryable_failure_stays_repeatable():
    """Collapsing retries would hide the behaviour an instructor wants to see."""
    assert is_interaction(EventType.CREDENTIAL_VALIDATION_FAILED)


def test_per_file_impact_telemetry_stays_repeatable():
    """FILE_IMPACT fires once per synthetic file; deduplicating it loses data."""
    assert is_interaction(EventType.FILE_IMPACT)
    assert is_progression(EventType.FILE_IMPACT_STARTED)
    assert is_progression(EventType.FILE_IMPACT_COMPLETED)


def test_scoring_noise_is_a_subset_of_the_interaction_events():
    assert SCORING_NOISE <= INTERACTION_EVENTS
    assert SCORING_NOISE, "at least PAGE_VIEW must be droppable noise"


# -- the deduplication key ----------------------------------------------------

def test_a_correlated_milestone_has_a_key():
    assert milestone_key("sess-1", "scen-1", EventType.PHISHING_EXPOSED) == (
        "sess-1", "scen-1", EventType.PHISHING_EXPOSED)


def test_interaction_telemetry_has_no_key_and_is_therefore_never_deduplicated():
    assert milestone_key("sess-1", "scen-1", EventType.PAGE_VIEW) is None


@pytest.mark.parametrize("session_id,scenario_id", [
    (None, "scen-1"), ("sess-1", None), ("", "scen-1"), ("sess-1", ""),
])
def test_an_uncorrelated_milestone_has_no_key(session_id, scenario_id):
    """No key means "record it": losing telemetry is worse than a duplicate."""
    assert milestone_key(session_id, scenario_id,
                         EventType.PHISHING_EXPOSED) is None


def test_the_key_separates_sessions_and_scenarios():
    a = milestone_key("sess-1", "scen-1", EventType.PHISHING_EXPOSED)
    assert a != milestone_key("sess-2", "scen-1", EventType.PHISHING_EXPOSED)
    assert a != milestone_key("sess-1", "scen-2", EventType.PHISHING_EXPOSED)


# -- dropping noise -----------------------------------------------------------

def test_dropping_noise_keeps_every_scored_event():
    events = [{"event_type": EventType.RANSOMWARE_LURE_VIEWED},
              {"event_type": EventType.PAGE_VIEW},
              {"event_type": EventType.PAGE_VIEW},
              {"event_type": EventType.RANSOMWARE_TRIGGERED}]
    assert [e["event_type"] for e in drop_scoring_noise(events)] == [
        EventType.RANSOMWARE_LURE_VIEWED, EventType.RANSOMWARE_TRIGGERED]


def test_dropping_noise_reads_objects_as_well_as_dicts():
    class Row:
        def __init__(self, event_type):
            self.event_type = event_type

    rows = [Row(EventType.PAGE_VIEW), Row(EventType.SCENARIO_COMPLETED)]
    assert [r.event_type for r in drop_scoring_noise(rows)] == [
        EventType.SCENARIO_COMPLETED]
