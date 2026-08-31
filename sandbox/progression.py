"""Scenario progression derived from SecurityEvent telemetry.

Since Milestone 3, ``SecurityEvent`` is the single authoritative telemetry
model: the dashboard funnel, the learner debrief and the evaluation harness all
compute progression from the same event stream through this module, rather than
from separate per-scenario counter tables.

Everything here is a pure function over a list of event-like objects, so the
same code runs against SQLAlchemy rows, the in-memory ``EventCollector``, and
JSON decoded from ``/sandbox/events``. Nothing here touches Flask or a database.
"""

from .events import EventType
from .telemetry import drop_scoring_noise

#: The canonical, ordered event sequence each scenario is expected to emit on a
#: successful run. These are the *definitions* the telemetry-completeness
#: measurement is scored against, so they live in one place and are imported by
#: both the application and the evaluation harness.
EXPECTED_SEQUENCES = {
    "file_impact": (
        EventType.SCENARIO_STARTED,
        EventType.FILE_IMPACT_STARTED,
        EventType.FILE_IMPACT,
        EventType.FILE_IMPACT_COMPLETED,
        EventType.SCENARIO_COMPLETED,
    ),
    "credential_reuse_phishing": (
        EventType.SCENARIO_STARTED,
        EventType.PHISHING_EXPOSED,
        EventType.CONSENT_GRANTED,
        EventType.PHISHING_FORM_VIEWED,
        EventType.CREDENTIAL_SUBMITTED,
        EventType.CREDENTIAL_VALIDATED,
        EventType.SANDBOX_LOGIN_SUCCEEDED,
        EventType.SYNTHETIC_RESOURCE_ACCESSED,
        EventType.SCENARIO_COMPLETED,
    ),
}

#: Funnel stages, derived from event types rather than stored separately.
#: ``(stage key, event type)`` in progression order.
PHISHING_FUNNEL = (
    ("marketplace", EventType.PHISHING_EXPOSED),
    ("payment", EventType.PHISHING_FORM_VIEWED),
    ("credentials", EventType.CREDENTIAL_SUBMITTED),
)
RANSOMWARE_FUNNEL = (
    ("menu", EventType.RANSOMWARE_LURE_VIEWED),
    ("interaction", EventType.RANSOMWARE_DOWNLOAD_CLICKED),
    ("triggered", EventType.RANSOMWARE_TRIGGERED),
)

#: event type -> funnel stage label, for rendering recent activity.
STAGE_BY_EVENT = {event: stage
                  for stage, event in PHISHING_FUNNEL + RANSOMWARE_FUNNEL}


def _field(event, name):
    """Read ``name`` from a row, a dict, or anything in between."""
    if isinstance(event, dict):
        return event.get(name)
    return getattr(event, name, None)


def event_types(events):
    return [_field(e, "event_type") for e in events]


def for_scenario(events, scenario_id):
    return [e for e in events if _field(e, "scenario_id") == scenario_id]


def for_session(events, session_id):
    return [e for e in events if _field(e, "session_id") == session_id]


def is_ordered(events):
    """True when timestamps are non-decreasing across the sequence.

    Ordering is only ever asserted as non-decreasing: two events emitted inside
    the same clock tick are legitimately equal, and insertion order (the row id)
    is the documented tie-break.
    """
    stamps = [_field(e, "timestamp") for e in events]
    if any(s is None for s in stamps):
        return False
    return all(a <= b for a, b in zip(stamps, stamps[1:]))


def matches_expected_sequence(events, scenario):
    """True when the observed types are exactly the expected ordered sequence.

    Repeats of a type that may legitimately occur more than once (``FILE_IMPACT``
    fires once per file) are collapsed before comparison, and raw interaction
    telemetry (``PAGE_VIEW``) is dropped entirely: a refresh in the middle of a
    run is browsing noise, not a step out of sequence.
    """
    expected = EXPECTED_SEQUENCES[scenario]
    events = drop_scoring_noise(events)
    observed = []
    for event_type in event_types(events):
        if not observed or observed[-1] != event_type:
            observed.append(event_type)
    return tuple(observed) == tuple(expected)


def completeness(events, scenario):
    """``captured_expected_events / expected_events`` for one scenario run.

    Counts *distinct expected types present*, so a run that emits every
    required event scores 1.0 regardless of how many times a repeatable event
    fired. Extra event types beyond the definition neither help nor hurt.
    """
    expected = EXPECTED_SEQUENCES[scenario]
    observed = set(event_types(drop_scoring_noise(events)))
    captured = sum(1 for event_type in expected if event_type in observed)
    return {
        "scenario": scenario,
        "expected": len(expected),
        "captured": captured,
        "ratio": captured / len(expected) if expected else 0.0,
        "missing": [e for e in expected if e not in observed],
    }


def scenario_progress(events, scenario):
    """How far a scenario run got, derived purely from its events."""
    expected = EXPECTED_SEQUENCES[scenario]
    observed = set(event_types(events))
    reached = 0
    for event_type in expected:
        if event_type not in observed:
            break
        reached += 1
    return {
        "scenario": scenario,
        "stages_reached": reached,
        "stages_total": len(expected),
        "furthest_event": expected[reached - 1] if reached else None,
        "completed": EventType.SCENARIO_COMPLETED in observed,
        "failed": EventType.SCENARIO_FAILED in observed,
    }


def funnel_counts(events, funnel):
    """Count events per funnel stage. ``funnel`` is PHISHING_/RANSOMWARE_FUNNEL.

    Every funnel stage is a progression milestone, which the write path records
    at most once per ``(session_id, scenario_id, event_type)`` -- so counting
    occurrences here counts runs, not requests. Raw interaction telemetry is not
    a funnel stage and so never appears in the result at all.
    """
    types = event_types(events)
    return {stage: types.count(event_type) for stage, event_type in funnel}


def conversion_rates(counts, funnel):
    """Stage-to-stage and end-to-end conversion percentages."""
    stages = [stage for stage, _ in funnel]
    first, second, third = (counts.get(s, 0) for s in stages)

    def pct(numerator, denominator):
        return (numerator / denominator * 100) if denominator else 0.0

    return {"conv_1_2": pct(second, first),
            "conv_2_3": pct(third, second),
            "conv_total": pct(third, first)}
