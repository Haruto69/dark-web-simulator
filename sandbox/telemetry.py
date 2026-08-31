"""The telemetry event model: progression milestones vs raw interaction events.

WHY THIS SPLIT EXISTS
---------------------
Until Milestone 4.2 every route that emitted telemetry appended a row on every
request. Several of those routes are plain ``GET`` pages -- ``/product/<id>``,
``/marketplace/tools``, ``/download/tool/<id>``. A refresh, a browser prefetch,
a link preview or a crawler therefore appended another "stage reached" row, and
the dashboard's funnel counts (and every conversion rate derived from them)
grew without a learner doing anything. Progression measured that way is not a
measurement; it is a request counter.

So event types are now split into two disjoint classes.

**Progression milestones** answer "did this run reach this stage?". They are
recorded **at most once per ``(session_id, scenario_id, event_type)``**: the
first request that reaches a stage records it and every repeat is a no-op. They
are what the dashboard funnel, the scenario-completion logic and the evaluation
harness read.

**Raw interaction telemetry** answers "what did the browser ask for?". It is
deliberately repeatable -- twenty refreshes legitimately produce twenty
``PAGE_VIEW`` rows -- and it never feeds a progression or conversion metric.
Some interaction types are *also* part of a scored sequence (``FILE_IMPACT``
fires once per synthetic file and the file-impact specification declares it
repeatable); this classification is about **idempotency of the write**, not
about whether a type is scored.

Nothing here touches Flask or a database: it is a pure classification that the
application, the templates and the tests all read from one place.
"""

from .events import ALL_EVENT_TYPES, EventType

#: Stage-reached events. Idempotent per ``(session_id, scenario_id, event_type)``.
#: Adding a type here makes it deduplicated at the write path; adding one to
#: ``INTERACTION_EVENTS`` makes it repeatable. Every declared type must appear
#: in exactly one of the two sets (asserted by ``tests/test_telemetry_model.py``).
PROGRESSION_EVENTS = frozenset({
    EventType.SCENARIO_STARTED,
    EventType.SCENARIO_COMPLETED,
    EventType.SCENARIO_FAILED,
    EventType.FILE_IMPACT_STARTED,
    EventType.FILE_IMPACT_COMPLETED,
    EventType.CONSENT_GRANTED,
    EventType.PHISHING_EXPOSED,
    EventType.PHISHING_FORM_VIEWED,
    EventType.CREDENTIAL_SUBMITTED,
    EventType.CREDENTIAL_VALIDATED,
    EventType.SANDBOX_LOGIN_SUCCEEDED,
    EventType.SYNTHETIC_RESOURCE_ACCESSED,
    EventType.RANSOMWARE_LURE_VIEWED,
    EventType.RANSOMWARE_DOWNLOAD_CLICKED,
    EventType.RANSOMWARE_TRIGGERED,
    EventType.RANSOMWARE_DEBRIEFED,
})

#: Repeatable telemetry. Never deduplicated, never counted as progression.
#:
#: * ``PAGE_VIEW`` -- a page was requested. The refresh-tolerant counterpart of
#:   the milestones above.
#: * ``FILE_IMPACT`` / ``FILE_IMPACT_REJECTED`` -- once per synthetic file.
#: * ``CREDENTIAL_VALIDATION_FAILED`` -- a learner may retry; collapsing the
#:   retries would hide exactly the behaviour an instructor wants to see.
#: * ``SANDBOX_*`` / ``INSTRUCTOR_*`` -- lifecycle and auth telemetry. These
#:   describe the lab, not a learner's progress through a scenario.
INTERACTION_EVENTS = frozenset({
    EventType.PAGE_VIEW,
    EventType.FILE_IMPACT,
    EventType.FILE_IMPACT_REJECTED,
    EventType.CREDENTIAL_VALIDATION_FAILED,
    EventType.SANDBOX_CREATED,
    EventType.SANDBOX_RESET,
    EventType.SANDBOX_DESTROYED,
    EventType.SANDBOX_REAPED,
    EventType.SANDBOX_REAP_SCAN,
    EventType.INSTRUCTOR_LOGIN_SUCCEEDED,
    EventType.INSTRUCTOR_LOGIN_FAILED,
    EventType.INSTRUCTOR_LOGGED_OUT,
})

#: Interaction types that carry a ``scenario_id`` and therefore turn up inside a
#: scenario-scoped query, but which describe browsing rather than progress.
#: Sequence scoring drops these before comparing against an expected sequence,
#: so refresh noise cannot break an otherwise correct run. The evaluation oracle
#: declares its own frozen copy of this set (see
#: ``evaluation/specifications.py``) rather than importing this one.
SCORING_NOISE = frozenset({EventType.PAGE_VIEW})

#: Sanity check at import time: the two classes partition the declared universe.
assert PROGRESSION_EVENTS.isdisjoint(INTERACTION_EVENTS)
assert PROGRESSION_EVENTS | INTERACTION_EVENTS == frozenset(ALL_EVENT_TYPES)


def is_progression(event_type):
    """True when ``event_type`` is a stage-reached milestone (deduplicated)."""
    return event_type in PROGRESSION_EVENTS


def is_interaction(event_type):
    """True when ``event_type`` is repeatable raw telemetry."""
    return event_type in INTERACTION_EVENTS


def milestone_key(session_id, scenario_id, event_type):
    """The idempotency key for one progression milestone, or ``None``.

    ``None`` means the event cannot be deduplicated because it is not
    correlated to both a session and a scenario. Such an event is always
    written -- silently dropping uncorrelated telemetry would lose data, which
    is worse than the duplicate this milestone is trying to prevent.
    """
    if not is_progression(event_type):
        return None
    if not session_id or not scenario_id:
        return None
    return (str(session_id), str(scenario_id), str(event_type))


def _field(event, name):
    """Read ``name`` from a row, a dict, or anything in between."""
    if isinstance(event, dict):
        return event.get(name)
    return getattr(event, name, None)


def drop_scoring_noise(events):
    """Return ``events`` without the raw interaction noise scoring ignores.

    Used wherever an observed stream is compared against an expected sequence.
    Accepts rows, dicts or plain objects, like the rest of the progression code.
    """
    return [e for e in events if _field(e, "event_type") not in SCORING_NOISE]
