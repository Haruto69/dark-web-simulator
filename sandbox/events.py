"""Structured telemetry event types emitted by the sandbox subsystem."""

from datetime import datetime


class EventType:
    SANDBOX_CREATED = "SANDBOX_CREATED"
    SANDBOX_RESET = "SANDBOX_RESET"
    SANDBOX_DESTROYED = "SANDBOX_DESTROYED"
    SCENARIO_STARTED = "SCENARIO_STARTED"
    SCENARIO_COMPLETED = "SCENARIO_COMPLETED"
    SCENARIO_FAILED = "SCENARIO_FAILED"
    FILE_IMPACT_STARTED = "FILE_IMPACT_STARTED"
    FILE_IMPACT = "FILE_IMPACT"
    FILE_IMPACT_REJECTED = "FILE_IMPACT_REJECTED"
    FILE_IMPACT_COMPLETED = "FILE_IMPACT_COMPLETED"


ALL_EVENT_TYPES = tuple(
    value for key, value in vars(EventType).items()
    if not key.startswith("_") and isinstance(value, str)
)


def make_event(event_type, scenario_id=None, session_id=None, source=None,
               target=None, details=None, timestamp=None):
    """Build a plain-dict telemetry event.

    Deliberately free of Flask/SQLAlchemy so scenario code stays
    framework-independent; the Flask layer supplies a recorder callable that
    persists these dicts into the SecurityEvent table.
    """
    return {
        "event_type": event_type,
        "scenario_id": scenario_id,
        "session_id": session_id,
        "source": source,
        "target": target,
        "details": details,
        # Naive UTC, matching the existing funnel tables' `datetime.utcnow`
        # default so all timestamps in the SQLite schema are comparable.
        "timestamp": timestamp or datetime.utcnow(),
    }


class EventCollector:
    """Minimal in-memory recorder; the default when no persistence is wired."""

    def __init__(self):
        self.events = []

    def __call__(self, event):
        self.events.append(event)
        return event

    def types(self):
        return [e["event_type"] for e in self.events]
