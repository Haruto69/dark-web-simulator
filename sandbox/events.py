"""Structured telemetry event types emitted by the sandbox subsystem."""

from .timeutil import utcnow


class EventType:
    SANDBOX_CREATED = "SANDBOX_CREATED"
    SANDBOX_RESET = "SANDBOX_RESET"
    SANDBOX_DESTROYED = "SANDBOX_DESTROYED"
    SANDBOX_REAPED = "SANDBOX_REAPED"
    SANDBOX_REAP_SCAN = "SANDBOX_REAP_SCAN"
    SCENARIO_STARTED = "SCENARIO_STARTED"
    SCENARIO_COMPLETED = "SCENARIO_COMPLETED"
    SCENARIO_FAILED = "SCENARIO_FAILED"
    FILE_IMPACT_STARTED = "FILE_IMPACT_STARTED"
    FILE_IMPACT = "FILE_IMPACT"
    FILE_IMPACT_REJECTED = "FILE_IMPACT_REJECTED"
    FILE_IMPACT_COMPLETED = "FILE_IMPACT_COMPLETED"

    # -- multi-stage phishing / synthetic credential-reuse scenario --------
    # None of these events ever carries a password value; see
    # ``sandbox/identity.py`` and ``sandbox/scenarios/phishing.py``.
    CONSENT_GRANTED = "CONSENT_GRANTED"
    PHISHING_EXPOSED = "PHISHING_EXPOSED"
    PHISHING_FORM_VIEWED = "PHISHING_FORM_VIEWED"
    CREDENTIAL_SUBMITTED = "CREDENTIAL_SUBMITTED"
    CREDENTIAL_VALIDATED = "CREDENTIAL_VALIDATED"
    CREDENTIAL_VALIDATION_FAILED = "CREDENTIAL_VALIDATION_FAILED"
    SANDBOX_LOGIN_SUCCEEDED = "SANDBOX_LOGIN_SUCCEEDED"
    SYNTHETIC_RESOURCE_ACCESSED = "SYNTHETIC_RESOURCE_ACCESSED"

    # -- ransomware-awareness scenario (was RansomwareFunnel) --------------
    RANSOMWARE_LURE_VIEWED = "RANSOMWARE_LURE_VIEWED"
    RANSOMWARE_DOWNLOAD_CLICKED = "RANSOMWARE_DOWNLOAD_CLICKED"
    RANSOMWARE_TRIGGERED = "RANSOMWARE_TRIGGERED"
    RANSOMWARE_DEBRIEFED = "RANSOMWARE_DEBRIEFED"

    # -- RewindSec counterfactual training lifecycle (R2) ------------------
    # One paired execution emits at most one of each of these. For TRAINING_*
    # events ``scenario_id`` carries the unique ``execution_id`` of the paired
    # execution rather than a scenario run id -- see ``training_service.py``.
    # Details are bounded metadata only: digests, choice ids, action keys,
    # confidence. Never snapshot state, never an exception message.
    TRAINING_EXECUTION_STARTED = "TRAINING_EXECUTION_STARTED"
    TRAINING_BASELINE_CAPTURED = "TRAINING_BASELINE_CAPTURED"
    TRAINING_FACTUAL_CAPTURED = "TRAINING_FACTUAL_CAPTURED"
    TRAINING_REWIND_VERIFIED = "TRAINING_REWIND_VERIFIED"
    TRAINING_COUNTERFACTUAL_CAPTURED = "TRAINING_COUNTERFACTUAL_CAPTURED"
    TRAINING_EXECUTION_COMPLETED = "TRAINING_EXECUTION_COMPLETED"
    TRAINING_EXECUTION_FAILED = "TRAINING_EXECUTION_FAILED"

    # -- raw interaction telemetry ----------------------------------------
    # Repeatable by design. A PAGE_VIEW records that a page was *requested*;
    # it is not a scenario stage and never feeds a progression metric. See
    # ``sandbox/telemetry.py`` for the milestone/interaction split.
    PAGE_VIEW = "PAGE_VIEW"

    # -- instructor authentication ----------------------------------------
    # Auth telemetry never records a password, a username or a source address.
    INSTRUCTOR_LOGIN_SUCCEEDED = "INSTRUCTOR_LOGIN_SUCCEEDED"
    INSTRUCTOR_LOGIN_FAILED = "INSTRUCTOR_LOGIN_FAILED"
    INSTRUCTOR_LOGGED_OUT = "INSTRUCTOR_LOGGED_OUT"


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
        # Naive UTC (see sandbox/timeutil.py) so every timestamp in the
        # SQLite schema is directly comparable.
        "timestamp": timestamp or utcnow(),
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
