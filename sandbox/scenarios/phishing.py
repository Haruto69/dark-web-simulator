"""Multi-stage phishing / synthetic credential-reuse scenario.

WHAT THIS IS
------------
A *state machine* inside the simulator. A learner is lured from the mock
marketplace to a phishing-style login form, submits the sandbox identity the
simulator itself issued them, and the simulator then demonstrates the
consequence: the same synthetic identity opens a synthetic "internal" resource.

WHAT THIS IS NOT
----------------
It is not a credential-stuffing or account-takeover tool, and must never be
extended into one:

  * the only credentials it understands are the derived, session-scoped
    identities from :mod:`sandbox.identity` (``*@lab.local``);
  * the "reuse" stage targets a **fixed allow-list of internal resource keys**
    -- there is no URL, host, port or destination parameter anywhere;
  * no socket is ever opened. Validation is a local HMAC comparison;
  * a submitted password is compared and then dropped. It is never returned,
    logged, stored, flashed or embedded in telemetry.

Every stage emits telemetry correlated by a single ``scenario_id``.
"""

import uuid

from ..errors import ScenarioStateError
from ..events import EventType, make_event

SCENARIO_NAME = "credential_reuse_phishing"

#: Ordered stages. The Flask layer keeps the current stage in the *server-side*
#: session; ``require_stage`` refuses to skip ahead, so consent and validation
#: cannot be bypassed by requesting a later URL directly.
STAGES = (
    "start",
    "exposed",
    "consented",
    "form_viewed",
    "credential_validated",
    "sandbox_login",
    "resource_accessed",
    "completed",
)

#: The complete universe of "reuse" destinations. Keys only -- never a URL.
SYNTHETIC_RESOURCES = {
    "hr-portal": {
        "title": "hr.lab.local - Employee Records (synthetic)",
        "summary": "Simulated HR portal. Shows the sandbox's synthetic "
                   "employee dataset that the reused identity now reaches.",
    },
    "file-archive": {
        "title": "files.lab.local - Document Archive (synthetic)",
        "summary": "Simulated document archive backed by this session's "
                   "disposable sandbox workspace.",
    },
}
DEFAULT_RESOURCE = "hr-portal"

#: Stand-in recorded when the submitted username is not a known sandbox
#: identity. Keeps a learner-typed real address out of the database entirely.
NON_SANDBOX_IDENTITY = "<non-sandbox-identity>"


def stage_index(stage):
    try:
        return STAGES.index(stage)
    except ValueError:
        return -1


def new_scenario_id():
    return uuid.uuid4().hex[:12]


class PhishingScenario:
    name = SCENARIO_NAME
    description = (
        "Marketplace lure -> phishing-style login -> synthetic credential "
        "validation -> sandbox-only credential reuse -> synthetic resource "
        "access -> debrief. Contained entirely within the simulator."
    )

    def __init__(self, manager, identity_store):
        self.manager = manager
        self.identities = identity_store

    # -- telemetry ---------------------------------------------------------
    def _emit(self, event_type, scenario_id, session_id, target=None, details=None):
        return self.manager.recorder(make_event(
            event_type, scenario_id=scenario_id, session_id=session_id,
            source="scenario:%s" % self.name, target=target, details=details))

    # -- guards ------------------------------------------------------------
    @staticmethod
    def require_stage(current, minimum):
        """Refuse to run a stage before its prerequisite has been reached."""
        if stage_index(current) < stage_index(minimum):
            raise ScenarioStateError(
                "scenario stage %r is required before this step (current: %r)"
                % (minimum, current))
        return current

    @staticmethod
    def _advance(current, reached):
        """Keep the furthest stage reached, so re-visits never regress state."""
        return reached if stage_index(reached) > stage_index(current) else current

    # -- stages ------------------------------------------------------------
    def expose(self, session_id, scenario_id=None, lure=None):
        """Stage 1: the learner meets the lure on the mock marketplace."""
        scenario_id = scenario_id or new_scenario_id()
        self._emit(EventType.SCENARIO_STARTED, scenario_id, session_id,
                   target=self.name, details="scenario=%s started" % self.name)
        self._emit(EventType.PHISHING_EXPOSED, scenario_id, session_id,
                   target=(str(lure)[:200] if lure else None),
                   details="learner reached the phishing lure")
        return {"scenario_id": scenario_id, "stage": "exposed"}

    def grant_consent(self, session_id, scenario_id, stage):
        """Stage 2: server-side record that the briefing was accepted."""
        self.require_stage(stage, "exposed")
        self._emit(EventType.CONSENT_GRANTED, scenario_id, session_id,
                   details="learner accepted the simulation briefing")
        return {"scenario_id": scenario_id,
                "stage": self._advance(stage, "consented")}

    def view_form(self, session_id, scenario_id, stage):
        """Stage 3: the phishing-style login form is rendered."""
        self.require_stage(stage, "consented")
        self._emit(EventType.PHISHING_FORM_VIEWED, scenario_id, session_id,
                   details="phishing-style login form displayed")
        return {"scenario_id": scenario_id,
                "stage": self._advance(stage, "form_viewed")}

    def submit_credential(self, session_id, scenario_id, stage, username, password):
        """Stage 4: validate a submitted identity, then discard the password.

        ``password`` exists only as a local variable for the duration of the
        HMAC comparison. Nothing derived from it is returned.
        """
        self.require_stage(stage, "form_viewed")
        submitted = (username or "").strip().lower()[:120]

        # Only a *recognised* synthetic identity is ever retained. If a learner
        # ignores the briefing and types a real address, we must not store it,
        # so it is collapsed to a placeholder before it reaches telemetry or
        # the database.
        username = (submitted if submitted in self.identities.usernames()
                    else NON_SANDBOX_IDENTITY)

        self._emit(EventType.CREDENTIAL_SUBMITTED, scenario_id, session_id,
                   target=username,
                   details="credential submitted (password not retained)")

        valid, reason = self.identities.validate(session_id, submitted, password)
        del submitted
        del password  # explicit: the submitted secret leaves scope here

        if valid:
            self._emit(EventType.CREDENTIAL_VALIDATED, scenario_id, session_id,
                       target=username,
                       details="matched a sandbox identity issued to this session")
            return {"scenario_id": scenario_id,
                    "stage": self._advance(stage, "credential_validated"),
                    "valid": True, "reason": reason,
                    "synthetic_username": username}

        self._emit(EventType.CREDENTIAL_VALIDATION_FAILED, scenario_id, session_id,
                   target=username, details="reason=%s" % reason)
        return {"scenario_id": scenario_id, "stage": stage, "valid": False,
                "reason": reason, "synthetic_username": username}

    def reuse_credential(self, session_id, scenario_id, stage, synthetic_username):
        """Stage 5: the contained "credential reuse" state transition.

        No destination is accepted from the caller: the identity is simply
        marked as authenticated against this session's own sandbox.
        """
        self.require_stage(stage, "credential_validated")
        self._emit(EventType.SANDBOX_LOGIN_SUCCEEDED, scenario_id, session_id,
                   target=str(synthetic_username)[:120],
                   details="sandbox-internal reuse of the validated synthetic "
                           "identity; no external service contacted")
        return {"scenario_id": scenario_id,
                "stage": self._advance(stage, "sandbox_login")}

    def access_resource(self, session_id, scenario_id, stage, resource_key=None):
        """Stage 6: open one allow-listed synthetic internal resource."""
        self.require_stage(stage, "sandbox_login")
        key = resource_key or DEFAULT_RESOURCE
        if key not in SYNTHETIC_RESOURCES:
            raise ScenarioStateError("unknown synthetic resource: %r" % (key,))
        self._emit(EventType.SYNTHETIC_RESOURCE_ACCESSED, scenario_id, session_id,
                   target=key, details=SYNTHETIC_RESOURCES[key]["title"])
        return {"scenario_id": scenario_id,
                "stage": self._advance(stage, "resource_accessed"),
                "resource": dict(SYNTHETIC_RESOURCES[key], key=key)}

    def complete(self, session_id, scenario_id, stage):
        """Stage 7: educational debrief reached."""
        self.require_stage(stage, "resource_accessed")
        self._emit(EventType.SCENARIO_COMPLETED, scenario_id, session_id,
                   target=self.name, details="scenario=%s completed" % self.name)
        return {"scenario_id": scenario_id,
                "stage": self._advance(stage, "completed")}
