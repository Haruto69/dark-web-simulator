"""The ``ransomware_incident_response`` scenario (RewindSec milestone R4).

The second complete learner-facing RewindSec scenario, and the first whose
consequence environment is the **real contained sandbox** rather than an
in-memory state machine:

    synthetic workstation, one document already impacted
      -> learner response decision (+ confidence)
      -> progressive controlled file impact inside the sandbox
      -> factual state, observed from the workspace
      -> rewind: destroy, reseed, reapply the same one-file symptom
      -> verified identical baseline
      -> alternative response
      -> side-by-side comparison

The starting state is deliberately **not** the pristine five-file dataset. The
learner arrives at the moment they first notice suspicious file activity, so
the baseline both branches run from is:

    five known synthetic files, exactly one of them already impacted

AUTHORED TRAINING MODEL
-----------------------
The file counts each response produces (1, 2, 3, 5) are an authored teaching
model. They exist to give every response a deterministic, observable and
comparable consequence. They are **not** a predictive model of real-world
ransomware propagation speed, and must never be documented as one.

SAFETY BOUNDARY
---------------
This module contains no filesystem logic at all. Every impact is requested
through :meth:`sandbox.manager.SandboxManager.apply_synthetic_impact`, which
validates each target against the fixed synthetic allow-list before the
existing backend and ``impact_core`` gates (allow-listed filename *and*
known-baseline content) run downstream. There is no encryption, no key, no
path, no glob, no recursion, no directory listing, no shell, no subprocess and
no network here. The learner never supplies a target: the progression is a
module-level constant.
"""

import copy

from sandbox.dataset import BASELINE_FILENAMES
from training import (Choice, ConsequenceSpec, DecisionPoint,
                      ScenarioDefinition)
from training.adapters.base import ConsequenceAdapter
from training.errors import AdapterProtocolError

RANSOMWARE_SCENARIO_KEY = "ransomware_incident_response"
RANSOMWARE_SCENARIO_VERSION = 1
RANSOMWARE_DECISION_ID = "respond_to_file_impact"
RANSOMWARE_PROMPT_KEY = "first_observed_file_impact"

#: The learner scenario is published only on the contained backend. The local
#: backend provides workspace confinement but no container, process or network
#: isolation, so it is never presented to a learner as the same thing.
REQUIRED_BACKEND = "docker"

# -- action vocabulary -------------------------------------------------------
# Closed and symbolic. The adapter is the only component that resolves these.
ACTION_ISOLATED_AND_REPORTED = "workstation_isolated_and_reported"
ACTION_REPORTED_ONLY = "incident_reported_without_isolation"
ACTION_RESTARTED = "workstation_restarted"
ACTION_WORK_CONTINUED = "work_continued_on_workstation"

RANSOMWARE_ACTIONS = frozenset({
    ACTION_ISOLATED_AND_REPORTED,
    ACTION_REPORTED_ONLY,
    ACTION_RESTARTED,
    ACTION_WORK_CONTINUED,
})

#: The fixed order in which synthetic files are impacted. Taken straight from
#: the existing dataset declaration order, so it is deterministic, reviewable
#: and identical on every machine. No randomness, no discovery, no globbing.
IMPACT_PROGRESSION = tuple(BASELINE_FILENAMES)

#: S0: the single file already impacted when the learner first looks at the
#: workstation. One fixed name from the allow-list, chosen here and never by a
#: request.
INITIAL_IMPACT = IMPACT_PROGRESSION[0]

#: How far along :data:`IMPACT_PROGRESSION` each response ends up. The first
#: entry is always S0's single file, so every response is measured from the
#: same starting symptom.
#:
#: AUTHORED TRAINING MODEL -- deterministic scenario outcomes for controlled
#: comparison, not a prediction of real propagation speed.
ACTION_IMPACT_TOTAL = {
    ACTION_ISOLATED_AND_REPORTED: 1,
    ACTION_REPORTED_ONLY: 2,
    ACTION_RESTARTED: 3,
    ACTION_WORK_CONTINUED: len(IMPACT_PROGRESSION),
}

#: Authored response flags each action sets, beyond the file impact itself.
ACTION_FLAGS = {
    ACTION_ISOLATED_AND_REPORTED: {"isolated": True, "restarted": False,
                                   "reported": True},
    ACTION_REPORTED_ONLY: {"isolated": False, "restarted": False,
                           "reported": True},
    ACTION_RESTARTED: {"isolated": False, "restarted": True,
                       "reported": False},
    ACTION_WORK_CONTINUED: {"isolated": False, "restarted": False,
                            "reported": False},
}


def additional_targets(action_key):
    """The files an action impacts *in addition* to S0's one file.

    Always a prefix of :data:`IMPACT_PROGRESSION` with S0's file removed, so
    every target is provably an allow-listed synthetic filename and the
    sequence is identical on every run.
    """
    total = ACTION_IMPACT_TOTAL[action_key]
    return tuple(IMPACT_PROGRESSION[1:total])


def ransomware_choices():
    """The decision's choices, in the order the learner sees them."""
    return (
        Choice("isolate_and_report",
               "Isolate the workstation and report the incident",
               ConsequenceSpec(ACTION_ISOLATED_AND_REPORTED),
               description="Disconnect the machine from the network, then "
                           "tell the security team what you saw."),
        Choice("report_without_isolating",
               "Report the incident but leave the workstation connected",
               ConsequenceSpec(ACTION_REPORTED_ONLY),
               description="Tell the security team, and carry on with the "
                           "machine still on the network."),
        Choice("restart_workstation",
               "Restart the workstation",
               ConsequenceSpec(ACTION_RESTARTED),
               description="Reboot the machine and see whether the problem "
                           "clears itself."),
        Choice("continue_working",
               "Keep working and see if the problem stops",
               ConsequenceSpec(ACTION_WORK_CONTINUED),
               description="Carry on with your work and wait to see whether "
                           "anything else happens."),
    )


RANSOMWARE_SCENARIO = ScenarioDefinition(
    scenario_key=RANSOMWARE_SCENARIO_KEY,
    version=RANSOMWARE_SCENARIO_VERSION,
    title="Ransomware Incident Response",
    competency_tags=("endpoint_containment", "incident_reporting",
                     "ransomware_response"),
    decision_points=(DecisionPoint(RANSOMWARE_DECISION_ID,
                                   RANSOMWARE_PROMPT_KEY,
                                   ransomware_choices()),))

#: Stable choice ids, for server-side validation of a submitted choice.
RANSOMWARE_CHOICE_IDS = RANSOMWARE_SCENARIO.decision(
    RANSOMWARE_DECISION_ID).choice_ids


def ransomware_choice_labels():
    """``choice_id -> display label``, derived from the definition itself."""
    decision = RANSOMWARE_SCENARIO.decision(RANSOMWARE_DECISION_ID)
    return {choice.choice_id: choice.label for choice in decision.choices}


# -- observed-state validation ----------------------------------------------
#: Workspace statuses the adapter accepts. ``missing`` is deliberately absent:
#: a baseline file that is neither present nor impacted means the workspace is
#: not in a state this scenario can reason about, and the run fails closed.
OBSERVABLE_STATUSES = frozenset({"baseline", "impacted"})


class WorkspaceIntegrityError(AdapterProtocolError):
    """The observed workspace is not a state this scenario can describe.

    Raised for an unknown filename, a duplicate, a missing baseline file, or an
    unexpected status. Fails closed: an unrecognised workspace is never
    canonicalised into a snapshot and never persisted.
    """


def read_file_condition(rows):
    """Validate a backend workspace report and split it into two ordered lists.

    ``rows`` is exactly what ``SandboxManager.workspace_state`` returns:
    ``[{"name", "status", "present_as"}, ...]``. Only the fixed synthetic
    universe may appear. Ordering of the result follows
    :data:`IMPACT_PROGRESSION`, never the order the backend happened to report,
    so the digest depends on the workspace condition alone.
    """
    if not isinstance(rows, (list, tuple)):
        raise WorkspaceIntegrityError(
            "workspace state must be a sequence, got %s" % type(rows).__name__)
    seen = {}
    for row in rows:
        if not isinstance(row, dict):
            raise WorkspaceIntegrityError("workspace entry is not a mapping")
        name, status = row.get("name"), row.get("status")
        if name not in IMPACT_PROGRESSION:
            raise WorkspaceIntegrityError(
                "workspace contains an entry outside the fixed synthetic "
                "dataset; refusing to describe it")
        if name in seen:
            raise WorkspaceIntegrityError(
                "workspace reported %r more than once" % name)
        if status not in OBSERVABLE_STATUSES:
            raise WorkspaceIntegrityError(
                "synthetic file %r has unexpected status %r" % (name, status))
        seen[name] = status
    missing = [name for name in IMPACT_PROGRESSION if name not in seen]
    if missing:
        raise WorkspaceIntegrityError(
            "workspace is missing %d known synthetic file(s)" % len(missing))
    impacted = [name for name in IMPACT_PROGRESSION if seen[name] == "impacted"]
    available = [name for name in IMPACT_PROGRESSION
                 if seen[name] == "baseline"]
    return impacted, available


def build_state(impacted, available, flags):
    """The canonical scenario state.

    Contains only: known synthetic filenames, their counts, and three authored
    boolean response flags. No file contents, no host path, no container id, no
    backend stderr, no learner text.
    """
    return {
        "endpoint": {
            "isolated": bool(flags["isolated"]),
            "restarted": bool(flags["restarted"]),
        },
        "incident": {"reported": bool(flags["reported"])},
        "files": {
            "impacted": list(impacted),
            "available": list(available),
            "impacted_count": len(impacted),
            "available_count": len(available),
        },
    }


def _blank_flags():
    return {"isolated": False, "restarted": False, "reported": False}


class RansomwareConsequenceAdapter(ConsequenceAdapter):
    """Consequence environment backed by the real disposable sandbox.

    Satisfies the R1 adapter contract. The sandbox is reached only through
    ``SandboxManager``; this class holds no container handle, runs no command
    and touches no filesystem.

    One action per branch. ``prepare`` and ``rewind`` both rebuild the exact
    same starting point -- a freshly reseeded pristine workspace with the one
    predetermined file re-impacted -- and reset the logical action state, so
    the runtime's independent fingerprint check on the rewind is a real test
    rather than a formality.
    """

    supported_actions = RANSOMWARE_ACTIONS
    environment_kind = "contained_synthetic_workstation"

    def __init__(self, manager, sandbox_id, session_id=None):
        if manager is None or sandbox_id is None:
            raise AdapterProtocolError(
                "the ransomware adapter needs a SandboxManager and a "
                "session-scoped sandbox id")
        self.manager = manager
        # Server-derived. Never taken from a form, query string or URL.
        self.sandbox_id = sandbox_id
        self.session_id = session_id
        self._flags = _blank_flags()
        self._applied = None

    @property
    def applied_action(self):
        """The one action applied on this branch, or ``None``."""
        return self._applied

    # -- lifecycle ---------------------------------------------------------
    def _establish_initial_impact(self):
        """Pristine workspace, then exactly the one predetermined impact."""
        self.manager.reset(self.sandbox_id, session_id=self.session_id)
        self.manager.apply_synthetic_impact(
            [INITIAL_IMPACT], sandbox_id=self.sandbox_id,
            session_id=self.session_id)
        self._flags = _blank_flags()
        self._applied = None

    def prepare(self):
        self._establish_initial_impact()

    def rewind(self):
        self._establish_initial_impact()

    # -- observation -------------------------------------------------------
    def capture_state(self):
        """Derive the state from the actual sandbox workspace.

        A pure observation: nothing here writes, and the flags are read from
        this adapter's own logical response state.
        """
        impacted, available = read_file_condition(
            self.manager.workspace_state(self.sandbox_id))
        return build_state(impacted, available, copy.deepcopy(self._flags))

    # -- consequence -------------------------------------------------------
    def apply(self, action_key):
        self.require_supported(action_key)
        if self._applied is not None:
            # One learner response per branch. Stacking two responses would
            # make the branch uncomparable, so it is refused rather than
            # silently compounded.
            raise AdapterProtocolError(
                "a response has already been applied on this branch; rewind "
                "before applying another")
        targets = additional_targets(action_key)
        if targets:
            self.manager.apply_synthetic_impact(
                list(targets), sandbox_id=self.sandbox_id,
                session_id=self.session_id)
        self._flags = dict(ACTION_FLAGS[action_key])
        self._applied = action_key

    def describe(self):
        info = dict(super().describe())
        info["synthetic_file_allow_list"] = sorted(IMPACT_PROGRESSION)
        info["initial_impact_count"] = 1
        return info
