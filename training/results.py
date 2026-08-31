"""The paired outcome of one counterfactual decision experiment.

The result is a single explicit object, not a bag of loose dictionaries: the
factual branch, the counterfactual branch, the verified baseline they both
started from, and the delta between them belong together, and separating them
would make it possible to report a comparison whose two halves never shared a
baseline.

Terminology is deliberate and stays internal:

    factual          the path the learner first chose and observed
    counterfactual   the alternative path replayed from the same baseline

A user interface may later present these as "Your Path" and "Rewind Path". That
wording is not baked in here.
"""

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from .comparison import StateDiff
from .definitions import validate_confidence, validate_response_ms
from .errors import BaselineVerificationError
from .snapshots import StateSnapshot

FACTUAL = "factual"
COUNTERFACTUAL = "counterfactual"


def derive_pair_id(scenario_identity: str, decision_id: str,
                   factual_choice_id: str, counterfactual_choice_id: str,
                   baseline_digest: str,
                   session_ref: Optional[str] = None) -> str:
    """A stable, correlatable identifier derived from what was compared.

    Content-derived rather than time- or random-derived, so the same experiment
    is recognisably the same experiment across processes and reruns -- which is
    what reproducibility checking needs. ``session_ref`` (an opaque caller-side
    reference, e.g. a pseudonymous session id) separates one learner's run from
    another's without introducing a timestamp.
    """
    material = json.dumps({
        "scenario": scenario_identity,
        "decision": decision_id,
        "factual": factual_choice_id,
        "counterfactual": counterfactual_choice_id,
        "baseline": baseline_digest,
        "session_ref": session_ref,
    }, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class BranchOutcome:
    """One executed path: the choice taken and the state it produced."""

    role: str
    choice_id: str
    action_key: str
    resulting_snapshot: StateSnapshot
    confidence: Optional[int] = None
    response_time_ms: Optional[int] = None

    def __post_init__(self):
        object.__setattr__(self, "confidence",
                           validate_confidence(self.confidence))
        object.__setattr__(self, "response_time_ms",
                           validate_response_ms(self.response_time_ms))

    @property
    def digest(self) -> str:
        return self.resulting_snapshot.digest

    def as_dict(self) -> Dict[str, Any]:
        return {
            "role": self.role,
            "choice_id": self.choice_id,
            "action_key": self.action_key,
            "state_digest": self.digest,
            "state": self.resulting_snapshot.state,
            "confidence": self.confidence,
            "response_time_ms": self.response_time_ms,
        }


@dataclass(frozen=True)
class CounterfactualPair:
    """Two branches of one decision, provably run from one verified baseline.

    ``rewound_snapshot`` is retained on purpose: it is the evidence that the
    environment really was returned to ``baseline_snapshot`` before the
    counterfactual branch executed, and its digest is asserted equal to the
    baseline digest at construction time.
    """

    pair_id: str
    scenario_key: str
    scenario_version: int
    decision_id: str
    baseline_snapshot: StateSnapshot
    rewound_snapshot: StateSnapshot
    factual: BranchOutcome
    counterfactual: BranchOutcome
    difference: StateDiff
    adapter_info: Dict[str, Any] = field(default_factory=dict)
    session_ref: Optional[str] = None

    def __post_init__(self):
        # A pair that did not start from one verified baseline must not be
        # representable at all. An explicit raise, not an assert: this check
        # must survive ``python -O``.
        if self.baseline_snapshot.digest != self.rewound_snapshot.digest:
            raise BaselineVerificationError(
                self.baseline_snapshot.digest, self.rewound_snapshot.digest,
                "refusing to construct a CounterfactualPair whose branches did "
                "not start from the same verified baseline")

    @property
    def scenario_identity(self) -> str:
        return "{0}@{1}".format(self.scenario_key, self.scenario_version)

    @property
    def baseline_digest(self) -> str:
        return self.baseline_snapshot.digest

    @property
    def branches_diverged(self) -> bool:
        """Whether the two choices actually produced different outcomes."""
        return self.factual.digest != self.counterfactual.digest

    def as_dict(self) -> Dict[str, Any]:
        """Structured result, ready for a telemetry mapping in a later
        milestone. Nothing here writes to the database."""
        return {
            "pair_id": self.pair_id,
            "scenario_key": self.scenario_key,
            "scenario_version": self.scenario_version,
            "scenario_identity": self.scenario_identity,
            "decision_id": self.decision_id,
            "session_ref": self.session_ref,
            "baseline_digest": self.baseline_digest,
            "rewound_digest": self.rewound_snapshot.digest,
            "baseline_verified": True,
            "factual": self.factual.as_dict(),
            "counterfactual": self.counterfactual.as_dict(),
            "difference": self.difference.as_dict(),
            "branches_diverged": self.branches_diverged,
            "adapter": dict(self.adapter_info),
        }
