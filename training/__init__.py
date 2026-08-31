"""RewindSec training runtime -- deterministic counterfactual replay.

A framework-independent core: given a scenario definition and a consequence
adapter, it executes one decision twice -- the learner's factual path, then the
alternative path replayed from a *verified identical* baseline -- and reports a
structured comparison of the two outcomes.

The invariant this package exists to enforce:

    The counterfactual branch is executed only after the environment has been
    rewound and its canonical baseline fingerprint matches the baseline
    captured before the factual branch.

Both outcomes are really executed in a controlled environment. Neither is a
hypothetical narrated by a language model.

This package must not import Flask, SQLAlchemy or ``sandbox``. It is driven by
those layers, never the reverse.
"""

from .adapters.base import ConsequenceAdapter
from .comparison import (ADDED, CHANGED, REMOVED, StateChange, StateDiff,
                         diff_snapshots, diff_states)
from .definitions import (CONFIDENCE_MAX, CONFIDENCE_MIN, Choice,
                          ConsequenceSpec, DecisionPoint, ScenarioDefinition,
                          validate_confidence)
from .errors import (AdapterProtocolError, BaselineVerificationError,
                     ConfidenceValueError, ScenarioDefinitionError,
                     SnapshotError, TrainingError, UnknownActionError)
from .results import (COUNTERFACTUAL, FACTUAL, BranchOutcome,
                      CounterfactualPair, derive_pair_id)
from .runtime import CounterfactualRuntime
from .snapshots import StateSnapshot, canonical_json, fingerprint

__all__ = [
    "ADDED", "CHANGED", "REMOVED",
    "CONFIDENCE_MIN", "CONFIDENCE_MAX",
    "FACTUAL", "COUNTERFACTUAL",
    "AdapterProtocolError", "BaselineVerificationError", "BranchOutcome",
    "Choice", "ConfidenceValueError", "ConsequenceAdapter", "ConsequenceSpec",
    "CounterfactualPair", "CounterfactualRuntime", "DecisionPoint",
    "ScenarioDefinition", "ScenarioDefinitionError", "SnapshotError",
    "StateChange", "StateDiff", "StateSnapshot", "TrainingError",
    "UnknownActionError",
    "canonical_json", "derive_pair_id", "diff_snapshots", "diff_states",
    "fingerprint", "validate_confidence",
]
