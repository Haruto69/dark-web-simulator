"""Optional lifecycle observation for the counterfactual runtime.

The runtime is the single implementation of the paired experiment. Telemetry
must therefore be emitted *from inside it*, in the order operations actually
happen -- not reconstructed afterwards from a finished result, which would let
the recorded timeline claim an ordering the run never had.

So the runtime accepts an optional observer: a callable taking one
:class:`RuntimeObservation`. It stays framework-independent. This module
imports nothing but the standard library, and an observation carries only
bounded, safe scalars -- never raw state, never secrets.

``context`` is an opaque mapping the caller hands to the runtime and gets back
on every observation. The runtime never reads it. That is how an application
correlates observations with its own execution identity without the runtime
knowing what an ``execution_id`` is.

Observer failures are **not** swallowed. If an observer raises, the exception
propagates and the run stops where it stopped. Silently discarding a failed
telemetry write would leave a completed experiment with a timeline that never
recorded it -- a worse outcome than a loud failure the application can record
against the execution row.
"""

from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Callable, Mapping, Optional

# -- lifecycle stages --------------------------------------------------------
# Deliberately few: one per causally meaningful step of the paired experiment,
# not one per function call.

BASELINE_CAPTURED = "baseline_captured"
FACTUAL_CAPTURED = "factual_captured"
REWIND_VERIFIED = "rewind_verified"
COUNTERFACTUAL_CAPTURED = "counterfactual_captured"
PAIR_COMPLETED = "pair_completed"

STAGES = (BASELINE_CAPTURED, FACTUAL_CAPTURED, REWIND_VERIFIED,
          COUNTERFACTUAL_CAPTURED, PAIR_COMPLETED)

#: The order the runtime emits them in when a run succeeds. A run that fails
#: baseline verification stops after REWIND_VERIFIED is *not* reached.
EXPECTED_ORDER = STAGES


@dataclass(frozen=True)
class RuntimeObservation:
    """One causally-ordered fact about a paired run in progress."""

    stage: str
    scenario_key: str
    scenario_version: int
    decision_id: str
    context: Mapping[str, Any] = field(default_factory=dict)
    details: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "context",
                           MappingProxyType(dict(self.context or {})))
        object.__setattr__(self, "details",
                           MappingProxyType(dict(self.details or {})))

    @property
    def scenario_identity(self) -> str:
        return "{0}@{1}".format(self.scenario_key, self.scenario_version)

    def as_dict(self):
        return {
            "stage": self.stage,
            "scenario_key": self.scenario_key,
            "scenario_version": self.scenario_version,
            "scenario_identity": self.scenario_identity,
            "decision_id": self.decision_id,
            "context": dict(self.context),
            "details": dict(self.details),
        }


Observer = Callable[[RuntimeObservation], Any]


class ObservationCollector:
    """Minimal in-memory observer, mirroring ``sandbox.events.EventCollector``."""

    def __init__(self):
        self.observations = []

    def __call__(self, observation: RuntimeObservation):
        self.observations.append(observation)
        return observation

    def stages(self):
        return [item.stage for item in self.observations]


def emit(observer: Optional[Observer], observation: RuntimeObservation):
    """Deliver one observation, if an observer is configured."""
    if observer is None:
        return None
    return observer(observation)
