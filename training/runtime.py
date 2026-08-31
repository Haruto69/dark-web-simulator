"""The RewindSec counterfactual runtime.

One decision is executed twice from one verified starting state:

    prepare        -> capture baseline S0
    apply(A)       -> capture factual state S_A
    rewind         -> capture rewound state S0'
    VERIFY         fingerprint(S0') == fingerprint(S0), else fail closed
    apply(B)       -> capture counterfactual state S_B
    diff(S_A, S_B)

The verification step is the research invariant of the whole system. Without
it, a comparison between S_A and S_B could reflect uncontrolled environmental
drift rather than the learner's decision, and the counterfactual claim would
not be defensible. So the runtime never trusts an adapter's word that a rewind
succeeded: it re-captures the state and checks the fingerprint itself, and if
they differ it raises :class:`BaselineVerificationError` *before* applying the
alternative consequence.

This module imports nothing from Flask, SQLAlchemy or the ``sandbox`` package.
"""

from typing import Any, Mapping, Optional

from . import observation as obs
from .adapters.base import ConsequenceAdapter
from .comparison import diff_snapshots
from .definitions import (Choice, DecisionPoint, ScenarioDefinition,
                          validate_confidence, validate_response_ms)
from .errors import (AdapterProtocolError, BaselineVerificationError,
                     UnknownActionError)
from .results import COUNTERFACTUAL, FACTUAL, BranchOutcome, CounterfactualPair, derive_pair_id
from .snapshots import StateSnapshot

LABEL_BASELINE = "baseline"
LABEL_FACTUAL = "factual"
LABEL_REWOUND = "rewound"
LABEL_COUNTERFACTUAL = "counterfactual"


class CounterfactualRuntime:
    """Drives one scenario against one consequence adapter.

    The scenario's whole action vocabulary is validated against the adapter at
    construction time, so an unresolvable action is refused before any
    environment is touched rather than midway through a branch.
    """

    def __init__(self, scenario: ScenarioDefinition,
                 adapter: ConsequenceAdapter,
                 observer: Optional[obs.Observer] = None,
                 observer_context: Optional[Mapping[str, Any]] = None):
        if not isinstance(scenario, ScenarioDefinition):
            raise AdapterProtocolError(
                "scenario must be a ScenarioDefinition, got {0}".format(
                    type(scenario).__name__))
        if not isinstance(adapter, ConsequenceAdapter):
            raise AdapterProtocolError(
                "adapter must implement the ConsequenceAdapter contract, got "
                "{0}".format(type(adapter).__name__))
        adapter.check_protocol()
        if observer is not None and not callable(observer):
            raise AdapterProtocolError("observer must be callable")
        self.scenario = scenario
        self.adapter = adapter
        # Optional and inert by default: with no observer the runtime behaves
        # exactly as it did in R1.
        self.observer = observer
        self.observer_context = dict(observer_context or {})
        self._verify_vocabulary()

    def _observe(self, stage: str, decision_id: str, **details) -> None:
        """Emit one lifecycle observation, if an observer is configured.

        Deliberately not wrapped in try/except: a telemetry write that fails
        must stop the run loudly rather than leave a completed experiment with
        an incomplete timeline. See ``training/observation.py``.
        """
        if self.observer is None:
            return
        obs.emit(self.observer, obs.RuntimeObservation(
            stage=stage,
            scenario_key=self.scenario.scenario_key,
            scenario_version=self.scenario.version,
            decision_id=decision_id,
            context=self.observer_context,
            details=details))

    def _verify_vocabulary(self) -> None:
        missing = [key for key in self.scenario.action_keys
                   if key not in self.adapter.supported_actions]
        if missing:
            raise UnknownActionError(
                "scenario {0} names actions the adapter cannot resolve: {1}; "
                "no consequence was executed".format(
                    self.scenario.identity, ", ".join(sorted(missing))))

    # -- primitive steps ---------------------------------------------------
    def _capture(self, label: str) -> StateSnapshot:
        return StateSnapshot.capture(self.adapter.capture_state(), label=label)

    def establish_baseline(self) -> StateSnapshot:
        """Prepare the environment and record the state both branches start
        from."""
        self.adapter.prepare()
        return self._capture(LABEL_BASELINE)

    def apply_choice(self, choice: Choice, label: str) -> StateSnapshot:
        """Enact one choice and capture the state it produced."""
        self.adapter.require_supported(choice.action_key)
        self.adapter.apply(choice.action_key)
        return self._capture(label)

    def rewind_and_verify(self, baseline: StateSnapshot) -> StateSnapshot:
        """Rewind, then prove the environment matches ``baseline``.

        Returns the rewound snapshot on success. Raises
        :class:`BaselineVerificationError` on any mismatch -- the caller must
        not continue, and :meth:`run_decision_pair` does not.
        """
        self.adapter.rewind()
        rewound = self._capture(LABEL_REWOUND)
        if rewound.digest != baseline.digest:
            raise BaselineVerificationError(baseline.digest, rewound.digest)
        return rewound

    # -- the experiment ----------------------------------------------------
    def run_decision_pair(self, decision_id: str, factual_choice_id: str,
                          counterfactual_choice_id: str,
                          factual_confidence: Optional[int] = None,
                          counterfactual_confidence: Optional[int] = None,
                          factual_response_ms: Optional[int] = None,
                          counterfactual_response_ms: Optional[int] = None,
                          session_ref: Optional[str] = None,
                          ) -> CounterfactualPair:
        """Execute both branches of one decision from one verified baseline."""
        decision: DecisionPoint = self.scenario.decision(decision_id)
        factual_choice = decision.choice(factual_choice_id)
        counterfactual_choice = decision.choice(counterfactual_choice_id)

        # Reject bad learner-supplied readings before touching the
        # environment, so an invalid confidence cannot leave a half-run behind.
        factual_confidence = validate_confidence(factual_confidence)
        counterfactual_confidence = validate_confidence(
            counterfactual_confidence)
        factual_response_ms = validate_response_ms(factual_response_ms)
        counterfactual_response_ms = validate_response_ms(
            counterfactual_response_ms)

        # Each observation is emitted immediately after the operation it
        # describes and before the next one begins, so an observed timeline is
        # the causal order of the experiment rather than a reconstruction of it.
        baseline = self.establish_baseline()
        self._observe(obs.BASELINE_CAPTURED, decision.decision_id,
                      baseline_digest=baseline.digest)

        factual_state = self.apply_choice(factual_choice, LABEL_FACTUAL)
        self._observe(obs.FACTUAL_CAPTURED, decision.decision_id,
                      choice_id=factual_choice.choice_id,
                      action_key=factual_choice.action_key,
                      confidence=factual_confidence,
                      response_time_ms=factual_response_ms,
                      state_digest=factual_state.digest)

        # Fails closed: the counterfactual branch below is unreachable unless
        # the rewound environment fingerprints identically to the baseline. No
        # REWIND_VERIFIED observation is emitted on a mismatch, because the
        # rewind was not verified.
        rewound = self.rewind_and_verify(baseline)
        self._observe(obs.REWIND_VERIFIED, decision.decision_id,
                      baseline_digest=baseline.digest,
                      rewound_digest=rewound.digest)

        counterfactual_state = self.apply_choice(counterfactual_choice,
                                                 LABEL_COUNTERFACTUAL)
        self._observe(obs.COUNTERFACTUAL_CAPTURED, decision.decision_id,
                      choice_id=counterfactual_choice.choice_id,
                      action_key=counterfactual_choice.action_key,
                      confidence=counterfactual_confidence,
                      response_time_ms=counterfactual_response_ms,
                      state_digest=counterfactual_state.digest)

        factual_outcome = BranchOutcome(
            role=FACTUAL, choice_id=factual_choice.choice_id,
            action_key=factual_choice.action_key,
            resulting_snapshot=factual_state,
            confidence=factual_confidence,
            response_time_ms=factual_response_ms)
        counterfactual_outcome = BranchOutcome(
            role=COUNTERFACTUAL, choice_id=counterfactual_choice.choice_id,
            action_key=counterfactual_choice.action_key,
            resulting_snapshot=counterfactual_state,
            confidence=counterfactual_confidence,
            response_time_ms=counterfactual_response_ms)

        pair = CounterfactualPair(
            pair_id=derive_pair_id(
                self.scenario.identity, decision.decision_id,
                factual_choice.choice_id, counterfactual_choice.choice_id,
                baseline.digest, session_ref),
            scenario_key=self.scenario.scenario_key,
            scenario_version=self.scenario.version,
            decision_id=decision.decision_id,
            baseline_snapshot=baseline,
            rewound_snapshot=rewound,
            factual=factual_outcome,
            counterfactual=counterfactual_outcome,
            difference=diff_snapshots(factual_state, counterfactual_state),
            adapter_info=dict(self.adapter.describe()),
            session_ref=session_ref)

        self._observe(obs.PAIR_COMPLETED, decision.decision_id,
                      pair_id=pair.pair_id,
                      baseline_digest=pair.baseline_digest,
                      factual_digest=pair.factual.digest,
                      counterfactual_digest=pair.counterfactual.digest,
                      branches_diverged=pair.branches_diverged,
                      change_count=len(pair.difference))
        return pair
