# RewindSec training runtime (milestone R1)

The `training/` package is the deterministic core of RewindSec: it executes one
learner decision **twice** — the path the learner actually took, and the
alternative path replayed from a verified identical starting state — and reports
a structured comparison of the two outcomes.

It is deliberately framework-independent. It imports nothing from Flask,
SQLAlchemy, or the `sandbox` package, and is tested without Flask and without
Docker. The application layer drives this runtime; the runtime never reaches
back into the application.

## Deterministic counterfactual execution, not a generated hypothetical

This distinction is the point of the system.

A language model can *describe* what might have happened had the learner chosen
differently. That description is a plausible narration, not evidence: it is not
reproducible, it is not verifiable, and nothing was actually run.

RewindSec **executes both outcomes**. The alternative branch is a real
consequence applied to a real controlled environment, starting from a state
whose canonical fingerprint has been proven equal to the one the first branch
started from. The comparison the learner sees is a record of two things that
happened, not a story about one that did not.

## The invariant

> The counterfactual branch is executed only after the environment has been
> rewound and its canonical baseline fingerprint matches the baseline captured
> before the factual branch.

Executed order, enforced in `CounterfactualRuntime.run_decision_pair`:

```
prepare()               ->  capture baseline   S0
apply(factual action)   ->  capture factual    S_A
rewind()                ->  capture rewound    S0'
VERIFY  fingerprint(S0') == fingerprint(S0)     <-- else fail closed
apply(counterfactual)   ->  capture alternative S_B
diff(S_A, S_B)
```

If the fingerprints differ, the runtime raises `BaselineVerificationError` and
the alternative consequence **is never applied**. This matters because the only
variable that may differ between the two branches is the learner's decision. A
comparison drawn across two different starting states would reflect uncontrolled
environmental drift, and the counterfactual claim would not be defensible.

An adapter is never trusted to self-report a successful rewind. The runtime
re-captures the state and checks the fingerprint itself.

The invariant is pinned by two tests named so they can be cited directly:

- `test_counterfactual_branch_runs_from_verified_identical_baseline`
- `test_counterfactual_branch_refuses_mismatched_rewind_baseline`

## Fingerprints

A `StateSnapshot` holds canonical JSON (sorted keys, no insignificant
whitespace, NaN and Infinity rejected) and its SHA-256 digest. Python's built-in
`hash()` is never used: it is salted per process and would make digests
incomparable across runs, which is exactly what reproducibility checking needs.

Two logically equivalent states therefore produce the same digest regardless of
mapping insertion order. Snapshots reject keys that look like credentials
(`password`, `secret`, `token`, `api_key`, …) — snapshots are compared and
retained, so they must not carry secrets.

## The consequence safety boundary

A scenario definition may name **what** should happen. It may never describe
**how** to make it happen.

A `ConsequenceSpec` carries a single opaque `action_key`: a short symbolic token
matching `^[a-z][a-z0-9_]{0,63}$`. That pattern alone excludes shell commands,
dotted import paths, URLs, and filesystem paths, and a further deny-list rejects
tokens containing `import`, `eval`, `exec`, `subprocess`, `system`, `popen` and
`lambda`. A `Choice` must hold a real `ConsequenceSpec` — a bare string or a
callable is refused.

```python
Choice("isolate_endpoint", "Disconnect and report",
       ConsequenceSpec("endpoint_isolated"))     # allowed

ConsequenceSpec("docker exec -it sandbox sh")     # ScenarioDefinitionError
ConsequenceSpec("sandbox.backends.docker:Docker") # ScenarioDefinitionError
Choice("x", "Run it", some_callable)              # ScenarioDefinitionError
```

Resolution happens only inside a **trusted adapter**, which declares a fixed
`supported_actions` vocabulary. `CounterfactualRuntime.__init__` validates the
scenario's entire action vocabulary against the adapter up front, so an
unresolvable action fails before any environment is touched — never midway
through a branch.

## Adapters

```
prepare()          bring the environment to its verified starting state
capture_state()    return a JSON-safe mapping (a pure observation)
apply(action_key)  enact one named consequence
rewind()           restore the starting state
```

That is the whole contract. The runtime holds no container handle and issues no
command, so the same runtime drives an in-memory fake today and, in a later
milestone, a sandbox adapter delegating through `SandboxManager`. The runtime
must never reach into `DockerBackend` or `LocalBackend` directly.

`training/adapters/memory.py` provides `InMemoryConsequenceAdapter` (the
deterministic fake used throughout the tests) and `DriftingRewindAdapter`, a
deliberately broken adapter whose rewind does not restore baseline — it exists
to prove the runtime fails closed.

## Result structure

`CounterfactualPair` is one explicit object, not a bag of loose dictionaries:

```
pair_id                content-derived, stable, no timestamps
scenario_key / version
decision_id
baseline_snapshot      S0   (+ digest)
rewound_snapshot       S0'  retained as the evidence of verification
factual                BranchOutcome: choice_id, action_key, S_A,
                       optional confidence (0..100), optional response_time_ms
counterfactual         BranchOutcome: the same, for the replayed path
difference             StateDiff between S_A and S_B
adapter_info, session_ref
```

The type itself refuses construction when the baseline and rewound digests
differ, so a pair whose branches did not share a baseline is not representable —
even by code that bypasses the runtime.

Terminology stays *factual* / *counterfactual* internally. A UI may later say
"Your Path" and "Rewind Path"; that wording is not baked into the runtime.

## State diff

`diff_states(before, after)` walks mappings recursively and returns changes in
sorted path order. Every change is `added`, `removed`, or `changed`. Subtrees are
reported leaf by leaf. Lists are compared atomically (one changed value, not a
positional edit script) — deterministic and easy to reason about; positional list
diffing can come later if a scenario needs it.

```python
{"path": ["files", "impacted"], "pointer": "files.impacted",
 "change": "changed", "from": 5, "to": 1}
```

The delta is a neutral factual record. No prose, no scoring, no safe/unsafe
labels — interpretation belongs to a later milestone, and keeping it out is what
lets the delta stay evidence.

## Deliberately not in R1

No Flask wiring, no route changes, no telemetry writes, no `SecurityEvent`
schema change, and no conversion of the existing phishing, file-impact or
ransomware flows — those continue to work exactly as before, alongside this
package. No scoring, mastery levels, misconception inference, adaptive
difficulty, or LLM integration.

`CounterfactualPair.as_dict()` exposes enough structured data that authoritative
telemetry can be wired deliberately in the next milestone, once the new event
model is designed.

## Worked example

```python
from training import (Choice, ConsequenceSpec, CounterfactualRuntime,
                      DecisionPoint, ScenarioDefinition)
from training.adapters import InMemoryConsequenceAdapter

baseline = {"account": {"compromised": False},
            "files": {"impacted": 0},
            "endpoint": {"isolated": False}}


def reuse(state):
    state["account"]["compromised"] = True
    state["files"]["impacted"] = 5


def isolate(state):
    state["endpoint"]["isolated"] = True
    state["files"]["impacted"] = 1


adapter = InMemoryConsequenceAdapter(
    baseline, {"credentials_reused": reuse, "endpoint_isolated": isolate})

scenario = ScenarioDefinition(
    scenario_key="credential_prompt", version=1,
    title="Unexpected credential prompt",
    competency_tags=("phishing",),
    decision_points=(DecisionPoint("respond_to_prompt", "unexpected_prompt", (
        Choice("reuse_password", "Enter the usual password",
               ConsequenceSpec("credentials_reused")),
        Choice("isolate_endpoint", "Disconnect and report",
               ConsequenceSpec("endpoint_isolated")),
    )),))

pair = CounterfactualRuntime(scenario, adapter).run_decision_pair(
    "respond_to_prompt",
    factual_choice_id="reuse_password",
    counterfactual_choice_id="isolate_endpoint",
    factual_confidence=80)
```

Result:

```
baseline   S0    947bf5fc  {"account":{"compromised":false},"endpoint":{"isolated":false},"files":{"impacted":0}}
factual    S_A   d9e4a1b3  {"account":{"compromised":true},"endpoint":{"isolated":false},"files":{"impacted":5}}
rewind     S0'   947bf5fc  == S0  -> verified, the alternative may proceed
counterfac S_B   cddea897  {"account":{"compromised":false},"endpoint":{"isolated":true},"files":{"impacted":1}}

delta (factual -> counterfactual)
  account.compromised   changed   true -> false
  endpoint.isolated     changed   false -> true
  files.impacted        changed   5 -> 1
```
