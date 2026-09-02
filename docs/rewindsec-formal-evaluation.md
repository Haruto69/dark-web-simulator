# RewindSec formal evaluation harness

A formal SYSTEMS evaluation harness for the **current** RewindSec architecture
(human decision -> technical consequence -> exact rewind -> counterfactual
consequence -> state comparison). Lives in `evaluation/rewindsec_formal_run.py`
and `evaluation/rewindsec_specifications.py`.

## Distinction from the historical harness

`evaluation/formal_run.py` and `evaluation/specifications.py` measure the
**earlier conference-simulator architecture** -- single-branch scenarios
(`credential_reuse_phishing`, `ransomware_awareness`, `file_impact`) with a
progression-milestone telemetry model. That harness is preserved untouched:
this work does not modify its behaviour, rename its scenarios, or bump its
`SPECIFICATION_VERSION`.

This new harness is deliberately distinguishable at every level:

| | historical | RewindSec (this doc) |
|---|---|---|
| module | `evaluation/formal_run.py` | `evaluation/rewindsec_formal_run.py` |
| oracle | `evaluation/specifications.py` | `evaluation/rewindsec_specifications.py` |
| version constant | `SPECIFICATION_VERSION` | `REWINDSEC_SPECIFICATION_VERSION` |
| results directory | `evaluation/results/formal/` | `evaluation/results/rewindsec-formal/` |
| sandbox id prefix | (historical `formal_sandbox_id`) | `rwsf-` |
| scenarios measured | `credential_reuse_phishing`, `ransomware_awareness`, `file_impact` | `phishing_credential_compromise`, `ransomware_incident_response`, `mfa_fatigue_response`, `business_email_compromise` |

Never write RewindSec-formal results into `evaluation/results/formal/`, and
never present historical containment/measurement results as current RewindSec
measurements.

## What this measures (system properties only)

* **A -- pair matrix**: every distinct ordered (factual, counterfactual)
  choice pair per scenario (4 choices -> 12 ordered pairs -> 48 total across
  the four scenarios), each run once and fully verified.
* **B -- deterministic repeatability**: one fixed representative pair per
  scenario, run N times; verifies identical baseline/rewind/factual/
  counterfactual digests and canonical states, identical `pair_id`, but a
  unique `execution_id` per run.
* **C -- rewind integrity**: independently checks `digest(S0) ==
  digest(S0')` for every evaluated pair (reusing Experiment A/B's own
  observations rather than re-running), plus a controlled *negative* test
  (in pytest, not a paper measurement) proving the runtime refuses a
  deliberately corrupted rewind rather than reporting success.
* **D -- staged factual-preview integrity**: measured only for the scenarios
  whose *current* learner flow actually stages a factual preview before the
  authoritative pair -- verified from code to be **ransomware, MFA and BEC**
  (phishing's route does not stage a preview and is correctly excluded).
  Includes a fail-closed check: a deliberately mismatched staged digest must
  cause the execution to be recorded `failed`, never `completed`.
* **E -- training telemetry correctness**: the six-event training lifecycle,
  scored against the independent oracle, reusing Experiment A/B's
  observations (explicitly marked as reused in the result JSON) rather than
  re-running an identical workload.
* **F -- server-side pair latency**: `server_side_pair_seconds`, measured with
  `time.perf_counter()`, reported per scenario (never averaged across
  scenarios, never combining Docker ransomware latency with in-memory
  scenarios).
* **G -- bounded concurrency / isolation**: small concurrency levels (default
  1, 2, 4, 8; 3 trials each), verifying unique session/execution identity, no
  cross-session ownership, and Docker sandbox isolation where applicable.

Containment checks (Docker network/rootfs/capabilities/etc.) are
**re-validated by reusing `evaluation/containment.py`'s existing independent
checks** -- this harness does not reimplement Docker security logic.

## What this does NOT measure

This harness makes **no claim** of educational effectiveness, learning
improvement, behavioural transfer improvement, retention improvement,
statistical significance, or study-arm superiority. It never reads
`StudyEnrollment`, `StudyIntervention`, or `StudyAssessmentAttempt` rows, and
never computes an arm comparison, p-value, or effect size. Passing every
systems check in this harness demonstrates only that the *system* behaves as
specified -- it says nothing about whether a human learner benefits from using
it. Human efficacy is a separate, future study, entirely out of scope here.

## The independent oracle

`evaluation/rewindsec_specifications.py` freezes, as literal strings/tuples
written after reading the current production code (not derived from it at
import time):

* the four scenario keys, their decision ids, and their exact choice ids /
  action keys;
* the six training lifecycle event names, in their required order, plus the
  `TRAINING_EXECUTION_FAILED` event a successful run must never contain;
* independently-checkable consequence facts per choice (e.g. ransomware's
  impacted-file counts: `isolate_and_report` -> 1, `report_without_isolating`
  -> 2, `restart_workstation` -> 3, `continue_working` -> 5);
* which scenarios require Docker, and which scenarios' current learner flow
  stages a factual preview;
* an independently-written canonical-JSON + SHA-256 digest implementation
  (`independent_digest`/`verify_stored_digest`), used to re-verify every
  digest a formal run reports rather than trusting the value production
  returns.

The module must never import scenario/choice tables from
`scenario_adapters`/`training_service`, `training_service.SUCCESS_EVENT_ORDER`,
learning-quality mappings, or a runtime's own result expectations. This is
enforced by `assert_no_production_imports()` (AST-based, not by trusting the
docstring) and asserted independently again from
`tests/test_rewindsec_formal_evaluation.py`.

## Commands

```
# Focused evaluator self-tests
python -m pytest tests/test_rewindsec_formal_evaluation.py -q

# A tiny, non-admissible smoke run (implies --allow-dirty)
python -m evaluation.rewindsec_formal_run --smoke

# A full formal run (refuses a dirty tree; requires Docker for ransomware)
python -m evaluation.rewindsec_formal_run
```

Useful flags: `--experiments A,B,C,D,E,F,G`, `--scenarios <comma list>`,
`--repeatability-runs`, `--staging-runs`, `--performance-runs`,
`--concurrency`, `--concurrency-trials`, `--skip-containment`,
`--docker-image`, `--results-dir`.

## Docker requirement

The ransomware scenario's consequence environment is the real disposable
Docker sandbox -- never `LocalBackend`. Whenever ransomware is selected
alongside a data-producing experiment, the run calls
`evaluation.environment.require_docker_backend` (the same guard the historical
harness uses -- reused, not reimplemented) before doing anything else, and
refuses to start if Docker or the target image is unavailable. There is no
silent fallback that would let an unconfined run masquerade as a contained
measurement.

## Dirty-tree / admissibility policy

By default, a formal run refuses to start against a dirty git working tree.
`--allow-dirty` overrides this for development/smoke use; every result file
from such a run is stamped `admissible: false` and `development_run: true` in
its `metadata`. `--smoke` additionally implies `--allow-dirty`, shrinks every
repeat count to a token size, and writes to a `smoke/` subdirectory of the
results directory. Numbers from a non-admissible run are never citable as
formal results.

## Result directory

`evaluation/results/rewindsec-formal/` (smoke runs: `.../smoke/`), containing
-- only for experiments that actually ran -- `metadata.json`, `summary.json`,
and per-experiment `<name>.json` / `<name>.csv` pairs (`containment`,
`pair_matrix`, `repeatability`, `staging`, `telemetry`, `performance`,
`concurrency`). Every file embeds the specification version, git commit and
dirty state, OS/Python/CPU/memory, Docker versions and target image identity
where relevant, the exact experiment configuration, and a timestamp. No
secrets are ever written. Failed trials are always retained in the rows (never
dropped from a denominator, retried away, or reported as success); a run's
summary lists failed row indices / execution ids explicitly.
