# Ransomware Incident Response (RewindSec milestone R4)

The second complete RewindSec scenario, and the first whose consequence
environment is the real contained sandbox rather than an in-memory state
machine.

    synthetic workstation, one document already impacted
      -> learner response decision (+ confidence)
      -> progressive controlled file impact inside a container
      -> factual state, observed from the workspace
      -> rewind: destroy, reseed, reapply the same one-file symptom
      -> verified identical baseline
      -> alternative response
      -> side-by-side comparison, rendered from the persisted execution

---

## Scenario definition

| | |
|---|---|
| `scenario_key` | `ransomware_incident_response` |
| `version` | `1` |
| `decision_id` | `respond_to_file_impact` |
| `prompt_key` | `first_observed_file_impact` |
| competency tags | `endpoint_containment`, `incident_reporting`, `ransomware_response` |

Defined in `scenario_adapters/ransomware.py`. As with phishing, the definition
names *what* may happen and never *how*: every choice carries an opaque
symbolic `ConsequenceSpec` action key, and `training/definitions.py` rejects
paths, URLs, dotted import paths, commands and callables at construction time.

### The four responses

| choice id | display label | action key |
|---|---|---|
| `isolate_and_report` | Isolate the workstation and report the incident | `workstation_isolated_and_reported` |
| `report_without_isolating` | Report the incident but leave the workstation connected | `incident_reported_without_isolation` |
| `restart_workstation` | Restart the workstation | `workstation_restarted` |
| `continue_working` | Keep working and see if the problem stops | `work_continued_on_workstation` |

Only the adapter resolves an action key. The runtime validates the scenario's
whole vocabulary against the adapter before any environment is touched, so an
unresolvable key fails closed rather than being interpreted.

---

## The fixed initial one-file impact

The baseline both branches run from is **not** the pristine five-file dataset.
The learner arrives at the moment they first notice suspicious file activity:

    five known synthetic files, exactly one of them already impacted

`INITIAL_IMPACT` is `employee_records.csv` — the first entry of the existing
`sandbox/dataset.py` declaration order. It is a module constant, chosen once and
never supplied by a request.

`prepare()` establishes S0 as:

1. `SandboxManager.reset(...)` — destroy and reseed, producing a workspace
   proven byte-identical to the synthetic baseline;
2. `SandboxManager.apply_synthetic_impact([INITIAL_IMPACT], ...)` — exactly one
   allow-listed target;
3. reset the logical response state.

`rewind()` performs the identical sequence. R1 then independently re-captures
the state and refuses to run the alternative branch unless
`digest(S0') == digest(S0)`.

---

## Authored progression model

`IMPACT_PROGRESSION` is the dataset declaration order:

    employee_records.csv, finance_report.txt, project_notes.txt,
    client_database.csv, thesis_draft.txt

Each response ends at a fixed point along it, always including S0's one file:

| response | total impacted | endpoint | incident |
|---|---|---|---|
| `isolate_and_report` | 1 | isolated | reported |
| `report_without_isolating` | 2 | connected | reported |
| `restart_workstation` | 3 | restarted, connected | not reported |
| `continue_working` | 5 | connected | not reported |

**The progressive file counts are deterministic scenario outcomes used for
controlled comparison; they are not a predictive model of real-world ransomware
propagation speed.** They exist so that every response has an observable,
reproducible consequence that can be compared against another response under
identical starting conditions. No randomness, no timing dependence, no
discovery: two runs of the same action sequence produce byte-identical
canonical state.

---

## Docker requirement

The published learner module runs **only** on the contained `DockerBackend`.
`training_routes._containment_status()` requires all of:

* a sandbox manager and a session-derived sandbox id are wired in;
* `backend.name == "docker"`;
* `backend.is_available()` — a live daemon;
* `backend.image_available()` — the target image is built.

If any check fails the module reports itself unavailable: `/training` lists it
as *Unavailable here*, the briefing explains why, and every state-changing route
returns `503` with the unavailable page. No `TrainingExecution` is created and
no impact is applied. There is deliberately no fallback to `LocalBackend` —
workspace confinement is not the same claim as container isolation, and the
learner is never shown a reduced-isolation run as if it were the real thing.
`LocalBackend` remains available for development and for the test suite.

---

## Safe file-impact boundary

`scenario_adapters/ransomware.py` contains **no filesystem logic at all**. It
holds no container handle, runs no command, and never touches
`manager.backend`. Every impact goes through one narrow method.

### The one SandboxManager extension

`SandboxManager.apply_synthetic_impact(targets, sandbox_id, session_id)` was
added in R4. It adds no capability; it is a validating delegation that exists
because the manager previously exposed no way to impact a *subset* of the
dataset without either reaching into `self.backend` or driving
`FileImpactScenario` (whose `SCENARIO_*` / `FILE_IMPACT_*` progression telemetry
belongs to the instructor demo, not to a paired training execution).

It is *stricter* than `backend.run_impact`:

* `targets` must be an explicit non-empty list — an empty selection does **not**
  mean "the entire dataset", so nothing can impact everything by omission;
* every target passes `normalise_target` here, before the backend sees it;
* a refused target raises instead of being returned as a result row, so a
  caller cannot mistake a refusal for an applied impact.

Downstream, both existing gates in `sandbox/impact_core.py` still run
unmodified: the name must be in `BASELINE_FILENAMES`, **and** the bytes on disk
must be the known synthetic baseline. `DockerBackend.image_available()` was also
added — a read-only `docker image inspect` for the availability check above.

### What is still absent, and must stay absent

No encryption, keys, ciphers or decryption path. No arbitrary targets or paths,
traversal, globbing, recursion, directory walking or filesystem discovery. No
user-supplied filenames. No host mounts, Docker socket, network, persistence,
propagation, shell, arbitrary commands, executables, malware, or
ransom-payment logic. The learner has no control over which filesystem paths are
operated on: the progression is a module-level constant.

---

## Adapter state schema

`capture_state()` derives the file condition from the actual sandbox workspace
via `SandboxManager.workspace_state`, and adds three authored response flags:

```json
{
  "endpoint": {"isolated": false, "restarted": false},
  "incident": {"reported": false},
  "files": {
    "impacted": ["employee_records.csv"],
    "available": ["finance_report.txt", "project_notes.txt",
                  "client_database.csv", "thesis_draft.txt"],
    "impacted_count": 1,
    "available_count": 4
  }
}
```

Deliberately absent: file contents, host paths, the container id, backend
stderr, learner text. Ordering follows `IMPACT_PROGRESSION`, never the order the
backend happened to report, so the digest depends on the workspace condition
alone.

`read_file_condition` **fails closed** with `WorkspaceIntegrityError` on an
unknown filename, a duplicate, a missing baseline file, or an unexpected status.
An unrecognised workspace is never canonicalised into a snapshot and never
persisted.

---

## One action per branch

    prepare()   establishes S0 and resets the logical action state
    apply(a)    exactly one response
    apply(b)    refused (AdapterProtocolError) until a rewind happens
    rewind()    re-establishes S0 and resets the logical action state

Stacking two responses would make a branch uncomparable, so it is refused rather
than silently compounded.

---

## The factual preview, and deterministic replay

The learner must *see* what their first response caused before choosing a
rewind path, but `run_pair` executes factual + rewind + counterfactual together.
Rather than bypassing `CounterfactualRuntime`, R4 stages a deterministic
**preview** using the same adapter and the same action key:

| step | route | what happens |
|---|---|---|
| A | `POST /training/ransomware/start` | `prepare()` establishes S0; the baseline digest and state are recorded in the server-side session |
| B | `GET /training/ransomware/workstation` | the live workspace is re-observed and must still fingerprint as that same S0, else fail closed (409) |
| C | `POST /training/ransomware/decision` | `prepare()` re-establishes S0, the digest is re-proved, then the factual action is applied and the preview snapshot captured |
| D | `GET /training/ransomware/outcome` | renders the stored preview snapshot — nothing is executed, so a refresh impacts nothing |
| E | `POST /training/ransomware/rewind` | the alternative is chosen |
| F | — | `training_service().run_pair(...)` runs the authoritative experiment |

The authoritative run is unchanged: prepare S0 → apply factual → capture →
rewind → verify → apply counterfactual → capture.

---

## Preview-to-pair consistency

The state shown to the learner before the rewind must be the state the
authoritative factual branch later produces. `TrainingService.run_pair` gained
two optional checks, applied *after* the pair is built and *before* the row is
completed:

    expected_baseline_digest
    expected_factual_digest

A mismatch raises `StagedExecutionMismatchError` inside the guarded section, so
the execution is recorded as **failed** — never completed — with that class name
as `failure_type`, a `TRAINING_EXECUTION_FAILED` event, and no comparison
rendered. The pure R1 runtime is untouched: it still knows nothing about
browser staging, and these are checks on the *record*, not inputs to the
experiment.

R4 therefore establishes, in one attempt:

    decision-page baseline digest
      == factual-preview baseline digest
      == paired execution baseline digest
      == rewound counterfactual baseline digest

---

## Factual and counterfactual semantics

`factual_*` always carries the response the learner actually made first;
`counterfactual_*` the alternative they picked after the rewind. They are never
swapped so that the more damaging branch lands on a particular side. If the
learner chooses `isolate_and_report` and rewinds to `continue_working`, "Your
path" is `isolate_and_report` — and the reverse holds equally.

Response times mirror R3 and are measured server-side in bounded integer
milliseconds: the factual latency ends when the response is submitted, and the
counterfactual latency ends when the alternative is submitted. Sandbox
execution time is never counted as learner decision latency.

---

## Telemetry

The authoritative timeline is R2's, unchanged and not duplicated:

    TRAINING_EXECUTION_STARTED
    TRAINING_BASELINE_CAPTURED
    TRAINING_FACTUAL_CAPTURED
    TRAINING_REWIND_VERIFIED
    TRAINING_COUNTERFACTUAL_CAPTURED
    TRAINING_EXECUTION_COMPLETED

No new event types, and no legacy `SCENARIO_*` / `FILE_IMPACT_*` progression
from this flow — which is precisely why the narrow `apply_synthetic_impact`
delegation was preferred over driving `FileImpactScenario`. Low-level
`SANDBOX_CREATED` / `SANDBOX_RESET` lifecycle events occur naturally through
`SandboxManager` and may coexist. The `TrainingExecution` row's state and
digests are the paired-experiment evidence.

---

## Session isolation and lifecycle

The sandbox id is derived server-side from the session id
(`sandbox_id_for_session`). There is no route parameter, form field or query
string anywhere in the training blueprint through which a learner could name a
sandbox. Two learners never share a workspace, and one session can neither
inspect, reset, impact nor read results from another's — the result row is found
through the server-side session and its `session_id` must still match.

Start and restart create or reset only the learner's own sandbox. Ownership
label protections, the stale reaper and the rest of the established lifecycle
are unchanged; R4 adds no global Docker cleanup.

---

## Legacy flow separation

The legacy `/ransomware/*` marketplace demo is untouched and still passes its
own tests. The new module depends on none of it: no fake download, no symbolic
`RansomwareRunState`, no ransom screen, no marketplace. It also has no ransom
note, no countdown, no payment address and no hacker terminal — the workstation
view is a neutral file list, an alert line and four responses. Removing the
legacy flow is a later cleanup milestone, once both new core scenarios are
stable.
