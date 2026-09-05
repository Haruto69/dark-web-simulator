# Provenance: RewindSec v1 vs RewindSec 2.0

This is an engineering document, not a research narrative. It records which
parts of this repository belong to the **pre-2.0 (v1) system** and which belong
to the **RewindSec 2.0 rebuild**, so that no later change can silently present
v1 artifacts as 2.0 evidence.

It exists because the two systems will live side by side in one repository for
a while, and because the most damaging possible defect here is not a crash. It
is a table, a results file or a figure that is quietly attributed to the wrong
architecture.

**Baseline of record:** tag `v1.0.0` = commit `0421c8a`
(*Polish RewindSec frontend experience*), on branch `rewindsec-redesign`.
That tag is the complete, working v1 system. Anything described below as "v1"
can be recovered from it exactly.

---

## 1. The rules

1. **v1 study and evaluation data must never be pooled with, relabelled as, or
   presented as RewindSec 2.0 evidence.** Not by re-running a v1 harness against
   2.0 code, not by adding 2.0 rows to a v1 table, not by merging result
   directories.
2. **Every historical evaluation result stays attributable to the architecture
   it actually measured.** The files under `evaluation/results/**` measured v1.
   They do not become 2.0 measurements because 2.0 later exists in the same
   repository.
3. **RewindSec 2.0 uses separately named packages, models, tables, harnesses and
   results directories.** Separation is structural, not a matter of discipline:
   if the names are disjoint, no query, join or glob can accidentally mix the
   two populations.
4. **No module under `rewindsec/` may import v1 study, learning, scenario or
   historical evaluation code.** Enforced statically by
   `tests/test_provenance.py`.
5. **Historical v1 code is not deleted or rewritten during the 2.0 rebuild.**
   It is the provenance of published and in-progress claims.

---

## 2. Reusable technical ideas and infrastructure

These are **not** v1-specific claims. They are engineering assets, and 2.0 is
expected to reuse or port them. Reusing them creates no provenance problem,
because they carry no experimental result.

| Component | What is reusable |
|---|---|
| `training/snapshots.py` | Canonical JSON (`canonical_json`) + SHA-256 state fingerprinting (`fingerprint`), with rejection of secret-shaped keys, non-finite floats and non-string keys. Explicitly avoids process-salted `hash()`. |
| `training/runtime.py` | The **verify-before-continue** invariant: after a rewind, re-capture and re-hash, and fail closed on mismatch (`CounterfactualRuntime.rewind_and_verify`, `BaselineVerificationError`). |
| `training/adapters/base.py` | The `prepare` / `capture_state` / `apply` / `rewind` contract, the closed symbolic action vocabulary, and the rule that capturing state must never change it. |
| `sandbox/` (all of it) | Container containment flags, ownership by label + name prefix, content-verified readiness seeding, the two-gate synthetic file impact (`sandbox/impact_core.py`), path policy (`sandbox/paths.py`), derived sandbox ids (`sandbox/session_scope.py`), age-based reaping. |
| `sandbox/sanitize.py`, `sandbox/pseudonym.py` | Error sanitisation and pseudonymisation for instructor-facing views. |
| `telemetry_ledger.py` | The SAVEPOINT + unique-constraint idempotency claim pattern. |
| `security.py` | CSRF, login throttling, session rotation, instructor auth. |
| `manage.py` | Explicit, confirmation-gated database commands. |

Reuse of these is a code decision. It is never, on its own, evidence about
2.0's behaviour: 2.0 must be measured by its own harness.

---

## 3. v1 learner architecture

The v1 learner experience: one labelled threat-family module per URL, one
decision per attempt, attempt state in the signed Flask cookie, a full page
render per step, and a rewind that reconstructs a single authored baseline.

| Path | Role |
|---|---|
| `training/` | Framework-free paired-counterfactual runtime, scenario definitions, comparison and observation types. |
| `training_routes.py` | The `/training` blueprint: phishing and ransomware flows (`brief`, `start`, `inbox`/`workstation`, `decision`, `outcome`, `rewind`, `result`). |
| `training_flow.py` | `SyntheticModule` / `register_synthetic_module`, the shared MFA and BEC flow. |
| `training_service.py` | The Flask/SQLAlchemy seam: identity, persistence, staged-preview integrity, telemetry translation. |
| `scenario_adapters/` | `phishing.py`, `ransomware.py`, `mfa.py`, `bec.py`, `presentation.py` — the four v1 scenario keys. |
| `TrainingExecution` (`app.py`) | One paired-execution result row: digests, both branch states, the difference, failure type. |
| `learning/`, `learning_service.py`, `learning_routes.py` | The v1 pedagogy layer: reflection quality, concept evidence, transfer probes. |
| `LearningReflection`, `ConceptEvidence`, `TransferAttempt` (`app.py`) | The v1 pedagogy tables. |
| v1 learner templates | `templates/training_*.html`, `templates/_training_*.html`, `templates/index.html`, `templates/resources.html`, and `templates/training_base.html`. |
| v1 scenario docs | `docs/phishing-scenario.md`, `docs/ransomware-scenario.md`, `docs/mfa-scenario.md`, `docs/bec-scenario.md`, `docs/learning-layer.md`, `docs/training-runtime.md`. |

**Status:** frozen for reference. 2.0 will replace this learner architecture,
but the v1 code stays until 2.0 covers its function, and its behaviour is not
edited to suit 2.0.

**Provenance note:** these modules define what the v1 study and the v1 formal
evaluation actually measured. Changing them retroactively changes the meaning of
every stored result, which is why they are not refactored during the rebuild.

---

## 4. v1 study and protocol artifacts

A randomised pilot **of the v1 phishing module**. Disabled by default
(`REWINDSEC_STUDY_ENABLED`), fail-closed without its three secrets.

| Path | Role |
|---|---|
| `study/` | Framework-free protocol code: `assignment.py` (HMAC arm allocation), `protocol.py` (phase machine), `continuity.py` (return codes), `assessment.py`, `errors.py`. |
| `study_service.py` | Enrollment, phase advance, the three arms, retention windows, `export_rows()`, `dashboard()`. |
| `study_routes.py` | The `/study` blueprint. |
| `StudyEnrollment`, `StudyIntervention`, `StudyAssessmentAttempt` (`app.py`) | The three v1 study tables. |
| `templates/study_*.html` | The participant-facing study screens. |
| `docs/study-protocol.md` | The protocol as executed. |
| `tests/test_study_*.py` | Eight test modules, including the privacy assertions. |

**Status:** **frozen**. Do not repoint, extend or reuse for 2.0.

**Why frozen:** the arms, the assessment items and the retention windows are all
defined against v1's single-decision phishing module. A participant row in
`StudyEnrollment` means "took part in the v1 pilot" and can mean nothing else.
Recruiting 2.0 participants into these tables would make the two populations
indistinguishable after the fact.

**For 2.0:** a new protocol, new tables with new names, and a new document. Not
an extra column on these.

---

## 5. v1 evaluation artifacts and results

Two harnesses exist, measuring two different v1 architectures. Both are
historical.

| Harness | Measures | Results |
|---|---|---|
| `evaluation/formal_run.py` + `evaluation/specifications.py` | The earlier Milestone-4 simulator (scenario keys `credential_reuse_phishing`, `file_impact`, `ransomware_awareness`). | `evaluation/results/formal/` |
| `evaluation/rewindsec_formal_run.py` + `evaluation/rewindsec_specifications.py` | The v1 paired-counterfactual architecture (scenario keys `phishing_credential_compromise`, `ransomware_incident_response`, `mfa_fatigue_response`, `business_email_compromise`). | `evaluation/results/rewindsec-formal/` |

Supporting modules: `evaluation/containment.py`, `evaluation/environment.py`,
`evaluation/metrics.py`, `evaluation/run_experiments.py`. Documentation:
`docs/rewindsec-formal-evaluation.md`.

**Status:** **frozen.** Do not edit either harness's semantics, and do not edit
any file under `evaluation/results/**`.

### Standing caveat on the stored `rewindsec-formal` results

`evaluation/results/rewindsec-formal/smoke/metadata.json` records
`"admissible": false`, `"development_run": true`, `"smoke": true`,
`"git_tree_dirty": true`, at commit `7a72743` — which is **not** the `v1.0.0`
baseline. These are development numbers produced by a reduced-configuration
smoke run against a dirty tree. They are not admissible results for any claim
about anything, and the `admissible: false` flag must never be dropped when
these files are summarised, copied or quoted.

### How the results are protected

`evaluation/results/` is listed in `.gitignore` (line 38), so **git does not
track these files and cannot detect a change to them**. That makes an explicit
integrity record necessary rather than optional.

`evaluation/results_manifest.json` records the relative path, SHA-256 and byte
size of each of the 32 artifacts present at commit `0421c8a`.
`tests/test_provenance.py` verifies every entry when the results tree exists,
and skips when it does not — a fresh clone or a CI machine legitimately has no
results tree, and failing there would be noise rather than signal. Files present
on disk but absent from the manifest are allowed, so a **new** run can be added
without editing the manifest; what the manifest forbids is a listed artifact
being modified or deleted.

**For 2.0:** a third harness, named separately (e.g.
`evaluation/rewindsec2_*`), writing to a separate directory (e.g.
`evaluation/results/rewindsec2/`), with its own independent oracle. Never
re-run a v1 harness against 2.0 code and report the numbers as a continuation.

---

## 6. RewindSec 2.0 artifacts

Everything 2.0 owns lives under `rewindsec/`.

| Path | Role |
|---|---|
| `rewindsec/core/rng.py` | `SeededRandom`: the single randomness owner, with independently derived named streams and full state capture/restore. |
| `rewindsec/core/simtime.py` | `SimClock`: integer-millisecond simulation time, independent of the wall clock. |
| `rewindsec/core/events.py` | `Event` and `EventSpec`: the canonical event model, with SHA-256-derived event identity and behavioural (never threat-family) type names. |
| `rewindsec/core/scheduler.py` | `EventScheduler`: the deterministic delayed-event queue, ordered by `(fire_at_ms, priority, insertion_seq)`. |

Rules for anything added here:

* **Framework-free core.** Nothing under `rewindsec/core/` may import Flask,
  SQLAlchemy, `sandbox`, or any v1 module.
* **No hidden nondeterminism.** Nothing under `rewindsec/core/` may import
  `secrets`, `uuid`, `time` or `datetime`. `random` may be imported only by
  `rewindsec/core/rng.py`, where it is wrapped behind explicitly seeded
  `random.Random` instances that the session owns.
* **Separate names.** 2.0 models, tables, harnesses and results directories get
  their own names; they never extend a v1 one.

Both rules are enforced by
`tests/test_rewindsec2_core_boundaries.py` and `tests/test_provenance.py`.

Wall-clock timestamps are not banned from the project — only from deterministic
state. They belong in diagnostic and telemetry layers outside `rewindsec/core/`.

### Batch 1: simulation domain and persistence

`rewindsec/domain/` and `rewindsec/persistence/` add the storage-independent
session aggregate on top of the core above, and the port/adapter pair that
persists it.

| Path | Role |
|---|---|
| `rewindsec/domain/session.py` | `SimulationSession`: the aggregate root composing the core (`SeededRandom`, `SimClock`, `EventScheduler`) with the domain objects below, and the only object responsible for cross-object referential integrity. |
| `rewindsec/domain/world.py` | `WorldState`: versioned, generic, auditable workplace state (no Mail/Files/Browser backends yet — later batches). |
| `rewindsec/domain/context_ledger.py` | `ContextLedger`: the available-vs-observed distinction as first-class state. |
| `rewindsec/domain/actions.py` | `LearnerAction`/`ActionLog`: observational vs. consequential learner actions, with their own SHA-256-derived id scheme, distinct from event ids. |
| `rewindsec/domain/session_events.py` | `SessionEventLog` (reuses `core.events.derive_event_id` directly) and `ScheduleAuditLog`, the durable record of what was scheduled/fired/cancelled and why, independent of the live scheduler's own swept state. |
| `rewindsec/domain/incidents.py` | `IncidentGraph`: the generic, threat-agnostic causal consequence graph. |
| `rewindsec/persistence/ports.py` | `SessionRepository`: the storage-independent repository contract, with an optimistic-concurrency (`expected_revision`) update contract. |
| `rewindsec/persistence/sqlalchemy_adapter.py` | The one adapter Batch 1 ships: reuses the app's existing SQLAlchemy dependency, isolated from Flask, no pickle, versioned JSON snapshots. |

Rules for anything added here:

* **Storage- and framework-independent domain.** Nothing under
  `rewindsec/domain/` may import Flask, Flask-SQLAlchemy, SQLAlchemy, `random`,
  or any v1 module; it must be usable in a pure Python test with no app context
  and no database.
* **SQLAlchemy stays in the adapter.** Only `rewindsec/persistence/
  sqlalchemy_adapter.py` may import SQLAlchemy; `ports.py` (the contract) does
  not, and neither module imports Flask.
* **One event-id scheme.** `SessionEventLog` uses `core.events.derive_event_id`
  directly; it does not invent a second one. `LearnerAction` ids use their own,
  distinct, SHA-256 label so the two schemes can never collide.

Enforced by `tests/test_rewindsec2_domain_boundaries.py`, alongside the
adversarial unit and resume-determinism suites
(`tests/test_rewindsec2_domain_*.py`, `tests/test_rewindsec2_persistence_*.py`,
`tests/test_rewindsec2_resume_determinism.py`,
`tests/test_rewindsec2_cross_process_determinism.py`).

No application content, threat-family engine, scoring, or UI wiring is part of
this batch — see the batch's own completion report for the full boundary.

---

## 7. Quick reference

| Category | Verdict |
|---|---|
| Reusable infrastructure (§2) | Port or reuse freely. Carries no experimental claim. |
| v1 learner architecture (§3) | Frozen for reference. Replaced by 2.0, not edited to suit it. |
| v1 study artifacts (§4) | Frozen. Never extended or repointed for 2.0. |
| v1 evaluation harnesses and results (§5) | Frozen. Never re-run against 2.0 and reported as continuous. |
| RewindSec 2.0 (§6) | New names, new tables, new harness, framework-free deterministic core. |
