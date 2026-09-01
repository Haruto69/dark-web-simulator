# The RewindSec learning layer (milestone R6)

The counterfactual rewind is not the whole intervention. It shows a learner
what each of two responses actually produced; it does not establish that they
understand the principle behind that comparison, that their confidence matched
the quality of their judgement, which concepts need reinforcement, or whether
the principle survives a change of surface.

R6 adds the layer that asks those four questions, and it asks them
deterministically.

The complete loop is now:

```
observe
  -> decide
  -> state confidence
  -> experience the factual consequence
  -> rewind
  -> try the alternative
  -> compare the executed technical outcomes      <- R1-R5 end here
  -> structured self-explanation                  <- R6
  -> confidence / response feedback               <- R6
  -> concept-level learning evidence              <- R6
  -> unseen transfer probe                        <- R6
```

## Two packages, one direction of dependency

```
training/   executes deterministic counterfactual technical consequences
learning/   interprets completed learner choices using authored
            pedagogical definitions
```

`learning/` imports nothing but the standard library: no Flask, no SQLAlchemy,
no `app`, no `sandbox`, no Docker, no HTTP, no templates — and no `training`
either, so the edge between them runs in one direction only. The scenario keys
it classifies are declared as literals and tied back to the shipped scenarios
by test rather than by import (`tests/test_learning_definitions.py`).

`CounterfactualRuntime` is deliberately not taught about response quality,
confidence bands, concept evidence or reflection. A runtime that scored its own
output could no longer be said to be measuring anything.

The application-side seam is `learning_service.py` (identity, ownership,
idempotent persistence) and `learning_routes.py` (the browser flow), mirroring
the `training_service` / `training_routes` split R2 and R3 established.

## Deterministic, and LLM-free

There is no language model anywhere in this layer, at import time or at
runtime. Every classification, explanation, concept statement, feedback
sentence and probe is written by hand and fixed at import time. Two identical
inputs always produce two equal outputs, and every artifact a learner produces
can be re-derived from the persisted row plus the authored definitions.

## The response quality model

A learner's choice is not globally "correct" or "incorrect". Responses are
classified at three levels, and always **within a scenario**:

| Level | Meaning in the exercise |
| --- | --- |
| `PROTECTIVE` | The response broke the attack chain or contained the incident. |
| `PARTIAL` | The response helped, but left the decisive risk unaddressed. |
| `RISKY` | The response allowed the chain of events to continue. |

These are **authored training classifications**, written by the people who
designed the exercise. They are not measurements and not claims about a person.

The lookup key is always `(scenario_key, choice_id)`. There is no global
`choice_id -> quality` table anywhere in the package, because
`report_without_isolating` means something only inside the ransomware scenario.
An unknown scenario and an unknown choice raise distinct errors and neither
falls back to another scenario's table.

| Scenario | Choice | Quality |
| --- | --- | --- |
| `phishing_credential_compromise` | `follow_link_and_sign_in` | RISKY |
| | `inspect_sender` | PROTECTIVE |
| | `verify_independently` | PROTECTIVE |
| | `report_message` | PROTECTIVE |
| `ransomware_incident_response` | `isolate_and_report` | PROTECTIVE |
| | `report_without_isolating` | PARTIAL |
| | `restart_workstation` | RISKY |
| | `continue_working` | RISKY |
| `mfa_fatigue_response` | `approve_request` | RISKY |
| | `deny_and_report` | PROTECTIVE |
| | `review_signin_details` | PARTIAL |
| | `verify_through_known_channel` | PROTECTIVE |
| `business_email_compromise` | `authorize_payment` | RISKY |
| | `reply_to_request` | PARTIAL |
| | `verify_via_known_contact` | PROTECTIVE |
| | `escalate_to_finance_security` | PROTECTIVE |

## Confidence interpretation

The raw 0..100 reading remains the authoritative measurement and is carried
through unchanged into every artifact, so a later statistical analysis works
from the measurement rather than from a bucket.

`HIGH_CONFIDENCE_THRESHOLD = 70` exists only to select a sentence of learner
feedback:

| Quality | Confidence | Interpretation | Evidence signal |
| --- | --- | --- | --- |
| PROTECTIVE | >= 70 | `confident_protective` | `supporting_evidence` |
| PROTECTIVE | < 70 | `fragile_protective` | `fragile_understanding` |
| RISKY | >= 70 | `high_confidence_risk` | `misconception_candidate` |
| RISKY | < 70 | `recognized_uncertainty` | `needs_reinforcement` |
| PARTIAL | any | `partial_response` | `partial_understanding` |

> **The threshold is an authored feedback rule, not a validated psychometric
> cutoff.** It was chosen for pedagogical legibility, has not been calibrated
> against any instrument, and no claim about a learner's metacognition should be
> derived from which side of it a reading falls.

`PARTIAL` is interpreted the same way whatever the confidence: the response left
the decisive risk in place, and how sure the learner felt about it does not
change what the exercise can claim. A confidence that was never stated is
treated as the cautious reading (`fragile_protective`, `recognized_uncertainty`)
so an absent measurement can never manufacture the strongest signal.

## Concept evidence

A concept tag is a stable, machine-readable identifier for one security idea
the exercise teaches. A choice is mapped only to the concepts it genuinely
provides evidence about — tagging every response with every scenario concept
would make the evidence meaningless, and a test asserts no choice carries its
scenario's full tag set.

| Scenario | Concepts |
| --- | --- |
| phishing | `sender_verification`, `independent_verification`, `credential_exposure` |
| ransomware | `endpoint_isolation`, `incident_reporting`, `recovery_sequence` |
| MFA | `mfa_prompt_verification`, `unexpected_authentication`, `incident_reporting` |
| BEC | `secondary_channel_verification`, `payment_change_verification`, `incident_escalation` |
| quishing probe | `independent_verification`, `credential_exposure`, `channel_switching` |
| update probe | `trusted_software_source`, `endpoint_isolation`, `incident_reporting` |

### What a `ConceptEvidence` row means

> "In this exercise, this response was authored as evidence of this kind about
> this concept."

That is the whole claim.

> **Concept evidence is an authored training signal, not a validated
> psychological diagnosis or mastery score.**

It is not a permanent learner trait, not a validated mastery score, and not a
clinical or educational assessment. R6 computes **no global mastery
percentage** and averages nothing: rows are counted and grouped, never summed
into a number about a person.

### Language

The internal signal `misconception_candidate` names a property of a *response*
— an authored risky choice made with high stated confidence is the pattern most
worth reinforcing. It never reaches a page. The learner-facing wording says:

> "This response suggests these concepts may need reinforcement."

not

> ~~"You have a misconception."~~

A test scans the entire learner-facing vocabulary for diagnosis, mastery and
shame language and fails if any appears.

## Structured self-explanation

After the technical comparison, the learner selects the security principle that
best accounts for what the comparison shows. This is a self-explanation
intervention, and it is deliberately a **structured** one: the learner chooses
from three or four authored options rather than writing prose.

Call it *structured self-explanation* in the documentation, the UI and the
paper. Describing it as unrestricted free-form explanation would misstate the
intervention.

Why structured:

* **Privacy.** Free text is an unbounded channel for personal information; a
  selected identifier is not.
* **Determinism.** Grading prose would need either a runtime model or a human
  rater, and both break the reproducibility the whole system is built on.
* **Reproducibility.** `explanation_id` is stable across runs and sessions, so
  two learners who reason the same way produce the same datum.
* **No free-text grading.** R6 ships no rater, automated or otherwise.

Each scenario has exactly one prompt, three or four options with stable ids,
exactly one preferred explanation, and concept tags per option. A distractor is
plausible but not deceptive: each names a real security-adjacent idea that is
simply not the principle this scenario turns on.

### Prompts are scenario-level, and must stay valid for every allowed pair

A prompt must hold for **every** pair of distinct choices in its scenario, so it
may not presuppose that a particular high-level outcome differed between the two
branches. Several legitimate comparisons are two protective responses whose
technical states differ while the major security outcome does not:

| Scenario | Comparison | Same major outcome |
| --- | --- | --- |
| phishing | `inspect_sender` vs `report_message` | neither exposes credentials or grants synthetic account access |
| MFA | `deny_and_report` vs `verify_through_known_channel` | neither creates a synthetic session or resource access |
| BEC | `verify_via_known_contact` vs `escalate_to_finance_security` | neither authorises the payment |

Asking "why did account access differ?" would be false in those cases. So each
prompt asks which **security principle** the comparison demonstrates, and each
preferred explanation states that principle rather than narrating one branch
against the other.

This also keeps reflection correctness independent of which branch was factual.
The reflection tests understanding of the scenario's principle after the
comparison; it is not a recall question about which response the learner made
first. The evidence semantics are unchanged: the **factual** choice remains the
behavioural evidence, the counterfactual remains intervention context, and the
reflection remains explanation evidence.

The technical state diff on the result page is untouched and still shows the
actual differences truthfully — including for the pairs above, whose states
genuinely do differ even though the major outcome does not.

| Scenario | Prompt | Preferred explanation |
| --- | --- | --- |
| phishing | Which security principle best explains the significance of the two responses you compared? | Verifying or rejecting a suspicious request before disclosing credentials breaks the path from the request to credential exposure and unauthorised synthetic account access. |
| ransomware | Which incident-response principle best explains the consequences shown in this comparison? | Early endpoint isolation limits further *authored* file-impact progression; reporting or recovery actions without containment do not provide the same containment effect. |
| MFA | Which authentication principle best explains the security significance of the responses you compared? | An unexpected MFA request should be denied or independently verified rather than approved, because approval authorises the synthetic sign-in. |
| BEC | Which verification principle best explains the security significance of the responses you compared? | A payment-change request should be verified through a known independent channel, because replying within a potentially compromised email thread does not independently establish authenticity. |

The ransomware explanation says "authored file-impact progression" on purpose.
The file-count model is a deterministic scenario outcome chosen so two responses
can be compared under identical conditions; it is **not** a prediction of how
quickly real ransomware propagates.

## Factual vs counterfactual evidence

This distinction matters for the paper and is enforced in code:

| Act | What it is |
| --- | --- |
| **factual choice** | behavioural evidence — what the learner did unassisted |
| **counterfactual choice** | comparison / intervention context |
| **structured reflection** | explanation evidence — after the intervention |
| **transfer probe** | first response on an unseen surface, after the intervention |

`LearningService.assess_execution` reads `factual_choice_id` and
`factual_confidence` only. The counterfactual branch is the alternative the
learner explored *after* seeing the consequence — part of the intervention, not
a sample of unassisted behaviour — and scoring it as though it were would
misdescribe what was measured. A test asserts the counterfactual's assessment
never appears in the stored `factual_decision` evidence.

## Persistence

Three small tables, deliberately separate from `TrainingExecution`, which stays
exactly what R2 made it: the technical paired-execution result artifact. No
reflection, concept evidence, transfer result or learning score column is added
to it. The learning artifacts link by `execution_id` and nothing else.

Everything is SQLite-compatible: plain columns and `Text`, no vendor JSON type,
nothing `db.create_all()` cannot create. R6 adds no migration machinery,
because the repository still has none.

### `LearningReflection`

`reflection_id` (uuid4, unique), `execution_id` (**unique**), `session_id`,
`scenario_key`, `prompt_key`, `selected_explanation_id`,
`preferred_explanation`, `created_at`.

Exactly one per completed `TrainingExecution`, enforced by the unique
constraint rather than by route discipline alone.

### `ConceptEvidence`

`session_id`, `execution_id`, `scenario_key`, `concept_tag`, `evidence_source`,
`evidence_signal`, `response_quality`, `confidence`, `created_at`, with a
unique constraint on `(execution_id, evidence_source, concept_tag)`.

`evidence_source` is `factual_decision` or `structured_reflection` (with
`transfer_probe` reserved).

### `TransferAttempt`

`attempt_id` (uuid4, unique), `session_id`, `source_execution_id`,
`source_scenario_key`, `probe_key`, `probe_version`, `choice_id`,
`response_quality`, `confidence`, `response_time_ms`, `created_at`, with a
unique constraint on `(source_execution_id, probe_key)`.

### Idempotency

Both write paths catch the integrity error and re-read rather than trusting a
prior `SELECT`, so two concurrent submissions still leave exactly one first
response — which a check-then-insert alone would not guarantee.

* Refresh: no write, anywhere.
* Repeated POST of a reflection: returns the existing feedback; the first
  recorded explanation is never overwritten.
* Repeated POST of a probe: shows the existing result; the first response is
  never replaced.

A Back-button resubmission therefore cannot change research data.

## Unseen transfer probes

A probe presents a security situation on a *different surface* from the
training scenario just completed, and records the learner's **first response**
— before any feedback, comparison or rewind. It is the one measurement in
RewindSec taken after the intervention and without it.

A probe is **not** a counterfactual training module. There is no paired
execution, no baseline fingerprint, no rewind and no `TrainingExecution` row;
`CounterfactualRuntime` is never involved and no `TRAINING_*` event is emitted.

R6 ships exactly two, and no more.

### A. `quishing_portal_qr` (v1) — source: phishing

A printed notice at a fictional polytechnic carries a QR sticker asking staff
to scan it to confirm a registration and their access. Different fictional
organisation, different pretext, different medium: a test asserts none of the
R3 scenario's organisation, sender or lure domain appears on the probe.

| Choice | Quality |
| --- | --- |
| `scan_and_sign_in` | RISKY |
| `inspect_qr_request` | PARTIAL |
| `verify_via_official_portal` | PROTECTIVE |
| `report_qr_message` | PROTECTIVE |

The QR figure is a locally drawn decorative SVG generated from a fixed
arithmetic rule over cell coordinates. It **encodes nothing**. There is no URL,
host, path, payload, `href`, `src` or `data:` URI anywhere on the page — tested
— and no camera or scanning is required or possible.

### B. `unexpected_update_attachment` (v1) — source: ransomware

A workplace chat message says "Critical security update required immediately"
and references an update package. There is **no attachment**: the package name
is inert display text, no file of that name exists in the repository, no route
serves one, and nothing can be opened, downloaded or executed.

| Choice | Quality |
| --- | --- |
| `run_attached_update` | RISKY |
| `restart_then_try_update` | RISKY |
| `verify_update_through_it` | PROTECTIVE |
| `isolate_and_report_attachment` | PROTECTIVE |

### Unlocking, and where the source comes from

A probe is reachable only after (a) a completed `TrainingExecution` for its
source scenario belonging to *this session*, and (b) that execution's
structured reflection having been recorded.

`source_execution_id` is **never accepted from a browser**. The probe names its
source *scenario*; a fixed table maps that to a module; the module's
server-side session state holds the execution id; and the loaded row's
`session_id` is checked again in the service. There is no route parameter, form
field or query string anywhere in the learning blueprint through which a
learner could name an execution.

### Not near, not far

These are recorded as **unseen transfer probes**. Nothing in the code, the
schema or the documentation hard-codes a claim that they represent validated
near or far transfer; how the surfaces differ is a study-design question left
open deliberately.

> **Transfer probes record the learner's first response before feedback or
> replay.**

## MFA and BEC in R6

Both receive the structured self-explanation, the decision assessment, the
confidence feedback and the concept evidence. Neither gets a transfer probe.
Their learning feedback page ends with "Return to training modules", and no
further probes were invented for them.

## Routes

```
GET  /training/learn/<module>/reflection    the structured self-explanation
POST /training/learn/<module>/reflection    record it (once)
GET  /training/learn/<module>/feedback      the deterministic learning review
GET  /training/transfer/<probe>             an unseen probe
POST /training/transfer/<probe>             record the first response (once)
GET  /training/transfer/<probe>/feedback    the probe's authored review
```

`<module>` (`phishing`, `ransomware`, `mfa`, `bec`) and `<probe>` (`quishing`,
`update-attachment`) both resolve through fixed allow-lists. Anything else is a
404 before a lookup happens. No scenario definition, adapter, template or import
path is ever named by a URL.

Every completed technical result page now leads with **"Continue to learning
review"**, and the technical comparison remains visible and complete beneath it.

## Feedback is recomputed, never submitted

The feedback page's three sources of truth are the completed
`TrainingExecution`, the persisted `LearningReflection` and the authored
definitions. No response quality, "correct" flag, confidence category or
concept classification is ever read from a hidden field, a query string or a
form — a test posts all four and asserts nothing changes.

The page shows: the learner's first response and its quality; their stated
confidence and one authored sentence about it; the preferred explanation and
whether their selection matched; and one to three authored concept statements.
That section is headed **"What the comparison shows"** rather than anything
claiming the outcomes differed, for the reason given above.
It shows no grade, no percentage, no mastery bar, no badge, no points, no
leaderboard, no psychological label and no raw state JSON.

## Privacy and safety

* **No free text.** R6 persists no learner-written explanation. Every selection
  is a fixed authored identifier, and there is no `<textarea>` or text input
  anywhere in the flow.
* **No external action.** Probes never fetch a URL, open a socket, download
  content, execute an attachment, call an identity provider, touch a payment
  service, invoke a subprocess or decode anything. Tests drive both probes with
  `subprocess`, `socket` and `os.system` patched to raise.
* **No secrets in learning state.** No password, credential, token, bank
  account, routing number, real email address, arbitrary URL or host path.
* **Session isolation.** Every artifact is scoped to the canonical
  `session_id`. Authorisation is never by pseudonymous label — a label is a
  display artifact, and treating one as an authenticator would make the
  pseudonymisation load-bearing for access control.
* **No Docker required.** The whole R6 layer, including both probes, runs with
  no daemon, no container and no sandbox operation. The ransomware *technical*
  scenario still requires the contained backend; its learning review does not.

## Telemetry decision

**R6 adds no new `SecurityEvent` types.**

`SecurityEvent` remains the authoritative ordered timeline;
`TrainingExecution` remains the technical result artifact; the three new tables
are learning artifacts. Each carries an indexed `created_at`, which is
sufficient to place a reflection, a piece of evidence or a probe attempt on a
timeline relative to the execution it references.

Adding `LEARNING_REFLECTION_COMPLETED` and `TRANSFER_PROBE_COMPLETED` was
considered and rejected for R6:

* the artifacts' own timestamps already answer every ordering question the
  layer raises;
* `sandbox/telemetry.py` asserts at import that `PROGRESSION_EVENTS` and
  `INTERACTION_EVENTS` partition the declared universe, so two new types would
  have meant classifying them and touching the evaluation specifications with
  no analytical gain;
* a learner-interaction event that is neither technical counterfactual
  progression nor page traffic would have blurred a split Milestone 4.2 made
  deliberately sharp.

The six `TRAINING_*` lifecycle events of a successful execution therefore stay
exactly six, before and after the whole learning sequence — asserted per
scenario in `tests/test_learning_flow.py`.

## What R6 deliberately does not do

No study or control groups, randomisation, consent forms, demographics or
recruitment. No statistical significance, effect size or claim of improved
learning. No global mastery score. No adaptive next-scenario selection and no
automatic remediation from concept evidence. No delayed-retention scheduling,
no instructor research dashboard, no CSV export, no additional probes, no LLM
reasoning, no free-text grading. Docker containment and the file-impact
mechanics are untouched.

Efficacy is not claimed. RewindSec has no human data yet.
