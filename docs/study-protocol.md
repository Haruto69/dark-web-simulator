# The RewindSec study protocol (milestone R7)

R7 adds a **research mode**: the infrastructure needed to run a randomised
controlled pilot of RewindSec without contaminating the ordinary training
experience.

It is infrastructure only.

> **RewindSec does not claim efficacy from the existence of this
> infrastructure.** Learning-effect claims require data collected under an
> appropriate approved study protocol.

> **Research-mode enablement is not a substitute for institutional ethics
> review, participant consent, or study registration where those are
> required.**

> **Enabling research mode is an operational setting and does not constitute
> ethics approval, consent, or study registration.**

No participant has been recruited, no approval has been obtained, and no
approval number, consent text or registration identifier appears anywhere in
this repository. Nothing in the application computes a p-value, an effect size,
a significance test or an "improvement" label.

## The question the infrastructure is built to test

> Does deterministic counterfactual replay plus structured self-explanation
> improve protective transfer behaviour compared with a conventional debrief and
> with factual-consequence simulation?

R7 makes that question *testable*. It does not answer it, and no part of the
software behaves as though it had been answered.

## Scope: the phishing module only

The protocol is `rewindsec_phishing_pilot`, version `1`, and its single source
scenario is `phishing_credential_compromise`.

That restriction is deliberate:

* all three intervention arms can be implemented on it **without Docker**, so
  the pilot can run wherever a browser can;
* every participant can be shown an **identical** initial scenario, message and
  decision;
* the factual first decision is therefore measurable identically in every arm,
  before any intervention exists;
* the immediate transfer probe (`quishing_portal_qr`) already exists and is
  built on the same underlying principle.

**Ransomware, MFA fatigue and BEC are not part of this protocol.** They remain
full RewindSec demonstration modules, and no human-study claim may be made about
any of them.

Everything in the data model is keyed by `(protocol_key, protocol_version)`, so
a second source scenario can later be added as a second protocol without
rewriting a table, a route or an export column.

## The three arms

Stable keys, used throughout the code, the database and the export. The
learner-facing UI never names one, and the words "control" and "experimental"
appear nowhere in the participant flow.

| key | intervention |
|---|---|
| `awareness_debrief` | first decision → concise static awareness debrief |
| `factual_consequence` | first decision → the learner's own response executed and shown → concise authored debrief |
| `counterfactual_replay` | first decision → factual consequence → exact rewind → learner-chosen alternative → paired comparison → structured self-explanation |

### Arm A — `awareness_debrief`

After the first decision the participant sees a short authored page stating the
three principles the scenario turns on: inspect the request, verify through an
independently trusted channel, never present credentials to an unverified
request.

The consequence adapter is **not** constructed and **not** applied. No branch
state, no simulated account access, no rewind, no alternative decision, no state
diff and no structured reflection appear. It is the conventional awareness
condition, and it is deliberately a *real* conventional debrief rather than a
weakened one — an arm built to lose would not be worth comparing against.

No `TrainingExecution` row exists for this arm.

### Arm B — `factual_consequence`

The real `PhishingConsequenceAdapter` runs from a verified S0:

```
prepare → capture baseline → apply the learner's own action → capture factual result
```

The resulting state is shown, followed by the same authored debrief Arm A
receives. There is no rewind, no alternative execution, no paired counterfactual
and no state diff.

Refreshing does not re-apply the action: the intervention row's
`factual_result_digest` is the idempotency gate, so what the participant sees
cannot drift from what was recorded.

No `TrainingExecution` row exists for this arm either.

### Arm C — `counterfactual_replay`

The real RewindSec mechanism, reused unchanged. After the same first decision
and the same factual consequence, the participant chooses an alternative, and
the R2 `TrainingService` runs the pair over the R1 `CounterfactualRuntime`. Both
staged digests are passed through, so the service fails closed if the
authoritative run does not reproduce exactly the baseline the participant
started from and exactly the factual outcome they were shown.

The comparison is then displayed and the existing R6 structured
self-explanation is recorded, producing a `LearningReflection` and its derived
`ConceptEvidence`.

**Exactly one `TrainingExecution` row exists for this arm**, and the same six
`TRAINING_*` lifecycle events are emitted, once each.

### Why `TrainingExecution` is not reused for arms A and B

`TrainingExecution` means **one paired counterfactual execution**. Arm A
executes nothing and Arm B executes one branch; neither has a pair. Writing a
row for either would have made the table's name false and would have quietly
broken every query and test that relies on its meaning.

`StudyIntervention` exists instead. Which of its columns are populated *is* the
arm difference, recorded explicitly rather than inferred.

## The identical first decision

Every arm sees the same fictional organisation, the same message, the same four
choices in the same order, the same confidence control and the same visual
treatment. The arm is not consulted anywhere on that page, and the decision is
persisted **before** any arm-specific content is resolved.

Recorded once, and never revisable: `choice_id`, the raw confidence `0..100`,
the server-measured `response_time_ms`, the authored response quality (derived
server-side, never submitted) and the concept tags.

This is the pre-intervention behavioural measure. Nothing later — not the
counterfactual choice, not the reflection, not a transfer response — is treated
as the baseline.

## The measurements

### Immediate transfer

All three arms answer the same probe, `quishing_portal_qr`, immediately after
their intervention. It is *reused* from `learning.transfer` rather than copied,
so the instrument is literally the same one the ordinary flow uses.

**No feedback is shown afterwards.** The completion page says only "Response
recorded." Revealing the response quality, the protective answer or the security
principle would make the measurement a further training intervention and would
contaminate the retention probe that follows it. The ordinary, non-study R6
probe keeps its full feedback; the suppression exists only in study mode.

### Retention window

Set from the moment the immediate response is recorded:

```
retention_open_at  = immediate_completed_at + 7 days
retention_close_at = immediate_completed_at + 14 days
```

**The 7–14 day window is an authored study protocol choice, not evidence that
this interval is optimal.** Neither figure is calibrated against anything.

Submission is impossible before the window opens and after it closes; inside it
exactly one attempt is accepted, and a repeated POST returns the stored first
response rather than replacing it. The boundary is inclusive at both ends, so a
participant arriving on the instant the window opens is admitted.

### Retention transfer probe

`smishing_account_notice`, version 1 — study-only, and deliberately **not**
registered in `learning.TRANSFER_PROBES`, so it is unreachable from the ordinary
R6 transfer routes.

A fictional mobile-message notification claims an account action is required
urgently and asks the participant to sign in through the route the message
supplies. It tests the same underlying verification principle on a third
surface: an email in training, a printed QR code immediately after, a phone
message later.

| choice | display | quality |
|---|---|---|
| `follow_message_and_sign_in` | Use the message route and sign in | RISKY |
| `inspect_message_details` | Inspect the message details first | PARTIAL |
| `open_official_service` | Open the known official service independently | PROTECTIVE |
| `report_suspicious_message` | Report the suspicious message | PROTECTIVE |

Concepts: `independent_verification`, `credential_exposure`,
`channel_switching`.

There is no SMS, no external URL, no clickable destination, no login, no
credential form and no network call. The page is static authored simulation.

This is a **retention transfer probe**. It is not called "far transfer":
whether two surfaces are near or far is a judgement about the surfaces, and
nothing here is entitled to make it.

## Assignment

Balanced, deterministic, permuted blocks of six — two of each arm per block.

Within a block the order is a permutation derived by keyed HMAC-SHA256 from
`(secret, protocol_key, protocol_version, block_index)`, applied by Fisher–Yates
with rejection sampling over the fixed multiset. The *contents* of every block
are fixed by construction, so a bug in the shuffle can misorder a block but
cannot unbalance one.

Three properties follow:

* **Balanced** — every complete block is 2/2/2; a run stopping mid-block is at
  worst two participants away from balance.
* **Unpredictable to a participant** — without the secret the next slot's arm is
  not derivable from the arms already issued. A learner cannot request one,
  guess one, or submit one: no form field, query string, header or cookie value
  is consulted by the allocator.
* **Reproducible and auditable** — given the secret and the slot numbers, the
  whole sequence can be recomputed later. That is what makes an allocation
  auditable rather than merely unrecorded.

The allocation is written once at enrollment and never rewritten. No route
updates `arm_key` or `allocation_slot`; every `/study/admin` route is read-only.

### Concurrency

The slot is **claimed by insertion**, not chosen after a count. A unique
constraint on `(protocol_key, protocol_version, allocation_slot)` means two
simultaneous enrollments computing the same next slot collide; the loser rolls
back, recomputes and retries. Count-then-choose without the constraint would
hand both participants the same slot, the same arm, and an unbalanced block.

### The allocation secret

```
REWINDSEC_STUDY_ASSIGNMENT_SECRET
```

Mandatory when research mode is enabled; the flow fails closed with a 503
without it. It is deliberately **not** Flask's `secret_key`: that key has a
documented random development fallback, and it is rotated for reasons unrelated
to the study. An unkeyed permutation would make the sequence public; a random
fallback would make it irreproducible. Both are disqualifying.

## Research-mode gating

Research mode is **off by default**.

```
REWINDSEC_STUDY_ENABLED=1
REWINDSEC_STUDY_ASSIGNMENT_SECRET=<high-entropy value>
REWINDSEC_STUDY_ACCESS_CODE=<code given to participants>
```

With it off, every `/study` route returns 404 — not 403: a deployment that has
not been configured for research should not advertise that one could exist. No
enrollment can be created, and the ordinary training and learning flows behave
exactly as before.

With it on but either secret missing, the flow serves 503 and creates nothing.

The access code is an access gate and nothing more. It is compared in constant
time, never stored on an enrollment row, never rendered, and never logged. Its
purpose is to stop an ordinary learner wandering into a research protocol.

## Privacy model

**No personally identifying information is collected at any point.** There is no
name, email address, student id, phone number, college registration number, date
of birth, gender or demographic field anywhere in the study tables, and none is
needed by this protocol. There is no IP address, geolocation, user-agent
fingerprint or device identifier: analytics of that kind are not added.

A participant is a UUID4 (`participant_id`) and an allocation slot.

Every value stored from a form is an authored identifier or a bounded integer.
**There is no free-text input anywhere in the study flow**, so a participant
cannot write personal information into the research record even by accident.

`StudyEnrollment.session_id` exists for authorisation only — it says which
browser session currently owns the enrollment — and is **absent from the
research export**.

## Return-code continuity

The retention probe opens a week later, and a browser cookie frequently does not
survive that. Without a way back, retention attrition would be an artifact of
cookie lifetime rather than of anything being measured.

At enrollment the participant is issued one high-entropy opaque code
(`secrets.token_urlsafe(24)`, 192 bits) and shown it **once**. Only a keyed
HMAC-SHA256 digest is stored. `POST /study/resume` re-binds the current browser
session to the existing enrollment.

* The code is derived from nothing — not the `participant_id`, not the
  `session_id`, not the slot, not a clock — so possessing one reveals nothing
  about the participant it belongs to.
* Resuming changes `session_id` and nothing else. The `participant_id`, the
  arm, the slot, the first decision, the intervention and every recorded attempt
  are untouched.
* The raw code is never persisted, never logged, never placed in a query string
  or a URL, never echoed back into a page, never written to the session and
  never exported. Resume is POST-only so a code cannot reach browser history, a
  proxy log or a `Referer` header.
* Because only a digest is kept, a lost code cannot be recovered or resent. That
  is the cost of it being unable to identify anyone.

It is a pseudonymous continuity credential, not personal data.

## Server-authoritative phases

Progress is stored on the enrollment and advanced only through the authored
per-arm progression:

```
awareness_debrief      enrolled → source_decision_recorded → intervention_completed
                       → immediate_transfer_completed → retention_waiting
                       → retention_completed

factual_consequence    … → source_decision_recorded → factual_preview
                       → intervention_completed → …

counterfactual_replay  … → source_decision_recorded → factual_preview
                       → counterfactual_completed → reflection_completed
                       → intervention_completed → …
```

Only the *immediate* successor is a legal transition. A phase an arm does not
list is not reachable for that arm at all, which is why cross-arm contamination
is a phase error rather than a template accident: an Arm A participant asking
for the comparison page is asking for a phase Arm A has never had.

There is no phase field in any form, no phase in any URL, and nothing a browser
submits names one. Typing a later route redirects the participant to wherever
they actually are.

## Research data semantics

**Baseline behaviour** is the factual first decision, stored once.

**Outcome variables** made available for analysis:

* primary — immediate transfer response quality;
* secondary — retention transfer response quality, response times, raw
  confidence readings, occurrence of a risky response given with high stated
  confidence, factual first-choice quality, and (Arm C only) whether the
  selected structured explanation was the preferred one.

**The application computes none of the statistics.** No significance test, no
p-value, no effect size, no causal claim and no "learning improvement" label is
produced anywhere in the code, the dashboard or the export. The software stores
and describes observations; analysis belongs in the paper workflow, after real
data collected under an appropriate approved protocol exists.

### Missing data

Missingness is represented, never imputed. A participant who never returned did
not answer riskily — they did not answer. A missing retention attempt, an
expired window and an incomplete intervention are each reported as themselves,
and an unobserved measurement exports as an **empty** cell, never as a zero and
never as a response quality. Collapsing the two would manufacture the study's
own outcome variable.

## Instructor views

`/study/admin` — instructor-authenticated, read-only, **descriptive counts
only**: enrolled totals and per-arm counts; intervention, immediate and
retention completion; retention due, completed and expired; baseline, immediate
and retention response-quality counts by arm; and counts of risky responses
given with high stated confidence.

It includes a participant flow table — assigned → completed intervention →
completed immediate transfer → eligible for retention → completed retention —
as descriptive operational reporting.

No name, no raw `session_id` (removed from the context by `display_dict()`, not
merely omitted by the template), no return-code digest, and no statement that
one arm did better than another.

## Research export

`/study/admin/export.csv` — instructor-authenticated, one row per
`StudyEnrollment`, in a fixed column order declared once in
`StudyService.EXPORT_COLUMNS` and asserted by test.

`participant_id` is the research correlation identifier. The instructor HTML
label (`P-XXXXXX`) is a display artifact and is deliberately not a join key.

Deliberately **absent**: the raw Flask `session_id`, the return-code digest, the
access code, IP addresses, user agents, credentials and any learner-authored
text. The internal evaluation APIs return a canonical `session_id` because the
formal harness joins on it; a research export has no such need.

The file is written by the `csv` module rather than by string concatenation, so
quoting and escaping stay correct by construction.

## Telemetry decision: no new event types

`SecurityEvent` remains the single general event timeline, and R7 adds **no**
`STUDY_*` event types.

The study artifacts already carry the timestamps a study needs —
`created_at`, `intervention_started_at`, `intervention_completed_at`,
`immediate_transfer_completed_at`, `retention_open_at`, `retention_close_at`,
`retention_completed_at`, and a `created_at` on every attempt. A parallel stream
of a dozen `STUDY_*` events would restate them in a second place that could
disagree, and would recreate exactly the parallel analytics system Milestone 3
removed once already.

Arm C still emits the ordinary six `TRAINING_*` lifecycle events, because it
runs an ordinary paired execution. Arms A and B emit none, because they run no
pair — and that asymmetry is itself an accurate record of what happened.

## What R7 deliberately does not do

No participant recruitment. No claim of ethics approval, consent or
registration. No collection of names, emails or demographics. No p-values,
effect sizes or significance tests. No claim of learning improvement. No "far
transfer" label. No adaptive training. No LLM anywhere. No free text. No fourth
arm. No second source scenario. No change to Docker containment, the ransomware
mechanics, or the normal MFA/BEC training flows. No rewrite of
`CounterfactualRuntime`.
