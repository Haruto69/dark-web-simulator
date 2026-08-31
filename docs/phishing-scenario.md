# R3: Phishing & Credential Compromise — the first end-to-end scenario

R1 built the deterministic counterfactual runtime. R2 connected it to
persistence and telemetry. R3 puts a learner in front of it: one polished
scenario, played entirely in the browser, from a realistic message to an
executed side-by-side comparison.

```
realistic inbox
  -> learner decision (+ confidence)
  -> controlled technical consequence
  -> rewind
  -> alternative decision
  -> verified identical baseline
  -> alternative consequence
  -> side-by-side comparison
```

## Where the code lives, and why

```
training/            pure runtime. No Flask, no SQLAlchemy, no sandbox, no
                     Docker, no HTTP, no templates. Unchanged by R3.
scenario_adapters/   this scenario: its ScenarioDefinition, its consequence
                     adapter, and the presentation mapper.
training_routes.py   the learner-facing Flask blueprint.
training_service.py  the R2 seam: execution identity, persistence, telemetry.
```

`scenario_adapters/` exists specifically so that R1's framework-independence
invariant survives. A phishing adapter legitimately wants the application's
synthetic-resource allow-list, and a presentation mapper exists only to render
an application UI; putting either under `training/adapters` would have made the
pure package depend on the application. Two tests pin the layering:
`test_the_training_package_stays_independent_of_flask_and_the_sandbox` and
`test_scenario_adapters_stay_out_of_the_http_layer` (which also forbids
`training/` importing `scenario_adapters`).

The adapter package is application-level but still Flask-free: it imports no
route, no request and no session, so a consequence can be executed with no HTTP
request in flight — which is how the runtime tests drive it.

## The scenario definition

```
scenario_key      phishing_credential_compromise
version           1
decision_id       respond_to_message
prompt_key        urgent_account_verification_message
competency_tags   credential_hygiene, phishing, reporting
```

The setting is a fictional organisation, **Northgate Campus Services**, on a
`.lab` domain that resolves nowhere. No real institution's name, branding or
login page is reproduced anywhere in the flow, and no real service is contacted.

### Action vocabulary

Four choices, four opaque action keys. Stable machine identifiers; the display
labels are free to change without changing the data.

| choice_id | label | action_key |
|---|---|---|
| `follow_link_and_sign_in` | Follow the link and sign in | `credential_submitted_to_lookalike` |
| `inspect_sender` | Inspect the sender details | `sender_details_inspected` |
| `verify_independently` | Verify through a trusted channel | `request_verified_out_of_band` |
| `report_message` | Report the message | `message_reported_to_security` |

The definition names *what* happens and never *how*. `ConsequenceSpec` rejects
URLs, paths, dotted import paths, commands and callables at construction time,
and `CounterfactualRuntime` validates the whole vocabulary against the adapter
before any environment is touched. `PhishingConsequenceAdapter.supported_actions`
is exactly the four keys above and nothing else resolves.

## Consequence state

Small, deterministic, JSON-safe, and free of anything the learner typed:

```json
{
  "message":  {"sender_inspected": false, "verified_independently": false,
               "reported": false},
  "identity": {"exposed": false},
  "account":  {"synthetic_access": false},
  "resource": {"accessed": false, "key": null},
  "incident": {"created": false},
  "evidence": {"sender_mismatch_visible": false,
               "verification_outcome": null}
}
```

The exposure flag lives under `identity`, not `credential`: `training.snapshots`
rejects credential-shaped state keys outright, and that guard is worth keeping
sharp. Only the *fact* of exposure is ever recorded — never a password, an email
address, a username, free text, a URL or a host path. `resource.key` holds an
allow-listed key from `sandbox.scenarios.phishing.SYNTHETIC_RESOURCES`, never a
destination.

Transitions, all pure functions of the action key:

| action | effect |
|---|---|
| `credential_submitted_to_lookalike` | `identity.exposed`, `account.synthetic_access`, `resource.accessed` → true; `resource.key` → `hr-portal` |
| `sender_details_inspected` | `message.sender_inspected`, `evidence.sender_mismatch_visible` → true |
| `request_verified_out_of_band` | `message.verified_independently` → true; `evidence.verification_outcome` → `request_not_legitimate` |
| `message_reported_to_security` | `message.reported`, `incident.created` → true |

No randomness, no clock, no network, no filesystem, no LLM. `rewind()` restores
a deep copy of the canonical baseline, and the runtime independently re-captures
and re-fingerprints the state rather than trusting the adapter's word for it.

## Synthetic credential safety

The unsafe branch keeps the useful part of the earlier implementation: the
learner really does meet a sign-in page and really does use a credential.

* only the session-issued `@lab.local` identity from `sandbox.identity`
  validates, by local HMAC comparison — no socket is opened, ever;
* the submitted password exists only as an argument to that comparison and is
  dropped there. It is never persisted, logged, flashed, echoed, returned in a
  response or written to telemetry;
* the submitted username is compared and discarded. A learner who types a real
  address gets a failed validation and *nothing is retained* — it does not reach
  `TrainingExecution`, `SecurityEvent` or the session;
* another session's identity does not validate, because derivation is keyed by
  session id;
* the factual branch is not executable until a valid synthetic credential has
  actually been submitted. Skipping the sign-in redirects back to it.

`test_phishing_training_never_persists_submitted_password` checks the stored
execution, every event row, the rendered result page and the session cookie.

## Learner workflow

| route | method | what it does |
|---|---|---|
| `/training` | GET | module home; the RewindSec learner entry point |
| `/training/phishing` | GET | safety briefing and this session's lab identities |
| `/training/phishing/start` | POST | begins (or explicitly restarts) an attempt |
| `/training/phishing/inbox` | GET | the message, the four choices, the confidence slider |
| `/training/phishing/decision` | POST | records the factual choice, confidence and latency |
| `/training/phishing/signin` | GET/POST | the synthetic sign-in, unsafe branch only |
| `/training/phishing/outcome` | GET | what that path produced, plus the rewind form |
| `/training/phishing/rewind` | POST | runs the paired execution through `training_service()` |
| `/training/phishing/result` | GET | the executed side-by-side comparison |

The scenario requires no marketplace, product page or dark-web navigation. The
legacy `/phishing/*` flow is untouched and still runs its own state machine and
`PHISHING_*` telemetry for the existing regression tests.

Confidence is an integer 0..100 from a range slider, validated server-side
(ASCII digits only, in range) and rejected with `400` otherwise. Response time
is measured **server-side**, from when the decision page was rendered to when it
was submitted, so there is no client value to trust; anything outside 0..1h is
recorded as "not measured" rather than as an implausible number. It is learner
interaction metadata, not a security control.

## Factual vs counterfactual

`factual_*` always carries the choice the learner made **first**; `counterfactual_*`
the alternative selected **after** the rewind. They are never swapped so that a
particular branch lands on a particular side. A learner who reports the message
and then compares against signing in sees "Report the message" under *Your
path*, and the research record preserves that observed ordering.

The server requires `counterfactual_choice != factual_choice`, and both must be
one of the four stable ids.

## Result persistence and rendering

The comparison is produced by `training_service().run_pair(...)` — the real
runtime — and the result page renders from the persisted `TrainingExecution`
row, never from submitted form values. A completed row holds:

```
scenario_key = phishing_credential_compromise, scenario_version = 1
decision_id  = respond_to_message
factual_choice_id / counterfactual_choice_id
both confidences, both response times
baseline_digest == rewound_digest      (refused otherwise)
factual_result_digest / counterfactual_result_digest
factual_state_json / counterfactual_state_json / difference_json
status = completed
```

`scenario_adapters/presentation.py` maps state pointers and stored diff entries
to sentences from a fixed allow-listed table — no LLM, no generated prose, no
raw JSON shown to a learner. A state field added later but not described there
renders nothing rather than leaking an internal key name.

## Refresh and idempotency

`POST → Redirect → GET` throughout. The current `execution_id` is held in the
server-side session, so:

* refreshing `/training/phishing/result` re-reads the stored row — no new
  `TrainingExecution`, no re-run, no additional `TRAINING_*` events;
* re-submitting the rewind (double click, back-then-submit) redirects to the
  existing result instead of running a second experiment. This is enforced
  server-side, not by a disabled button;
* "Start again" is an explicit POST and deliberately creates a new attempt.
  Repeating the same experiment produces the **same `pair_id`** (that is the
  point of `pair_id`) and a **different `execution_id`**.

## Session isolation

No result route takes an id. `execution_id` is read only from the server-side
session, and the loaded row's `session_id` must still match the caller's — so
one learner has no address with which to name another's result, and forcing a
foreign id into their own session still fails. Synthetic identity, factual
choice, confidence, progress and result are all per-session.

## Telemetry

The new flow emits the standard R2 lifecycle and nothing else:

```
TRAINING_EXECUTION_STARTED
TRAINING_BASELINE_CAPTURED
TRAINING_FACTUAL_CAPTURED
TRAINING_REWIND_VERIFIED
TRAINING_COUNTERFACTUAL_CAPTURED
TRAINING_EXECUTION_COMPLETED
```

No new `EventType` was added in R3, and no legacy `PHISHING_*` event is emitted
by the new flow — duplicating the same causal progression into two event
families would leave two timelines to reconcile. `TRAINING_*` is the
authoritative timeline here; the legacy events remain for the legacy routes.
