# MFA Fatigue (`mfa_fatigue_response`)

The third complete learner-facing RewindSec module (milestone R5). An approval
request the learner did not ask for arrives, accompanied by an urgent message
insisting it be accepted. The learner responds, sees what that response
actually produced, rewinds to a verified identical baseline, and takes a
different response from the same starting point.

> The authentication approval and account access are local synthetic state
> transitions. RewindSec does not contact an identity provider or issue a real
> MFA request.

## Scenario definition

| | |
|---|---|
| `scenario_key` | `mfa_fatigue_response` |
| `version` | `1` |
| `decision_id` | `respond_to_unexpected_mfa_prompt` |
| `prompt_key` | `unexpected_push_approval_request` |
| competency tags | `mfa_security`, `authentication_verification`, `incident_reporting` |

Declared in `scenario_adapters/mfa.py`. As with every RewindSec scenario, the
definition names *what* may happen and never *how*: each choice carries an
opaque `ConsequenceSpec` action key, and `training.definitions` rejects URLs,
paths, dotted import paths, callables and commands by construction.

## Action vocabulary

The complete, closed set. Only `MfaConsequenceAdapter` resolves these, and the
runtime refuses any action outside the adapter's declared vocabulary before the
environment is touched.

| choice id | label | action key |
|---|---|---|
| `approve_request` | Approve the sign-in request | `mfa_request_approved` |
| `deny_and_report` | Deny the request and report it | `mfa_request_denied_and_reported` |
| `review_signin_details` | Review the sign-in details | `mfa_signin_details_reviewed` |
| `verify_through_known_channel` | Verify the request through a known support channel | `mfa_request_verified_out_of_band` |

## Context

The module is set at a fictional organisation using an invented identity
service, **Northgate Identity**, on a `.lab` domain that resolves nowhere. The
approval card, the sign-in details (application, time, device, location, request
number) and the urgent chat message are authored fixtures held in
`training_routes.MFA_CONTEXT`. No real vendor's product, branding or interface
is reproduced, and nothing on the page is derived from the learner's browser,
connection or account.

The page does not announce that the request is an attack. The learner is given
the same information a person would actually have, and decides.

## Baseline state

```json
{
  "mfa":      {"request_pending": true, "approved": false, "denied": false},
  "evidence": {"details_reviewed": false, "unexpected_device_visible": false,
               "verified_out_of_band": false, "verification_outcome": null},
  "account":  {"synthetic_session_created": false},
  "resource": {"accessed": false},
  "incident": {"reported": false}
}
```

JSON-safe, deterministic and free of secrets. Every value is a boolean, `null`,
or the one fixed symbolic token `request_not_recognised`. Deliberately absent:
any username, password, IP address, device identifier, push token or identity
provider response.

## Deterministic consequence model

Authored training outcomes, chosen so four responses can be compared under
identical conditions. They are not a claim that every real MFA incident behaves
this way.

| action | resulting state |
|---|---|
| `mfa_request_approved` | approved; no longer pending; synthetic session created; synthetic internal resource accessed |
| `mfa_request_denied_and_reported` | denied; no longer pending; no session; no resource access; incident reported |
| `mfa_signin_details_reviewed` | details reviewed; the fixed unrecognised device/location becomes visible; request still pending; no session; no resource access |
| `mfa_request_verified_out_of_band` | verification performed, outcome `request_not_recognised`; incident reported; no session; no resource access |

Each transition is a pure function of the action key: no randomness, no clock,
no network, no filesystem, no LLM. Two runs of the same action sequence produce
byte-identical canonical state.

## Adapter contract

`MfaConsequenceAdapter` implements the R1 contract — `prepare`,
`capture_state`, `apply`, `rewind` — and nothing else.

* one action per branch: a second `apply` before a `rewind` raises
  `AdapterProtocolError`, because two stacked responses would make the branch
  uncomparable;
* `capture_state` is a pure observation returning a copy;
* `rewind` restores a deep copy of the canonical baseline, and the runtime
  verifies that independently by fingerprint — the adapter is never trusted to
  self-report a successful rewind;
* an action outside `MFA_ACTIONS` raises `UnknownActionError`.

## Learner flow

| method | path | purpose |
|---|---|---|
| GET | `/training/mfa` | briefing |
| POST | `/training/mfa/start` | establish the baseline, begin or restart |
| GET | `/training/mfa/prompt` | the approval card, the urgent message, the four choices, the confidence slider |
| POST | `/training/mfa/decision` | factual choice + confidence, then the factual preview |
| GET | `/training/mfa/outcome` | what the factual response produced, then the rewind form |
| POST | `/training/mfa/rewind` | the alternative, then the authoritative paired run |
| GET | `/training/mfa/result` | the executed side-by-side comparison |

Registered from the shared R5 helper in `training_flow.py`. POST → Redirect →
GET throughout: refreshing `outcome` or `result` re-reads stored state and
re-executes nothing. Every state-changing POST requires the application's
existing CSRF token.

## Factual preview and the exact rewind invariant

The learner must see their factual consequence *before* the rewind, so the
decision route runs a deterministic preview: it constructs a fresh adapter,
re-establishes the baseline, **proves the baseline digest matches the one the
learner was shown**, applies their action key, and stores the resulting
canonical state and digest in the server-side session.

The authoritative record is still the paired execution. `run_pair` is therefore
given `expected_baseline_digest` and `expected_factual_digest`, and the R4
integrity gate applies unchanged:

```
visible baseline == preview baseline == paired baseline == rewound baseline
preview factual digest == authoritative factual branch digest
```

A mismatch raises `StagedExecutionMismatchError` inside the service's guarded
section, so the execution is recorded as `failed`, never as `completed`, and
the learner is not shown a comparison claiming they experienced something they
did not.

## Factual vs counterfactual semantics

`factual_*` always carries the response the learner actually made first;
`counterfactual_*` the alternative they chose after the rewind. Branches are
never reordered by outcome severity: approving first and denying second is
recorded, and displayed, in exactly that order.

## Persistence and telemetry

One completed `TrainingExecution` row per attempt, with
`scenario_key = mfa_fatigue_response`, `scenario_version = 1`,
`decision_id = respond_to_unexpected_mfa_prompt`. No scenario-specific column
was added. Confidence is an integer 0..100 per branch; response time is bounded
integer milliseconds measured server-side from when the decision page was
rendered to when the choice was submitted, excluding consequence rendering.

Telemetry is exactly the existing six-event lifecycle —
`TRAINING_EXECUTION_STARTED`, `TRAINING_BASELINE_CAPTURED`,
`TRAINING_FACTUAL_CAPTURED`, `TRAINING_REWIND_VERIFIED`,
`TRAINING_COUNTERFACTUAL_CAPTURED`, `TRAINING_EXECUTION_COMPLETED`. No `MFA_*`
event family exists.

## Safety and privacy

* No Docker, no container, no `SandboxManager`. The consequence is account
  state, so there is nothing to contain.
* No sockets, no HTTP requests, no subprocesses, no shell, no real service.
* Nothing learner-typed is retained: the only inputs the flow accepts are a
  choice id from a fixed set and an integer confidence.
* Progress lives in the server-side session. Execution ids are never accepted
  from a URL or a form, and a stored row is served only when its `session_id`
  still matches the requesting session.
* State rendering is scenario-scoped: MFA state is described only by the MFA
  vocabulary registered in `scenario_adapters/presentation.py`. A learner never
  sees raw state JSON, and no sentence is generated by a language model.
