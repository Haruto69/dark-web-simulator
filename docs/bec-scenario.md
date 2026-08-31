# Business Email Compromise (`business_email_compromise`)

The fourth complete learner-facing RewindSec module (milestone R5). A supplier
thread asks for the bank details on an overdue invoice to be changed, and for
payment to be released urgently. The learner responds, sees what that response
actually produced, rewinds to a verified identical baseline, and takes a
different response from the same starting point.

> The payment and loss values are synthetic scenario state. RewindSec does not
> initiate or simulate a networked financial transaction.

## Scenario definition

| | |
|---|---|
| `scenario_key` | `business_email_compromise` |
| `version` | `1` |
| `decision_id` | `respond_to_payment_change_request` |
| `prompt_key` | `supplier_payment_detail_change_request` |
| competency tags | `business_email_compromise`, `payment_verification`, `secondary_channel_verification`, `incident_reporting` |

Declared in `scenario_adapters/bec.py`. The definition carries only opaque
action keys; URLs, paths, callables and commands are rejected by
`training.definitions` at construction time.

## Action vocabulary

| choice id | label | action key |
|---|---|---|
| `authorize_payment` | Approve the payment using the new details | `payment_authorized_to_changed_details` |
| `reply_to_request` | Reply to the email for confirmation | `unverified_thread_replied_to` |
| `verify_via_known_contact` | Call the supplier using the saved contact details | `supplier_verified_via_known_channel` |
| `escalate_to_finance_security` | Escalate the request to Finance and Security | `payment_request_escalated` |

## Context

Entirely fictional. **Northgate Operations** receives an invoice-change request
from **Asterline Office Supplies**, on a `.lab` address that resolves nowhere.
The message claims the supplier's banking details have changed, that the
invoice is overdue, and that payment must be released today. No real company,
bank account, routing number, payment link or person appears anywhere.

The inbox is deliberately **not** another credential form: there is no
password field and no sign-in step. The learning objective is payment
verification and secondary-channel checking.

## Synthetic payment model

One fixed invoice, declared as module constants:

| | |
|---|---|
| invoice reference | `INV-DEMO-1042` |
| amount | `18450` (`GBP`, authored figure) |
| status | unpaid, overdue |

The amount, the destination and the supplier are never read from HTTP input.
`BecConsequenceAdapter.apply` takes one symbolic action key and nothing else,
and the recorded loss is the module constant. Extra form fields — an `amount`,
an `account`, a `destination` — are ignored entirely; there is no code path
that reads them, and the state schema has no field they could reach. The
payment system is an in-memory deterministic state transition: no payment API,
no banking API, no ledger, no network, no transfer.

## Baseline state

```json
{
  "message":      {"request_received": true,
                   "replied_to_unverified_thread": false},
  "verification": {"known_contact_used": false, "change_confirmed": null},
  "payment":      {"authorized": false, "synthetic_loss": 0},
  "incident":     {"finance_escalated": false, "security_reported": false}
}
```

Every value is a boolean, `null`, or an integer. There are no strings at all,
so no address, reference or free text can be carried. Deliberately absent: real
bank information, account numbers, routing numbers, any user-entered recipient,
any arbitrary amount, any payment credential, and the learner's email address.

## Deterministic consequence model

Authored training outcomes, chosen so four responses can be compared under
identical conditions.

| action | resulting state |
|---|---|
| `payment_authorized_to_changed_details` | payment authorized; fixed synthetic loss of 18,450 recorded; nothing verified |
| `unverified_thread_replied_to` | the unverified thread is replied to; payment still pending; no secondary-channel verification occurred (in this authored scenario the trusted conversation remains the attacker-controlled one) |
| `supplier_verified_via_known_channel` | the saved contact is used; the requested banking change is disproved (`change_confirmed = false`); payment not authorized; no loss |
| `payment_request_escalated` | payment held; Finance escalated; Security reported; no loss |

No attacker dialogue is generated; the outcome is a factual, observable state
change and nothing else. Each transition is a pure function of the action key.

## Adapter contract

`BecConsequenceAdapter` implements the R1 contract — `prepare`,
`capture_state`, `apply`, `rewind`.

* one action per branch; a second `apply` before a `rewind` raises
  `AdapterProtocolError`;
* `capture_state` is a pure observation returning a copy;
* `rewind` restores a deep copy of the canonical baseline, verified
  independently by the runtime's fingerprint check;
* an action outside `BEC_ACTIONS` raises `UnknownActionError`.

## Learner flow

| method | path | purpose |
|---|---|---|
| GET | `/training/bec` | briefing |
| POST | `/training/bec/start` | establish the baseline, begin or restart |
| GET | `/training/bec/inbox` | the message, the invoice on file, the four choices, the confidence slider |
| POST | `/training/bec/decision` | factual choice + confidence, then the factual preview |
| GET | `/training/bec/outcome` | what the factual response produced, then the rewind form |
| POST | `/training/bec/rewind` | the alternative, then the authoritative paired run |
| GET | `/training/bec/result` | the executed side-by-side comparison |

Registered from the shared R5 helper in `training_flow.py`, in the existing
RewindSec training visual language. POST → Redirect → GET throughout; every
state-changing POST requires the existing CSRF token.

## Factual preview and the exact rewind invariant

Identical to the MFA module and to R4. The decision route re-establishes the
baseline on a fresh adapter, proves its digest matches the one the learner was
shown, applies their action key, and stores the resulting canonical state and
digest. `run_pair` is then given `expected_baseline_digest` and
`expected_factual_digest`, so:

```
visible baseline == preview baseline == paired baseline == rewound baseline
preview factual digest == authoritative factual branch digest
```

A mismatch raises `StagedExecutionMismatchError` inside the guarded section:
the execution is recorded as `failed` and no completed `TrainingExecution` is
left behind.

## Factual vs counterfactual semantics

`factual_*` is always the response the learner made first. Authorising the
payment and then rewinding to verify is recorded, and displayed, in that order;
branches are never reordered by outcome severity.

## Result presentation

Side by side — **Your path** and **Rewind path** — showing whether the payment
was authorised or held, the synthetic loss where applicable, whether the
supplier was contacted independently, whether the requested change was
confirmed or disproved, whether the unverified thread was replied to, and both
escalations. Every sentence comes from the allow-listed BEC vocabulary in
`scenario_adapters/presentation.py`, keyed by the stored row's own scenario. No
raw state JSON, no generated prose, no correct/incorrect label.

## Persistence and telemetry

One completed `TrainingExecution` per attempt, with
`scenario_key = business_email_compromise`, `scenario_version = 1`,
`decision_id = respond_to_payment_change_request`. No scenario-specific column
was added. Telemetry is exactly the existing six `TRAINING_*` lifecycle events;
no `BEC_*` or `PAYMENT_*` event family exists.

## Safety and privacy

* No Docker, no container, no `SandboxManager`; no sockets, no HTTP requests,
  no subprocesses, no shell.
* No payment execution of any kind, real or simulated over a network.
* The only accepted inputs are a choice id from a fixed set and an integer
  confidence.
* Session-scoped progress; an execution row is served only to the session that
  owns it, and execution ids are never accepted from a URL or a form.
