# Dark Web Risk Simulator (Demo)

A training simulation tool for understanding dark web risks.

## Setup Instructions

### 1. Create Virtual Environment
```shell
python3 -m venv venv
```

### 2. Activate Environment
For Linux/macOS:
```shell
source venv/bin/activate
```

For Windows:
```shell
.\venv\Scripts\activate
```

### 3. Install Dependencies
```shell
# Upgrade pip
pip install --upgrade pip

# Install required packages
pip install -r requirements.txt
```

### 4. Run Application
```shell
python app.py
```

### 5. Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `FLASK_SECRET_KEY` | random per process | Session signing key. Set it for stable sessions. |
| `FLASK_DEBUG` | `0` (off) | Debug mode. Never enable on a shared network. |
| `FLASK_RUN_HOST` | `127.0.0.1` | Bind address. Loopback-only by default. |
| `FLASK_RUN_PORT` | `5000` | Port. |
| `SIMULATOR_DATABASE_URI` | `sqlite:///simulator.db` | Event/telemetry database. |
| `SANDBOX_LOCAL_ROOT` | `instance/sandbox_workspaces` | Scratch root for the local backend. |
| `INSTRUCTOR_PASSWORD` | unset | **Required for instructor access.** While unset, every instructor route stays closed. |
| `SYNTHETIC_IDENTITY_SECRET` | falls back to `FLASK_SECRET_KEY` | Derivation key for the per-session sandbox identities. Set it for identities that survive a restart. |

---

# Session model, authentication and credential privacy

## Passwords are never stored

**No learner-submitted password is ever written anywhere in this application.**
There is no password column in the schema, no password in any log line, no
password on the dashboard, and no password in any API response. The phishing
scenario compares a submitted value against a locally derived synthetic one and
drops it in the same function call.

**No external authentication service is ever contacted.** Credential validation
is an in-process HMAC comparison (`sandbox/identity.py`). The simulator opens no
socket to validate anything, and the "credential reuse" stage is a state
transition inside the learner's own sandbox — not a login attempt against
anything, local or remote.

### What was removed

Milestone 1 stored submitted usernames *and plaintext passwords* in a
`SimulatedCredential` table, rendered them at `/deets`, and exposed usernames
from every session at `/api/logs` with no authentication. All of that is gone:

| Old behaviour | Now |
| --- | --- |
| `SimulatedCredential` (plaintext passwords) | table **dropped on start-up**; replaced by `CredentialInteraction` (metadata only) |
| `/deets` — every credential, unauthenticated | instructor-only; renders interaction metadata, no credential values |
| `/api/logs` — usernames across all sessions | instructor-only; returns `SecurityEvent` telemetry only |
| `/dashboard` — unauthenticated credential dump | instructor-only; no credential values |
| `/process_payment/<id>` — displayed "captured" credentials | **route removed** |
| `/payment/<id>` | redirects into the consent-gated scenario |
| `/phishing/login` — captured and stored anything typed | validates a synthetic identity, stores no password |

### Migration

This is a SQLite-backed teaching demo with no production data, so the migration
is a drop rather than an Alembic history: `drop_legacy_tables()` issues
`DROP TABLE IF EXISTS simulated_credential` on every start-up. Any passwords
captured by an older build are destroyed the first time this code runs. To start
completely clean, delete `instance/simulator.db` and restart.

## Per-session sandbox isolation

There is no shared `primary` sandbox. Each learner session gets its own logical
sandbox, addressed by an id **derived** from the Flask session uuid:

```
flask session uuid  --sha256-->  sess-<16 hex>   (sandbox/session_scope.py)
```

* The id is stable for the session, so create/reset are idempotent.
* It is never taken from request data. No route accepts a sandbox id parameter,
  so a learner cannot name another learner's sandbox — there is no field to put
  it in.
* It is still validated by `validate_sandbox_id()` before reaching a backend.
* There is no inverse function: instructors enumerate sandboxes from the
  backend (`/sandbox/sessions`), never by un-hashing an id.

Session A's files, telemetry, scenario state and synthetic credentials are all
independent of session B's; resetting or destroying one leaves the other
untouched. Instructor views may aggregate across sessions; learner actions never
cross one.

## Instructor authentication

One role, one password, held in `INSTRUCTOR_PASSWORD`. There is no user table,
no OAuth and no token header — this is a lab access control, not a SaaS identity
system.

| Route | Method | Purpose |
| --- | --- | --- |
| `/instructor/login` | GET, POST | Sign in. Compared with `hmac.compare_digest`; never echoed back |
| `/instructor/logout` | POST | Clear the session flag |

A successful login stores a single boolean in the Flask session. When
`INSTRUCTOR_PASSWORD` is unset, login always fails and every instructor route
stays closed — the deployment fails closed, not open.

Protected: `/dashboard`, `/deets`, `/api/logs`, all `/sandbox/*` routes
(including the read-only `status`, `events` and `sessions`), and the
`/ransomware/simulate` and `/ransomware/restore` demo controls.

## CSRF protection

`security.init_csrf()` installs a `before_request` hook that rejects **every**
non-safe method (POST/PUT/PATCH/DELETE) without a valid per-session token, with
HTTP 400. Enforcement is global rather than per-route, so a newly added POST
handler is protected by default instead of by remembering a decorator.

* Token: 32 random URL-safe bytes, stored in the session, compared with
  `hmac.compare_digest`.
* Supplied as the `csrf_token` form field, an `X-CSRF-Token` header, or a
  `csrf_token` JSON key.
* Available in templates as `{{ csrf_token() }}`.
* GET/HEAD/OPTIONS stay read-only and require nothing.
* A token minted for one session does not authorise another.

## Synthetic credential model

Sandbox identities are **derived, never stored** (`sandbox/identity.py`):

```
password = "lab-" + HMAC-SHA256(secret, session_id || username)[:10]
username = employee01@lab.local, employee02@lab.local
```

* They exist only inside the simulator and correspond to no real service.
  `lab.local` resolves nowhere; no realistic real-world domain is used.
* They are keyed by the learner's session, so the identity issued to session A
  does not authenticate in session B.
* There is no credential table, so there is nothing to dump or leak.
* The learner sees their own identities on their own briefing page. The
  instructor dashboard never shows a password, because none exists to show.

Lifecycle: issued on the consent page → typed into the phishing form → compared
→ discarded. Only metadata survives (`synthetic_username`, `credential_valid`,
`timestamp`, `scenario_id`, `session_id`, `product_id`, `event_type`).

## Phishing scenario flow

```
/product/<id>          marketplace lure          PHISHING_EXPOSED
      |
/phishing/consent      briefing, consent POST    CONSENT_GRANTED
      |
/phishing/login  GET   phishing-style form       PHISHING_FORM_VIEWED
      |
/phishing/login  POST  submit + validate         CREDENTIAL_SUBMITTED
      |                                          CREDENTIAL_VALIDATED
      |                                          (or CREDENTIAL_VALIDATION_FAILED)
      |                sandbox-only reuse        SANDBOX_LOGIN_SUCCEEDED
      |
/phishing/portal       synthetic resource        SYNTHETIC_RESOURCE_ACCESSED
      |
/phishing/debrief      educational debrief       SCENARIO_COMPLETED
```

The stage lives in the **server-side** session and the scenario refuses to skip
ahead, so consent and credential validation cannot be bypassed by requesting a
later URL directly.

### What the "reuse" stage is not

It is not a credential-stuffing or account-takeover tool, and must never be
extended into one:

- the only credentials it understands are this session's `*@lab.local`
  identities;
- the destination is an **allow-listed resource key** (`hr-portal`,
  `file-archive`) — there is no URL, host, port or path parameter anywhere;
- no socket is opened and no external service is contacted;
- an unrecognised key falls back to the default rather than being fetched.

## Consent boundary

Consent is enforced **server-side**, not by an HTML checkbox. `/phishing/login`
redirects back to the briefing until `CONSENT_GRANTED` has been recorded for the
session. The briefing states plainly that this is a training simulation, that
only sandbox credentials may be used, that real credentials must never be
entered, that submitted passwords are not stored, and that activity is logged as
scenario telemetry.

## Scenario correlation

Every scenario execution gets a stable `scenario_id`, and every `SecurityEvent`
carries `session_id`, `scenario_id`, `event_type` and `timestamp`. Ordering is
`(timestamp, id)` — total and stable, because `id` is a monotonic autoincrement,
so events sharing a timestamp still resolve to insertion order.

Instructors can inspect an ordered, filtered timeline:

```
/sandbox/events?scenario_id=<id>
/sandbox/events?session_id=<id>&limit=200
/sandbox/sessions
```

---

# Conference Sandbox Architecture

> *Dark Web Risk Sandbox: A Container-Isolated Multi-Stage Cybersecurity Simulation Environment*

## What the sandbox does

The sandbox replaces the previous purely symbolic `status = "encrypted"` database
flag with a **real filesystem operation performed inside a disposable, isolated
target** — while keeping that operation deliberately trivial and reversible.

```
Flask (scenario controller, instructor UI)
  ↓
SandboxManager            create / status / reset / destroy
  ↓
Isolated Docker target    disposable container, no network, no mounts
  ↓
Synthetic workspace       /workspace, five fabricated files
  ↓
Telemetry                 structured SecurityEvent rows in SQLite
  ↓
Dashboard                 sandbox panel: state, files, recent events
```

## There is no malware here

This project contains **no real malware and no ransomware capability**. The
"file impact emulator" (`sandbox/impact_core.py`) does exactly one thing:

```
finance_report.txt  →  finance_report.txt.demo_locked
```

It **renames** a file. Contents are never read for transformation, never
encrypted, and never altered — the rename is losslessly reversible, and the
tests assert byte-for-byte content equality after impact.

Constraints enforced in code, not just by convention:

- **No cryptography of any kind.** No keys, ciphers, or keying material.
- **Fixed allow-list of targets.** Only the five synthetic filenames are
  operable. There is no user-supplied filesystem root and no request parameter
  that can widen the list.
- **No directory walking.** Directories are never enumerated, so recursion over
  arbitrary trees is not merely blocked — it is not implemented.
- **Traversal rejected.** `..`, absolute paths, nested paths, backslashes,
  drive letters, and NUL bytes all raise `UnsafePathError`
  (`sandbox/paths.py`), and the Docker backend validates host-side so an unsafe
  target never even reaches the container.
- **No propagation, persistence, privilege escalation, or evasion.**
- **No network egress.** The container runs with `--network none`.

The code is not deployable as an offensive tool; stripped of its guard rails it
would be a five-line rename script.

## Threat / safety boundary

| | Inside the boundary | Outside |
| --- | --- | --- |
| Filesystem | `/workspace` in the container | host filesystem is unreachable — no bind mounts, no volumes |
| Network | none (`--network none`) | Internet, host services, other containers |
| Privilege | uid 10001, all capabilities dropped, `no-new-privileges` | root, Docker socket, host PID/IPC namespaces |
| Data | five fabricated files | no real personal, financial, or client data exists anywhere in the sandbox |
| Lifetime | destroyed on reset | nothing survives a reset |

Telemetry stores only simulation metadata — event types, sandbox ids, synthetic
filenames. No credentials and no host paths are recorded.

## Backends

`SandboxManager.autodetect()` picks:

1. **`DockerBackend`** — the isolation-bearing backend, and the one the threat
   boundary above describes. Used whenever Docker is available.
2. **`LocalBackend`** — a fallback that runs the same validated scenario against
   a project-controlled scratch directory. It provides *workspace confinement
   only*: no container, process, user, or network isolation. It exists so the
   system is testable and demonstrable without Docker.

The active backend and its `isolation_summary` are always shown on the
dashboard, and a reduced-isolation run is flagged with a warning banner, so a
local run can never be mistaken for a contained one.

## Docker requirements

Docker Engine 20.10+ (Docker Desktop on Windows/macOS). Build the target image
from the repository root:

```bash
docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
```

The image contains a Python runtime and the `sandbox` package only. The Flask
app, its database, and the marketplace content are never copied in.

## Operating the sandbox

Instructor controls live under `/sandbox` and appear as buttons on `/dashboard`.

| Route | Method | Action |
| --- | --- | --- |
| `/sandbox/create` | POST | Create a disposable sandbox and seed the baseline |
| `/sandbox/scenario/file-impact` | POST | Run the constrained file-impact scenario |
| `/sandbox/reset` | POST | Destroy and recreate — restores the baseline |
| `/sandbox/destroy` | POST | Remove the sandbox entirely |
| `/sandbox/status` | GET | Sandbox state, backend, isolation summary, file states |
| `/sandbox/events` | GET | Telemetry in `(timestamp, id)` order (`?scenario_id=`, `?session_id=`, `?limit=`) |
| `/sandbox/sessions` | GET | Every session sandbox the backend currently owns |

All of these require an instructor session (`INSTRUCTOR_PASSWORD`), and all POST
routes require a CSRF token. Each route acts on the sandbox derived from the
caller's own session; none of them accepts a sandbox id.

## Synthetic files

Defined once in `sandbox/dataset.py` and generated identically for both
backends:

```
/workspace/employee_records.csv
/workspace/finance_report.txt
/workspace/project_notes.txt
/workspace/client_database.csv
/workspace/thesis_draft.txt
```

Every value in them is fabricated. They contain no real employees, clients, or
financial figures.

## Reset and reproducibility

Reset is **destroy + recreate**, not in-place repair. The baseline is generated
from `dataset.py` at container start, so a fresh sandbox is byte-identical every
time and a reset cannot leave residue behind. This is what makes the later
experimental claims — reproducibility, isolation, reset correctness, telemetry
completeness — measurable rather than asserted.

## Telemetry event types

Lifecycle and file impact: `SANDBOX_CREATED`, `SANDBOX_RESET`,
`SANDBOX_DESTROYED`, `SCENARIO_STARTED`, `SCENARIO_COMPLETED`,
`SCENARIO_FAILED`, `FILE_IMPACT_STARTED`, `FILE_IMPACT`,
`FILE_IMPACT_REJECTED`, `FILE_IMPACT_COMPLETED`.

Phishing / credential reuse: `PHISHING_EXPOSED`, `CONSENT_GRANTED`,
`PHISHING_FORM_VIEWED`, `CREDENTIAL_SUBMITTED`, `CREDENTIAL_VALIDATED`,
`CREDENTIAL_VALIDATION_FAILED`, `SANDBOX_LOGIN_SUCCEEDED`,
`SYNTHETIC_RESOURCE_ACCESSED`, `SCENARIO_COMPLETED`.

No event ever carries a password value.

Example:

```
FILE_IMPACT  target=/workspace/finance_report.txt
             details="renamed to finance_report.txt.demo_locked (contents unchanged)"
```

## Tests

```bash
python -m pytest tests -q
```

Tests run entirely against pytest temp directories and a throwaway SQLite
database — they never touch the developer's files or the real `simulator.db`.
Docker integration tests skip automatically when Docker or the target image is
unavailable.

---

## Important Notice
⚠️ **This is a simulation tool for training purposes only.**
- Do not enter real credentials — use only the sandbox identities the
  simulator issues you
- Submitted passwords are never stored, logged, or displayed
- No external authentication service is ever contacted
- All data is simulated
- For educational use only

## Requirements
- Python 3.7+
- pip package manager
- Internet connection for dependencies

## License
This project is for demonstration purposes only.
