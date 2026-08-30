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
| `INSTRUCTOR_MAX_ATTEMPTS` | `5` | Failed logins from one address before lockout. |
| `INSTRUCTOR_LOCKOUT_SECONDS` | `300` | Lockout duration and failure-window length. |
| `SANDBOX_MAX_AGE_SECONDS` | `7200` | Default staleness threshold for `POST /sandbox/reap`. |
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

### Migration and development database commands

This is a SQLite-backed teaching demo with no production data, so there is no
Alembic history: superseded tables are dropped outright. **Dropping is explicit,
never automatic.** Until Milestone 4, importing `app` ran `DROP TABLE` and
deleted every product and demo-file row, so simply starting the server destroyed
whatever a classroom session had recorded. Start-up now only creates missing
tables and seeds *empty* ones; anything destructive is a named command:

```bash
python manage.py status
python manage.py init
python manage.py reset-demo
python manage.py drop-legacy
python manage.py reset-all
```

`status` prints the schema and row counts; `init` creates missing tables and
seeds only empty ones; `reset-demo` replaces the marketplace and demo-file rows;
`drop-legacy` drops the superseded Milestone 1/2 tables; `reset-all` drops every
table and rebuilds. Each destructive command names the database it is about to
change and asks for confirmation; pass `--yes` in a script.

No current model creates `simulated_credential`, `phishing_funnel` or
`ransomware_funnel`, so a database created by this build never contains one.
`drop-legacy` exists for databases left over from an older build, where it
destroys any plaintext passwords an early prototype captured.

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

**Session rotation.** On successful authentication the entire Flask session is
cleared and a **fresh CSRF token** is minted before the instructor flag is set,
so anything an attacker managed to fix in the session beforehand — including a
CSRF token they had observed — is void afterwards. One value is deliberately
carried across: `session_id`, which is a *correlation* identifier (it names the
instructor's own sandbox and ties their telemetry together) and authenticates
nothing. Signing out clears the session wholesale rather than popping one key.

**Login throttling.** A bounded in-memory limiter locks a source address after
`INSTRUCTOR_MAX_ATTEMPTS` failures for `INSTRUCTOR_LOCKOUT_SECONDS`; a locked
source is rejected with HTTP 429 and a `Retry-After` header *before* the
password is compared. Its limitations are real and deliberate:

* **process-local** — multiple workers each keep their own counters, so the
  effective limit scales with worker count; this prototype runs one process;
* **lost on restart** — restarting the app clears all lockouts;
* **keyed by remote address** — a classroom behind one NAT shares a bucket and
  can lock itself out;
* **bounded to 512 tracked keys**, so a flood of spoofed addresses cannot grow
  memory without limit (the oldest entry is evicted);
* it raises the cost of online guessing on a lab network and is **not** a
  defence against a distributed attacker.

This is adequate for an academic sandbox and is not claimed to be more.

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
| Filesystem | `/workspace`, a **tmpfs** in the container | host filesystem is unreachable — no bind mounts, no volumes; the rest of the root filesystem is **read-only** |
| Network | none (`--network none`) | Internet, host services, other containers |
| Privilege | uid 10001, all capabilities dropped, `no-new-privileges` | root, Docker socket, host PID/IPC namespaces |
| Data | five fabricated files | no real personal, financial, or client data exists anywhere in the sandbox |
| Lifetime | destroyed on reset | nothing survives a reset |

### Measured containment

Each property below is asserted by a test in `tests/test_docker_containment.py`,
against a real container, and each was observed to hold on Docker 29.7.2
(Linux containers). These are *controlled containment tests*: every probe is
either a read of container configuration or a benign operation expected to
fail. None attempts an escape or an attack, and the container has no network,
so a network probe cannot reach a third party even in principle.

| Property | Observed |
| --- | --- |
| Network mode | `none`; no address, no ports, no networks but `none` |
| Root filesystem | `ReadonlyRootfs: true` |
| Workspace | tmpfs (`/proc/mounts` shows `tmpfs … /workspace`), not a bind mount |
| User | `10001:10001`; `os.getuid()` returns `10001` |
| Capabilities | `CapDrop: [ALL]`, `CapAdd` empty |
| `no-new-privileges` | present in `SecurityOpt` |
| Privileged | `false` |
| Host namespaces | network/PID/IPC/UTS all unshared |
| Bind mounts / volumes | none; no mount of type `bind` |
| Docker socket | absent from the config and from the filesystem |
| Memory limit | 268435456 bytes (256 MiB) |
| PID limit | 128 |
| Ownership label | `dws-sandbox=1` |

Negative probes, all of which failed as required:

| Probe | Result |
| --- | --- |
| TCP to `1.1.1.1:53` | `OSError: [Errno 101] Network is unreachable` |
| DNS for `example.com` | `socket.gaierror: Temporary failure in name resolution` |
| TCP to host gateway `172.17.0.1:80` | network unreachable |
| Write to `/etc`, `/opt/simulator`, `/` | `PermissionError` (read-only rootfs) |
| Write to `/workspace` | **succeeds** — the one writable path, by design |
| Raw socket (`CAP_NET_RAW`) | `PermissionError: Operation not permitted` |
| `chown /etc/hostname` (`CAP_CHOWN`) | `PermissionError: Operation not permitted` |
| Host filesystem via `/host`, `/mnt/c`, `/c` | none exist |
| Scenario target `../../etc/passwd`, `/etc/passwd`, `nested/dir/f.txt` | `status: rejected` |
| Unknown filename inside `/workspace` | `status: rejected` (not in the fixed dataset) |
| Reading another sandbox's workspace | not visible; impacting one leaves the other at baseline |

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
local run can never be mistaken for a contained one. The evaluation harness
goes further: it refuses to auto-detect, takes the backend as an explicit
argument, and records it in every result file, so a LocalBackend measurement
can never be reported as a container-sandbox result.

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
| `/sandbox/sessions` | GET | Every session sandbox the backend owns, with `created_at` and `age_seconds` |
| `/sandbox/reap` | POST | Destroy stale sandboxes (`max_age`, `dry_run`) |

All of these require an instructor session (`INSTRUCTOR_PASSWORD`), and all POST
routes require a CSRF token. Each route acts on the sandbox derived from the
caller's own session; none of them accepts a sandbox id.

## Sandbox lifecycle and reaping

Long classroom sessions accumulate sandboxes, so `SandboxManager` can remove
stale ones. Safety is structural rather than procedural:

1. **Ownership is proven, not assumed.** Candidates come only from
   `backend.sandbox_metadata()`, which reports a sandbox only when it carries
   this application's ownership marker — a `dws-sandbox=1` Docker label, or a
   `.dws-sandbox.json` marker file for the local backend — *and* its name is a
   valid sandbox id. An unrelated container or a directory someone dropped into
   the scratch root is never enumerated, so it can never be removed.
2. **Ids are re-validated** against `SANDBOX_ID_RE` immediately before use.
3. **Unknown age is never reaped.** A sandbox whose `created_at` cannot be read
   is skipped, so a parsing failure can only ever under-delete.
4. **Deterministic.** `stale_sandboxes(max_age, now=...)` is pure and sorted; it
   depends only on the inventory, the threshold and the supplied clock, which is
   what makes it testable without waiting.
5. **`dry_run=True`** reports the selection without destroying anything.
6. **Floor on the HTTP route.** `POST /sandbox/reap` refuses a `max_age` below
   60 seconds, so a mistyped value cannot wipe an active class.

Creation timestamps come from the runtime itself (`docker inspect .Created`)
rather than being tracked in the Flask process, so they survive a restart.

Cleanup emits telemetry like everything else: one `SANDBOX_REAP_SCAN` per
invocation and one `SANDBOX_REAPED` per sandbox destroyed.

## Evaluation harness

`evaluation/` is a standalone package — **no benchmark logic lives in a Flask
route**. `metrics.py` holds pure statistics (unit-tested against hand-computed
values); `run_experiments.py` drives the experiments and writes raw results.

```bash
python -m evaluation.run_experiments --list
python -m evaluation.run_experiments --backend docker --runs 20
python -m evaluation.run_experiments --backend local --experiments A,C
python -m evaluation.run_experiments --backend docker --experiments E --scales 10,25,50,100
```

| Experiment | Measures |
| --- | --- |
| A — Reproducibility | baseline correctness, expected impacted files, event sequence, reset correctness; reports success / reset-correctness / telemetry-completeness rates |
| B — Session isolation | no cross-session filesystem changes, no cross-session events, no cross-session identity reuse, reset isolation |
| C — Telemetry completeness | `captured_expected_events / expected_events` against the declared sequence in `sandbox/progression.py` |
| D — Execution overhead | create / scenario / reset / destroy latency — mean, median, stdev, p95, min, max, via `time.perf_counter` |
| E — Scaling | telemetry storage growth, event query latency and lifecycle overhead at 10/25/50/100 scenario executions |

Each run writes `evaluation/results/<experiment>_<backend>_<timestamp>.{json,csv}`.
The JSON carries full structure plus metadata (backend, UTC timestamp, run
count, Python version, platform, Docker version, wall time); the CSV carries one
row per raw observation. **Results are gitignored** — they are machine-specific
and are not committed unless we deliberately decide to publish a specific set.

### Research constraints this harness respects

* The backend is explicit and recorded; LocalBackend numbers are never presented
  as container-sandbox numbers.
* Raw observations are written verbatim alongside the summaries; failures are
  recorded in an `error` column rather than being swallowed (there is a test
  asserting a broken backend shows up as a failed run, not a silent pass).
* Nothing here measures a person. **No claim about educational effectiveness,
  learner awareness or susceptibility reduction is supported by this work.** The
  research scope is system design, containment, reproducibility, scenario
  correctness, telemetry correctness and execution overhead.

## Formal evaluation (Milestone 4)

`run_experiments.py` above is the exploratory harness. The measurements reported
in the paper come from `evaluation/formal_run.py`, which adds an independent
correctness oracle, a recorded machine profile, warm-up discipline and a
concurrency experiment.

```bash
docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
python -m evaluation.formal_run --dry-run
python -m evaluation.formal_run
```

`--dry-run` writes the profile and the containment results only; the second form
runs the full A–F suite.

### The oracle is independent of the implementation

`evaluation/specifications.py` declares each evaluated scenario's expected
observable event sequence as **frozen literal strings**. It imports nothing from
`sandbox/` — not `EventType`, not `EXPECTED_SEQUENCES` — and a test enforces
that. `sandbox/progression.py` keeps its own definitions for the dashboard and
the learner debrief, but the experimental oracle is specified separately, so an
experiment cannot grade the implementation against itself: if production
telemetry drifts, the frozen specification does not follow it and the run
reports a mismatch.

Each specification declares `required` (ordered), `repeatable`, `optional` and
`forbidden` event types. `evaluate()` returns a verdict naming every failure
mode separately — missing event, unexpected event, wrong order, wrong
`scenario_id`, wrong `session_id`, incomplete fields, non-monotonic timestamps —
and `tests/test_specifications.py` proves the oracle catches each of them.

### Measurement methodology

| Discipline | What is done |
| --- | --- |
| Backend | `DockerBackend` only. `require_docker_backend()` aborts the run if Docker is unreachable or the image is missing. There is **no fallback path to `LocalBackend`**. |
| Prebuilt image | The target image is built beforehand; its image id (and repo digest where one exists) is recorded. Build time is never inside a measured interval. |
| Warm-up | `--warmup` complete lifecycles (create, scenario, reset, destroy) run first and are **discarded**. This absorbs Docker Desktop's first-container costs. The discarded observations are still written to `metadata.json`, so the size of what was excluded stays visible. |
| Clock | `time.perf_counter` throughout — monotonic, highest resolution, unaffected by wall-clock adjustment. |
| Setup vs execution | Creation, scenario execution, reset and destroy are timed as four separate intervals and reported separately. No aggregate is presented as scenario cost. |
| Raw data | Every observation is written, not only aggregates. Failures appear as failed trials in an `error` column; nothing is downgraded to a warning. |
| Cleanup | Every sandbox is destroyed in a `finally` block, including after a failure, and the run ends with a sweep that reports any surviving labelled container. |

### Recorded experiment profile

`metadata.json` records OS, OS release and version, machine, CPU count, host and
Docker-VM memory, Python version and implementation, Docker Desktop client
version, Docker engine version, engine OS, the target image identifier and
digest, the git commit SHA and whether the tree was dirty, the specification
version, and the experiment timestamp. A field the machine will not report is
recorded as `null` rather than guessed.

### Experiments

| Experiment | Size | Measures |
| --- | --- | --- |
| A — Reproducibility | 30 runs | identical baseline (by content digest), expected file set, expected scenario result, exact event sequence, content unchanged by the rename-only impact, reset returns the exact baseline, no stale sandbox remains |
| B — Session isolation | 30 trials × 3 simultaneous sandboxes | filesystem, telemetry, `scenario_id`, `session_id`, synthetic-identity and reset isolation; every violation recorded explicitly |
| C — Telemetry correctness | 30 runs per scenario | completeness, exact-sequence rate, event precision, correlation and ordering correctness against the frozen specification; raw observed sequences retained |
| D — Performance | 50 measured runs after warm-up | create / scenario / reset / destroy separately: mean, median, stdev, min, max, p95, plus every raw observation |
| E — Scaling | 10, 25, 50, 100 | cumulative events, SQLite database size, ordered-query latency, scenario-filtered query latency, lifecycle latency, bytes per event |
| F — Concurrency | 1, 2, 4, 8 concurrent sandboxes | completion success rate, isolation violations, creation and scenario latency, total batch time. Deliberately bounded to safe workstation limits — **this is not a stress or denial-of-service test** |

### Containment re-validation

`evaluation/containment.py` runs the measured containment checks and emits a
record per check instead of an assertion, so results are exportable.
`containment.json` and `containment.csv` carry `check`, `category`,
`description`, `passed`, `expected` and `observed` for network-none, read-only
rootfs, tmpfs workspace, noexec/nosuid flags, non-root uid, dropped
capabilities, no-new-privileges, no privileged mode, no host mounts, no Docker
socket, memory and PID limits, blocked network probe, blocked DNS probe, blocked
rootfs write, blocked capability use, no visible host filesystem, blocked
invalid target, blocked unknown filename, and cross-sandbox isolation.

### Result layout

```
evaluation/results/formal/
    metadata.json        profile, configuration, warm-up, cleanup
    containment.json     containment checks + summary
    containment.csv      one row per check
    reproducibility.csv  experiment A raw observations
    isolation.csv        experiment B raw observations
    telemetry.csv        experiment C raw observations
    performance.csv      experiment D raw observations
    scaling.csv          experiment E raw observations
    concurrency.csv      experiment F raw observations
    summary.json         every experiment's aggregate results
```

`evaluation/results/` is gitignored; formal results are not committed unless we
deliberately decide to publish a specific set.

### Scope of the conclusions these results support

Every measurement was taken on **one Windows 11 workstation running Docker
Desktop's Linux VM**. The results describe that configuration and generalise to
no other operating system or deployment. They record that the declared Docker
isolation options were applied and that a set of benign probes failed as
expected; they are not a security audit and are not evidence of production-grade
containment. Nothing here measures a person: no claim about educational
effectiveness, phishing susceptibility or learner awareness follows from any
number this suite produces.

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

## One telemetry model

`SecurityEvent` is the single authoritative telemetry model. The Milestone 2
`PhishingFunnel` and `RansomwareFunnel` tables — a second analytics system whose
stage strings could drift out of step with the scenario events — are gone: their
tables are dropped on start-up and every funnel figure on the dashboard is now
*derived* from events by `sandbox/progression.py`. A stage count is literally a
count of the event that defines that stage, so the two can no longer disagree.

`sandbox/progression.py` is shared by the application and the evaluation
harness, so the expected sequences scored in Experiment C are the same
definitions the dashboard reasons about:

```python
EXPECTED_SEQUENCES["file_impact"]
EXPECTED_SEQUENCES["credential_reuse_phishing"]
```

Every event carries `session_id`, `scenario_id`, `event_type`, `timestamp` and
`source`, with `target`/`details` where they apply. Ordering is `(timestamp, id)`
— total and stable, because `id` is a monotonic autoincrement. **No event ever
carries a password**, including the authentication events.

## Telemetry event types

Lifecycle and file impact: `SANDBOX_CREATED`, `SANDBOX_RESET`,
`SANDBOX_DESTROYED`, `SCENARIO_STARTED`, `SCENARIO_COMPLETED`,
`SCENARIO_FAILED`, `FILE_IMPACT_STARTED`, `FILE_IMPACT`,
`FILE_IMPACT_REJECTED`, `FILE_IMPACT_COMPLETED`.

Phishing / credential reuse: `PHISHING_EXPOSED`, `CONSENT_GRANTED`,
`PHISHING_FORM_VIEWED`, `CREDENTIAL_SUBMITTED`, `CREDENTIAL_VALIDATED`,
`CREDENTIAL_VALIDATION_FAILED`, `SANDBOX_LOGIN_SUCCEEDED`,
`SYNTHETIC_RESOURCE_ACCESSED`, `SCENARIO_COMPLETED`.

Ransomware awareness: `RANSOMWARE_LURE_VIEWED`, `RANSOMWARE_DOWNLOAD_CLICKED`,
`RANSOMWARE_TRIGGERED`, `RANSOMWARE_DEBRIEFED`.

Lifecycle hygiene: `SANDBOX_REAP_SCAN`, `SANDBOX_REAPED`.

Instructor authentication: `INSTRUCTOR_LOGIN_SUCCEEDED`,
`INSTRUCTOR_LOGIN_FAILED`, `INSTRUCTOR_LOGGED_OUT`. These record that an
attempt happened and nothing else — no password, no username, no source address.

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

Docker integration and containment tests skip automatically when Docker or the
target image is unavailable. To run them, build the image first:

```bash
docker build -t dark-web-sandbox-target:latest -f docker/sandbox-target/Dockerfile .
```

With the image present the whole suite runs with **no skips**; the Docker tests
create and destroy their own short-lived containers and always clean up.

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
