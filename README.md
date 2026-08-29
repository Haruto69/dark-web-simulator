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
| `SANDBOX_INSTRUCTOR_TOKEN` | unset | When set, `/sandbox/*` control routes require this token. |

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
| `/sandbox/events` | GET | Telemetry in timestamp order (`?scenario_id=`, `?limit=`) |

Set `SANDBOX_INSTRUCTOR_TOKEN` to require an `X-Instructor-Token` header (or
`token` field) on the four control routes; the read-only routes stay open.

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

`SANDBOX_CREATED`, `SANDBOX_RESET`, `SANDBOX_DESTROYED`, `SCENARIO_STARTED`,
`SCENARIO_COMPLETED`, `SCENARIO_FAILED`, `FILE_IMPACT_STARTED`, `FILE_IMPACT`,
`FILE_IMPACT_REJECTED`, `FILE_IMPACT_COMPLETED`.

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
- Do not enter real credentials
- All data is simulated
- For educational use only

## Requirements
- Python 3.7+
- pip package manager
- Internet connection for dependencies

## License
This project is for demonstration purposes only.
