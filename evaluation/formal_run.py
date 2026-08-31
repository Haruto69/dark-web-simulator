"""Formal experiment suite for the conference paper (Milestone 4).

    python -m evaluation.formal_run                  # everything, default sizes
    python -m evaluation.formal_run --experiments A,D
    python -m evaluation.formal_run --dry-run        # profile + containment only

Results are written to ``evaluation/results/formal/`` as one CSV of raw
observations per experiment, one JSON per experiment carrying the same rows
plus summaries, and ``metadata.json`` / ``summary.json`` for the run as a whole.
Nothing is committed automatically.

MEASUREMENT METHODOLOGY
-----------------------
*Backend.* ``DockerBackend`` only. :func:`environment.require_docker_backend`
aborts the run if Docker is unreachable or the target image is missing; there is
no fallback path to ``LocalBackend``, because a measurement taken without a
container must never be reported as a container measurement.

*Prebuilt image.* The target image is built beforehand and its id (and repo
digest, when one exists) is recorded in the profile. Image build time is
therefore **not** inside any measured interval, and the first-pull/first-build
cost cannot contaminate a latency sample.

*Warm-up.* Before any timed experiment, ``--warmup`` complete sandbox
lifecycles (create, scenario, reset, destroy) are executed and **discarded**.
This absorbs Docker Desktop's first-container costs -- VM page-cache warming,
image layer materialisation, containerd bookkeeping -- which otherwise show up
as a large first observation. Warm-up timings are recorded separately in
``metadata.json`` so the reader can see what was excluded and how large it was.

*Clock.* ``time.perf_counter`` throughout: monotonic, highest resolution
available, unaffected by wall-clock adjustment mid-run.

*Setup vs execution.* Sandbox creation, scenario execution, reset and destroy
are timed as four separate intervals and reported separately. No aggregate
"total" is presented as if it were scenario cost.

*Cleanup.* Every sandbox is destroyed in a ``finally`` block, including after a
failure, and the run ends with a sweep that reports any container carrying this
application's ownership label that survived.

*Oracle.* Event sequences are judged by ``evaluation/specifications.py``, which
is independent of the production progression definitions. A failed trial is
recorded as a failed trial; nothing here downgrades a failure to a warning.

WHAT THESE RESULTS DO NOT SUPPORT
---------------------------------
Nothing here measures a person. No claim about educational effectiveness,
phishing susceptibility or learner awareness follows from any number produced by
this module. Every measurement was taken on a single Windows 11 workstation
running Docker Desktop's Linux VM, and generalises to no other configuration.
"""

import argparse
import csv
import json
import os
import re

import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox import (EventCollector, FileImpactScenario, PhishingScenario,
                     SandboxManager, SyntheticIdentityStore,
                     sandbox_id_for_session)
from sandbox.backends.docker import DEFAULT_IMAGE, DockerBackend
from sandbox.dataset import BASELINE_FILENAMES, SYNTHETIC_FILES
from sandbox.paths import IMPACT_SUFFIX

from evaluation import specifications
from evaluation.containment import run_containment_checks, summarise_containment
from evaluation.environment import (FORMAL_BACKEND, FormalRunError,
                                    experiment_profile, require_docker_backend)
from evaluation.metrics import (aggregate_flags, mean_ratio, summarise,
                                time_call)

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "results", "formal")

#: Prefix on every sandbox this module creates, so the final sweep can tell a
#: leaked experiment sandbox from a learner's.
FORMAL_PREFIX = "fml-"

DEFAULT_WARMUP = 3
DEFAULT_REPRODUCIBILITY_RUNS = 30
DEFAULT_ISOLATION_TRIALS = 30
DEFAULT_ISOLATION_SANDBOXES = 3
DEFAULT_TELEMETRY_RUNS = 30
DEFAULT_PERFORMANCE_RUNS = 50
DEFAULT_SCALES = (10, 25, 50, 100)
DEFAULT_CONCURRENCY_LEVELS = (1, 2, 4, 8)
DEFAULT_CONCURRENCY_TRIALS = 3


def formal_sandbox_id(tag):
    return "%s%s-%s" % (FORMAL_PREFIX, tag[:6], uuid.uuid4().hex[:8])


# ------------------------------------------------------------- observation

def workspace_digests(backend, sandbox_id):
    """``{filename: sha256}`` for everything in the container's workspace.

    One ``docker exec`` for the whole directory, so a scenario's content
    invariants are checked from *inside* the sandbox rather than inferred from
    the status labels the implementation reports about itself.
    """
    script = (
        "import hashlib,json,os\n"
        "out={}\n"
        "for n in sorted(os.listdir('/workspace')):\n"
        "    p=os.path.join('/workspace',n)\n"
        "    if os.path.isfile(p):\n"
        "        out[n]=hashlib.sha256(open(p,'rb').read()).hexdigest()\n"
        "print(json.dumps(out))\n")
    completed = backend._run(
        ["exec", "--", backend._container(sandbox_id), "python", "-c", script],
        check=False)
    try:
        return json.loads(completed.stdout)
    except ValueError:
        return {}


def baseline_digests():
    """Expected digests of the untouched synthetic dataset, from the definition."""
    import hashlib
    return {name: hashlib.sha256(text.encode("utf-8")).hexdigest()
            for name, text in SYNTHETIC_FILES.items()}


#: The impacted representation, declared here as a literal template rather than
#: imported from the production emulator module. The oracle must state
#: independently what it expects to find; importing the producer's own
#: formatter would make Experiment A check the implementation against itself.
DEMO_STATE_TEMPLATE = ("DWS-DEMO-STATE\n"
                       "original_filename=%s\n"
                       "original_sha256=%s\n"
                       "simulation_only=true\n")


def impacted_digests():
    """Expected digests after the demo impact.

    The demo impact is no longer rename-only: each synthetic file is renamed
    *and* its content replaced by a fixed placeholder that depends only on the
    filename and the file's own baseline digest. Both are known here from the
    dataset definition, so the post-impact workspace is fully predictable and
    is checked by content rather than by the labels the implementation reports
    about itself.
    """
    import hashlib
    expected = {}
    for name, digest in baseline_digests().items():
        placeholder = (DEMO_STATE_TEMPLATE % (name, digest)).encode("utf-8")
        expected[name + IMPACT_SUFFIX] = hashlib.sha256(placeholder).hexdigest()
    return expected


def plaintext_absent(backend, sandbox_id):
    """True when no baseline plaintext marker survives anywhere in /workspace.

    Read from inside the container, over every file present, so the claim
    "the original synthetic content is no longer in the workspace" is measured
    rather than asserted.
    """
    markers = sorted({text.splitlines()[1] for text in SYNTHETIC_FILES.values()
                      if len(text.splitlines()) > 1})
    script = (
        "import json,os,sys\n"
        "blob=''\n"
        "for n in sorted(os.listdir('/workspace')):\n"
        "    p=os.path.join('/workspace',n)\n"
        "    if os.path.isfile(p):\n"
        "        blob+=open(p,encoding='utf-8',errors='replace').read()\n"
        "print(json.dumps([m for m in %r if m in blob]))\n" % (markers,))
    completed = backend._run(
        ["exec", "--", backend._container(sandbox_id), "python", "-c", script],
        check=False)
    try:
        return json.loads(completed.stdout) == []
    except ValueError:
        return False


def scenario_events(collector, scenario_id):
    return [e for e in collector.events if e.get("scenario_id") == scenario_id]


def new_manager(backend, collector=None):
    """A manager with its own recorder. One per concurrent worker."""
    return SandboxManager(backend, recorder=collector or EventCollector(),
                          default_sandbox_id=None)


# ------------------------------------------------------------------ warm-up

def warm_up(backend, iterations):
    """Run and discard complete lifecycles; return the discarded timings.

    Returned rather than thrown away entirely so ``metadata.json`` can state how
    large the excluded observations were. They are never mixed into a reported
    statistic.
    """
    discarded = []
    for index in range(iterations):
        manager = new_manager(backend)
        sandbox_id = formal_sandbox_id("warm")
        row = {"warmup_index": index}
        try:
            _, row["create_seconds"] = time_call(manager.create, sandbox_id,
                                                 session_id="warmup-%d" % index)
            _, row["scenario_seconds"] = time_call(
                FileImpactScenario(manager).run, sandbox_id=sandbox_id,
                session_id="warmup-%d" % index)
            _, row["reset_seconds"] = time_call(manager.reset, sandbox_id,
                                                session_id="warmup-%d" % index)
            _, row["destroy_seconds"] = time_call(manager.destroy, sandbox_id,
                                                  session_id="warmup-%d" % index)
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001 - recorded, never hidden
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            try:
                backend.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
        discarded.append(row)
    return discarded


# --------------------------------------------- A: reproducibility (>= 30 runs)

def experiment_a(backend, runs):
    """A. Independent verification of every reproducibility claim, per run."""
    expected_baseline = baseline_digests()
    expected_impacted = impacted_digests()
    expected_names = sorted(BASELINE_FILENAMES)
    rows = []

    for index in range(runs):
        collector = EventCollector()
        manager = new_manager(backend, collector)
        sandbox_id = formal_sandbox_id("repro")
        session_id = "formal-a-%d" % index
        row = {"run": index, "sandbox_id": sandbox_id, "session_id": session_id}
        try:
            manager.create(sandbox_id, session_id=session_id)

            # 1. identical baseline dataset, verified by content, not by label
            created = workspace_digests(backend, sandbox_id)
            row["baseline_identical"] = created == expected_baseline
            row["baseline_file_set_correct"] = sorted(created) == expected_names

            result = FileImpactScenario(manager).run(
                sandbox_id=sandbox_id, session_id=session_id)

            # 2. expected scenario result and expected post-impact file set
            row["scenario_id"] = result["scenario_id"]
            row["impacted_count"] = result["impacted"]
            row["expected_impacted"] = len(BASELINE_FILENAMES)
            after = workspace_digests(backend, sandbox_id)
            row["scenario_result_correct"] = (
                result["impacted"] == len(BASELINE_FILENAMES))
            row["impacted_file_set_correct"] = (
                sorted(after) == sorted(expected_impacted))

            # 3. content impact: every impacted file holds the fixed demo
            #    state, and no baseline plaintext survives in the workspace
            row["content_impact_correct"] = after == expected_impacted
            row["plaintext_absent"] = plaintext_absent(backend, sandbox_id)

            # 4. event sequence, judged by the independent oracle
            verdict = specifications.evaluate(
                scenario_events(collector, result["scenario_id"]),
                "file_impact", scenario_id=result["scenario_id"],
                session_id=session_id)
            row["event_sequence_correct"] = verdict.ok
            row["telemetry_completeness"] = verdict.completeness
            row["telemetry_complete"] = verdict.completeness == 1.0
            row["events_ordered"] = verdict.timestamps_ordered
            row["missing_events"] = ";".join(verdict.missing)
            row["unexpected_events"] = ";".join(verdict.unexpected)
            row["observed_sequence"] = ",".join(verdict.observed)

            # 5. reset returns the exact baseline, by content
            manager.reset(sandbox_id, session_id=session_id)
            row["reset_exact_baseline"] = (
                workspace_digests(backend, sandbox_id) == expected_baseline)

            # 6. no stale sandbox remains after destroy
            manager.destroy(sandbox_id, session_id=session_id)
            row["destroyed"] = backend.status(sandbox_id)["state"] == "absent"
            row["no_stale_sandbox"] = (
                sandbox_id not in backend.list_sandboxes())
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            try:
                backend.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass

        row["run_succeeded"] = not row["error"] and all(
            row.get(flag) for flag in (
                "baseline_identical", "baseline_file_set_correct",
                "scenario_result_correct", "impacted_file_set_correct",
                "content_impact_correct", "plaintext_absent",
                "event_sequence_correct",
                "reset_exact_baseline", "destroyed", "no_stale_sandbox"))
        rows.append(row)

    summary = {
        "scenario_success_rate": aggregate_flags(rows, "run_succeeded"),
        "baseline_correctness_rate": aggregate_flags(rows, "baseline_identical"),
        "expected_file_set_rate": aggregate_flags(rows, "baseline_file_set_correct"),
        "scenario_result_rate": aggregate_flags(rows, "scenario_result_correct"),
        "content_impact_rate": aggregate_flags(rows, "content_impact_correct"),
        "plaintext_absent_rate": aggregate_flags(rows, "plaintext_absent"),
        "reset_correctness_rate": aggregate_flags(rows, "reset_exact_baseline"),
        "telemetry_completeness_rate": aggregate_flags(rows, "telemetry_complete"),
        "mean_telemetry_completeness": mean_ratio(rows, "telemetry_completeness"),
        "exact_event_sequence_rate": aggregate_flags(rows, "event_sequence_correct"),
        "no_stale_sandbox_rate": aggregate_flags(rows, "no_stale_sandbox"),
        "failed_runs": [r["run"] for r in rows if not r["run_succeeded"]],
    }
    fields = ["run", "sandbox_id", "session_id", "scenario_id",
              "baseline_identical", "baseline_file_set_correct",
              "impacted_count", "expected_impacted", "scenario_result_correct",
              "impacted_file_set_correct", "content_impact_correct",
              "plaintext_absent",
              "event_sequence_correct", "telemetry_completeness",
              "telemetry_complete", "events_ordered", "missing_events",
              "unexpected_events", "observed_sequence", "reset_exact_baseline",
              "destroyed", "no_stale_sandbox", "run_succeeded", "error"]
    return "reproducibility", summary, rows, fields


# ------------------------------------------------ B: session isolation (>= 30)

def experiment_b(backend, trials, sandboxes_per_trial):
    """B. Simultaneously existing sandboxes must not observe one another."""
    identities = SyntheticIdentityStore("formal-evaluation-derivation-key")
    expected_baseline = baseline_digests()
    expected_impacted = impacted_digests()
    rows = []

    for index in range(trials):
        collector = EventCollector()
        manager = new_manager(backend, collector)
        sessions = ["formal-b-%d-%d" % (index, n)
                    for n in range(sandboxes_per_trial)]
        ids = [formal_sandbox_id("iso%d" % n) for n in range(sandboxes_per_trial)]
        row = {"trial": index, "sandboxes": sandboxes_per_trial,
               "violations": []}
        try:
            for sandbox_id, session_id in zip(ids, sessions):
                manager.create(sandbox_id, session_id=session_id)
            row["all_created"] = all(
                backend.status(s)["state"] == "running" for s in ids)

            marker = "marker-%s" % uuid.uuid4().hex[:8]
            backend._run(["exec", "--", backend._container(ids[0]), "python",
                          "-c", "open('/workspace/%s','w').write('x')" % marker],
                         check=False)

            result = FileImpactScenario(manager).run(
                sandbox_id=ids[0], session_id=sessions[0])

            # filesystem isolation, by content
            first_digests = workspace_digests(backend, ids[0])
            row["target_impacted"] = all(
                first_digests.get(name) == digest
                for name, digest in expected_impacted.items())
            row["marker_absent_elsewhere"] = all(
                marker not in workspace_digests(backend, other)
                for other in ids[1:])
            row["filesystem_isolated"] = (
                row["marker_absent_elsewhere"]
                and all(workspace_digests(backend, other) == expected_baseline
                        for other in ids[1:]))

            # telemetry / scenario_id / session_id isolation, via the oracle
            events = scenario_events(collector, result["scenario_id"])
            verdict = specifications.evaluate(
                events, "file_impact", scenario_id=result["scenario_id"],
                session_id=sessions[0])
            row["telemetry_isolated"] = verdict.session_id_correct
            row["scenario_id_isolated"] = verdict.scenario_id_correct
            row["session_id_isolated"] = (
                {e.get("session_id") for e in events} == {sessions[0]})
            row["foreign_session_events"] = len(
                [e for e in events if e.get("session_id") != sessions[0]])
            row["distinct_scenario_ids"] = len(
                {e.get("scenario_id") for e in events})

            # synthetic identity isolation
            issued = identities.identities(sessions[0])[0]
            row["own_identity_valid"] = identities.validate(
                sessions[0], issued["username"], issued["password"])[0]
            row["identity_isolated"] = all(
                not identities.validate(other, issued["username"],
                                        issued["password"])[0]
                for other in sessions[1:])
            row["derived_ids_distinct"] = (
                len({sandbox_id_for_session(s) for s in sessions}) == len(sessions))

            # reset isolation
            manager.reset(ids[0], session_id=sessions[0])
            row["reset_isolated"] = all(
                workspace_digests(backend, other) == expected_baseline
                for other in ids[1:])
            row["reset_restored_target"] = (
                workspace_digests(backend, ids[0]) == expected_baseline)
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            for sandbox_id in ids:
                try:
                    backend.destroy(sandbox_id)
                except Exception:  # noqa: BLE001
                    pass

        checks = ("all_created", "target_impacted", "filesystem_isolated",
                  "telemetry_isolated", "scenario_id_isolated",
                  "session_id_isolated", "own_identity_valid",
                  "identity_isolated", "derived_ids_distinct",
                  "reset_isolated", "reset_restored_target")
        row["violations"] = ";".join(c for c in checks if not row.get(c))
        row["trial_succeeded"] = not row["error"] and not row["violations"]
        rows.append(row)

    summary = {
        "trial_success_rate": aggregate_flags(rows, "trial_succeeded"),
        "filesystem_isolation_rate": aggregate_flags(rows, "filesystem_isolated"),
        "telemetry_isolation_rate": aggregate_flags(rows, "telemetry_isolated"),
        "scenario_id_isolation_rate": aggregate_flags(rows, "scenario_id_isolated"),
        "session_id_isolation_rate": aggregate_flags(rows, "session_id_isolated"),
        "identity_isolation_rate": aggregate_flags(rows, "identity_isolated"),
        "reset_isolation_rate": aggregate_flags(rows, "reset_isolated"),
        # Recorded explicitly and never softened into a warning.
        "isolation_violations": [
            {"trial": r["trial"], "violations": r["violations"],
             "error": r["error"]}
            for r in rows if r["violations"] or r["error"]],
        "total_violating_trials": sum(1 for r in rows if not r["trial_succeeded"]),
    }
    fields = ["trial", "sandboxes", "all_created", "target_impacted",
              "marker_absent_elsewhere", "filesystem_isolated",
              "telemetry_isolated", "scenario_id_isolated",
              "session_id_isolated", "foreign_session_events",
              "distinct_scenario_ids", "own_identity_valid",
              "identity_isolated", "derived_ids_distinct", "reset_isolated",
              "reset_restored_target", "violations", "trial_succeeded", "error"]
    return "isolation", summary, rows, fields


# ------------------------------------------- C: telemetry correctness (>= 30)

def _telemetry_row(index, scenario, events, expected_scenario_id,
                   expected_session_id, error=""):
    """Score one observed sequence against the frozen specification."""
    row = {"run": index, "scenario": scenario,
           "expected_events": len(specifications.SPECIFICATIONS[scenario].required),
           "error": error}
    if error:
        row.update({"captured_expected_events": 0, "completeness": 0.0,
                    "complete": False, "sequence_exact": False,
                    "correlation_correct": False, "session_correct": False,
                    "ordering_correct": False, "unexpected_events": "",
                    "missing_events": "", "total_events": 0,
                    "observed_sequence": "", "precision": None})
        return row

    verdict = specifications.evaluate(events, scenario,
                                      scenario_id=expected_scenario_id,
                                      session_id=expected_session_id)
    permitted = specifications.SPECIFICATIONS[scenario].permitted
    correct_events = sum(1 for t in verdict.observed if t in permitted)
    row.update({
        "captured_expected_events": int(round(
            verdict.completeness * row["expected_events"])),
        "completeness": verdict.completeness,
        "complete": verdict.completeness == 1.0,
        "sequence_exact": verdict.order_correct and not verdict.missing,
        "correlation_correct": verdict.scenario_id_correct,
        "session_correct": verdict.session_id_correct,
        "ordering_correct": verdict.timestamps_ordered,
        "unexpected_events": ";".join(verdict.unexpected),
        "missing_events": ";".join(verdict.missing),
        "total_events": len(verdict.observed),
        "observed_sequence": ",".join(verdict.observed),
        # Precision-style: of the events actually emitted, how many are
        # permitted by the specification. 1.0 means nothing extraneous.
        "precision": (correct_events / len(verdict.observed)
                      if verdict.observed else None),
        "verdict_ok": verdict.ok,
    })
    return row


def _run_file_impact_telemetry(backend, index):
    collector = EventCollector()
    manager = new_manager(backend, collector)
    sandbox_id = formal_sandbox_id("tele")
    session_id = "formal-c-fi-%d" % index
    try:
        manager.create(sandbox_id, session_id=session_id)
        result = FileImpactScenario(manager).run(sandbox_id=sandbox_id,
                                                 session_id=session_id)
        return _telemetry_row(index, "file_impact",
                              scenario_events(collector, result["scenario_id"]),
                              result["scenario_id"], session_id)
    except Exception as exc:  # noqa: BLE001
        return _telemetry_row(index, "file_impact", [], None, session_id,
                              error="%s: %s" % (type(exc).__name__, exc))
    finally:
        try:
            backend.destroy(sandbox_id)
        except Exception:  # noqa: BLE001
            pass


def _run_phishing_telemetry(backend, index):
    """Drive the phishing state machine directly.

    The scenario object is the same one the Flask routes drive; it performs no
    container operation of its own, so no sandbox is created here and none is
    leaked. The route layer is separately covered by the HTTP test suite.
    """
    collector = EventCollector()
    manager = new_manager(backend, collector)
    identities = SyntheticIdentityStore("formal-evaluation-derivation-key")
    scenario = PhishingScenario(manager, identities)
    session_id = "formal-c-ph-%d" % index
    try:
        state = scenario.expose(session_id, lure="marketplace")
        scenario_id, stage = state["scenario_id"], state["stage"]
        stage = scenario.grant_consent(session_id, scenario_id, stage)["stage"]
        stage = scenario.view_form(session_id, scenario_id, stage)["stage"]
        issued = identities.identities(session_id)[0]
        outcome = scenario.submit_credential(session_id, scenario_id, stage,
                                             issued["username"], issued["password"])
        stage = outcome["stage"]
        stage = scenario.reuse_credential(session_id, scenario_id, stage,
                                          outcome["synthetic_username"])["stage"]
        stage = scenario.access_resource(session_id, scenario_id, stage)["stage"]
        scenario.complete(session_id, scenario_id, stage)
        return _telemetry_row(index, "credential_reuse_phishing",
                              scenario_events(collector, scenario_id),
                              scenario_id, session_id)
    except Exception as exc:  # noqa: BLE001
        return _telemetry_row(index, "credential_reuse_phishing", [], None,
                              session_id, error="%s: %s" % (type(exc).__name__, exc))


#: Matches the hidden CSRF field the ransomware templates render.
_CSRF_RE = re.compile(rb'name="csrf_token" value="([^"]+)"')


def _csrf_token(client):
    """Scrape this client's CSRF token from a rendered page, as a browser has it."""
    page = client.get("/files/browser")
    match = _CSRF_RE.search(page.data)
    if not match:
        raise RuntimeError("no CSRF token rendered on /files/browser")
    return match.group(1).decode()


def _run_ransomware_telemetry(flask_client_factory, index):
    """Drive the ransomware-awareness scenario through its real HTTP routes.

    This scenario is application-level only: it marks this session's own
    RansomwareRunState row and touches no sandbox and no real file. Its telemetry therefore has to be
    collected through the Flask routes that emit it.
    """
    session_id = None
    try:
        client, module = flask_client_factory()
        for path in ("/marketplace/tools", "/download/tool/1"):
            response = client.get(path)
            if response.status_code != 200:
                raise RuntimeError("%s returned %d" % (path, response.status_code))
        # Milestone 4.1: the two stages that change state are POSTs and carry
        # this client's CSRF token, exactly as the browser forms do.
        for path in ("/ransomware/activate", "/ransomware/reveal"):
            response = client.post(path, data={"csrf_token": _csrf_token(client)})
            if response.status_code != 200:
                raise RuntimeError("%s returned %d" % (path, response.status_code))
        with client.session_transaction() as flask_session:
            session_id = flask_session.get("session_id")
            scenario_id = flask_session.get("ransomware_scenario_id")
        with module.app.app_context():
            rows = (module.SecurityEvent.query
                    .filter(module.SecurityEvent.scenario_id == scenario_id)
                    .order_by(module.SecurityEvent.timestamp.asc(),
                              module.SecurityEvent.id.asc()).all())
            events = [r.to_dict() | {"timestamp": r.timestamp} for r in rows]
        return _telemetry_row(index, "ransomware_awareness", events,
                              scenario_id, session_id)
    except Exception as exc:  # noqa: BLE001
        return _telemetry_row(index, "ransomware_awareness", [], None, session_id,
                              error="%s: %s" % (type(exc).__name__, exc))


def experiment_c(backend, runs, flask_client_factory=None):
    """C. Captured telemetry versus the independent specification."""
    rows = []
    for index in range(runs):
        rows.append(_run_file_impact_telemetry(backend, index))
    for index in range(runs):
        rows.append(_run_phishing_telemetry(backend, index))
    if flask_client_factory is not None:
        for index in range(runs):
            rows.append(_run_ransomware_telemetry(flask_client_factory, index))

    by_scenario = {}
    for scenario in sorted({r["scenario"] for r in rows}):
        subset = [r for r in rows if r["scenario"] == scenario]
        by_scenario[scenario] = {
            "runs": len(subset),
            "mean_completeness": mean_ratio(subset, "completeness"),
            "telemetry_completeness_rate": aggregate_flags(subset, "complete"),
            "exact_sequence_rate": aggregate_flags(subset, "sequence_exact"),
            "correlation_correctness_rate": aggregate_flags(subset, "correlation_correct"),
            "session_correctness_rate": aggregate_flags(subset, "session_correct"),
            "ordering_correctness_rate": aggregate_flags(subset, "ordering_correct"),
            "mean_event_precision": mean_ratio(subset, "precision"),
            "failed_runs": [r["run"] for r in subset if r["error"]],
            "expected_sequence": list(
                specifications.SPECIFICATIONS[scenario].required),
        }
    summary = {"by_scenario": by_scenario,
               "specification_version": specifications.SPECIFICATION_VERSION,
               "total_runs": len(rows)}
    fields = ["run", "scenario", "expected_events", "captured_expected_events",
              "completeness", "complete", "sequence_exact",
              "correlation_correct", "session_correct", "ordering_correct",
              "precision", "total_events", "missing_events",
              "unexpected_events", "observed_sequence", "error"]
    return "telemetry", summary, rows, fields


# ---------------------------------------------------- D: performance (>= 50)

def experiment_d(backend, runs):
    """D. Four separately timed lifecycle phases, warm-up already excluded."""
    rows = []
    for index in range(runs):
        manager = new_manager(backend)
        sandbox_id = formal_sandbox_id("perf")
        session_id = "formal-d-%d" % index
        row = {"run": index, "sandbox_id": sandbox_id,
               "create_seconds": None, "scenario_seconds": None,
               "reset_seconds": None, "destroy_seconds": None}
        try:
            _, row["create_seconds"] = time_call(manager.create, sandbox_id,
                                                 session_id=session_id)
            _, row["scenario_seconds"] = time_call(
                FileImpactScenario(manager).run, sandbox_id=sandbox_id,
                session_id=session_id)
            _, row["reset_seconds"] = time_call(manager.reset, sandbox_id,
                                                session_id=session_id)
            _, row["destroy_seconds"] = time_call(manager.destroy, sandbox_id,
                                                  session_id=session_id)
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            try:
                backend.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
        rows.append(row)

    complete = [r for r in rows if not r["error"]]
    phases = ("create_seconds", "scenario_seconds", "reset_seconds",
              "destroy_seconds")
    summary = {phase: summarise([r[phase] for r in complete]) for phase in phases}
    summary["completed_runs"] = len(complete)
    summary["failed_runs"] = [r["run"] for r in rows if r["error"]]
    fields = ["run", "sandbox_id"] + list(phases) + ["error"]
    return "performance", summary, rows, fields


# -------------------------------------------------------------- E: scaling

def experiment_e(backend, scales):
    """E. Telemetry storage growth and query latency against event volume."""
    import shutil
    import sqlite3
    import tempfile

    rows = []
    scratch = tempfile.mkdtemp(prefix="dws-formal-scale-")
    db_path = os.path.join(scratch, "telemetry.db")
    connection = sqlite3.connect(db_path)
    connection.execute(
        "CREATE TABLE security_event ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, scenario_id TEXT,"
        " session_id TEXT, event_type TEXT NOT NULL, timestamp TEXT,"
        " source TEXT, target TEXT, details TEXT)")
    connection.execute("CREATE INDEX ix_event_scenario ON security_event(scenario_id)")
    connection.execute("CREATE INDEX ix_event_session ON security_event(session_id)")
    connection.execute("CREATE INDEX ix_event_ts ON security_event(timestamp)")
    connection.commit()

    sandbox_id = formal_sandbox_id("scale")
    manager = new_manager(backend)
    total_events = 0
    try:
        manager.create(sandbox_id, session_id="formal-e")
        for scale in scales:
            collector = EventCollector()
            manager.recorder = collector
            scenario_times, lifecycle_times = [], []
            last_scenario_id = None
            errors = 0
            for n in range(scale):
                try:
                    result, elapsed = time_call(
                        FileImpactScenario(manager).run,
                        sandbox_id=sandbox_id, session_id="formal-e-%d" % n)
                    scenario_times.append(elapsed)
                    last_scenario_id = result["scenario_id"]
                    _, reset_elapsed = time_call(backend.reset, sandbox_id)
                    lifecycle_times.append(elapsed + reset_elapsed)
                except Exception:  # noqa: BLE001 - counted, not hidden
                    errors += 1

            events = collector.events
            _, insert_seconds = time_call(_insert_events, connection, events)
            connection.commit()
            total_events += len(events)
            size_bytes = os.path.getsize(db_path)

            _, query_ordered_seconds = time_call(
                _query, connection,
                "SELECT id FROM security_event ORDER BY timestamp ASC, id ASC")
            _, query_scenario_seconds = time_call(
                _query, connection,
                "SELECT id FROM security_event WHERE scenario_id = ?"
                " ORDER BY timestamp ASC, id ASC", (last_scenario_id,))

            rows.append({
                "scale_scenario_runs": scale,
                "scenario_errors": errors,
                "events_inserted": len(events),
                "cumulative_events": total_events,
                "db_size_bytes": size_bytes,
                "bytes_per_event": (size_bytes / total_events) if total_events else None,
                "insert_seconds": insert_seconds,
                "query_ordered_seconds": query_ordered_seconds,
                "query_by_scenario_seconds": query_scenario_seconds,
                "scenario_mean_seconds": summarise(scenario_times)["mean"],
                "scenario_p95_seconds": summarise(scenario_times)["p95"],
                "lifecycle_mean_seconds": summarise(lifecycle_times)["mean"],
                "lifecycle_p95_seconds": summarise(lifecycle_times)["p95"],
            })
    finally:
        try:
            backend.destroy(sandbox_id)
        except Exception:  # noqa: BLE001
            pass
        connection.close()
        shutil.rmtree(scratch, ignore_errors=True)

    summary = {
        "scales": list(scales),
        "final_cumulative_events": rows[-1]["cumulative_events"] if rows else 0,
        "final_db_size_bytes": rows[-1]["db_size_bytes"] if rows else 0,
        "final_bytes_per_event": rows[-1]["bytes_per_event"] if rows else None,
        "query_ordered_seconds": summarise([r["query_ordered_seconds"] for r in rows]),
        "query_by_scenario_seconds": summarise(
            [r["query_by_scenario_seconds"] for r in rows]),
        "lifecycle_mean_seconds": summarise(
            [r["lifecycle_mean_seconds"] for r in rows
             if r["lifecycle_mean_seconds"] is not None]),
        "total_scenario_errors": sum(r["scenario_errors"] for r in rows),
    }
    fields = ["scale_scenario_runs", "scenario_errors", "events_inserted",
              "cumulative_events", "db_size_bytes", "bytes_per_event",
              "insert_seconds", "query_ordered_seconds",
              "query_by_scenario_seconds", "scenario_mean_seconds",
              "scenario_p95_seconds", "lifecycle_mean_seconds",
              "lifecycle_p95_seconds"]
    return "scaling", summary, rows, fields


def _insert_events(connection, events):
    connection.executemany(
        "INSERT INTO security_event"
        " (scenario_id, session_id, event_type, timestamp, source, target, details)"
        " VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(e.get("scenario_id"), e.get("session_id"), e["event_type"],
          e["timestamp"].isoformat(), e.get("source"), e.get("target"),
          e.get("details")) for e in events])


def _query(connection, sql, params=()):
    return connection.execute(sql, params).fetchall()


# ---------------------------------------------------------- F: concurrency

def _concurrent_worker(backend, level, trial, worker):
    """One independent sandbox, created and destroyed by this worker alone.

    Each worker gets its own manager and its own event collector, so the
    measurement does not depend on any shared mutable state between threads.
    """
    collector = EventCollector()
    manager = new_manager(backend, collector)
    sandbox_id = formal_sandbox_id("cc%d" % worker)
    session_id = "formal-f-%d-%d-%d" % (level, trial, worker)
    record = {"concurrency": level, "trial": trial, "worker": worker,
              "sandbox_id": sandbox_id, "session_id": session_id,
              "create_seconds": None, "scenario_seconds": None,
              "destroy_seconds": None, "isolation_violation": "", "error": ""}
    try:
        _, record["create_seconds"] = time_call(manager.create, sandbox_id,
                                                session_id=session_id)
        result, record["scenario_seconds"] = time_call(
            FileImpactScenario(manager).run, sandbox_id=sandbox_id,
            session_id=session_id)
        record["scenario_id"] = result["scenario_id"]

        digests = workspace_digests(backend, sandbox_id)
        if digests != impacted_digests():
            record["isolation_violation"] = "workspace_content_unexpected"

        verdict = specifications.evaluate(
            scenario_events(collector, result["scenario_id"]), "file_impact",
            scenario_id=result["scenario_id"], session_id=session_id)
        record["sequence_correct"] = verdict.ok
        if not verdict.session_id_correct:
            record["isolation_violation"] = (
                (record["isolation_violation"] + ";session_id_leak").strip(";"))
        if not verdict.scenario_id_correct:
            record["isolation_violation"] = (
                (record["isolation_violation"] + ";scenario_id_leak").strip(";"))

        _, record["destroy_seconds"] = time_call(manager.destroy, sandbox_id,
                                                 session_id=session_id)
        record["completed"] = True
    except Exception as exc:  # noqa: BLE001
        record["error"] = "%s: %s" % (type(exc).__name__, exc)
        record["completed"] = False
    finally:
        # Cleanup runs even when the worker failed part-way through.
        try:
            backend.destroy(sandbox_id)
        except Exception:  # noqa: BLE001
            pass
    return record


def experiment_f(backend, levels, trials):
    """F. A modest, bounded concurrency experiment.

    This is deliberately *not* a stress or denial-of-service test: the maximum
    level is a small number of sandboxes chosen to stay well inside a single
    workstation's Docker Desktop limits, each doing the ordinary scenario work
    exactly once.
    """
    rows = []
    for level in levels:
        for trial in range(trials):
            started = time.perf_counter()
            with ThreadPoolExecutor(max_workers=level) as pool:
                records = list(pool.map(
                    lambda worker: _concurrent_worker(backend, level, trial, worker),
                    range(level)))
            batch_seconds = time.perf_counter() - started
            for record in records:
                record["batch_seconds"] = batch_seconds
            rows.extend(records)

    by_level = {}
    for level in levels:
        subset = [r for r in rows if r["concurrency"] == level]
        completed = [r for r in subset if r["completed"]]
        batches = sorted({(r["trial"], r["batch_seconds"]) for r in subset})
        by_level[str(level)] = {
            "workers": len(subset),
            "completion_success_rate": aggregate_flags(subset, "completed"),
            "isolation_violations": [
                {"trial": r["trial"], "worker": r["worker"],
                 "violation": r["isolation_violation"]}
                for r in subset if r["isolation_violation"]],
            "isolation_violation_count": sum(
                1 for r in subset if r["isolation_violation"]),
            "create_seconds": summarise([r["create_seconds"] for r in completed]),
            "scenario_seconds": summarise([r["scenario_seconds"] for r in completed]),
            "destroy_seconds": summarise([r["destroy_seconds"] for r in completed]),
            "batch_seconds": summarise([b for _, b in batches]),
            "errors": [r["error"] for r in subset if r["error"]],
        }
    summary = {
        "levels": list(levels), "trials_per_level": trials,
        "by_level": by_level,
        "total_isolation_violations": sum(
            1 for r in rows if r["isolation_violation"]),
        "total_failed_workers": sum(1 for r in rows if not r["completed"]),
    }
    fields = ["concurrency", "trial", "worker", "sandbox_id", "session_id",
              "scenario_id", "create_seconds", "scenario_seconds",
              "destroy_seconds", "batch_seconds", "sequence_correct",
              "isolation_violation", "completed", "error"]
    return "concurrency", summary, rows, fields


# ------------------------------------------------------------------- output

def write_csv(path, rows, fields):
    with open(path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def write_json(path, payload):
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump(payload, handle, indent=2, default=str)


def leftover_sandboxes(backend):
    """Every owned container still present, split into ours and other."""
    try:
        owned = backend.sandbox_metadata()
    except Exception:  # noqa: BLE001
        return {"error": "could not enumerate containers", "formal": [], "other": []}
    return {
        "formal": [r["sandbox_id"] for r in owned
                   if r["sandbox_id"].startswith(FORMAL_PREFIX)],
        "other": [r["sandbox_id"] for r in owned
                  if not r["sandbox_id"].startswith(FORMAL_PREFIX)],
    }


def sweep(backend):
    """Destroy any formal-run sandbox that survived, and report what was found."""
    before = leftover_sandboxes(backend)
    for sandbox_id in before.get("formal", []):
        try:
            backend.destroy(sandbox_id)
        except Exception:  # noqa: BLE001
            pass
    after = leftover_sandboxes(backend)
    return {"leaked_before_sweep": before.get("formal", []),
            "leaked_after_sweep": after.get("formal", []),
            "other_owned_containers": after.get("other", []),
            "clean": not after.get("formal")}


# ---------------------------------------------------- Flask client factory

def make_flask_client_factory():
    """A factory yielding a fresh Flask test client for the ransomware scenario.

    The app is configured onto a throwaway SQLite database and pinned to the
    Docker backend like everything else in a formal run -- the ransomware
    routes never touch the sandbox, so no container results from this, but
    nothing is allowed to quietly select ``LocalBackend`` either.
    """
    import tempfile

    scratch = tempfile.mkdtemp(prefix="dws-formal-app-")
    os.environ["SIMULATOR_DATABASE_URI"] = (
        "sqlite:///" + os.path.join(scratch, "formal.db").replace("\\", "/"))
    os.environ["SANDBOX_LOCAL_ROOT"] = os.path.join(scratch, "sandboxes")
    os.environ["SANDBOX_BACKEND"] = FORMAL_BACKEND
    os.environ.setdefault("FLASK_SECRET_KEY", "formal-run-key-%s" % uuid.uuid4().hex)
    os.environ.setdefault("SYNTHETIC_IDENTITY_SECRET",
                          "formal-run-identity-%s" % uuid.uuid4().hex)
    sys.modules.pop("app", None)
    import app as app_module
    app_module.app.config["TESTING"] = True

    def factory():
        return app_module.app.test_client(), app_module

    return factory, scratch


# ------------------------------------------------------------------- driver

EXPERIMENTS = ("A", "B", "C", "D", "E", "F")
EXPERIMENT_TITLES = {
    "A": "reproducibility", "B": "session isolation",
    "C": "telemetry correctness", "D": "performance",
    "E": "scaling", "F": "concurrency",
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Formal experiment suite (Milestone 4)")
    parser.add_argument("--backend", default=FORMAL_BACKEND,
                        help="recorded verbatim; only 'docker' is accepted")
    parser.add_argument("--image", default=DEFAULT_IMAGE)
    parser.add_argument("--experiments", default=",".join(EXPERIMENTS))
    parser.add_argument("--warmup", type=int, default=DEFAULT_WARMUP)
    parser.add_argument("--runs-a", type=int, default=DEFAULT_REPRODUCIBILITY_RUNS)
    parser.add_argument("--trials-b", type=int, default=DEFAULT_ISOLATION_TRIALS)
    parser.add_argument("--sandboxes-b", type=int, default=DEFAULT_ISOLATION_SANDBOXES)
    parser.add_argument("--runs-c", type=int, default=DEFAULT_TELEMETRY_RUNS)
    parser.add_argument("--runs-d", type=int, default=DEFAULT_PERFORMANCE_RUNS)
    parser.add_argument("--scales", default=",".join(str(s) for s in DEFAULT_SCALES))
    parser.add_argument("--concurrency",
                        default=",".join(str(c) for c in DEFAULT_CONCURRENCY_LEVELS))
    parser.add_argument("--concurrency-trials", type=int,
                        default=DEFAULT_CONCURRENCY_TRIALS)
    parser.add_argument("--results-dir", default=RESULTS_DIR)
    parser.add_argument("--skip-containment", action="store_true")
    parser.add_argument("--dry-run", action="store_true",
                        help="write the profile and containment results only")
    args = parser.parse_args(argv)

    # Refuse to start rather than silently degrade. Section 3 of Milestone 4.
    require_docker_backend(args.backend, args.image)

    results_dir = os.path.abspath(args.results_dir)
    os.makedirs(results_dir, exist_ok=True)
    backend = DockerBackend(image=args.image)

    selected = [letter.strip().upper() for letter in args.experiments.split(",")
                if letter.strip()]
    unknown = [letter for letter in selected if letter not in EXPERIMENTS]
    if unknown:
        raise SystemExit("unknown experiment(s): %s" % ", ".join(unknown))
    scales = tuple(int(v) for v in args.scales.split(",") if v.strip())
    concurrency = tuple(int(v) for v in args.concurrency.split(",") if v.strip())

    profile = experiment_profile(args.backend, image=args.image, extra={
        "specification_version": specifications.SPECIFICATION_VERSION,
        "isolation_summary": backend.isolation_summary,
        "results_dir": results_dir,
    })
    print("=== formal experiment profile ===")
    for key in ("os", "python_version", "cpu_count", "docker_desktop_client_version",
                "docker_engine_version", "target_image_id", "git_commit",
                "git_tree_dirty"):
        print("  %-32s %s" % (key, profile.get(key)))

    run_started = time.perf_counter()
    run_record = {"profile": profile,
                  "specifications": specifications.specification_manifest(),
                  "configuration": {
                      "warmup_iterations": args.warmup,
                      "reproducibility_runs": args.runs_a,
                      "isolation_trials": args.trials_b,
                      "isolation_sandboxes_per_trial": args.sandboxes_b,
                      "telemetry_runs_per_scenario": args.runs_c,
                      "performance_runs": args.runs_d,
                      "scaling_scales": list(scales),
                      "concurrency_levels": list(concurrency),
                      "concurrency_trials_per_level": args.concurrency_trials,
                      "experiments_selected": selected,
                  }}
    summaries = {}
    flask_scratch = None

    try:
        # 11. containment re-validation, before any formal measurement
        if not args.skip_containment:
            print("\n=== containment re-validation ===")
            checks, containment_seconds = time_call(run_containment_checks, backend)
            containment_summary = summarise_containment(checks)
            containment_summary["elapsed_seconds"] = containment_seconds
            write_json(os.path.join(results_dir, "containment.json"),
                       {"profile": profile, "summary": containment_summary,
                        "checks": checks})
            write_csv(os.path.join(results_dir, "containment.csv"), checks,
                      ["check", "category", "description", "passed", "expected",
                       "observed"])
            summaries["containment"] = containment_summary
            print("  %d/%d checks passed%s"
                  % (containment_summary["passed"],
                     containment_summary["checks_run"],
                     "" if containment_summary["all_passed"]
                     else "  FAILED: %s" % containment_summary["failed_checks"]))

        if args.dry_run:
            print("\ndry run: no timed experiment was executed")
        else:
            # 4. warm-up, excluded from every reported statistic
            print("\n=== warm-up (%d discarded lifecycles) ===" % args.warmup)
            discarded = warm_up(backend, args.warmup)
            run_record["warmup"] = {
                "iterations": args.warmup,
                "discarded_observations": discarded,
                "note": "excluded from every reported statistic; recorded so "
                        "the magnitude of the excluded first-run cost is visible",
                "create_seconds": summarise(
                    [d["create_seconds"] for d in discarded
                     if d.get("create_seconds") is not None]),
            }
            print("  discarded create latencies: %s"
                  % [round(d.get("create_seconds") or 0, 3) for d in discarded])

            if "C" in selected:
                try:
                    factory, flask_scratch = make_flask_client_factory()
                except Exception as exc:  # noqa: BLE001
                    print("  ransomware telemetry unavailable: %s" % exc)
                    factory = None
            else:
                factory = None

            for letter in selected:
                title = EXPERIMENT_TITLES[letter]
                print("\n=== Experiment %s: %s ===" % (letter, title))
                started = time.perf_counter()
                if letter == "A":
                    name, summary, rows, fields = experiment_a(backend, args.runs_a)
                elif letter == "B":
                    name, summary, rows, fields = experiment_b(
                        backend, args.trials_b, args.sandboxes_b)
                elif letter == "C":
                    name, summary, rows, fields = experiment_c(
                        backend, args.runs_c, flask_client_factory=factory)
                elif letter == "D":
                    name, summary, rows, fields = experiment_d(backend, args.runs_d)
                elif letter == "E":
                    name, summary, rows, fields = experiment_e(backend, scales)
                else:
                    name, summary, rows, fields = experiment_f(
                        backend, concurrency, args.concurrency_trials)
                elapsed = time.perf_counter() - started
                summary["wall_seconds"] = elapsed
                summary["observations"] = len(rows)

                write_csv(os.path.join(results_dir, name + ".csv"), rows, fields)
                write_json(os.path.join(results_dir, name + ".json"),
                           {"experiment": letter, "name": name,
                            "profile": profile, "summary": summary,
                            "observations": rows})
                summaries[name] = summary
                print(json.dumps(summary, indent=2, default=str)[:2000])
                print("  wrote %s.csv / %s.json (%.1fs)" % (name, name, elapsed))
    finally:
        # 13. every Docker resource this run created is removed.
        cleanup = sweep(backend)
        run_record["cleanup"] = cleanup
        run_record["total_wall_seconds"] = time.perf_counter() - run_started
        write_json(os.path.join(results_dir, "metadata.json"), run_record)
        write_json(os.path.join(results_dir, "summary.json"),
                   {"profile": profile,
                    "configuration": run_record["configuration"],
                    "cleanup": cleanup, "experiments": summaries})
        if flask_scratch:
            import shutil
            shutil.rmtree(flask_scratch, ignore_errors=True)

    print("\n=== cleanup ===")
    print("  leaked before sweep : %s" % cleanup["leaked_before_sweep"])
    print("  leaked after sweep  : %s" % cleanup["leaked_after_sweep"])
    print("  other owned         : %s" % cleanup["other_owned_containers"])
    print("\nresults written to %s" % results_dir)
    return 0 if cleanup["clean"] else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FormalRunError as error:
        print("formal run refused: %s" % error, file=sys.stderr)
        raise SystemExit(2)
