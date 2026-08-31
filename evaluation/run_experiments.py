"""Controlled synthetic experiments for the RewindSec sandbox.

Run from the repository root::

    python -m evaluation.run_experiments --backend docker --runs 20
    python -m evaluation.run_experiments --backend local --experiments A,C
    python -m evaluation.run_experiments --backend docker --list

Every experiment writes raw observations to ``evaluation/results/`` as both
JSON (full structure) and CSV (flat, one row per observation) together with the
metadata needed to reproduce it: backend, timestamp, run count, Python version
and Docker version.

RESEARCH RULES ENFORCED HERE
----------------------------
* The backend is never auto-detected. It is an explicit argument and is
  recorded in every output file, so a LocalBackend measurement can never be
  reported as a container-sandbox result.
* Raw observations are written verbatim. This module computes summary
  statistics but draws no conclusions; interpretation belongs in the write-up.
* Nothing here measures a human being. No claim about educational effect is
  supported by this harness.
"""

import argparse
import csv
import json
import os
import shutil
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox import (EventCollector, EventType, FileImpactScenario,
                     SandboxManager, SyntheticIdentityStore,
                     sandbox_id_for_session)
from sandbox.backends.docker import DockerBackend
from sandbox.backends.local import LocalBackend
from sandbox.dataset import BASELINE_FILENAMES, SYNTHETIC_FILES
from sandbox.progression import (EXPECTED_SEQUENCES, completeness, is_ordered,
                                 matches_expected_sequence)
from evaluation.metrics import (aggregate_flags, mean_ratio, rate,
                                run_metadata, summarise, time_call)

RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "results")

#: Sandbox ids used by the harness are prefixed so they are trivially
#: distinguishable from learner sandboxes and can be cleaned up wholesale.
EVAL_PREFIX = "eval-"


# ---------------------------------------------------------------- plumbing

def make_manager(backend_name, scratch_root, recorder=None):
    """Build a manager on an explicitly named backend. Never auto-detects."""
    if backend_name == "docker":
        backend = DockerBackend()
        if not backend.is_available():
            raise SystemExit(
                "Docker backend requested but Docker is unavailable. "
                "Refusing to silently fall back to the local backend.")
    elif backend_name == "local":
        backend = LocalBackend(scratch_root)
    else:
        raise SystemExit("unknown backend: %r" % backend_name)
    return SandboxManager(backend, recorder=recorder, default_sandbox_id=None)


def eval_sandbox_id(tag):
    """A short, valid, collision-resistant sandbox id for one experiment run."""
    return "%s%s-%s" % (EVAL_PREFIX, tag[:8], uuid.uuid4().hex[:8])


def workspace_signature(manager, sandbox_id):
    """Deterministic signature of the workspace: (name, status) pairs.

    Filename-level rather than byte-level. The byte-level expectation -- the
    baseline before the impact, the fixed demo placeholder after it -- is
    checked by Experiment A in ``formal_run`` and by the test suite; this
    signature exists to compare *workspace shape* across runs.
    """
    return tuple(sorted((f["name"], f["status"], f["present_as"] or "")
                        for f in manager.workspace_state(sandbox_id)))


def baseline_signature():
    """The expected baseline signature, computed from the dataset definition."""
    return tuple(sorted((name, "baseline", name) for name in BASELINE_FILENAMES))


def impacted_signature():
    return tuple(sorted((name, "impacted", name + ".demo_locked")
                        for name in BASELINE_FILENAMES))


def write_results(name, metadata, summary, rows, fieldnames):
    """Write one experiment's raw rows (CSV) and full result (JSON)."""
    os.makedirs(RESULTS_DIR, exist_ok=True)
    stamp = time.strftime("%Y%m%dT%H%M%S")
    base = "%s_%s_%s" % (name, metadata["backend"], stamp)

    json_path = os.path.join(RESULTS_DIR, base + ".json")
    with open(json_path, "w", encoding="utf-8", newline="\n") as handle:
        json.dump({"experiment": name, "metadata": metadata,
                   "summary": summary, "observations": rows},
                  handle, indent=2, default=str)

    csv_path = os.path.join(RESULTS_DIR, base + ".csv")
    with open(csv_path, "w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow(row)

    return {"json": json_path, "csv": csv_path}


# ------------------------------------------------- Experiment A: reproducibility

def experiment_a(manager, backend_name, runs):
    """A. Repeat the file-impact scenario; check baseline, impact, events, reset."""
    expected_baseline = baseline_signature()
    expected_impacted = impacted_signature()
    rows = []

    for index in range(runs):
        sandbox_id = eval_sandbox_id("repro")
        collector = EventCollector()
        original_recorder = manager.recorder
        manager.recorder = collector
        row = {"run": index, "sandbox_id": sandbox_id}
        try:
            manager.create(sandbox_id, session_id="eval-a-%d" % index)
            row["baseline_correct"] = workspace_signature(manager, sandbox_id) == expected_baseline

            result = FileImpactScenario(manager).run(
                sandbox_id=sandbox_id, session_id="eval-a-%d" % index)
            row["impacted_count"] = result["impacted"]
            row["expected_impacted"] = len(BASELINE_FILENAMES)
            row["impact_correct"] = (
                result["impacted"] == len(BASELINE_FILENAMES)
                and workspace_signature(manager, sandbox_id) == expected_impacted)

            scenario_events = [e for e in collector.events
                               if e.get("scenario_id") == result["scenario_id"]]
            row["event_sequence_correct"] = matches_expected_sequence(
                scenario_events, "file_impact")
            row["events_ordered"] = is_ordered(scenario_events)
            score = completeness(scenario_events, "file_impact")
            row["telemetry_ratio"] = score["ratio"]
            row["telemetry_missing"] = ";".join(score["missing"])

            manager.reset(sandbox_id, session_id="eval-a-%d" % index)
            row["reset_correct"] = workspace_signature(manager, sandbox_id) == expected_baseline
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001 - recorded, never hidden
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            try:
                manager.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
            manager.recorder = original_recorder
        row["run_succeeded"] = not row.get("error") and all(
            row.get(flag) for flag in ("baseline_correct", "impact_correct",
                                       "reset_correct"))
        rows.append(row)

    summary = {
        "success_rate": aggregate_flags(rows, "run_succeeded"),
        "baseline_correctness_rate": aggregate_flags(rows, "baseline_correct"),
        "impact_correctness_rate": aggregate_flags(rows, "impact_correct"),
        "reset_correctness_rate": aggregate_flags(rows, "reset_correct"),
        "event_sequence_correctness_rate": aggregate_flags(rows, "event_sequence_correct"),
        "event_ordering_rate": aggregate_flags(rows, "events_ordered"),
        "mean_telemetry_completeness": mean_ratio(rows, "telemetry_ratio"),
    }
    metadata = run_metadata(backend_name, scenario="file_impact", runs=runs)
    fields = ["run", "sandbox_id", "baseline_correct", "impacted_count",
              "expected_impacted", "impact_correct", "event_sequence_correct",
              "events_ordered", "telemetry_ratio", "telemetry_missing",
              "reset_correct", "run_succeeded", "error"]
    return "experiment_a_reproducibility", metadata, summary, rows, fields


# ---------------------------------------------------- Experiment B: isolation

def experiment_b(manager, backend_name, runs, sandboxes_per_run=3):
    """B. Concurrent sandboxes: no cross-session files, events or identities."""
    identities = SyntheticIdentityStore("evaluation-harness-key")
    rows = []

    for index in range(runs):
        collector = EventCollector()
        original_recorder = manager.recorder
        manager.recorder = collector
        sessions = ["eval-b-%d-%d" % (index, n) for n in range(sandboxes_per_run)]
        ids = [eval_sandbox_id("iso%d" % n) for n in range(sandboxes_per_run)]
        row = {"run": index, "sandboxes": sandboxes_per_run}
        try:
            for sandbox_id, session_id in zip(ids, sessions):
                manager.create(sandbox_id, session_id=session_id)

            # Impact the first sandbox only.
            target_result = FileImpactScenario(manager).run(
                sandbox_id=ids[0], session_id=sessions[0])

            row["target_impacted"] = (
                workspace_signature(manager, ids[0]) == impacted_signature())
            row["others_unchanged"] = all(
                workspace_signature(manager, other) == baseline_signature()
                for other in ids[1:])

            # Event isolation: the scenario's events belong to one session only.
            scenario_events = [e for e in collector.events
                               if e.get("scenario_id") == target_result["scenario_id"]]
            row["event_sessions"] = len({e.get("session_id") for e in scenario_events})
            row["no_cross_session_events"] = (
                row["event_sessions"] == 1
                and {e.get("session_id") for e in scenario_events} == {sessions[0]})

            # Identity isolation: session 0's credential must not validate elsewhere.
            issued = identities.identities(sessions[0])[0]
            row["own_identity_valid"] = identities.validate(
                sessions[0], issued["username"], issued["password"])[0]
            row["cross_identity_rejected"] = all(
                not identities.validate(other, issued["username"],
                                        issued["password"])[0]
                for other in sessions[1:])

            # Resetting the impacted sandbox must not disturb the others.
            manager.reset(ids[0], session_id=sessions[0])
            row["reset_isolated"] = all(
                workspace_signature(manager, other) == baseline_signature()
                for other in ids[1:])

            # Derived sandbox ids for distinct sessions must differ.
            row["derived_ids_distinct"] = (
                len({sandbox_id_for_session(s) for s in sessions}) == len(sessions))
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            for sandbox_id in ids:
                try:
                    manager.destroy(sandbox_id)
                except Exception:  # noqa: BLE001
                    pass
            manager.recorder = original_recorder
        row["run_succeeded"] = not row.get("error") and all(
            row.get(flag) for flag in
            ("target_impacted", "others_unchanged", "no_cross_session_events",
             "own_identity_valid", "cross_identity_rejected", "reset_isolated",
             "derived_ids_distinct"))
        rows.append(row)

    summary = {
        "success_rate": aggregate_flags(rows, "run_succeeded"),
        "filesystem_isolation_rate": aggregate_flags(rows, "others_unchanged"),
        "event_isolation_rate": aggregate_flags(rows, "no_cross_session_events"),
        "identity_isolation_rate": aggregate_flags(rows, "cross_identity_rejected"),
        "reset_isolation_rate": aggregate_flags(rows, "reset_isolated"),
    }
    metadata = run_metadata(backend_name, scenario="session_isolation", runs=runs,
                            extra={"sandboxes_per_run": sandboxes_per_run})
    fields = ["run", "sandboxes", "target_impacted", "others_unchanged",
              "event_sessions", "no_cross_session_events", "own_identity_valid",
              "cross_identity_rejected", "reset_isolated", "derived_ids_distinct",
              "run_succeeded", "error"]
    return "experiment_b_isolation", metadata, summary, rows, fields


# ----------------------------------------- Experiment C: telemetry completeness

def experiment_c(manager, backend_name, runs):
    """C. captured_expected_events / expected_events, per scenario run.

    Only the file-impact scenario is driven here: it is the scenario this
    harness can execute headlessly. The phishing sequence is defined in the
    same table and is measured by the HTTP-level test suite instead.
    """
    rows = []
    for index in range(runs):
        sandbox_id = eval_sandbox_id("tele")
        collector = EventCollector()
        original_recorder = manager.recorder
        manager.recorder = collector
        row = {"run": index, "scenario": "file_impact",
               "expected_events": len(EXPECTED_SEQUENCES["file_impact"])}
        try:
            manager.create(sandbox_id, session_id="eval-c-%d" % index)
            result = FileImpactScenario(manager).run(
                sandbox_id=sandbox_id, session_id="eval-c-%d" % index)
            scenario_events = [e for e in collector.events
                               if e.get("scenario_id") == result["scenario_id"]]
            score = completeness(scenario_events, "file_impact")
            row.update({
                "captured_expected_events": score["captured"],
                "completeness_ratio": score["ratio"],
                "missing_events": ";".join(score["missing"]),
                "total_events_emitted": len(scenario_events),
                "ordered": is_ordered(scenario_events),
                "sequence_exact": matches_expected_sequence(scenario_events,
                                                            "file_impact"),
                "correlated": len({e.get("scenario_id") for e in scenario_events}) == 1,
                "error": "",
            })
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
        finally:
            try:
                manager.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
            manager.recorder = original_recorder
        rows.append(row)

    summary = {
        "mean_completeness_ratio": mean_ratio(rows, "completeness_ratio"),
        "full_completeness_rate": rate(
            sum(1 for r in rows if r.get("completeness_ratio") == 1.0), len(rows)),
        "ordering_rate": aggregate_flags(rows, "ordered"),
        "exact_sequence_rate": aggregate_flags(rows, "sequence_exact"),
        "correlation_rate": aggregate_flags(rows, "correlated"),
        "expected_sequence": list(EXPECTED_SEQUENCES["file_impact"]),
    }
    metadata = run_metadata(backend_name, scenario="file_impact", runs=runs)
    fields = ["run", "scenario", "expected_events", "captured_expected_events",
              "completeness_ratio", "missing_events", "total_events_emitted",
              "ordered", "sequence_exact", "correlated", "error"]
    return "experiment_c_telemetry", metadata, summary, rows, fields


# ------------------------------------------------- Experiment D: overhead

def experiment_d(manager, backend_name, runs):
    """D. Lifecycle latency: create, scenario, reset, destroy."""
    rows = []
    for index in range(runs):
        sandbox_id = eval_sandbox_id("perf")
        session_id = "eval-d-%d" % index
        row = {"run": index, "sandbox_id": sandbox_id}
        try:
            _, row["create_seconds"] = time_call(
                manager.create, sandbox_id, session_id=session_id)
            _, row["scenario_seconds"] = time_call(
                FileImpactScenario(manager).run,
                sandbox_id=sandbox_id, session_id=session_id)
            _, row["reset_seconds"] = time_call(
                manager.reset, sandbox_id, session_id=session_id)
            _, row["destroy_seconds"] = time_call(
                manager.destroy, sandbox_id, session_id=session_id)
            row["error"] = ""
        except Exception as exc:  # noqa: BLE001
            row["error"] = "%s: %s" % (type(exc).__name__, exc)
            try:
                manager.destroy(sandbox_id)
            except Exception:  # noqa: BLE001
                pass
        rows.append(row)

    good = [r for r in rows if not r["error"]]
    summary = {
        phase: summarise([r[phase] for r in good if r.get(phase) is not None])
        for phase in ("create_seconds", "scenario_seconds", "reset_seconds",
                      "destroy_seconds")
    }
    summary["completed_runs"] = len(good)
    summary["failed_runs"] = len(rows) - len(good)
    metadata = run_metadata(backend_name, scenario="file_impact", runs=runs,
                            extra={"clock": "time.perf_counter"})
    fields = ["run", "sandbox_id", "create_seconds", "scenario_seconds",
              "reset_seconds", "destroy_seconds", "error"]
    return "experiment_d_overhead", metadata, summary, rows, fields


# -------------------------------------------------- Experiment E: scaling

DEFAULT_SCALES = (10, 25, 50, 100)


def experiment_e(manager, backend_name, scales=DEFAULT_SCALES):
    """E. Telemetry growth and query latency against event volume.

    Event batches are generated by running the real scenario against a single
    sandbox, so the rows measured are real telemetry rows and not synthetic
    filler. Storage is measured against a throwaway SQLite file.
    """
    import sqlite3

    rows = []
    scratch = tempfile.mkdtemp(prefix="dws-eval-scale-")
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

    sandbox_id = eval_sandbox_id("scale")
    try:
        manager.create(sandbox_id, session_id="eval-e")
        total_events = 0
        last_scenario_id = None

        for scale in scales:
            collector = EventCollector()
            original_recorder = manager.recorder
            manager.recorder = collector
            lifecycle_times = []
            try:
                for n in range(scale):
                    _, elapsed = time_call(
                        FileImpactScenario(manager).run,
                        sandbox_id=sandbox_id, session_id="eval-e-%d" % n)
                    lifecycle_times.append(elapsed)
                    manager.backend.reset(sandbox_id)
            finally:
                manager.recorder = original_recorder

            events = collector.events
            if events:
                last_scenario_id = events[-1].get("scenario_id")

            _, insert_seconds = time_call(
                _insert_events, connection, events)
            total_events += len(events)

            connection.commit()
            size_bytes = os.path.getsize(db_path)

            _, query_all_seconds = time_call(
                _query, connection,
                "SELECT id FROM security_event ORDER BY timestamp ASC, id ASC")
            _, query_scenario_seconds = time_call(
                _query, connection,
                "SELECT id FROM security_event WHERE scenario_id = ?"
                " ORDER BY timestamp ASC, id ASC", (last_scenario_id,))

            rows.append({
                "scale_scenario_runs": scale,
                "events_inserted": len(events),
                "cumulative_events": total_events,
                "db_size_bytes": size_bytes,
                "bytes_per_event": (size_bytes / total_events) if total_events else None,
                "insert_seconds": insert_seconds,
                "query_all_seconds": query_all_seconds,
                "query_by_scenario_seconds": query_scenario_seconds,
                "scenario_mean_seconds": summarise(lifecycle_times)["mean"],
                "scenario_p95_seconds": summarise(lifecycle_times)["p95"],
            })
    finally:
        try:
            manager.destroy(sandbox_id)
        except Exception:  # noqa: BLE001
            pass
        connection.close()
        shutil.rmtree(scratch, ignore_errors=True)

    summary = {
        "scales": list(scales),
        "final_cumulative_events": rows[-1]["cumulative_events"] if rows else 0,
        "final_db_size_bytes": rows[-1]["db_size_bytes"] if rows else 0,
        "query_all_seconds": summarise([r["query_all_seconds"] for r in rows]),
        "query_by_scenario_seconds": summarise(
            [r["query_by_scenario_seconds"] for r in rows]),
        "scenario_mean_seconds": summarise(
            [r["scenario_mean_seconds"] for r in rows if r["scenario_mean_seconds"]]),
    }
    metadata = run_metadata(backend_name, scenario="file_impact",
                            runs=sum(scales), extra={"scales": list(scales)})
    fields = ["scale_scenario_runs", "events_inserted", "cumulative_events",
              "db_size_bytes", "bytes_per_event", "insert_seconds",
              "query_all_seconds", "query_by_scenario_seconds",
              "scenario_mean_seconds", "scenario_p95_seconds"]
    return "experiment_e_scaling", metadata, summary, rows, fields


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


# ------------------------------------------------------------------- driver

EXPERIMENTS = {
    "A": ("reproducibility", experiment_a),
    "B": ("session isolation", experiment_b),
    "C": ("telemetry completeness", experiment_c),
    "D": ("execution overhead", experiment_d),
    "E": ("scaling", experiment_e),
}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Controlled experiments for the RewindSec sandbox")
    parser.add_argument("--backend", choices=("docker", "local"), default="docker",
                        help="Backend under test. Never auto-detected: the "
                             "choice is recorded in every result file.")
    parser.add_argument("--runs", type=int, default=10,
                        help="Runs for experiments A-D (default: 10)")
    parser.add_argument("--scales", default=",".join(str(s) for s in DEFAULT_SCALES),
                        help="Comma-separated scenario counts for experiment E")
    parser.add_argument("--experiments", default="A,B,C,D,E",
                        help="Comma-separated experiment letters to run")
    parser.add_argument("--results-dir", default=None)
    parser.add_argument("--list", action="store_true",
                        help="List experiments and exit")
    global RESULTS_DIR
    args = parser.parse_args(argv)

    if args.list:
        for letter, (title, _) in sorted(EXPERIMENTS.items()):
            print("  %s  %s" % (letter, title))
        return 0

    RESULTS_DIR = os.path.abspath(args.results_dir or RESULTS_DIR)

    selected = [letter.strip().upper() for letter in args.experiments.split(",")
                if letter.strip()]
    unknown = [letter for letter in selected if letter not in EXPERIMENTS]
    if unknown:
        raise SystemExit("unknown experiment(s): %s" % ", ".join(unknown))

    scratch = tempfile.mkdtemp(prefix="dws-eval-")
    manager = make_manager(args.backend, scratch)
    print("backend under test : %s (%s)" % (args.backend, manager.backend.name))
    print("isolation           : %s" % manager.backend.isolation_summary)
    print("runs                : %d" % args.runs)
    print("results directory   : %s" % RESULTS_DIR)

    scales = tuple(int(v) for v in args.scales.split(",") if v.strip())
    written = []
    try:
        for letter in selected:
            title, function = EXPERIMENTS[letter]
            print("\n=== Experiment %s: %s ===" % (letter, title))
            started = time.perf_counter()
            if letter == "E":
                name, metadata, summary, rows, fields = function(
                    manager, args.backend, scales=scales)
            else:
                name, metadata, summary, rows, fields = function(
                    manager, args.backend, args.runs)
            metadata["wall_seconds"] = time.perf_counter() - started
            paths = write_results(name, metadata, summary, rows, fields)
            written.append(paths)
            print(json.dumps(summary, indent=2, default=str))
            print("wrote %s" % os.path.basename(paths["json"]))
            print("wrote %s" % os.path.basename(paths["csv"]))
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    print("\n%d result file pair(s) written to %s" % (len(written), RESULTS_DIR))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
