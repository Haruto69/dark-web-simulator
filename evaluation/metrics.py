"""Measurement primitives for the evaluation harness.

Pure functions only: no Docker, no Flask, no filesystem. Keeping the statistics
separate from the experiment driver means the numbers reported in the paper are
computed by code that is unit-tested in isolation, and that the same summariser
is applied identically to every latency series.

Interpretation lives in the write-up, not here. These functions report what was
measured and nothing else.
"""

import math
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone


# -- latency summaries -------------------------------------------------------

def percentile(values, fraction):
    """Nearest-rank percentile of ``values`` (0.0 <= fraction <= 1.0).

    Nearest-rank is used rather than interpolation because these samples are
    small (tens of runs); interpolating between two observations would invent a
    value that was never measured.
    """
    if not values:
        return None
    if not 0.0 <= fraction <= 1.0:
        raise ValueError("fraction must be within [0, 1]")
    ordered = sorted(values)
    rank = max(1, math.ceil(fraction * len(ordered)))
    return ordered[rank - 1]


def summarise(values, unit="seconds"):
    """mean / median / stdev / p95 / min / max / n for one latency series.

    ``stdev`` is the *sample* standard deviation and is None for n < 2, rather
    than a misleading 0.0.
    """
    values = [float(v) for v in values]
    if not values:
        return {"n": 0, "unit": unit, "mean": None, "median": None,
                "stdev": None, "p95": None, "min": None, "max": None}
    return {
        "n": len(values),
        "unit": unit,
        "mean": statistics.fmean(values),
        "median": statistics.median(values),
        "stdev": statistics.stdev(values) if len(values) > 1 else None,
        "p95": percentile(values, 0.95),
        "min": min(values),
        "max": max(values),
    }


class Stopwatch:
    """Context manager timing a block with ``time.perf_counter``.

    ``perf_counter`` is monotonic and the highest-resolution clock available,
    so it is unaffected by wall-clock adjustments during a run.
    """

    def __init__(self):
        self.elapsed = None

    def __enter__(self):
        self._start = time.perf_counter()
        return self

    def __exit__(self, *exc_info):
        self.elapsed = time.perf_counter() - self._start
        return False


def time_call(function, *args, **kwargs):
    """Return ``(result, elapsed_seconds)`` for one call."""
    with Stopwatch() as watch:
        result = function(*args, **kwargs)
    return result, watch.elapsed


# -- rates -------------------------------------------------------------------

def rate(successes, total):
    """Proportion in [0, 1]; None when nothing was attempted.

    None rather than 0.0 keeps "no runs" distinguishable from "every run
    failed" in the reported results.
    """
    if not total:
        return None
    return successes / total


def aggregate_flags(records, key):
    """``{"true": n, "total": n, "rate": r}`` for a boolean field across runs."""
    total = len(records)
    successes = sum(1 for record in records if record.get(key))
    return {"true": successes, "total": total, "rate": rate(successes, total)}


def mean_ratio(records, key):
    """Mean of a per-run ratio field, or None when there are no runs."""
    values = [record[key] for record in records
              if record.get(key) is not None]
    return statistics.fmean(values) if values else None


# -- run metadata ------------------------------------------------------------

def docker_version():
    """Docker server version string, or None when Docker is unavailable.

    Recorded in every result file so a measurement can never be attributed to
    the wrong runtime.
    """
    try:
        completed = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, text=True, timeout=15, shell=False, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if completed.returncode != 0:
        return None
    return completed.stdout.strip() or None


def run_metadata(backend, scenario=None, runs=None, extra=None):
    """Reproducibility metadata attached to every result file.

    ``backend`` is mandatory and is recorded verbatim, because a LocalBackend
    measurement must never be mistaken for a container-sandbox measurement.
    """
    metadata = {
        "backend": backend,
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "runs": runs,
        "scenario": scenario,
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "docker_version": docker_version(),
    }
    if extra:
        metadata.update(extra)
    return metadata
