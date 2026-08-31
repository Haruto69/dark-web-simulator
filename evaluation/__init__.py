"""Reproducible evaluation harness for the RewindSec sandbox.

Deliberately outside the Flask application: no benchmark logic lives in a route
handler, so measurements cannot be perturbed by request handling, and the
harness can be run headlessly against either backend.

Scope of what this package measures (and only this):

  * reproducibility of the file-impact scenario and of reset,
  * session isolation between concurrent sandboxes,
  * telemetry completeness against declared expected event sequences,
  * execution overhead of the sandbox lifecycle,
  * scaling behaviour of telemetry storage and query latency.

It measures nothing about people. No claim about educational effectiveness,
learner awareness or susceptibility is supported by anything in this package.
"""

from .metrics import (Stopwatch, aggregate_flags, mean_ratio, percentile, rate,
                      run_metadata, summarise, time_call)

__all__ = ["summarise", "percentile", "rate", "aggregate_flags", "mean_ratio",
           "run_metadata", "Stopwatch", "time_call"]
