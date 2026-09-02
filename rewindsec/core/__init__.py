"""The deterministic core of RewindSec 2.0.

Every module in this package is pure Python standard library. It may not
import Flask, SQLAlchemy, the sandbox infrastructure, or any v1 module; and
with the single audited exception of ``rng.py`` it may not import ``random``,
``secrets``, ``uuid``, ``time`` or ``datetime``.

The reason is the project's central claim: a session must replay to a
bit-identical state from its seed and its recorded actions. Any of those
imports is a way for an unrepeatable value to enter simulation state without
anybody noticing, because the resulting bug is silent -- a replay that looks
correct but rerolled. ``tests/test_rewindsec2_core_boundaries.py`` enforces
the rule with AST inspection so it cannot be eroded by accident.

Wall-clock timestamps are not banned from the project, only from here. They
belong in diagnostic and telemetry layers, outside deterministic state.
"""

from rewindsec.core.rng import SeededRandom
from rewindsec.core.simtime import SimClock

__all__ = ["SeededRandom", "SimClock"]
