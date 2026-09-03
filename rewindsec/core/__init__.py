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

from rewindsec.core.events import (Event, EventSource, EventVisibility,
                                   derive_event_id)
from rewindsec.core.rng import SeededRandom
from rewindsec.core.scheduler import (EventScheduler, EventSpec,
                                      ScheduledEntry, derive_schedule_id)
from rewindsec.core.simtime import SimClock

#: Only the primitives callers outside the core are meant to build with. The
#: error classes, validators and state helpers stay reachable from their own
#: modules -- a wide top-level namespace makes every internal helper feel like
#: supported API, and then it is.
__all__ = [
    "Event",
    "EventScheduler",
    "EventSource",
    "EventSpec",
    "EventVisibility",
    "ScheduledEntry",
    "SeededRandom",
    "SimClock",
    "derive_event_id",
    "derive_schedule_id",
]
