"""One clock for the whole simulator.

``datetime.datetime.utcnow()`` is deprecated from Python 3.12 onward. Every
timestamp in this project is a **naive UTC** value, because the SQLite schema
stores naive datetimes and the telemetry ordering guarantees compare them
directly; switching the columns to aware datetimes would change stored data and
is out of scope for a measurement freeze.

So the replacement keeps the same value and drops the deprecation: take an
explicitly UTC-aware ``now`` and strip the tzinfo. Nothing else in the codebase
should call ``utcnow()`` on ``datetime`` directly.
"""

from datetime import datetime, timezone


def utcnow():
    """Current UTC time as a naive ``datetime``, matching the stored schema."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
