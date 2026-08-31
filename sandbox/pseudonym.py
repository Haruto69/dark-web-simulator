"""Stable pseudonymous labels for instructor-facing display.

WHY
---
A learner's ``session_id`` is a raw UUID that correlates every event, every
credential-interaction row and every sandbox workspace belonging to one person
in the room. It is the join key of the whole telemetry model, so it must stay
intact **internally**. It does not need to be printed on a projector.

Milestone 4.2 therefore separates the two uses:

  * **correlation** keeps the canonical ``session_id``. Nothing stored changes,
    and the internal evaluation APIs (``/api/logs``, ``/sandbox/events``) still
    return it -- the formal harness joins on it.
  * **display** uses :func:`short_id`, a deterministic one-way label. The
    instructor sees ``Session 4F2A91C8`` and can still tell two learners apart
    and follow one learner across tables, without the underlying identifier
    being on screen.

PROPERTIES
----------
* Deterministic: the same session always renders as the same label, across
  processes and restarts, so an instructor can compare two pages or two runs.
* Not reversible: BLAKE2s truncated to 32 bits of *displayed* output. It is a
  label, not an encryption of the id, and there is deliberately no inverse.
* Not a secret: it is derived from an unkeyed hash, so it must never be used
  for authorisation, lookup or as a database key. It is a printed nickname.

Truncation means collisions are possible in principle (birthday-bound around a
few tens of thousands of concurrent sessions for the default eight characters).
A classroom is three orders of magnitude below that, and a collision would
merely make two rows look alike on screen -- it cannot merge stored data,
because nothing joins on this value.
"""

import hashlib

#: Domain separator, so a label minted here can never coincide with a digest
#: some other part of the system derives from the same session id.
_PERSONALISATION = b"sim-disp"

DEFAULT_LENGTH = 8

#: Rendered in place of an absent id, so a missing session is visibly missing
#: rather than silently pseudonymised into something that looks real.
ABSENT = "-"


def short_id(value, length=DEFAULT_LENGTH):
    """A deterministic, non-reversible display label for ``value``.

    Returns ``ABSENT`` for an empty/absent id. The label is uppercase hex, so
    it is unambiguous when read aloud from a projector.
    """
    if value in (None, ""):
        return ABSENT
    digest = hashlib.blake2s(str(value).encode("utf-8"), digest_size=16,
                             person=_PERSONALISATION).hexdigest()
    return digest[:max(1, int(length))].upper()


def session_label(value, length=DEFAULT_LENGTH):
    """``short_id`` with the word an instructor actually reads: ``Session AB12``."""
    label = short_id(value, length)
    return label if label == ABSENT else "Session %s" % label
