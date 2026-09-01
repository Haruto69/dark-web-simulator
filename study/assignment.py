"""Balanced randomised allocation: keyed, deterministic permuted blocks of six.

The algorithm
-------------
Participants are allocated in blocks of six, each block containing exactly two
``awareness_debrief``, two ``factual_consequence`` and two
``counterfactual_replay``. Within a block the order is a permutation derived by
keyed HMAC from ``(secret, protocol_key, protocol_version, block_index)``.

Three properties follow, and all three matter for a pilot that has to be
defensible rather than merely random:

*  **Balanced.** Every complete block is 2/2/2, so allocation cannot drift with
   cohort size and a run that stops mid-block is at worst two participants away
   from balance.
*  **Unpredictable to a participant.** Without the secret, the arm of the next
   allocation slot is not derivable from the arms already issued. A learner
   cannot request, guess or submit an arm; nothing in any form or query string
   is consulted here.
*  **Reproducible and auditable.** Given the secret and the slot numbers, the
   whole allocation sequence can be recomputed years later. That is what makes
   an allocation *auditable* rather than merely unrecorded.

Why a secret is required
------------------------
An unkeyed permutation would be reproducible by anyone reading this file, which
makes the sequence public. A per-process random fallback would be unpredictable
but *irreproducible*, which cannot be audited. So the secret is mandatory:
:func:`require_secret` fails closed rather than inventing one.

It must not be Flask's ``secret_key``. That key is rotated for reasons that have
nothing to do with the study (a leaked cookie, a redeploy), it has a documented
random development fallback, and rotating it must never silently re-randomise an
allocation sequence that participants have already been assigned from.

Purity
------
Standard library only: ``hmac``, ``hashlib``. No Flask, no SQLAlchemy, no
``app``, no sandbox, no clock, no I/O. Allocation *slots* come from the caller;
how a slot is claimed uniquely under concurrency is a persistence concern and
lives in ``study_service``.
"""

import hashlib
import hmac

from .errors import StudyConfigurationError
from .protocol import (ARMS, PROTOCOL_KEY, PROTOCOL_VERSION, require_arm)

#: Participants per allocation block: two of each arm.
PER_ARM_PER_BLOCK = 2
BLOCK_SIZE = len(ARMS) * PER_ARM_PER_BLOCK

#: Domain separator, so a digest minted for allocation can never coincide with
#: one some other part of the system derives from the same secret.
_PERSONALISATION = b"rewindsec-study-allocation-v1"

#: The environment variable an operator sets. Named here so the routes, the
#: documentation and the error message cannot drift apart.
SECRET_ENV_VAR = "REWINDSEC_STUDY_ASSIGNMENT_SECRET"


def require_secret(secret):
    """Return the secret as bytes, or fail closed.

    Deliberately has no default. Research mode without a configured allocation
    secret is a misconfiguration, not a condition to work around.
    """
    if not secret:
        raise StudyConfigurationError(
            "research mode requires a study assignment secret; set {0}"
            .format(SECRET_ENV_VAR))
    return secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)


def block_index(allocation_slot):
    """Which block an allocation slot belongs to. Slots are 1-based."""
    if not isinstance(allocation_slot, int) or isinstance(allocation_slot, bool):
        raise StudyConfigurationError("allocation slot must be an integer")
    if allocation_slot < 1:
        raise StudyConfigurationError("allocation slots start at 1")
    return (allocation_slot - 1) // BLOCK_SIZE


def block_position(allocation_slot):
    """Position within the block, ``0..BLOCK_SIZE - 1``."""
    return (allocation_slot - 1) % BLOCK_SIZE


def _keystream(secret, label, length):
    """``length`` bytes of keyed pseudorandom material for one block.

    Counter-extended HMAC-SHA256, so the routine never runs short of bytes when
    rejection sampling has to retry.
    """
    out = bytearray()
    counter = 0
    while len(out) < length:
        out.extend(hmac.new(
            secret,
            _PERSONALISATION + b"|" + label + b"|" + str(counter).encode("ascii"),
            hashlib.sha256).digest())
        counter += 1
    return bytes(out[:length])


def _bounded(stream, cursor, bound):
    """An unbiased integer in ``0..bound-1``, and the advanced cursor.

    Rejection sampling on whole bytes. ``bound`` here is never above six, so the
    rejection region is small and the loop terminates immediately in practice;
    doing it properly anyway costs nothing and keeps the permutation uniform,
    which a plain modulo would not.
    """
    limit = (256 // bound) * bound
    while True:
        if cursor >= len(stream):
            raise StudyConfigurationError("allocation keystream exhausted")
        byte = stream[cursor]
        cursor += 1
        if byte < limit:
            return byte % bound, cursor


def block_permutation(secret, index, protocol_key=PROTOCOL_KEY,
                      protocol_version=PROTOCOL_VERSION):
    """The arm sequence for one whole block: a permutation of 2/2/2.

    Fisher-Yates over the fixed multiset, driven by the keyed stream. The
    multiset is built from :data:`~study.protocol.ARMS` in declaration order, so
    the *contents* of every block are fixed by construction and only the order
    is derived -- a bug in the shuffle can misorder a block but can never
    unbalance one.
    """
    key = require_secret(secret)
    label = b"%s|%d|%d" % (str(protocol_key).encode("utf-8"),
                           int(protocol_version), int(index))
    # Generous: five draws are needed, and rejection retries are rare.
    stream = _keystream(key, label, 64)

    deck = [arm for arm in ARMS for _ in range(PER_ARM_PER_BLOCK)]
    cursor = 0
    for position in range(len(deck) - 1, 0, -1):
        pick, cursor = _bounded(stream, cursor, position + 1)
        deck[position], deck[pick] = deck[pick], deck[position]
    return tuple(deck)


def arm_for_slot(secret, allocation_slot, protocol_key=PROTOCOL_KEY,
                 protocol_version=PROTOCOL_VERSION):
    """The arm allocated to one slot. Pure, total and reproducible.

    The slot is the only participant-specific input, and it is issued by the
    database under a uniqueness constraint (see ``study_service``). Nothing a
    browser sends reaches this function.
    """
    index = block_index(allocation_slot)
    permutation = block_permutation(secret, index, protocol_key,
                                    protocol_version)
    return require_arm(permutation[block_position(allocation_slot)])


def allocation_sequence(secret, count, first_slot=1, protocol_key=PROTOCOL_KEY,
                        protocol_version=PROTOCOL_VERSION):
    """``count`` consecutive allocations, for tests and for an audit."""
    return tuple(arm_for_slot(secret, slot, protocol_key, protocol_version)
                 for slot in range(first_slot, first_slot + count))


__all__ = [
    "PER_ARM_PER_BLOCK", "BLOCK_SIZE", "SECRET_ENV_VAR", "require_secret",
    "block_index", "block_position", "block_permutation", "arm_for_slot",
    "allocation_sequence",
]
