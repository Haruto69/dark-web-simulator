"""JSON-safe value validation shared across the simulation domain.

This is the same discipline ``rewindsec.core.events`` applies to event
payloads, generalised for reuse by :mod:`rewindsec.domain.world`,
:mod:`rewindsec.domain.context_ledger`, :mod:`rewindsec.domain.actions` and
:mod:`rewindsec.domain.incidents`. It is intentionally re-implemented here
rather than imported from ``core.events`` (whose freezing helpers are private)
so the domain does not reach into another module's internals for a rule that
belongs to it just as much.

The contract: a value is JSON-safe if it is built only from ``dict``, ``list``,
``str``, ``int``, ``float``, ``bool`` and ``None``. Anything else -- a set, a
callable, a class instance, ``bytes``, NaN, infinity -- cannot be stored in a
snapshot, replayed on restore, or safely handed to a future REST boundary, so
it is rejected at the door instead of failing later at serialisation time, far
from the offending caller.
"""

import json
from types import MappingProxyType

from rewindsec.domain.errors import InvalidJsonValueError

__all__ = [
    "freeze",
    "thaw",
    "canonical_json",
    "MAX_DEPTH",
    "MAX_JSON_SAFE_INT",
]

#: JSON nesting deeper than this is a bug rather than a payload.
MAX_DEPTH = 16

#: The largest integer every reasonable JSON consumer round-trips exactly.
MAX_JSON_SAFE_INT = 2 ** 53 - 1


def freeze(value, depth=0, path="value"):
    """Validate *value* recursively and return an immutable equivalent.

    Dicts become :class:`~types.MappingProxyType`, lists become tuples, so a
    caller cannot mutate a domain object's stored state by keeping a reference
    to what they passed in.
    """
    if depth > MAX_DEPTH:
        raise InvalidJsonValueError("%s nests deeper than %d levels" % (path, MAX_DEPTH))

    # bool before int: bool is an int subclass, and JSON keeps them distinct.
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        if not -MAX_JSON_SAFE_INT <= value <= MAX_JSON_SAFE_INT:
            raise InvalidJsonValueError(
                "%s: int %d is outside the JSON-safe range" % (path, value))
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise InvalidJsonValueError(
                "%s: NaN and infinity are not JSON values" % path)
        return value
    if isinstance(value, dict):
        frozen = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidJsonValueError(
                    "%s: keys must be strings, got %s" % (path, type(key).__name__))
            frozen[key] = freeze(item, depth + 1, "%s.%s" % (path, key))
        return MappingProxyType(frozen)
    if isinstance(value, list):
        return tuple(freeze(item, depth + 1, "%s[%d]" % (path, index))
                     for index, item in enumerate(value))
    if isinstance(value, tuple):
        raise InvalidJsonValueError(
            "%s: use a list, not a tuple. A tuple serialises to a JSON array "
            "and returns as a list, so it would not survive a round-trip "
            "unchanged." % path)
    if isinstance(value, (set, frozenset)):
        raise InvalidJsonValueError(
            "%s: sets have no stable JSON ordering; use a sorted list" % path)

    raise InvalidJsonValueError(
        "%s: %s is not a JSON value. Values must be built from dict, list, "
        "str, int, float, bool and None only -- no sets, no callables, no "
        "class instances, no bytes." % (path, type(value).__name__))


def thaw(value):
    """Return a plain, mutable, JSON-serialisable copy of a frozen value."""
    if isinstance(value, MappingProxyType):
        return {key: thaw(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [thaw(item) for item in value]
    return value


def canonical_json(state):
    """Serialise *state* canonically: sorted keys, tight separators.

    Equal states must produce equal text, or a digest built on top of this
    means nothing. ``allow_nan=False`` is belt-and-braces on top of
    :func:`freeze`, which already refuses NaN and infinity.
    """
    return json.dumps(state, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)
