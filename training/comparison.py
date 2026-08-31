"""Deterministic structural comparison of two canonical states.

Produces a machine-readable delta only. No prose, no judgement, no notion of a
"better" outcome -- interpretation belongs to a later milestone, and keeping it
out of here is what lets the delta stay a neutral factual record.

Mappings are walked recursively; every other value (including lists) is
compared atomically, so a list is reported as one changed value rather than as
a positional edit script. That keeps the output stable and easy to reason
about; positional list diffing can be added later if a scenario needs it.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"

_MISSING = object()


def _pointer(path: Tuple[str, ...]) -> str:
    """Dotted rendering of a path, for display and log correlation."""
    return ".".join(path) if path else "."


@dataclass(frozen=True)
class StateChange:
    """One difference between two states at a single location."""

    path: Tuple[str, ...]
    change: str
    before: Optional[Any] = None
    after: Optional[Any] = None

    @property
    def pointer(self) -> str:
        return _pointer(self.path)

    def as_dict(self) -> Dict[str, Any]:
        record: Dict[str, Any] = {
            "path": list(self.path),
            "pointer": self.pointer,
            "change": self.change,
        }
        if self.change in (REMOVED, CHANGED):
            record["from"] = self.before
        if self.change in (ADDED, CHANGED):
            record["to"] = self.after
        return record


@dataclass(frozen=True)
class StateDiff:
    """The complete, deterministically ordered delta between two states."""

    changes: Tuple[StateChange, ...]

    @property
    def is_empty(self) -> bool:
        return not self.changes

    def of_kind(self, change: str) -> Tuple[StateChange, ...]:
        return tuple(item for item in self.changes if item.change == change)

    @property
    def added(self) -> Tuple[StateChange, ...]:
        return self.of_kind(ADDED)

    @property
    def removed(self) -> Tuple[StateChange, ...]:
        return self.of_kind(REMOVED)

    @property
    def changed(self) -> Tuple[StateChange, ...]:
        return self.of_kind(CHANGED)

    def pointers(self) -> Tuple[str, ...]:
        return tuple(item.pointer for item in self.changes)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "changes": [item.as_dict() for item in self.changes],
            "counts": {
                ADDED: len(self.added),
                REMOVED: len(self.removed),
                CHANGED: len(self.changed),
            },
        }

    def __len__(self):
        return len(self.changes)


def _walk(before: Any, after: Any, path: Tuple[str, ...],
          out: List[StateChange]) -> None:
    if before is _MISSING and after is _MISSING:
        return

    # Whole subtrees are reported leaf by leaf rather than as one opaque blob,
    # so "endpoint.isolated was added" is visible instead of "endpoint
    # changed". A side that is absent is walked as an empty mapping.
    before_is_map = isinstance(before, Mapping) or before is _MISSING
    after_is_map = isinstance(after, Mapping) or after is _MISSING
    if before_is_map and after_is_map:
        left = before if isinstance(before, Mapping) else {}
        right = after if isinstance(after, Mapping) else {}
        keys = sorted(set(left) | set(right))
        if keys:
            for key in keys:
                _walk(left.get(key, _MISSING), right.get(key, _MISSING),
                      path + (key,), out)
            return
        # An empty mapping on one side carries no leaves; report it directly.
        if before is _MISSING:
            out.append(StateChange(path, ADDED, after=after))
            return
        if after is _MISSING:
            out.append(StateChange(path, REMOVED, before=before))
            return
        return

    if before is _MISSING:
        out.append(StateChange(path, ADDED, after=after))
        return
    if after is _MISSING:
        out.append(StateChange(path, REMOVED, before=before))
        return
    if before != after or type(before) is not type(after):
        out.append(StateChange(path, CHANGED, before=before, after=after))


def diff_states(before: Mapping[str, Any],
                after: Mapping[str, Any]) -> StateDiff:
    """Compare two JSON-like states, returning changes in sorted path order."""
    changes: List[StateChange] = []
    _walk(before, after, (), changes)
    return StateDiff(tuple(changes))


def diff_snapshots(before, after) -> StateDiff:
    """Compare two :class:`~training.snapshots.StateSnapshot` objects."""
    return diff_states(before.state, after.state)
