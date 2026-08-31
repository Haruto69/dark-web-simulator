"""Canonical, deterministically fingerprinted state snapshots.

A snapshot is the unit RewindSec compares. Two logically equivalent states must
produce the same digest in any process, on any platform, regardless of mapping
insertion order -- so the digest is SHA-256 over canonical JSON (sorted keys,
no insignificant whitespace, NaN/Infinity rejected) and never over Python's
built-in ``hash()``, which is salted per process.
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping

from .errors import SnapshotError

DIGEST_ALGORITHM = "sha256"

#: Keys whose presence indicates a secret has leaked into environment state.
#: Snapshots are persisted and compared, so they must stay free of credentials.
_SECRET_KEY_RE = re.compile(
    r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"credential|authorization|session[_-]?key)", re.IGNORECASE)

_ALLOWED_SCALARS = (str, int, float, bool, type(None))


def _reject_secrets(key):
    if _SECRET_KEY_RE.search(key):
        raise SnapshotError(
            "state key {0!r} looks like a secret; snapshots must not carry "
            "credentials".format(key))


def _canonicalise(value, path="$"):
    """Return a plain JSON-safe copy of ``value``, or explain why it is not."""
    if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
        return value
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise SnapshotError(
                "non-finite float at {0}; snapshot state must be "
                "deterministic".format(path))
        return value
    if isinstance(value, Mapping):
        out = {}
        for key in value:
            if not isinstance(key, str):
                raise SnapshotError(
                    "non-string mapping key {0!r} at {1}".format(key, path))
            _reject_secrets(key)
            out[key] = _canonicalise(value[key], "{0}.{1}".format(path, key))
        return out
    if isinstance(value, (list, tuple)):
        return [_canonicalise(item, "{0}[{1}]".format(path, index))
                for index, item in enumerate(value)]
    raise SnapshotError(
        "unsupported value of type {0} at {1}; snapshot state must be "
        "JSON-serialisable".format(type(value).__name__, path))


def canonical_json(state: Mapping[str, Any]) -> str:
    """Serialise ``state`` to its one canonical textual form."""
    if not isinstance(state, Mapping):
        raise SnapshotError(
            "snapshot state must be a mapping, got {0}".format(
                type(state).__name__))
    return json.dumps(_canonicalise(state), sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def fingerprint(state: Mapping[str, Any]) -> str:
    """Deterministic SHA-256 hex digest of a logical state."""
    return hashlib.sha256(canonical_json(state).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class StateSnapshot:
    """An immutable canonical view of one environment state.

    ``label`` records which point in the experiment the snapshot came from
    (``baseline``, ``factual``, ``rewound``, ``counterfactual``); it is
    descriptive only and never participates in the digest.
    """

    canonical_json: str
    digest: str
    label: str = ""
    algorithm: str = field(default=DIGEST_ALGORITHM)

    @classmethod
    def capture(cls, state: Mapping[str, Any], label: str = "") -> "StateSnapshot":
        text = canonical_json(state)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        return cls(canonical_json=text, digest=digest, label=label)

    @property
    def state(self) -> Dict[str, Any]:
        """A fresh mutable copy of the state; mutating it cannot affect self."""
        return json.loads(self.canonical_json)

    def matches(self, other: "StateSnapshot") -> bool:
        """True when both snapshots describe the same logical state."""
        return (isinstance(other, StateSnapshot)
                and self.algorithm == other.algorithm
                and self.digest == other.digest)

    def relabelled(self, label: str) -> "StateSnapshot":
        return StateSnapshot(self.canonical_json, self.digest, label,
                             self.algorithm)

    def __repr__(self):
        return "StateSnapshot(label={0!r}, digest={1}...)".format(
            self.label, self.digest[:12])
