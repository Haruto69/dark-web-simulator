"""RewindSec 2.0.

This package is the RewindSec 2.0 rebuild. It is deliberately kept separate
from the v1 code that still lives at the repository root (``training/``,
``learning/``, ``study/``, ``scenario_adapters/``, ``evaluation/``): see
``PROVENANCE.md`` for what belongs to which system and why the boundary
matters for research claims.

Nothing under this package may import v1 study, learning, scenario or
historical evaluation code. ``tests/test_provenance.py`` enforces that
statically.
"""

__all__ = []
