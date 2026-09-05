"""RewindSec 2.0 simulation domain: storage-independent session state.

Pure Python only. Nothing under this package may import Flask, Flask-
SQLAlchemy, SQLAlchemy, the prototype UI, or any v1 module (``study``,
``learning``, ``scenario_adapters``, ``evaluation``, ``sandbox``, ``training``)
-- see ``tests/test_rewindsec2_domain_boundaries.py``, which enforces this
mechanically the same way ``rewindsec/core/__init__.py`` does for the
deterministic core this package builds on.

The aggregate root is :class:`~rewindsec.domain.session.SimulationSession`.
Everything else in this package is a part it composes.
"""
