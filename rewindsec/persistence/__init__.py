"""Persistence adapters for :mod:`rewindsec.domain`.

``ports.py`` defines the storage-independent repository contract every
adapter must satisfy. ``sqlalchemy_adapter.py`` is the one adapter Batch 1
ships, built on the SQLAlchemy dependency the app already uses -- but the
domain itself never imports either module, so a test or a future adapter can
use the domain without pulling in a database at all.
"""
