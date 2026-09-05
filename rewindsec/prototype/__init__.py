"""The RewindSec 2.0 **UI prototype** -- fixture-backed, deliberately disposable.

Purpose
-------
This package exists to answer one product question before the expensive
backend batches start:

    "Do we actually want RewindSec 2.0 to look and behave like this?"

It is a presentation prototype. It renders a convincing synthetic workstation
and trainer console from *authored fixture data* so the product can be judged
by hand. It does not implement, and must not be read as implementing, any of
the RewindSec 2.0 backend mechanisms described in the architecture
specification: there is no ``SimulationSession``, no ``World``, no Context
Ledger, no causal consequence engine, no hazard scheduler, no persistence, no
scoring engine, no Evidence Graph, no Docker bridge and no SSE transport here.

What is real and what is mock
-----------------------------
Real, in the sense that it is genuinely served by the server:

* the fixture snapshot (:mod:`rewindsec.prototype.fixtures`) -- every message,
  file, contact, MFA prompt, consequence chain and trainer record is authored
  Python data returned as one JSON document from one endpoint;
* the routes and templates that render the shell.

Mock, and clearly marked as such in the UI:

* every state transition the learner causes. The prototype front end applies
  the *server-authored* consequence chains on a timer in the browser.

That split is the point. The consequence chains are declarative server data,
not client-invented behaviour, so the eventual production wiring replaces the
*transport* (fetch a snapshot, then play a fixture timeline) with a real one
(subscribe to server events) without the front end having to relearn what a
consequence is. The rule the architecture states as

    SERVER = authoritative simulation truth
    FRONTEND = presentation + learner interaction

is respected in shape here even though the truth is currently fixture data.

Isolation guarantees
--------------------
* Nothing here imports :mod:`rewindsec.core`. The deterministic core is not
  exercised, simulated or approximated by this prototype, and a reviewer must
  never read a prototype screenshot as evidence about the core.
* Nothing here imports the v1 ``study``/``learning``/``scenario_adapters``/
  ``evaluation`` code. ``tests/test_provenance.py`` enforces that statically.
* Every route lives under one ``/prototype`` prefix and every template and
  asset lives under a ``prototype/`` subdirectory, so the whole mock layer is
  removable by deleting this package, ``templates/prototype/``,
  ``static/prototype/`` and one ``register_blueprint`` call.
* The v1 learner, instructor and study surfaces are untouched.

Safety
------
All content is manually authored synthetic material: a fictional organisation,
fictional people, and inert ``.example`` destinations that cannot resolve. No
real credential is collected, no attachment is a real file, nothing is
executed, no external request is made, and no dataset is used. See
:func:`rewindsec.prototype.fixtures.safety_report`.
"""

__all__ = []
