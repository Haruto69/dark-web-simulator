"""Static guardrails on the RewindSec 2.0 deterministic core.

The core's whole value is that a session replays bit-identically from its seed
and its recorded actions. Every import banned here is a way for an unrepeatable
value to enter simulation state, and every resulting bug is *silent* -- a replay
that looks correct but rerolled. A reviewer cannot reliably catch that by
reading a diff, so it is enforced mechanically.

AST inspection rather than grep: a docstring that mentions ``time`` is not an
import, and a test that flagged it would be disabled within a week.
"""

import ast
import io
import os
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CORE_ROOT = REPO_ROOT / "rewindsec" / "core"

#: The core is pure Python. Importing any of these would make it depend on a
#: framework, on the host, or on the v1 architecture the historical evaluation
#: measured.
FORBIDDEN_FRAMEWORK_IMPORTS = frozenset({
    "flask", "flask_sqlalchemy", "sqlalchemy", "werkzeug",
    "sandbox", "app", "security", "telemetry_ledger", "manage",
    "training", "training_service", "training_routes", "training_flow",
    "scenario_adapters", "learning", "learning_service", "learning_routes",
    "study", "study_service", "study_routes", "evaluation",
})

#: Sources of values that differ between two runs of the same seed. ``random``
#: is handled separately because exactly one module is allowed to import it.
FORBIDDEN_NONDETERMINISM_IMPORTS = frozenset({
    "secrets", "uuid", "time", "datetime", "os", "socket", "platform",
    "tempfile", "getpass",
})

#: ``random`` is permitted here and nowhere else in the core, because this is
#: the module that wraps it behind explicitly seeded ``random.Random``
#: instances owned by the session. See rewindsec/core/rng.py.
RANDOM_IMPORT_ALLOWED_IN = frozenset({"rng.py"})


def core_modules():
    """Every ``.py`` file under ``rewindsec/core/``, excluding bytecode caches."""
    if not CORE_ROOT.is_dir():
        return []
    return sorted(p for p in CORE_ROOT.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _module_id(path):
    return str(pathlib.Path(path).relative_to(REPO_ROOT)).replace(os.sep, "/")


def _parse(path):
    return ast.parse(io.open(path, encoding="utf-8").read(), filename=str(path))


def _imported_top_level_names(path):
    """Return the top-level module names *path* imports.

    Relative imports (``level > 0``) are intra-package and are ignored.
    """
    names = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


MODULES = core_modules()


def test_core_package_exists_and_has_modules():
    """These guardrails must never pass vacuously."""
    assert CORE_ROOT.is_dir(), "rewindsec/core/ is missing"
    assert MODULES, "rewindsec/core/ contains no Python modules"
    names = {p.name for p in MODULES}
    assert {"__init__.py", "rng.py", "simtime.py", "events.py",
            "scheduler.py"} <= names, names


# -- framework and v1 independence -------------------------------------------

@pytest.mark.parametrize("module_path", MODULES, ids=_module_id)
def test_core_module_imports_no_framework_or_v1_code(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_FRAMEWORK_IMPORTS
    assert not forbidden, (
        "%s imports %s. rewindsec/core/ must stay pure Python: it has to be "
        "testable, digestible and replayable without a web framework, a "
        "database or the v1 architecture."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


# -- nondeterminism ----------------------------------------------------------

@pytest.mark.parametrize("module_path", MODULES, ids=_module_id)
def test_core_module_imports_no_nondeterminism_source(module_path):
    forbidden = (_imported_top_level_names(module_path)
                 & FORBIDDEN_NONDETERMINISM_IMPORTS)
    assert not forbidden, (
        "%s imports %s. Values from these differ between two runs of the same "
        "seed, so they must not reach deterministic state. Wall-clock "
        "timestamps belong in diagnostic and telemetry layers outside "
        "rewindsec/core/."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", MODULES, ids=_module_id)
def test_random_is_imported_only_by_the_module_that_wraps_it(module_path):
    imports_random = "random" in _imported_top_level_names(module_path)
    allowed = pathlib.Path(module_path).name in RANDOM_IMPORT_ALLOWED_IN
    if imports_random and not allowed:
        pytest.fail(
            "%s imports random. Only %s may, and only because it wraps it "
            "behind explicitly seeded random.Random instances the session "
            "owns. Draw from SeededRandom instead."
            % (_module_id(module_path), ", ".join(sorted(RANDOM_IMPORT_ALLOWED_IN))))


def test_the_module_allowed_to_import_random_actually_does():
    """Guards the allow-list against becoming stale.

    If rng.py stops importing random, the exemption must be removed rather
    than left as a standing licence nobody notices.
    """
    rng = CORE_ROOT / "rng.py"
    assert "random" in _imported_top_level_names(rng)


@pytest.mark.parametrize("module_path", MODULES, ids=_module_id)
def test_core_module_does_not_import_dynamically(module_path):
    """No ``__import__`` or ``importlib``: the static check must see everything.

    A dynamic import is a hole straight through every rule above.
    """
    names = _imported_top_level_names(module_path)
    assert "importlib" not in names, _module_id(module_path)

    for node in ast.walk(_parse(module_path)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "__import__", (
                "%s calls __import__, which defeats static import checking"
                % _module_id(module_path))


@pytest.mark.parametrize("module_path", MODULES, ids=_module_id)
def test_core_module_does_not_call_the_global_random_functions(module_path):
    """``random.random()`` at module level would bypass SeededRandom entirely.

    rng.py is allowed to import the module, but even there the only legitimate
    use is constructing ``random.Random`` instances -- never calling the
    module-level functions, which share one process-global generator that no
    session owns and no checkpoint can restore.
    """
    for node in ast.walk(_parse(module_path)):
        if not isinstance(node, ast.Attribute):
            continue
        if not (isinstance(node.value, ast.Name) and node.value.id == "random"):
            continue
        assert node.attr == "Random", (
            "%s uses random.%s. Only random.Random(...) is permitted; the "
            "module-level functions share a process-global generator that no "
            "session owns." % (_module_id(module_path), node.attr))


# -- the guardrails themselves -----------------------------------------------

def test_import_detection_distinguishes_prose_from_imports():
    """Guards the checker: blind to comments, sharp on real imports.

    Without this, a refactor that broke ``_imported_top_level_names`` would
    leave every boundary test above silently passing.
    """
    import tempfile

    prose = ('"""This module must not import time, secrets or sqlalchemy."""\n'
             "NOTE = 'no uuid here either'\n"
             "# import flask\n")
    real = "import time\nimport secrets\nfrom sqlalchemy import Column\n"

    with tempfile.TemporaryDirectory() as tmp:
        prose_path = os.path.join(tmp, "prose.py")
        real_path = os.path.join(tmp, "real.py")
        io.open(prose_path, "w", encoding="utf-8").write(prose)
        io.open(real_path, "w", encoding="utf-8").write(real)

        clean = _imported_top_level_names(prose_path)
        assert not clean & FORBIDDEN_NONDETERMINISM_IMPORTS
        assert not clean & FORBIDDEN_FRAMEWORK_IMPORTS

        dirty = _imported_top_level_names(real_path)
        assert dirty & FORBIDDEN_NONDETERMINISM_IMPORTS == {"time", "secrets"}
        assert dirty & FORBIDDEN_FRAMEWORK_IMPORTS == {"sqlalchemy"}


def test_forbidden_sets_do_not_overlap():
    """One rule, one message: a violation must not be reported twice."""
    assert not FORBIDDEN_FRAMEWORK_IMPORTS & FORBIDDEN_NONDETERMINISM_IMPORTS
    assert "random" not in FORBIDDEN_FRAMEWORK_IMPORTS
    assert "random" not in FORBIDDEN_NONDETERMINISM_IMPORTS


# -- the core really is importable in isolation ------------------------------

def test_core_imports_without_flask_or_sqlalchemy_loaded():
    """The static rules are backed up by actually importing in a clean process.

    A subprocess that has never imported Flask or SQLAlchemy must be able to
    use the core and produce the expected values. This catches a dependency
    that arrives through a package ``__init__`` rather than a direct import.
    """
    import subprocess
    import sys

    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from rewindsec.core import SeededRandom, SimClock\n"
        "clock = SimClock(); clock.advance(1000)\n"
        "value = SeededRandom(1).stream('timing').random()\n"
        "loaded = sorted(m for m in sys.modules\n"
        "                if m.split('.')[0] in {'flask', 'sqlalchemy', 'sandbox',\n"
        "                                       'app', 'study', 'learning',\n"
        "                                       'scenario_adapters', 'evaluation',\n"
        "                                       'training'})\n"
        "print(repr((clock.now_ms, value, loaded)))\n" % str(REPO_ROOT)
    )
    completed = subprocess.run([sys.executable, "-c", script],
                               capture_output=True, text=True,
                               cwd=str(REPO_ROOT), timeout=120)
    assert completed.returncode == 0, completed.stderr
    now_ms, value, loaded = ast.literal_eval(completed.stdout.strip())
    assert now_ms == 1000
    assert value == __import__(
        "rewindsec.core.rng", fromlist=["SeededRandom"]
    ).SeededRandom(1).stream("timing").random()
    assert loaded == [], "importing the core dragged in %s" % loaded
