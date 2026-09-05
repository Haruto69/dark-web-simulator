"""Static guardrails on the RewindSec 2.0 simulation domain.

Mirrors ``test_rewindsec2_core_boundaries.py``: AST inspection rather than
grep, so a docstring mentioning "flask" cannot trip a false positive and a
real import cannot hide behind one. The domain's whole value -- a session
aggregate that is a pure function of ``(seed, action sequence)`` and can be
tested without a running application -- depends on it never importing Flask,
Flask-SQLAlchemy, SQLAlchemy, the prototype UI, or any v1 module.

``rewindsec/persistence/`` is explicitly exempt from the SQLAlchemy rule: it
is the one place SQLAlchemy is allowed, because it is the adapter, not the
domain.
"""

import ast
import io
import os
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
DOMAIN_ROOT = REPO_ROOT / "rewindsec" / "domain"
PERSISTENCE_ROOT = REPO_ROOT / "rewindsec" / "persistence"

#: The domain must stay independent of any framework, any storage technology,
#: and every v1 module -- it has to be usable in a pure Python test with no
#: Flask app context and no database.
FORBIDDEN_FRAMEWORK_IMPORTS = frozenset({
    "flask", "flask_sqlalchemy", "sqlalchemy", "werkzeug",
    "sandbox", "app", "security", "telemetry_ledger", "manage",
    "training", "training_service", "training_routes", "training_flow",
    "scenario_adapters", "learning", "learning_service", "learning_routes",
    "study", "study_service", "study_routes", "evaluation",
})

#: Sources of values that differ between two runs of the same seed.
FORBIDDEN_NONDETERMINISM_IMPORTS = frozenset({
    "secrets", "uuid", "time", "datetime", "os", "socket", "platform",
    "tempfile", "getpass", "random",
})


def domain_modules():
    if not DOMAIN_ROOT.is_dir():
        return []
    return sorted(p for p in DOMAIN_ROOT.rglob("*.py")
                  if "__pycache__" not in p.parts)


def persistence_modules():
    if not PERSISTENCE_ROOT.is_dir():
        return []
    return sorted(p for p in PERSISTENCE_ROOT.rglob("*.py")
                  if "__pycache__" not in p.parts)


def _module_id(path):
    return str(pathlib.Path(path).relative_to(REPO_ROOT)).replace(os.sep, "/")


def _parse(path):
    return ast.parse(io.open(path, encoding="utf-8").read(), filename=str(path))


def _imported_top_level_names(path):
    names = set()
    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


DOMAIN_MODULES = domain_modules()
PERSISTENCE_MODULES = persistence_modules()


def test_domain_package_exists_and_has_modules():
    assert DOMAIN_ROOT.is_dir(), "rewindsec/domain/ is missing"
    assert DOMAIN_MODULES, "rewindsec/domain/ contains no Python modules"
    names = {p.name for p in DOMAIN_MODULES}
    assert {"__init__.py", "session.py", "world.py", "context_ledger.py",
            "actions.py", "session_events.py", "incidents.py"} <= names, names


@pytest.mark.parametrize("module_path", DOMAIN_MODULES, ids=_module_id)
def test_domain_module_imports_no_framework_or_v1_code(module_path):
    forbidden = _imported_top_level_names(module_path) & FORBIDDEN_FRAMEWORK_IMPORTS
    assert not forbidden, (
        "%s imports %s. rewindsec/domain/ must stay storage- and framework-"
        "independent: it has to be usable in a pure Python test with no "
        "Flask app context, no database, and none of the v1 modules."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", DOMAIN_MODULES, ids=_module_id)
def test_domain_module_imports_no_nondeterminism_source(module_path):
    forbidden = (_imported_top_level_names(module_path)
                 & FORBIDDEN_NONDETERMINISM_IMPORTS)
    assert not forbidden, (
        "%s imports %s. Every value in a session must be a pure function of "
        "(seed, action sequence); the wall clock and ambient randomness must "
        "not be able to enter it. Draw randomness from SeededRandom "
        "(rewindsec.core.rng), passed in as an argument, never imported "
        "here." % (_module_id(module_path), ", ".join(sorted(forbidden))))


@pytest.mark.parametrize("module_path", DOMAIN_MODULES, ids=_module_id)
def test_domain_module_does_not_import_dynamically(module_path):
    names = _imported_top_level_names(module_path)
    assert "importlib" not in names, _module_id(module_path)
    for node in ast.walk(_parse(module_path)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            assert node.func.id != "__import__", (
                "%s calls __import__, which defeats static import checking"
                % _module_id(module_path))


# -- the persistence adapter is the one place SQLAlchemy may appear ----------

@pytest.mark.parametrize("module_path", PERSISTENCE_MODULES, ids=_module_id)
def test_persistence_module_imports_no_flask(module_path):
    forbidden = _imported_top_level_names(module_path) & {
        "flask", "flask_sqlalchemy", "werkzeug", "app",
    }
    assert not forbidden, (
        "%s imports %s. A persistence adapter must be testable directly "
        "against an Engine, with no Flask app context."
        % (_module_id(module_path), ", ".join(sorted(forbidden))))


def test_ports_module_does_not_import_sqlalchemy():
    """The port/contract module must stay storage-technology-agnostic.

    Only the concrete adapter may import SQLAlchemy; the interface it
    implements must not, or a caller could not depend on the port alone.
    """
    ports = PERSISTENCE_ROOT / "ports.py"
    assert ports.is_file(), "rewindsec/persistence/ports.py is missing"
    forbidden = _imported_top_level_names(ports) & {"sqlalchemy", "flask", "flask_sqlalchemy"}
    assert not forbidden, forbidden


def test_sqlalchemy_adapter_actually_imports_sqlalchemy():
    """Guards the exemption against becoming stale."""
    adapter = PERSISTENCE_ROOT / "sqlalchemy_adapter.py"
    assert adapter.is_file(), "rewindsec/persistence/sqlalchemy_adapter.py is missing"
    assert "sqlalchemy" in _imported_top_level_names(adapter)


# -- the domain really is importable without Flask or SQLAlchemy loaded -----

def test_domain_imports_without_flask_or_sqlalchemy_loaded():
    """A clean subprocess must be able to build and mutate a session.

    Catches a dependency that arrives through a package ``__init__`` rather
    than a direct import -- the same backstop
    ``test_rewindsec2_core_boundaries.py`` applies to the core.
    """
    import subprocess
    import sys

    script = (
        "import sys\n"
        "sys.path.insert(0, %r)\n"
        "from rewindsec.domain.session import SimulationSession\n"
        "from rewindsec.domain.enums import Focus, Mode\n"
        "s = SimulationSession.create('s1', 'learner-1', Focus.PHISHING, "
        "Mode.PRACTICE, root_seed=7)\n"
        "s.record_immediate_event('mail.delivered')\n"
        "loaded = sorted(m for m in sys.modules\n"
        "                if m.split('.')[0] in {'flask', 'sqlalchemy', 'sandbox',\n"
        "                                       'app', 'study', 'learning',\n"
        "                                       'scenario_adapters', 'evaluation',\n"
        "                                       'training'})\n"
        "print(repr((s.revision, loaded)))\n" % str(REPO_ROOT)
    )
    completed = subprocess.run([sys.executable, "-c", script],
                               capture_output=True, text=True,
                               cwd=str(REPO_ROOT), timeout=120)
    assert completed.returncode == 0, completed.stderr
    revision, loaded = ast.literal_eval(completed.stdout.strip())
    assert revision == 1
    assert loaded == [], "importing the domain dragged in %s" % loaded
