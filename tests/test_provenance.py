"""The v1 / RewindSec 2.0 provenance boundary.

The worst defect this repository can develop is not a crash. It is a table, a
results file or a figure quietly attributed to the wrong architecture. These
tests make the boundary described in ``PROVENANCE.md`` mechanical:

* no RewindSec 2.0 module may import v1 study, learning, scenario or historical
  evaluation code;
* the historical evaluation artifacts keep the bytes they had at ``v1.0.0``;
* the provenance document itself still states the distinction.

They are deliberately narrow. Each one protects a property that would be
expensive to discover late, and none of them assert prose wording.
"""

import ast
import hashlib
import io
import json
import os
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REWINDSEC2_ROOT = REPO_ROOT / "rewindsec"
PROVENANCE_DOC = REPO_ROOT / "PROVENANCE.md"
RESULTS_DIR = REPO_ROOT / "evaluation" / "results"
RESULTS_MANIFEST = REPO_ROOT / "evaluation" / "results_manifest.json"

#: Top-level modules that belong to the v1 system. A RewindSec 2.0 module that
#: imported any of them would couple the rebuild to the architecture the v1
#: study and evaluation measured -- which is exactly the coupling that makes a
#: later "is this a v1 or a 2.0 result?" question unanswerable.
V1_MODULES = frozenset({
    "study",
    "study_service",
    "study_routes",
    "learning",
    "learning_service",
    "learning_routes",
    "scenario_adapters",
    "evaluation",
})


def _imported_top_level_names(path):
    """Return the top-level module names *path* imports.

    AST-based rather than textual: a mention of ``study`` in a docstring, a
    comment or a string literal is not an import, and a test that flagged those
    would be abandoned the first time somebody legitimately documented the
    boundary. Relative imports (``level > 0``) are intra-package and are
    ignored.
    """
    tree = ast.parse(io.open(path, encoding="utf-8").read(), filename=str(path))
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names


def rewindsec2_modules():
    """Every ``.py`` file under ``rewindsec/``, excluding bytecode caches."""
    if not REWINDSEC2_ROOT.is_dir():
        return []
    return sorted(p for p in REWINDSEC2_ROOT.rglob("*.py")
                  if "__pycache__" not in p.parts)


# -- the import boundary -----------------------------------------------------

def test_rewindsec2_package_exists():
    """The boundary is meaningless if there is nothing on the 2.0 side."""
    assert REWINDSEC2_ROOT.is_dir(), "rewindsec/ package is missing"
    assert (REWINDSEC2_ROOT / "__init__.py").is_file()
    assert rewindsec2_modules(), "rewindsec/ contains no Python modules"


@pytest.mark.parametrize(
    "module_path", rewindsec2_modules(),
    ids=lambda p: str(pathlib.Path(p).relative_to(REPO_ROOT)).replace(os.sep, "/"))
def test_rewindsec2_module_does_not_import_v1(module_path):
    """No 2.0 module may depend on v1 study/learning/scenario/evaluation code."""
    forbidden = _imported_top_level_names(module_path) & V1_MODULES
    assert not forbidden, (
        "%s imports v1 module(s) %s. RewindSec 2.0 must not depend on the "
        "architecture the v1 study and evaluation measured; see PROVENANCE.md."
        % (pathlib.Path(module_path).relative_to(REPO_ROOT),
           ", ".join(sorted(forbidden))))


def test_import_detection_ignores_prose_but_catches_real_imports():
    """The AST check is neither blind nor trigger-happy.

    Guards the check itself: a fixture that only *mentions* a v1 module must
    pass, and one that actually imports it must be caught. Without this, a
    refactor that broke ``_imported_top_level_names`` would leave every
    boundary test silently passing.
    """
    import tempfile

    prose = ("'''This module deliberately does not use study or evaluation.'''\n"
             "NOTE = 'see scenario_adapters for the v1 equivalent'\n"
             "# import learning\n")
    real = "from study import assignment\nimport evaluation.formal_run\n"

    with tempfile.TemporaryDirectory() as tmp:
        prose_path = os.path.join(tmp, "prose.py")
        real_path = os.path.join(tmp, "real.py")
        io.open(prose_path, "w", encoding="utf-8").write(prose)
        io.open(real_path, "w", encoding="utf-8").write(real)

        assert not _imported_top_level_names(prose_path) & V1_MODULES
        assert _imported_top_level_names(real_path) & V1_MODULES == {
            "study", "evaluation"}


# -- historical evaluation results -------------------------------------------

def _load_manifest():
    with io.open(RESULTS_MANIFEST, encoding="utf-8") as handle:
        return json.load(handle)


def test_results_manifest_is_present_and_well_formed():
    """The manifest is tracked even though the results themselves are not."""
    assert RESULTS_MANIFEST.is_file(), (
        "evaluation/results_manifest.json is missing; it is the only integrity "
        "record for the historical results, which .gitignore excludes from git")
    manifest = _load_manifest()
    assert manifest["manifest_version"] == 1
    artifacts = manifest["artifacts"]
    assert artifacts, "the manifest lists no artifacts"

    seen = set()
    for entry in artifacts:
        path = entry["path"]
        assert path.startswith("evaluation/results/"), path
        assert ".." not in path.split("/"), path
        assert path not in seen, "duplicate manifest entry: %s" % path
        seen.add(path)
        assert len(entry["sha256"]) == 64
        assert int(entry["sha256"], 16) >= 0  # hex-only
        assert entry["size_bytes"] >= 0


def test_historical_evaluation_results_are_unmodified():
    """Every manifest-listed v1 result artifact still has its recorded bytes.

    Skipped when the results tree is absent: ``evaluation/results/`` is
    gitignored, so a fresh clone or a CI machine legitimately has no copy, and
    failing there would be noise rather than signal. When the tree *is* present
    -- as it is on the machine that produced these results -- every listed file
    must exist and hash exactly.

    Files on disk that the manifest does not list are allowed, so adding a new
    experiment run never requires editing the manifest. What is forbidden is a
    recorded artifact changing or disappearing.
    """
    if not RESULTS_DIR.is_dir():
        pytest.skip("evaluation/results/ is absent on this machine "
                    "(gitignored); nothing to verify")

    manifest = _load_manifest()
    missing, altered = [], []
    for entry in manifest["artifacts"]:
        path = REPO_ROOT / entry["path"]
        if not path.is_file():
            missing.append(entry["path"])
            continue
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"]:
            altered.append(entry["path"])

    assert not missing, (
        "historical evaluation artifact(s) deleted: %s. These files measured "
        "the v1 architecture; see PROVENANCE.md." % ", ".join(missing))
    assert not altered, (
        "historical evaluation artifact(s) modified: %s. v1 results must stay "
        "attributable to the architecture they measured; see PROVENANCE.md."
        % ", ".join(altered))


def test_inadmissible_smoke_run_keeps_its_flag():
    """The stored rewindsec-formal results stay marked inadmissible.

    They are a reduced smoke run against a dirty tree at a commit that is not
    the v1.0.0 baseline. The flag is the only thing standing between those
    numbers and an unsupportable claim, so it is asserted rather than trusted.
    """
    metadata = RESULTS_DIR / "rewindsec-formal" / "smoke" / "metadata.json"
    if not metadata.is_file():
        pytest.skip("evaluation/results/ is absent on this machine (gitignored)")
    with io.open(metadata, encoding="utf-8") as handle:
        recorded = json.load(handle)
    assert recorded["admissible"] is False
    assert recorded["development_run"] is True


# -- the provenance document -------------------------------------------------

def test_provenance_document_exists_and_states_the_distinction():
    """PROVENANCE.md exists and still names both systems and the core rule.

    Kept to substance, not wording: the document must name the v1 side, the 2.0
    side, the frozen artifact locations and the v1.0.0 baseline. How it phrases
    any of that is free to change.
    """
    assert PROVENANCE_DOC.is_file(), "PROVENANCE.md is missing"
    text = io.open(PROVENANCE_DOC, encoding="utf-8").read()
    assert len(text) > 1000, "PROVENANCE.md is too short to document anything"

    for required in ("RewindSec 2.0", "v1.0.0", "evaluation/results",
                     "rewindsec/", "study/", "learning/", "scenario_adapters/",
                     "results_manifest.json"):
        assert required in text, (
            "PROVENANCE.md no longer mentions %r" % required)

    lowered = text.lower()
    # The load-bearing claim: v1 evidence is not 2.0 evidence.
    assert "evidence" in lowered
    assert "frozen" in lowered
