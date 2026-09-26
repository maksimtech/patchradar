"""
PatchRadar — CI contract (G2)

The Tests workflow ran `patchradar --help` and `patchradar list` and never
invoked pytest, so the suite could not fail the build — and `respx`, imported
by the suite, was not declared anywhere, so the suite was not even installable
from the declared dependencies.

These tests are the regression guard for both halves.
"""
import ast
import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "test.yml"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# import name -> distribution name, where they differ
IMPORT_TO_DIST = {
    "patchradar": None,  # the project itself
    "yaml": "pyyaml",    # imported as yaml, distributed as pyyaml
}


def _pyproject() -> dict:
    return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))


def _declared_distributions() -> set[str]:
    data = _pyproject()
    declared = set()
    for spec in data["project"].get("dependencies", []):
        declared.add(re.split(r"[<>=!~\[ (]", spec, maxsplit=1)[0].strip().lower())
    for group in data.get("dependency-groups", {}).values():
        for spec in group:
            declared.add(re.split(r"[<>=!~\[ (]", spec, maxsplit=1)[0].strip().lower())
    return declared


def _third_party_imports(directory: Path) -> set[str]:
    found = set()
    for path in sorted(directory.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                # skip relative imports
                names = [node.module] if node.level == 0 and node.module else []
            else:
                continue
            for name in names:
                root = name.split(".")[0]
                if root in sys.stdlib_module_names or root in _repo_modules():
                    continue
                found.add(root)
    return found


def _repo_modules() -> set[str]:
    """This repository's own code outside the package — scripts/, tools/.

    tests/test_bump_version.py imports scripts/bump_version.py through
    sys.path. It is declared nowhere because there is nobody to declare it to,
    and reading that as an undeclared dependency would be the opposite of what
    this check is for.
    """
    return {
        path.stem
        for folder in ("scripts", "tools")
        for path in (REPO_ROOT / folder).glob("*.py")
    }


# ─── the workflow must actually run the suite ────────────────────────────────

def test_ci_workflow_invokes_pytest():
    content = TEST_WORKFLOW.read_text(encoding="utf-8")
    assert re.search(r"\bpytest\b", content), (
        "the Tests workflow never invokes pytest — the suite cannot fail the build"
    )


def test_ci_workflow_runs_the_tests_directory():
    content = TEST_WORKFLOW.read_text(encoding="utf-8")
    assert re.search(r"pytest[^\n]*\btests/?\b", content), "pytest is not pointed at tests/"


def test_ci_workflow_installs_the_dev_group():
    """Installing only the runtime deps leaves the suite unimportable."""
    content = TEST_WORKFLOW.read_text(encoding="utf-8")
    assert "--group dev" in content, "the dev dependency group is never installed in CI"


# ─── every test dependency must be declared ──────────────────────────────────

def test_every_test_import_is_declared():
    declared = _declared_distributions()
    missing = set()
    for module in _third_party_imports(REPO_ROOT / "tests"):
        dist = IMPORT_TO_DIST.get(module, module)
        if dist is None:
            continue
        if dist.lower() not in declared:
            missing.add(module)
    assert not missing, f"imported by tests/ but not declared in pyproject.toml: {sorted(missing)}"


def test_every_benchmark_import_is_declared():
    declared = _declared_distributions()
    missing = set()
    for module in _third_party_imports(REPO_ROOT / "benchmarks"):
        dist = IMPORT_TO_DIST.get(module, module)
        if dist is None:
            continue
        if dist.lower() not in declared:
            missing.add(module)
    assert not missing, f"imported by benchmarks/ but not declared: {sorted(missing)}"


def test_respx_is_declared():
    """Named explicitly — this is the dependency that was actually missing."""
    assert "respx" in _declared_distributions()


# ─── the one check name branch protection can require ────────────────────────

def test_tests_workflow_publishes_one_check_name_for_branch_protection():
    """A ruleset needs a context that survives a change to the matrix.

    Verified against the live repository on 2026-09-24: the workflow published
    `test (3.11, false)` through `test (3.15-dev, true)` and nothing else, so the
    ruleset had been given those five strings as required contexts — and then, at
    some point, the same strings were pasted into the field that takes *branch*
    patterns, where they matched no branch at all and main went unprotected.

    One summary job whose name does not move fixes both halves. The other four
    Radar already have it.
    """
    import yaml

    workflow = yaml.safe_load(TEST_WORKFLOW.read_text(encoding="utf-8"))
    jobs = workflow["jobs"]

    summary_key, summary = next(
        ((key, job) for key, job in jobs.items() if job.get("name") == "Tests"),
        (None, None),
    )
    assert summary is not None, f"no job named 'Tests' among {sorted(jobs)}"

    # exactly one, or the context would be ambiguous
    assert [job.get("name") for job in jobs.values()].count("Tests") == 1
    assert set(summary["needs"]) == set(jobs) - {summary_key}

    # A skipped required check counts as passed, so it has to run even when the
    # matrix fails, and fail explicitly in that case.
    assert summary["if"] == "always()"
    env = {k: v for step in summary["steps"] for k, v in step.get("env", {}).items()}
    assert any("needs.*.result" in value for value in env.values())
