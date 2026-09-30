"""The wait that keeps the Docker build from racing its own publish.

`docker.yml` and `publish.yml` both fire on the release, in parallel, and the
Dockerfile installs `patchradar==<new version>` from PyPI. A fixed `sleep 60`
stood in for the wait and lost that race on 2026.9.4, so the polling script was
ported from cookieradar — and then had no test of its own, which is the gap this
file closes. The same guess is still in place in the other two Radar that install
from the index, and cost apkradar a red build twice, on 2026-09-24 and
2026-09-30.

The failure is worth naming because it does not look like itself: pip reports
`No matching distribution found for patchradar==<version>`, listing versions up
to the *previous* release, which reads as "the publish failed" when PyPI already
holds the files and only the index has not caught up. On 2026-09-30 the wait did
its job during the 2026.42 release, and the job sitting on this step for minutes
was briefly read as a Docker build that had published nothing.

Two things have to be right, and the second is not obvious: the wait asks pip,
because pip is what the Dockerfile uses and what the index answers for; and it
runs *after* the version is extracted, because a release names 2026.42 while the
other Radar tag `v2026.41`, and `==v2026.41` is not a version pip can ever find.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WAIT_FOR_PYPI = ROOT / ".github" / "scripts" / "wait_for_pypi.sh"
WORKFLOWS = ROOT / ".github" / "workflows"

PACKAGE = "patchradar"


@pytest.fixture
def fake_pip(tmp_path):
    """A `pip` on PATH that fails until the call count reaches SUCCEED_AT.

    The script is run for real, by bash, with the retry interval set to zero.
    What is faked is only the answer from the index.
    """
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    pip = bin_dir / "pip"
    pip.write_text(
        "#!/bin/sh\n"
        f'echo "$@" >> "{log}"\n'
        f'n=$(wc -l < "{log}")\n'
        '[ "$n" -ge "$SUCCEED_AT" ]\n',
        encoding="utf-8",
    )
    pip.chmod(0o755)

    def run(succeed_at, *args):
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "SUCCEED_AT": str(succeed_at)}
        proc = subprocess.run(
            ["bash", str(WAIT_FOR_PYPI), *args],
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        calls = log.read_text(encoding="utf-8").splitlines() if log.exists() else []
        return proc, calls

    return run


def test_it_asks_pip_for_the_exact_version_and_stops_on_the_first_answer(fake_pip):
    proc, calls = fake_pip(1, PACKAGE, "2026.42", "5", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 1
    assert "download" in calls[0]
    assert "--no-deps" in calls[0]          # the package, not its dependency tree
    assert f"{PACKAGE}==2026.42" in calls[0]


def test_it_keeps_asking_until_the_index_has_caught_up(fake_pip):
    proc, calls = fake_pip(3, PACKAGE, "2026.42", "5", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 3


def test_it_gives_up_and_says_so_rather_than_letting_the_build_start(fake_pip):
    """A version that never appears is a failure, not something to build around.

    The failure has to name the version: "still not available" with no subject is
    the kind of message that sent the last investigations the wrong way.
    """
    proc, calls = fake_pip(99, PACKAGE, "2026.42", "4", "0")

    assert proc.returncode != 0
    assert len(calls) == 4
    assert f"{PACKAGE}==2026.42" in proc.stderr


def test_it_refuses_to_run_without_a_package_and_a_version(fake_pip):
    """Called wrong, it must not wait for nothing and then report success."""
    proc, calls = fake_pip(1)

    assert proc.returncode != 0
    assert calls == []
    assert "Usage" in proc.stderr


# ─── the workflow: where the wait sits, and what it is given ────────────────

yaml = pytest.importorskip("yaml")


def _workflow(name):
    wf = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    wf["on"] = wf.pop(True, wf.get("on"))     # PyYAML reads the `on` key as True
    return wf


def _docker_steps():
    return _workflow("docker.yml")["jobs"]["docker"]["steps"]


def test_the_wait_runs_after_the_version_is_known_and_before_the_build():
    steps = _docker_steps()
    names = [s.get("name", s.get("uses", "")) for s in steps]

    version = next(i for i, s in enumerate(steps) if s.get("id") == "version")
    wait = next(i for i, s in enumerate(steps) if "wait_for_pypi.sh" in s.get("run", ""))
    build = next(i for i, s in enumerate(steps) if "build-push-action" in s.get("uses", ""))

    assert version < wait < build, names


def test_the_version_the_wait_is_given_has_no_tag_prefix():
    """A release here is named 2026.42, but `gh release create` has also been
    given a `v` before now, and the other Radar tag with one. What reaches pip
    must be the distribution version either way."""
    steps = _docker_steps()
    version = next(s for s in steps if s.get("id") == "version")
    wait = next(s for s in steps if "wait_for_pypi.sh" in s.get("run", ""))

    assert "${RAW#v}" in version["run"]       # the prefix is stripped where it is read
    assert wait["env"]["VERSION"] == "${{ steps.version.outputs.VERSION }}"
    assert '"$VERSION"' in wait["run"]        # through the environment, not interpolated


def test_nothing_in_the_docker_workflow_waits_by_sleeping():
    """The regression this file exists for.

    A fixed sleep is a guess about someone else's queue, and on a re-run it
    restarts from this job's own start rather than from the publish finishing.
    """
    for step in _docker_steps():
        assert "sleep" not in step.get("run", ""), step.get("name")
