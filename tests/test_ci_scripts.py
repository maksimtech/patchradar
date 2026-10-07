"""The release's two jobs, and the race between them that is now gone.

`docker.yml` and `publish.yml` both fire on the release, in parallel. The image
used to install `patchradar==<new version>` from PyPI while publish.yml was still
uploading it, which is a race, and the history of it is the argument for how this
is arranged now:

  * a fixed `sleep 60` stood in for a wait and lost it (2026.9.4);
  * polling the index until pip could fetch the version narrowed it;
  * apkradar lost it anyway on 2026-10-03, fifteen seconds after the poll had
    reported the version available — because the poll runs on the runner and the
    multi-platform build resolves the index again, per platform, from whichever
    edge answers;
  * a bounded margin after the poll narrowed it further, and still did not close
    it, because nothing that waits can.

So the image is built from the source the tag points at and does not ask the index
about this package at all.

Which raised a question with an uncomfortable answer: what builds that branch? Not
docker.yml, which publishes as it builds. docker-build-check.yml exists for it and
was reachable by hand alone, so in practice nothing built these images between
releases, and the first attempt at a build was the one that published it. It now runs
on every push and pull request, which is what makes moving the release onto that
branch safe rather than merely cleaner.

Two things follow, and neither is obvious. A dispatched rebuild of an old version
has to check that version's tag out, because where the job stands in the tree now
decides what ships. And the one thing the old arrangement proved by accident — that
the file on PyPI installs — has to be said on purpose, which publish.yml now does,
after the upload, where a slow index delays a check instead of failing a build.

The failure this all came from is worth naming because it does not look like
itself: pip reports `No matching distribution found for patchradar==<version>`,
listing versions up to the *previous* release, which reads as "the publish failed"
when PyPI already holds the files and only the index has not caught up.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WAIT_FOR_PYPI = ROOT / ".github" / "scripts" / "wait_for_pypi.sh"
WORKFLOWS = ROOT / ".github" / "workflows"

PACKAGE = "patchradar"


def _bash() -> str:
    """The bash the script is written for: the one on PATH, and Git's on Windows.

    On Windows `bash` is also WSL's launcher in System32. CreateProcess looks
    there before PATH, and so does `shutil.which` from a shell that lists
    System32 first, and WSL drops the backslashes of the Windows path it is
    handed: "No such file or directory", exit 127, and every case below failed
    without the script running at all. Git for Windows ships a bash next to git.
    """
    found = shutil.which("bash")
    if os.name != "nt":
        return found or "bash"
    system32 = Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32"
    if found and Path(found).parent != system32:
        return found
    git = shutil.which("git")
    bundled = Path(git).resolve().parent.parent / "bin" / "bash.exe" if git else None
    return str(bundled) if bundled and bundled.is_file() else (found or "bash")


BASH = _bash()


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
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}", "SUCCEED_AT": str(succeed_at)}
        proc = subprocess.run(
            [BASH, str(WAIT_FOR_PYPI), *args],
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

    def start(succeed_at, *args):
        """The same script, left running, for the one case that is about *not* finishing."""
        env = {**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}",
               "SUCCEED_AT": str(succeed_at)}
        return subprocess.Popen(
            [BASH, str(WAIT_FOR_PYPI), *args],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    run.start = start
    return run


def test_it_asks_pip_for_the_exact_version_and_stops_on_the_first_answer(fake_pip):
    proc, calls = fake_pip(1, PACKAGE, "2026.42", "5", "0", "0")

    assert proc.returncode == 0, proc.stderr
    assert len(calls) == 1
    assert "download" in calls[0]
    assert "--no-deps" in calls[0]          # the package, not its dependency tree
    assert f"{PACKAGE}==2026.42" in calls[0]


def test_it_keeps_asking_until_the_index_has_caught_up(fake_pip):
    proc, calls = fake_pip(3, PACKAGE, "2026.42", "5", "0", "0")

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


def test_it_allows_the_index_a_grace_once_the_version_is_there(fake_pip):
    """The margin is a wait that happens, not a line in the log.

    apkradar 2026.42 built fifteen seconds after this script reported the version
    available — 16:31:21 against 16:31:36 — because the runner and the buildx
    container resolve different edges of the index. A grace that is printed and not
    taken would leave that exactly as it was while looking fixed.
    """
    start = time.monotonic()
    proc, calls = fake_pip(1, PACKAGE, "2026.42", "5", "0", "2")
    elapsed = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert elapsed >= 2, f"it reported a grace it did not take ({elapsed:.1f}s)"
    assert "agree with itself" in proc.stdout, "it waited without saying why"


def test_no_grace_waits_for_nothing_and_claims_nothing(fake_pip):
    """Zero has to mean zero, including in the log: a release that did not need the
    margin should not read as though it used one.

    Timed as a difference rather than against the clock. An absolute upper bound here
    read `< 2` and saw 21.4 seconds the first time five suites ran on one machine at
    once — measuring what the machine was doing rather than what the script was doing.
    The gap between a run that is given a grace and one that is not is the grace,
    whatever else is happening.
    """
    start = time.monotonic()
    proc, _ = fake_pip(1, PACKAGE, "2026.42", "5", "0", "0")
    without = time.monotonic() - start

    start = time.monotonic()
    waited, _ = fake_pip(1, PACKAGE, "2026.42", "5", "0", "3")
    with_grace = time.monotonic() - start

    assert proc.returncode == 0, proc.stderr
    assert waited.returncode == 0, waited.stderr
    assert "agree with itself" not in proc.stdout
    assert with_grace - without >= 2, (
        f"no grace took {without:.1f}s and a three second grace took "
        f"{with_grace:.1f}s, so the grace was not waited for"
    )


def test_the_default_grace_is_a_wait_and_not_zero(fake_pip):
    """Measured, without the suite paying the whole default for it.

    Started with no grace argument against an index that answers on the first ask,
    the script must still be running a few seconds later. Remove the default, or set
    it to zero, and it exits immediately and this fails — which is the point: every
    other case here passes a grace explicitly, so without this one the default could
    be deleted and nothing would notice.
    """
    proc = fake_pip.start(1, PACKAGE, "2026.42", "5", "0")
    try:
        with pytest.raises(subprocess.TimeoutExpired):
            proc.wait(timeout=3)
    finally:
        proc.kill()
        proc.wait(timeout=10)


# ─── the workflow: where the wait sits, and what it is given ────────────────

yaml = pytest.importorskip("yaml")


def _workflow(name):
    wf = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    wf["on"] = wf.pop(True, wf.get("on"))     # PyYAML reads the `on` key as True
    return wf


def _docker_steps():
    return _workflow("docker.yml")["jobs"]["docker"]["steps"]


def _publish_steps():
    return _workflow("publish.yml")["jobs"]["build-and-publish"]["steps"]


def test_the_release_image_is_built_from_the_tag_and_not_from_the_index():
    """What closes the race instead of narrowing it.

    The image used to install `patchradar==<new version>` from PyPI while
    publish.yml was still uploading it — a race no margin wins outright, because
    the runner and the multi-platform build container resolve different edges of
    the index. Built from the source the tag points at, the image asks the index
    nothing about this package.

    `local` is the branch docker-build-check.yml builds, and that workflow now runs
    on every push and pull request rather than by hand alone — the case above is
    about why. Until it did, nothing built either branch except the release.
    """
    steps = _docker_steps()
    build = next(s for s in steps if "build-push-action" in s.get("uses", ""))
    args = build["with"]["build-args"]

    assert "PATCHRADAR_SOURCE=local" in args
    assert "pypi" not in args
    assert not [s for s in steps if "wait_for_pypi.sh" in s.get("run", "")], (
        "nothing here needs the index now, so nothing here should wait for it"
    )


def test_the_image_is_built_before_a_release_and_not_only_during_one():
    """Otherwise the first attempt at building the image is the one that publishes it.

    docker.yml pushes to Docker Hub, `:latest` included, so it cannot be used to find
    out whether the image builds — running it *is* a release. docker-build-check.yml
    exists for that and was reachable only by hand, which means in practice nothing
    built these images between releases.

    That mattered more once the release stopped installing from the index: the branch
    the release takes is now the one that builds from this source tree, so it has to
    be built by something other than the release itself.
    """
    triggers = _workflow("docker-build-check.yml")["on"]

    assert "pull_request" in triggers, "a change that breaks the image should say so in its PR"
    assert "push" in triggers, "and on main, because that is what the next release builds"


def test_a_rebuild_checks_out_the_version_it_was_asked_for():
    """The trap that building from the checkout sets, and that the index did not.

    This workflow can be dispatched with the version of an already published
    release to rebuild. While the image installed that version from PyPI, where the
    job stood in the tree did not matter. Built from the checkout it matters
    entirely: left on the default branch, a rebuild would tag `main`'s code with an
    old release's number — the same accident `ARG PATCHRADAR_VERSION=2026.8.33` used
    to cause from the other direction.

    A version whose tag is spelled differently fails the checkout, loudly, which is
    the right way round.
    """
    checkout = next(s for s in _docker_steps() if "actions/checkout" in s.get("uses", ""))

    assert "inputs.version" in checkout.get("with", {}).get("ref", "")


def test_the_published_file_is_still_checked_where_it_was_published():
    """The old arrangement proved one thing by accident: that what lands on PyPI
    can be installed. Taking the image off the index would lose that, so the job
    that uploads says it on purpose — and *after* the upload, where a slow index
    delays a check instead of failing a build.
    """
    steps = _publish_steps()
    names = [s.get("name", s.get("uses", "")) for s in steps]

    upload = next(i for i, s in enumerate(steps) if "gh-action-pypi-publish" in s.get("uses", ""))
    version = next(i for i, s in enumerate(steps) if s.get("id") == "version")
    wait = next(i for i, s in enumerate(steps) if "wait_for_pypi.sh" in s.get("run", ""))
    verify = next(i for i, s in enumerate(steps) if "--version" in s.get("run", ""))

    assert upload < version < wait < verify, names
    assert 'patchradar==${VERSION}' in steps[verify]["run"], "it has to be the new one"


def test_the_check_asks_for_no_margin_because_there_is_one_resolver():
    """The grace exists because the runner and the buildx container ask different
    edges of the index. Here there is only the runner, which has just had `pip
    download` answer — so a margin would buy nothing, and a wait that buys nothing
    is the thing this script was rewritten to stop doing.
    """
    wait = next(s for s in _publish_steps() if "wait_for_pypi.sh" in s.get("run", ""))
    arguments = wait["run"].split("wait_for_pypi.sh", 1)[1].split()

    assert arguments[-1] == "0", wait["run"]


def test_the_version_the_check_is_given_has_no_tag_prefix():
    """A release here is named 2026.42, but `gh release create` has also been
    given a `v` before now, and the other Radar tag with one. What reaches pip
    must be the distribution version either way."""
    steps = _publish_steps()
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
