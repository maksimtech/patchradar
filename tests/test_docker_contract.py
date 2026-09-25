"""
PatchRadar — Docker persistence contract (G5)

docker-compose mounted the named volume at /root/.patchradar, but the image
runs as the unprivileged `patchradar` user, so the app wrote to
/home/patchradar/.patchradar instead. The volume stayed empty and the whole
watchlist plus CVE history was lost on every container recreation — silently,
because the database was still created inside the container's own filesystem.

These are static contract tests: they pin the three places that have to agree
(Dockerfile VOLUME, compose mount target, and the DB_PATH the app derives from
the container user's home) without needing a Docker daemon.
"""
import re
from pathlib import Path

# DEFAULT_DB_PATH, not DB_PATH: the suite redirects the live value at a
# temporary directory, and this contract is about the production location.
from patchradar.db.database import DEFAULT_DB_PATH

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "Dockerfile"
COMPOSE = REPO_ROOT / "docker-compose.yml"

DATA_DIR_NAME = ".patchradar"


def container_user() -> str:
    """The user the image finally runs as."""
    users = re.findall(r"^\s*USER\s+(\S+)", DOCKERFILE.read_text(encoding="utf-8"), re.MULTILINE)
    assert users, "Dockerfile declares no USER — the image would run as root"
    return users[-1]


def dockerfile_volumes() -> list[str]:
    """Paths declared by the Dockerfile VOLUME instruction."""
    content = DOCKERFILE.read_text(encoding="utf-8")
    match = re.search(r"^\s*VOLUME\s+(.+)$", content, re.MULTILINE)
    assert match, "Dockerfile declares no VOLUME"
    return re.findall(r'"([^"]+)"', match.group(1)) or [match.group(1).strip()]


def compose_mount_targets(service: str = "patchradar") -> list[str]:
    """Container-side targets of the compose volume mounts."""
    content = COMPOSE.read_text(encoding="utf-8")
    # entries look like `- <source>:<target>` under a `volumes:` key
    targets = re.findall(r"^\s*-\s+[\w./-]+:(/\S+)\s*$", content, re.MULTILINE)
    assert targets, "no volume mount found in docker-compose.yml"
    return targets


# ─── the three declarations must agree ───────────────────────────────────────

def test_compose_mounts_where_the_dockerfile_declares_the_volume():
    volumes = dockerfile_volumes()
    targets = compose_mount_targets()
    assert set(targets) <= set(volumes), (
        f"compose mounts {targets} but the image declares its data volume at "
        f"{volumes} — the mount would be a separate, unused directory"
    )


def test_volume_lives_in_the_container_users_home():
    """DB_PATH is Path.home()/'.patchradar', so the volume must match that."""
    user = container_user()
    expected = f"/home/{user}/{DATA_DIR_NAME}"
    assert expected in dockerfile_volumes(), (
        f"image runs as {user!r} (home /home/{user}) but declares its volume "
        f"elsewhere; the app writes to {expected}"
    )


def test_compose_does_not_mount_under_root_home():
    """Regression guard for the exact defect: a /root path with a non-root USER."""
    targets = compose_mount_targets()
    user = container_user()
    if user != "root":
        offending = [t for t in targets if t.startswith("/root/")]
        assert not offending, (
            f"compose mounts {offending} while the image runs as {user!r}; "
            "data written by the app would never reach the volume"
        )


def test_data_dir_name_matches_the_application():
    """If DB_PATH's directory is ever renamed, the Docker mounts must follow."""
    assert DEFAULT_DB_PATH.parent.name == DATA_DIR_NAME
    for volume in dockerfile_volumes():
        assert volume.endswith(f"/{DATA_DIR_NAME}"), (
            f"volume {volume!r} does not end in /{DATA_DIR_NAME}, "
            f"but the app stores its database in {DEFAULT_DB_PATH.parent}"
        )


def test_compose_declares_a_named_volume_for_persistence():
    content = COMPOSE.read_text(encoding="utf-8")
    assert re.search(r"^volumes:", content, re.MULTILINE), (
        "no top-level volumes: block — data would not survive `docker compose down`"
    )


# ─── building the image from the source being tested ─────────────────────────


BUILD_CHECK = REPO_ROOT / ".github" / "workflows" / "docker-build-check.yml"
PUBLISH_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "docker.yml"
SMOKE = REPO_ROOT / "tests" / "docker" / "smoke.py"


def test_the_dockerfile_can_build_from_the_working_tree():
    """Otherwise a build check only ever checks a release that already shipped.

    The Dockerfile installed `patchradar==${PATCHRADAR_VERSION}` from PyPI and
    nothing else, with 2026.8.33 as the default — an August release, against a
    package at 2026.9.6. An image built from that says nothing about the code
    about to be published, which is the one question a pre-publish check exists
    to answer.
    """
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert "PATCHRADAR_SOURCE" in dockerfile
    assert "local)" in dockerfile and "pypi)" in dockerfile


def test_a_plain_build_uses_the_working_tree():
    """The safe default: `docker build .` tests what is in front of you."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert re.search(r"ARG\s+PATCHRADAR_SOURCE=local", dockerfile)


def test_publishing_names_its_source_rather_than_inheriting_it():
    """docker.yml pushes to Docker Hub including :latest. It must not depend on
    a default that something else can change — and after this commit the default
    is the other branch."""
    published = PUBLISH_WORKFLOW.read_text(encoding="utf-8")

    assert "PATCHRADAR_SOURCE=pypi" in published


def test_a_pypi_build_has_to_say_which_version():
    """The stale default is the trap: `ARG PATCHRADAR_VERSION=2026.8.33` meant a
    build with no arguments published August's code under today's tag."""
    dockerfile = DOCKERFILE.read_text(encoding="utf-8")

    assert not re.search(r"ARG\s+PATCHRADAR_VERSION=\S", dockerfile), (
        "a default version here republishes an old release by accident"
    )


def test_the_build_check_builds_without_pushing():
    """The whole point: docker.yml cannot serve as a pre-publish check because
    running it publishes."""
    workflow = BUILD_CHECK.read_text(encoding="utf-8")

    assert "push: false" in workflow
    assert "PATCHRADAR_SOURCE=local" in workflow


def test_the_build_check_runs_the_smoke_test():
    workflow = BUILD_CHECK.read_text(encoding="utf-8")

    assert "tests/docker/smoke.py" in workflow
    assert SMOKE.is_file()


def test_the_smoke_test_checks_what_only_the_container_can_break():
    """A non-root user and a database under its home. The image creates
    /home/patchradar/.patchradar and chowns it; if that ever stops being true the
    application starts and then cannot write, which no unit test would catch."""
    smoke = SMOKE.read_text(encoding="utf-8")

    assert "init_db" in smoke or "patchradar.db" in smoke
    assert "version" in smoke
