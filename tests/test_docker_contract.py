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
