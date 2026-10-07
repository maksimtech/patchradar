FROM python:3.14-slim-trixie

# OCI metadata
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="PatchRadar"
LABEL org.opencontainers.image.description="CVE intelligence for your software stack"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/patchradar"
LABEL org.opencontainers.image.license="MIT"

# Upgrade the system packages the base image ships with
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Python environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Where patchradar comes from:
#   local (default, CI) → the code in this repository
#   pypi (release)      → patchradar==PATCHRADAR_VERSION from PyPI
# The default is local because a build with no arguments has to say something
# about the code in front of whoever ran it: with a PyPI default it said
# 2026.8.33 for ever.
ARG PATCHRADAR_SOURCE=local
ARG PATCHRADAR_VERSION=

COPY pyproject.toml README.md LICENSE /app/build/
COPY src/ /app/build/src/

# Install patchradar, then take the build tooling back out.
#
# A runtime image needs neither pip, setuptools nor wheel: the CMD runs
# `patchradar serve`, the healthcheck uses urllib, and no dependency imports
# pkg_resources. While they are installed, the copies they vendor are what a
# scanner reports — and a pin cannot reach those. On 2026-09-28 Docker Scout
# reported msgpack 1.1.2, setuptools 70.3.0, wheel 0.45.1 and jaraco-context
# 5.3.0 against the published image, although this file had pinned
# setuptools 78.1.1 and msgpack 1.2.1 since 2026-08-27: the vulnerable copies
# live under `pip/_vendor/` and `setuptools/_vendor/`, so installing a patched
# version alongside leaves them exactly where they were. Removing the tooling
# removes them; the pins are gone with it, msgpack never having been a
# dependency of this project.
#
# `pip uninstall` is the last pip call in this file, because it removes pip. A
# package that is not installed is a warning and not an error, so the build does
# not depend on which of the three the base image happens to ship.
RUN case "${PATCHRADAR_SOURCE}" in \
        local) pip wheel --no-deps --no-cache-dir --wheel-dir /app/wheel /app/build && \
               pip install --no-cache-dir --root-user-action=ignore --only-binary :all: /app/wheel/*.whl ;; \
        pypi) test -n "${PATCHRADAR_VERSION}" || { echo "PATCHRADAR_VERSION is required with PATCHRADAR_SOURCE=pypi" >&2; exit 1; } && \
              pip install --no-cache-dir --root-user-action=ignore --only-binary :all: "patchradar==${PATCHRADAR_VERSION}" ;; \
        *) echo "PATCHRADAR_SOURCE must be 'local' or 'pypi'" >&2; exit 1 ;; \
    esac && \
    rm -rf /app/build /app/wheel && \
    pip uninstall --yes --root-user-action=ignore pip setuptools wheel

# A non-root user, and its home, which is where the volume is mounted
RUN useradd -m -u 1000 patchradar && \
    mkdir -p /home/patchradar/.patchradar && \
    chown -R patchradar:patchradar /home/patchradar

USER patchradar
WORKDIR /home/patchradar

# Persistent data
VOLUME ["/home/patchradar/.patchradar"]

# Port
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Entry point
CMD ["patchradar", "serve", "--host", "0.0.0.0", "--port", "8000"]
