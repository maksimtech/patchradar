FROM python:3.14-slim-trixie

# Metadata OCI
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="PatchRadar"
LABEL org.opencontainers.image.description="Realtime CVE intelligence for your software stack"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/patchradar"
LABEL org.opencontainers.image.license="MIT"

# Aggiorna pacchetti di sistema per fix vulnerabilità
RUN apt-get update && apt-get upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*

# Ambiente Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Sorgente di patchradar:
#   local (default, CI) → il codice di questo repository
#   pypi (release)      → patchradar==PATCHRADAR_VERSION da PyPI
# Il default e' local perche' una build senza argomenti deve dire qualcosa sul
# codice che si ha davanti: con un default PyPI diceva 2026.8.33 per sempre.
ARG PATCHRADAR_SOURCE=local
ARG PATCHRADAR_VERSION=

COPY pyproject.toml README.md LICENSE /app/build/
COPY src/ /app/build/src/

# Installa patchradar con dipendenze aggiornate
RUN case "${PATCHRADAR_SOURCE}" in \
        local) pip install --no-cache-dir --root-user-action=ignore /app/build ;; \
        pypi) test -n "${PATCHRADAR_VERSION}" || { echo "PATCHRADAR_VERSION is required with PATCHRADAR_SOURCE=pypi" >&2; exit 1; } && \
              pip install --no-cache-dir --root-user-action=ignore --only-binary :all: "patchradar==${PATCHRADAR_VERSION}" ;; \
        *) echo "PATCHRADAR_SOURCE must be 'local' or 'pypi'" >&2; exit 1 ;; \
    esac && \
    rm -rf /app/build && \
    pip install --no-cache-dir --root-user-action=ignore --only-binary :all: "setuptools==78.1.1" "msgpack==1.2.1"

# Crea utente non-root per sicurezza
RUN useradd -m -u 1000 patchradar && \
    mkdir -p /home/patchradar/.patchradar && \
    chown -R patchradar:patchradar /home/patchradar

USER patchradar
WORKDIR /home/patchradar

# Volume per dati persistenti
VOLUME ["/home/patchradar/.patchradar"]

# Porta
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Avvio
CMD ["patchradar", "serve", "--host", "0.0.0.0", "--port", "8000"]
