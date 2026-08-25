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

# Installa patchradar da PyPI con dipendenze aggiornate
RUN pip install --no-cache-dir --root-user-action=ignore patchradar && \
    pip install --no-cache-dir --root-user-action=ignore "setuptools>=78.1.1" "msgpack>=1.2.1"

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
