FROM python:3.14-slim-bookworm

# Metadata OCI
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="PatchRadar"
LABEL org.opencontainers.image.description="Realtime CVE intelligence for your software stack"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/patchradar"
LABEL org.opencontainers.image.license="MIT"

# Ambiente Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Installa patchradar da PyPI
RUN pip install --no-cache-dir --root-user-action=ignore patchradar

# Volume per dati persistenti
VOLUME ["/root/.patchradar"]

# Porta
EXPOSE 8000

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Avvio
CMD ["patchradar", "serve", "--host", "0.0.0.0", "--port", "8000"]
