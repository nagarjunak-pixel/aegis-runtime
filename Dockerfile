# Stage 1: Build Operator Control Tower UI
FROM node:22-alpine AS ui-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm ci
COPY ui/ ./
RUN npm run build

# Stage 2: Hardened Python 3.12 Runtime
FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AEGIS_DATA_DIR=/var/lib/aegis

WORKDIR /app
RUN groupadd -r aegis && useradd -r -g aegis aegis && \
    mkdir -p /var/lib/aegis && chown -R aegis:aegis /var/lib/aegis

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/
COPY policies/ ./policies/
COPY --from=ui-builder /ui/dist ./ui/dist

RUN pip install --no-cache-dir .

USER aegis
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/v1/health')" || exit 1

ENTRYPOINT ["aegis"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8000"]
