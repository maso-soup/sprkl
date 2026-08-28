# SPRKL — intentionally vulnerable sparkling-water storefront (single image).
# Ships the attackable app (8080) and the oracle/scoring API (9090) in one container.
FROM python:3.13-slim

# A deliberately-outdated component banner is advertised at runtime (see /status);
# curl is present so blind-command-injection has a callback tool, matching a
# realistic corporate box.
RUN apt-get update && apt-get install -y --no-install-recommends curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENV SPRKL_APP_PORT=8080 \
    SPRKL_ORACLE_PORT=9090 \
    SPRKL_DATA=/data \
    SPRKL_ORACLE_KEY=sprkl-oracle-dev-key
RUN mkdir -p /data
VOLUME ["/data"]

EXPOSE 8080 9090
HEALTHCHECK --interval=30s --timeout=3s CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

CMD ["python", "serve.py"]
