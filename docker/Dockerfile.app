# The attackable storefront. Runs as an unprivileged user, contains no catalog,
# no rules, no scoring key, and no solve store. It reaches the scorer only through
# the one-way tap socket on a shared volume; it has no network route to the scorer.
FROM python:3.13-slim

RUN apt-get update && apt-get install -y --no-install-recommends curl iputils-ping \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Only the app and its shared record contract. Note what is NOT copied:
# scorer/, findings.yaml, tests/, tools/, cheatsheets — none of the answer key.
COPY app/ ./app/
COPY shared/ ./shared/
COPY serve.py .

RUN useradd -m sprkl && mkdir -p /data /run/sprkl && chown sprkl /data
USER sprkl

ENV SPRKL_APP_PORT=8081 \
    SPRKL_DATA=/data \
    SPRKL_SEED_FILE=/run/sprkl/seed.json \
    SPRKL_TAP_SOCKET=/run/sprkl/tap.sock \
    SPRKL_COLLAB_BASE=http://scorer:8088/c
EXPOSE 8081
CMD ["python", "serve.py"]
