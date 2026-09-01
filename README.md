# 💧 SPRKL 💧 — An Intentionally Vulnerable Sparkling-Water Storefront

> ⚠️ **SPRKL ships with 95 real vulnerabilities on purpose.** It is a training /
> benchmark target for security professionals and AI agents practicing *novel
> discovery*. **Do not deploy it to the public internet.** Authorized testing only.

SPRKL is a deliberately vulnerable web app themed as the storefront
for a sparkling-water brand. The twist that makes it a *benchmark*: a **separate
scorer** decides when a vulnerability is genuinely exploited and records it as ground
truth. Testers/agents **cannot self-report**, and — unlike Juice Shop — the scoring
logic, the findings catalog and the answer key do not live in the attackable app.

- **95 live findings** across **11 vulnerability families**, difficulty 1–6.
- Three tiers: unauthenticated storefront, retail customer accounts, corporate/admin.
- Full catalog + difficulty + category + OWASP/CWE mappings live in
  [`findings.yaml`](findings.yaml) — the single source of truth, **scorer-side only**.

## Architecture: two containers, one boundary

```
   tester ──HTTP──▶  scorer :8080  (ingress proxy)  ──▶  app :8081
                       │  observes every request/response, injects X-Request-Id
                       │  owns: rules, findings catalog, solve store, OAST collector
                       ▼
                     app reports what it did over a ONE-WAY unix socket ──▶ scorer
```

The attacker points tools at **`localhost:8080`** and it behaves like an
ordinary web app — the proxy is transparent. What changed is everything *behind*
8080:

- **The app** (`app/`) contains no findings catalog, no scoring rules, no scoring
  key and no solve store. It runs unprivileged, on an internal-only network with
  **no route to the internet** except back through the scorer. It emits neutral
  "taps" (`sql.exec`, `fs.read`, `tmpl.render`, `auth.result`, …) describing what
  it did — never a verdict.
- **The scorer** (`scorer/`) is the ingress proxy the tester talks to. It holds the
  rules (`scorer/rules.py`), the catalog (`findings.yaml`), and the solve store, and
  it joins each proxy-observed request with the app's taps to decide what counts.

So a file-read or RCE in the app yields *source code with a bug in it*, not an
annotated answer key: the ids, rules, catalog and key are all in the other
container.

### Evidence classes & provenance

Every finding is credited by one of two kinds of evidence, and the class is
**derived from the rule**, not hand-maintained:

| Class | Observed by | Forgeable by a compromised app? |
|---|---|---|
| **proxy-observed** | the scorer's ingress proxy (+ OAST collector) | No |
| **app-reported** | the app's taps | Only after RCE, and each tap must attach to a request the proxy actually saw |

The score API reports a **blackbox** count (solved before the tester gained any
source-read/RCE capability) separately from **post-capability** solves, plus
time-to-first-capability.

## Run it

```bash
docker compose up --build
# storefront (attack here): http://localhost:8080
# score API (host only):    http://localhost:9090   (X-Oracle-Key required)
```

### Reading the score

The score API is **always gated** by `X-Oracle-Key` (every route except
`/healthz`). The dev stack pins the key in `docker-compose.yml`; export
`SPRKL_ORACLE_KEY` to override, or leave it unset for a random per-run key that the
scorer prints and writes to `/runs/<run>/oracle-key.txt`.

```bash
KEY='X-Oracle-Key: sprkl-oracle-key-dev'
curl -s -H "$KEY" localhost:9090/oracle/score              # blackbox vs post-capability, by family
curl -s -H "$KEY" localhost:9090/oracle/solves             # ground-truth solve events
curl -s -H "$KEY" localhost:9090/oracle/findings           # catalog (ids/meta, no exploit steps)
curl -s -H "$KEY" localhost:9090/oracle/evidence-classes   # per-finding capability/prereq
curl -s -H "$KEY" localhost:9090/oracle/transcript         # record counts, quarantined taps
curl -s -H "$KEY" -X POST localhost:9090/oracle/reset       # fresh benchmark run
```

### Local (no Docker)

`scorer.harness.Harness` brings the whole stack up in-process (app subprocess +
proxy + scorer) — this is what the tests drive:

```bash
python3 -m venv .venv && ./.venv/bin/pip install -r requirements.txt
./.venv/bin/python -m tests.sweep     # one real exploit per finding; prints coverage
```

The app also runs standalone for debugging, generating its own run spec:

```bash
SPRKL_STANDALONE=1 ./.venv/bin/python serve.py   # storefront on :8081, no scorer
```

## Per-run randomization

The scorer generates each run's secrets and hands the app only values — never
meaning. No two runs share a JWT secret, canary token, MAC key or PRNG seed, so a
leaked cheatsheet does not transfer between runs. The **property** is preserved
even as the value changes: the JWT secret is drawn from a wordlist so
`jwt-weak-secret` stays crackable.

## Security properties

Holds even against full RCE in the app:

- the app image carries no `findings.yaml`, no `scorer/`, no rules, no scoring key;
- the app cannot mark anything solved (no such endpoint; solves are derived scorer-side);
- the app has no internet egress (internal-only Docker network);
- a forged tap is quarantined unless it attaches to a request the proxy observed.
- scorer oracle on port 9090 is gated by `X-Oracle-Key`

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [`NOTICE`](NOTICE).
Copyright 2026 Mason Jones.

SPRKL is intentionally vulnerable and is for authorized security training and
benchmarking only — do not deploy it to the public internet.
