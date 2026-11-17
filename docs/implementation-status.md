# Implementation status

Updated: 2026-11-13

## Implemented

- ABSS-I and ABSS-II sharing/reconstruction prototypes, CRT reconstruction,
  CSPRNG-backed parameter selection, and Hypothesis subset reconstruction
  properties.
- TTSS-I and TTSS-II trace/verify prototypes with bounded black-box tracing.
  TTSS-II uses standardized P-384/P-521 groups via PyCA/OpenSSL.
- AES-256-GCM vault payload encryption; vault, epoch, and version are bound as
  AAD, and DEKs retain fixed-width serialization when converted to integers.
- Risk scoring, adaptive 2/3/4-of-5 policy, fresh epoch rotation, node stores,
  fail-closed recovery during failed transitions, operator/admin approval,
  signed node responses, HMAC-authenticated replay-protected node requests,
  and a database-backed hash-chain audit log.
- FastAPI API and Next.js Control Room for vaults, nodes, risks, recovery,
  attack simulation, trace investigations, audit, configuration, and events.
- SQLAlchemy schema and Alembic migration. Compose defines PostgreSQL, Redis
  Streams, five isolated node containers/volumes, mTLS node transport, and the
  control API. Local mode remains process-local with five separate SQLite node
  files.
- Experiment runner and checked-in results for fixed and adaptive policies.
  Results are documented as scenario measurements rather than security
  probabilities or guarantees.

## Verification performed

- `python -m pytest tests -q`: 34 passed (one upstream Starlette/httpx deprecation
  warning). Coverage includes ABSS properties,
  crypto unit behavior, API recovery/rotation flows, node authorization,
  offline-node failure handling, tracing, audit verification, and certificate
  generation.
- `ruff check core services tests migrations scripts`: passed after the latest
  formatting fixes.
- `mypy core services`: passed after the latest typing fixes.
- `npm run build` in `apps/dashboard`: passed with static export at
  `/control-room`.
- The five-trial script generated 500 scenario rows and CSV/JSON/SVG outputs.
- Compose YAML parsed successfully, and the development certificate generator
  was exercised. Docker itself is not installed in this workspace, so the
  multi-container stack was not started or end-to-end verified.

## Remaining before claiming complete

- Docker deployment needs execution on a Docker-enabled host. Its mTLS
  configuration and separate containers exist, but successful startup,
  restart persistence, and actual cross-container operations are unverified.
- Redis Streams publication is enabled when `RISKSHARE_REDIS_URL` is set and
  included in Compose, but was not exercised against a Redis server here. The
  stream append behavior is covered with a client stub; current WebSocket
  fanout remains process-local.
- Recovery reconstruction still runs in the control API process. A separately
  sandboxed reconstruction worker and separate tracing service with durable,
  protected tracing-key custody are not implemented.
- Local auth rate limiting and token revocation are process-local. Audit chains
  lack external signed checkpoints. ABSS residues are not independently
  authenticated, and prototype trace logic needs independent cryptographic
  review.
- No formal proof, independent security review, production operations
  hardening, or concurrency/performance study has been completed.
- The Shamir 1979 and Forouzan PDFs named in the project brief were unavailable
  in the workspace; only the Leslie-Dutta paper and project concept document
  were reviewed.

This is a working academic research prototype, not a production key-management
system. Do not use it to protect production secrets.
