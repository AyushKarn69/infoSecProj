# Implementation roadmap

Milestones are sequenced so the mathematics is established before service integration.

1. **Research and architecture (current):** inspect repository and available references; document threat boundaries, architecture, research foundation, and limitations.
2. **ABSS-I foundation (current):** implement parameter generation/validation, sharing, CRT reconstruction; exercise subset correctness and invalid input behavior.
3. **ABSS-I traceability:** implement TTSS-I black-box tracing and verification only after the paper's oracle and parameter conventions are represented explicitly.
4. **ABSS-II / TTSS-II:** select and validate a concrete prime-order group with order exceeding residue moduli; implement tracing and public verification; assess non-imputability assumptions. Do not label a toy group secure.
5. **Core services:** AES-GCM object encryption, isolated worker boundary, vault/epoch models, explainable risk engine, quorum policy, and hash-chained audit.
6. **Node plane:** five separate node-agent processes and volumes, authenticated/replay-resistant release authorization, signed responses, health monitoring, and fail-closed recovery orchestration.
7. **Control API and persistence:** FastAPI, SQLAlchemy/Alembic, PostgreSQL, Redis Streams, authentication/authorization, rate limiting, idempotency, and WebSockets.
8. **Dashboard and simulation:** Next.js Control Room wired to real API data; attack and trace labs visibly distinguish simulation from measured cryptographic behavior.
9. **Evaluation and hardening:** reproducible experiments, collected CSV/JSON data, threat-model review, integration/security tests, setup docs, and known-limitations review.

Each milestone updates `implementation-status.md`. Do not claim completion of distributed security or research properties based on unit tests alone.
