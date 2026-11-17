# RiskShare

RiskShare is a research prototype for risk-adaptive threshold secret sharing. Its intended extension is to respond to elevated risk by creating a fresh cryptographic epoch at a stricter threshold; it does not relabel an existing share set.

## Current state

The repository includes ABSS-I/II sharing and reconstruction, TTSS-I/II tracing prototypes, AES-256-GCM helpers, explainable risk scoring, quorum policy state, a hash-chained audit log, a FastAPI control plane, five independent local SQLite share stores, and a Next.js Control Room wired to the API. The local workflow covers encrypted vault initialization, 2/3/4-of-5 epoch rotation, recovery approval, attack simulation, trace investigations, node status, and audit verification. Optional Redis Streams persistence is enabled by `RISKSHARE_REDIS_URL`; Compose configures it.

This remains a research demonstrator, not a production key-management system. Local mode runs five node agents inside the control API process, though each uses a separate SQLite file. Compose defines separate node containers with mTLS and persistent volumes, but Docker is unavailable in this workspace, so that deployment has not been executed here. Redis publication and persistent stream configuration are implemented but were not exercised against a live Redis server here. ABSS residues do not authenticate themselves; the tracing context is memory-only; and the audit chain has no external signed checkpoint. Recovery reconstruction remains inside the API process. Rate limiting and token revocation are process-local. Do not protect production secrets with this build.

## Run the cryptography tests

Python 3.11 or newer is required. Install the package and development tools in the active environment, then run:

```powershell
python -m pip install -e ".[dev]"
python -m pytest tests -q
```

## Run locally

1. Copy `.env.example` to `.env` and set distinct random secrets and passwords.
2. Start the API from the repository root: `python -m uvicorn services.control_api.app:app --env-file .env --reload --port 8000`.
3. In another terminal, build and serve the dashboard: `cd apps/dashboard`, `npm install`, `npm run build`, then return to the root and open `http://localhost:8000/control-room`.
4. Sign in as `operator` to create a recovery request and as a separate `admin` to approve it. Local development defaults are shown on the sign-in page and must be changed before use outside a private workstation.

Dashboard dependencies are pinned by `apps/dashboard/package-lock.json`. Python dependencies are resolved in `pylock.toml` for the current Python/platform using pip's experimental lock command; regenerate and review it when changing the supported platform or dependency set.

## Multi-container deployment

Set the required passwords/secrets in `.env`, generate development-only certificates with `python scripts/generate_dev_certs.py`, then run `docker compose -f infrastructure/compose.yaml up --build`. The node services require client certificates and verify HMAC-authenticated control requests. Development certificates are not for deployment outside the local demonstrator.

## Research and implementation notes

- [Research foundation](docs/research-foundation.md)
- [Architecture](docs/architecture.md)
- [Implementation roadmap](docs/implementation-roadmap.md)
- [Implementation status](docs/implementation-status.md)
- [Experiment results](docs/experiments/README.md)

The available reference documents are the Leslie–Dutta paper and the RiskShare project description. The referenced Shamir and Forouzan PDFs were not found in the workspace.
