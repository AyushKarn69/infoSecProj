FROM node:22-alpine AS dashboard-build
WORKDIR /app/apps/dashboard
COPY apps/dashboard/package.json apps/dashboard/package-lock.json ./
RUN npm ci
COPY apps/dashboard/ ./
ENV NEXT_PUBLIC_API_URL=http://localhost:8000
RUN npm run build

FROM python:3.13-slim AS riskshare
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md ./
COPY alembic.ini ./
COPY core/ ./core/
COPY services/ ./services/
COPY migrations/ ./migrations/
COPY apps/ ./apps/
COPY scripts/ ./scripts/
RUN python -m pip install --no-cache-dir .
COPY --from=dashboard-build /app/apps/dashboard/out ./apps/dashboard/out
EXPOSE 8000 8443
