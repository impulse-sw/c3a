FROM archlinux:latest AS runner
WORKDIR /app
COPY artifacts/c3a-worker.yaml c3a-worker.yaml
COPY artifacts/c3a-worker c3a-worker
COPY artifacts/c3a-frontend c3a-frontend
