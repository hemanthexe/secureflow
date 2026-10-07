# SecureFlow

SecureFlow is a production-oriented security platform monorepo: an API accepts repositories,
queues asynchronous scans, workers execute SAST/secret/dependency/IaC/Docker/Kubernetes checks,
and a web dashboard/CLI consumes findings, scores, SARIF and policy gates.

## Quick start

```bash
corepack enable
pnpm install
cp .env.example .env
docker compose up -d postgres redis
pnpm db:push
pnpm seed
pnpm dev
```

The scanner engine and tests work without Postgres or Redis. The API returns a clear `503`
dependency error when either service is unavailable. Demo scan:

```bash
pnpm --filter @secureflow/cli dev scan .
pnpm test
```

## GitHub creation commands

If `gh` is unavailable, create the repository in the GitHub web UI, then run:

```bash
git init
git add .
git commit -m "chore: initialize SecureFlow monorepo" \
  -m "Co-authored-by: Copilot App <223556219+Copilot@users.noreply.github.com>"
git branch -M main
git remote add origin https://github.com/ORG/secureflow.git
git push -u origin main
```

With GitHub CLI:

```bash
gh repo create ORG/secureflow --private --source . --remote origin --push
```

## Architecture

`packages/shared` contains contracts and deterministic hashing; `packages/scanners` has safe,
offline scanners; `packages/risk` computes severity-weighted scores; `packages/policy` evaluates
gates. `apps/api` is Fastify + Prisma, `apps/worker` is BullMQ, `apps/web` is Vite React, and
`apps/cli` provides local/SARIF workflows. Authentication is JWT-ready, with RBAC roles
`admin`, `analyst`, and `viewer`; production deployments should put the API behind TLS and rotate
`JWT_SECRET`.
