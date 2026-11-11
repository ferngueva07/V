# Login Pattern Radar

Browser-based workspace for reviewing sign-in activity and exploring explainable login-anomaly signals.

## Run & Operate

- `pnpm --filter @workspace/api-server run dev` — run the API server (port 5000)
- `pnpm --filter @workspace/login-pattern-radar run dev` — run the Login Pattern Radar website
- `pnpm --filter @workspace/login-pattern-radar run typecheck` — typecheck the website
- `pnpm run typecheck` — full typecheck across all packages
- `pnpm run build` — typecheck + build all packages
- `pnpm --filter @workspace/api-spec run codegen` — regenerate API hooks and Zod schemas from the OpenAPI spec
- `pnpm --filter @workspace/db run push` — push DB schema changes (dev only)
- Required env: `DATABASE_URL` — Postgres connection string

## Stack

- pnpm workspaces, Node.js 24, TypeScript 5.9
- API: Express 5
- Frontend: React, Vite, Wouter, Tailwind CSS
- DB: PostgreSQL + Drizzle ORM
- Validation: Zod (`zod/v4`), `drizzle-zod`
- API codegen: Orval (from OpenAPI spec)
- Build: esbuild (CJS bundle)

## Where things live

- `artifacts/login-pattern-radar/src/App.tsx` — website routes, dashboard state, and interactions
- `artifacts/login-pattern-radar/src/index.css` — website theme and responsive styling
- `artifacts/login-pattern-radar/src/lib/anomaly/` — login-event parsing, sample generation, feature extraction, and scoring
- `lib/api-spec/openapi.yaml` — shared API contract (the current website does not use it)

## Architecture decisions

- Login analysis runs in the browser using the uploaded project's anomaly-scoring pipeline.
- Imported events and model settings are saved in the current browser's local storage; there is no shared server-side dataset yet.
- Generated sample events are clearly identified as sample data, not a live sign-in feed.

## Product

- `/` — overview of the current analysis and model controls
- `/activity` — searchable event history with signal-by-signal explanations
- `/test` — score a hypothetical sign-in against a selected user's history
- CSV import/export and demo reset are available from the shared workspace shell.

## User preferences

No persistent user preferences recorded.

## Gotchas

- CSV imports must include `user_id`, `timestamp`, `location`, and `success` columns; files are limited to 50,000 rows.
- The website currently has no user accounts, live log ingestion, or cross-device persistence.

## Pointers

- See the `pnpm-workspace` skill for workspace structure, TypeScript setup, and package details
