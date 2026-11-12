# Login Pattern Radar

A browser-based dashboard for exploring login activity, investigating unusual sign-ins, and scanning local files for suspicious patterns.

## Getting started

Install Node.js 24 and pnpm 10.34.9, then run:

```sh
pnpm install --frozen-lockfile
pnpm --filter @workspace/login-pattern-radar run dev
```

Open [http://localhost:5173](http://localhost:5173). Set `PORT` and `BASE_PATH` before starting Vite if you need different values; they default to `5173` and `/`.

To check or build the application:

```sh
pnpm --filter @workspace/login-pattern-radar run typecheck
pnpm --filter @workspace/login-pattern-radar run build
```

The production files are written to `artifacts/login-pattern-radar/dist/public`. Configure your web server to serve `index.html` for application routes.

## Using the application

- **Overview:** review summary metrics and unusual logins.
- **Activity:** search and filter login events and inspect their signals.
- **Test a login:** score a hypothetical sign-in against the current dataset.
- **Scan files:** inspect multiple files for suspicious text patterns, risky file types, secrets, and login anomalies. Supported login logs include CSV, JSON/JSONL, Linux SSH auth logs, and Windows Security CSV exports.

Login CSVs use `user_id`, `timestamp`, `location`, and `success` columns. The import and scanner also recognize some common alternatives. CSV login imports are limited to 50,000 rows. The scanner rejects files over 100 MB and scans only the first 20 MB of larger accepted files. Classic syslog timestamps without a year are interpreted using the current year.

Scanning is pattern-based, not antivirus: findings can be false positives, and a file without findings is not necessarily safe. Archive contents are not recursively scanned. Login anomaly scores are signals for review, not proof of compromise.

File scanning and login analysis run in the browser. Imported login events and model settings may be saved in browser local storage; use a trusted device for sensitive data. The page loads fonts from Google Fonts.

## Repository

- `artifacts/login-pattern-radar/`: frontend and browser-based analysis.
- `artifacts/api-server/`: optional Express API; the frontend does not use it.
- `artifacts/mockup-sandbox/`: component preview application.
- `lib/`: shared API and database packages.

Run `pnpm run typecheck` to typecheck the workspace or `pnpm run build` to build it. Database operations require a PostgreSQL `DATABASE_URL`; they are not required to run the frontend.
