# Login Pattern Radar

A browser-based dashboard for exploring login activity, investigating unusual sign-ins, and scanning local files for suspicious patterns.

## Getting started

Install Node.js 24 and pnpm 10.34.9, then run:

```sh
pnpm install --frozen-lockfile
pnpm --filter @workspace/login-pattern-radar run dev
```

Open [http://localhost:5173](http://localhost:5173). Set `PORT` and `BASE_PATH` before starting Vite if you need different values; they default to `5173` and `/`.

The theme follows your system setting until you use the theme button in the top bar. Your choice is saved in browser local storage.

To check or build the application:

```sh
pnpm --filter @workspace/login-pattern-radar run typecheck
pnpm --filter @workspace/login-pattern-radar run build
pnpm --filter @workspace/scripts exec tsx --test tests/scanner.test.ts
```

The production files are written to `artifacts/login-pattern-radar/dist/public`. Configure your web server to serve `index.html` for application routes.

## Deploy manually to Netlify

1. Run the frontend build command above.
2. In Netlify, open the **existing site** and its **Deploys** page.
3. Drag `artifacts/login-pattern-radar/dist/public` into the manual deployment area, or upload a ZIP containing that folder's contents.
4. Wait for the deployment to publish. Verify the home page's inline **Upload a file** panel and open `/scan` directly.

The build includes a `_redirects` file so refreshing client-side routes works on Netlify. Upload the built files, not the source repository. Deploy to the existing site to keep its URL.

## Deploy to Render

The root `render.yaml` configures a static site, including the build command and client-side routing fallback. No API server, database, or application secrets are required.

1. Sign in to [Render](https://dashboard.render.com/) and select **New > Blueprint**.
2. Connect your GitHub account and grant Render access to `ferngueva07/V`.
3. Select that repository and the `main` branch, then review and apply the Blueprint.
4. Wait for the build to finish and open the site's assigned `onrender.com` URL. Check `/activity`, `/test`, and `/scan` directly as well as the home page.

Render assigns the live URL after creating the site. Subsequent pushes to the connected branch can redeploy it automatically. Check the service settings and pricing before confirming deployment.

## Using the application

- **Overview:** review summary metrics and unusual logins.
- **Inline upload:** choose or drop files directly into the overview's upload panel. Supported login histories update the dashboard without leaving the page; other files keep the existing dataset. Use **View scan report** for per-file findings and coverage.
- **Activity:** search and filter login events and inspect their signals.
- **Test a login:** score a hypothetical sign-in against the current dataset.
- **Scan files:** inspect multiple files for suspicious text patterns, risky file types, secrets, and login anomalies. Supported login logs include CSV, JSON/JSONL, Linux SSH auth logs, and Windows Security CSV exports.

Login CSVs use `user_id`, `timestamp`, `location`, and `success` columns. The import and scanner also recognize some common alternatives. CSV login imports are limited to 50,000 rows. The scanner accepts files of any type or size, but reads only the first 20 MiB of each; it reports partial scans and does not calculate a full-file hash for them. Login parsing is also capped at 50,000 records per file. Classic syslog timestamps without a year are interpreted using the current year.

Scanning is pattern-based, not antivirus: findings can be false positives, and a file without findings is not necessarily safe. Archive contents are not unpacked and binary formats are not fully analyzed. The login model ranks successful logins using four signals and a dataset-relative threshold; tied scores can flag more events than the selected percentage. It is not independently validated on real-world labeled data. Treat scores as review leads, not proof of compromise.

File scanning and login analysis run in the browser. Imported login events and model settings may be saved in browser local storage; use a trusted device for sensitive data. The page loads fonts from Google Fonts.

## Repository

- `artifacts/login-pattern-radar/`: frontend and browser-based analysis.
- `artifacts/api-server/`: optional Express API; the frontend does not use it.
- `artifacts/mockup-sandbox/`: component preview application.
- `lib/`: shared API and database packages.

Run `pnpm run typecheck` to typecheck the workspace or `pnpm run build` to build it. Database operations require a PostgreSQL `DATABASE_URL`; they are not required to run the frontend.
