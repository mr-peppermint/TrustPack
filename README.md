# TrustPack

TrustPack is a frontend prototype for reviewing the integrity of published packages against their source repositories. It presents package comparisons, risk findings, file-level changes, and provenance details in a dashboard-style web app.

The current project is a React frontend. It defaults to sample data and includes an optional HTTP API integration point; package comparison, provenance verification, and AI analysis are not implemented in this repository. The hackathon proposal and team/model details are in [HACKATHON.md](HACKATHON.md).

## Current features

- Dashboard with analysis totals and recent results.
- Analysis form for npm package name, version, and HTTPS source repository URL.
- Result view with risk score, findings, explanation, file changes, and provenance fields.
- Searchable and filterable analysis history. The sample history includes npm and PyPI records.
- Dark, light, and system theme preferences.
- Mock analysis and result data for exploring the interface without a backend.
- Configurable HTTP endpoints for connecting a backend.

## Requirements

- Node.js with npm

## Run locally

```sh
npm install
npm run dev
```

Vite prints the local development URL in the terminal. To create and serve a production build:

```sh
npm run build
npm run preview
```

## Backend configuration

Mock mode is enabled by default. To use the HTTP API, add a `.env.local` file in the project root:

```dotenv
VITE_USE_MOCK=false
VITE_API_BASE_URL=http://localhost:3000/api
VITE_ENDPOINT_START_ANALYSIS=/analyses
VITE_ENDPOINT_GET_RESULT=/analyses/{id}
VITE_ENDPOINT_HISTORY=/analyses
```

The frontend expects these JSON responses:

- `POST /analyses` (or the configured start endpoint), with `{ "ecosystem": "npm", "name": "...", "version": "...", "repoUrl": "..." }`; response: `{ "id": "..." }`.
- `GET /analyses/{id}` (or the configured result endpoint); response: an `AnalysisResult` object.
- `GET /analyses` (or the configured history endpoint); response: an array of `AnalysisSummary` objects.

See [src/types/analysis.ts](src/types/analysis.ts) for the response shapes. The API must allow browser requests from the frontend origin. Values prefixed with `VITE_` are exposed in the browser bundle, so do not put secrets in them.

## App routes

| Path | Page |
| --- | --- |
| `/` | About TrustPack |
| `/dashboard` | Analysis overview |
| `/new` | Start an analysis |
| `/analysis/:id` | Analysis result |
| `/history` | Search and filter past analyses |
| `/settings` | Theme and app configuration |

## Project layout

```text
src/
  components/   Shared layout, analysis, dashboard, and About page UI
  data/         In-memory mock analysis data and mock API behavior
  hooks/        Theme and analysis data hooks
  lib/          Formatting helpers
  pages/        App pages
  routes/       React Router configuration
  services/     Mock/HTTP analysis service boundary
  types/        Analysis request and response types
```

## Tech stack

- React 18 and TypeScript
- Vite
- React Router
- Tailwind CSS
- Lucide icons

## Current limitations

- New mock submissions create an in-memory history entry; data resets when the app reloads.
- Mock risk outcomes are illustrative and are not computed from package contents.
- The submission form currently supports npm only. PyPI appears in sample history and the shared types, but is disabled in the form.
- There is no backend, registry/repository fetcher, source-to-package comparison engine, signature verifier, or model inference client in this repository.

## License

See [LICENSE](LICENSE).
