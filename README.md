# TrustPack

[![CI](https://github.com/mr-peppermint/TrustPack/actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**TrustPack answers one question: does a package published to npm or PyPI actually correspond to the
source repository it claims to come from?**

It downloads the published artifact and the matching source revision, compares them file-by-file by
SHA-256, classifies every difference, checks registry integrity and provenance, and returns an
evidence-based verdict — never a bare "safe"/"unsafe". A deterministic risk engine computes that verdict;
an optional AI step can explain it in plain language, but cannot change it.

This repository contains both halves of the app:

| | |
|---|---|
| **`src/`** | React + TypeScript frontend — forms, risk summary, file-diff viewer, history |
| **`backend/`** | FastAPI service — registry/GitHub integration, archive comparison, risk scoring, optional Supabase cache and AI explanations |

For anything specific to one half, see **[backend/README.md](backend/README.md)** (architecture diagram,
risk model, full API reference, security model, Supabase cache setup, running across devices on a LAN) —
this file is the project-wide overview and quickstart.

## Contents

1. [Quickstart](#quickstart)
2. [Sample inputs and outputs](#sample-inputs-and-outputs)
3. [Features](#features)
4. [Configuration](#configuration)
5. [Routes (frontend)](#routes-frontend)
6. [Project layout](#project-layout)
7. [Testing and CI](#testing-and-ci)
8. [Contributing](#contributing)
9. [Stack](#stack)
10. [License](#license)

## Quickstart

Requires **Node.js 18+** and **Python 3.9+**. Run the backend and frontend in two terminals.

```bash
# Terminal 1 — backend (FastAPI, port 8000)
cd backend
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env            # edit if needed; works with every default off
python -m uvicorn app.main:app --reload --port 8000
```

```bash
# Terminal 2 — frontend (Vite, port 5173)
npm install
cp .env.example .env.local      # VITE_USE_MOCK=false, VITE_API_BASE_URL=http://localhost:8000
npm run dev
```

Open the printed `http://localhost:5173` URL, go to **New Analysis**, and submit an npm or PyPI package
with its source repository URL.

Without a `.env.local` (or with `VITE_USE_MOCK=true`), the frontend runs entirely on built-in mock data —
useful for UI work with no backend running at all.

Running the backend and frontend on **different physical devices** on the same network? See
[backend/README.md § Running across devices on a LAN](backend/README.md#running-across-devices-on-a-lan).
Want either one reachable from the internet, not just your own network? See
[backend/README.md § Deploying to the internet](backend/README.md#deploying-to-the-internet) —
[render.yaml](render.yaml) deploys the backend as a Render Blueprint; the frontend deploys separately to
any static host (Vercel, Netlify, ...).

## Sample inputs and outputs

These are real responses from a running backend (`POST /api/analyze`), lightly trimmed for length. Full
field reference: [backend/README.md § API](backend/README.md#api).

### 1. Clean match — npm, exact commit

```json
// Request
POST /api/analyze
{ "package_name": "is-odd", "version": "3.0.1",
  "repository_url": "https://github.com/jonschlinkert/is-odd" }
```
```json
// Response (200) — abbreviated
{
  "package": { "name": "is-odd", "version": "3.0.1", "ecosystem": "npm" },
  "source": {
    "repository": "https://github.com/jonschlinkert/is-odd",
    "commit": "a80ee0d831a8ee69f1fad5b4673491847975eb26",
    "resolution_method": "gitHead", "correspondence": "EXACT", "confidence": "HIGH"
  },
  "summary": { "identical": 4, "modified": 0, "added": 0, "removed": 8, "unexplained": 0 },
  "risk": { "verdict": "VERIFIED", "level": "LOW", "score": 0, "confidence": "HIGH" },
  "findings": [],
  "analysis_complete": true
}
```
The registry's own `gitHead` metadata points at a commit that exists in the repo, so correspondence is
`EXACT`. `removed: 8` is expected here — the repo has dev files (tests, configs) that npm's `files`
allowlist excludes from the published tarball; TrustPack's generated/expected-file detector accounts for
this and it doesn't raise the risk score.

### 2. No verifiable source — npm, inconclusive

```json
// Request
POST /api/analyze
{ "package_name": "left-pad", "version": "1.3.0" }   // no repository_url supplied
```
```json
// Response (200) — abbreviated
{
  "package": { "name": "left-pad", "version": "1.3.0", "ecosystem": "npm" },
  "source": { "repository": null, "commit": null, "correspondence": "NONE" },
  "risk": {
    "verdict": "WARNING", "level": "INCONCLUSIVE", "score": null, "confidence": "LOW",
    "rationale": [
      "Source correspondence could not be established (no matching gitHead or tag), so a comparison-based verdict would be misleading. Independent script/pattern findings, if any, were still evaluated."
    ]
  },
  "analysis_complete": true
}
```
No repository was supplied and the registry metadata had nothing to resolve one from, so no file
comparison could run at all. TrustPack reports this plainly as `INCONCLUSIVE` rather than guessing.

### 3. Inferred source — PyPI, warning from a static finding

```json
// Request
POST /api/analyze
{ "package_name": "requests", "version": "2.32.3", "ecosystem": "PyPI",
  "repository_url": "https://github.com/psf/requests" }
```
```json
// Response (200) — abbreviated
{
  "package": { "name": "requests", "version": "2.32.3", "ecosystem": "PyPI" },
  "source": {
    "repository": "https://github.com/psf/requests", "resolution_method": "tag",
    "correspondence": "INFERRED", "confidence": "MEDIUM",
    "notes": ["Matched version tag 'v2.32.3'. A tag name is a convention, not proof that the published artifact was built from it."]
  },
  "summary": { "identical": 66, "modified": 0, "added": 10, "removed": 62, "unexplained": 0 },
  "findings": [
    { "rule_id": "INSTALL_SCRIPT_EXEC", "file": "setup.py", "severity": "LOW",
      "evidence": "setup.py contains process execution inside custom install commands." }
  ],
  "risk": { "verdict": "WARNING", "level": "MEDIUM", "score": 11, "confidence": "MEDIUM" },
  "limitations": ["2 symlink(s) in the repository were not extracted and not compared: ..."],
  "analysis_complete": true
}
```
No commit was published with the release, so the repository match comes from a version tag — weaker
evidence than an exact commit, hence `INFERRED` and a lower confidence. The 66 identical files pass
file-by-file comparison; the `WARNING` comes entirely from the static `setup.py` finding, not from any
file difference.

### 4. Tampered package — high risk

Trimmed from [`backend/sample_report.json`](backend/sample_report.json), a synthetic example showing an
unexplained added/removed file pair alongside a lifecycle-script finding:

```json
{
  "package": { "name": "chart-utils", "version": "2.4.0" },
  "source": { "correspondence": "EXACT", "resolution_method": "gitHead" },
  "summary": { "identical": 1, "modified": 0, "added": 1, "removed": 1, "unexplained": 2 },
  "findings": [
    { "rule_id": "LIFECYCLE_SCRIPT_PRESENT", "file": "package.json", "severity": "HIGH" }
  ],
  "risk": { "level": "HIGH", "score": 44 }
}
```

### 5. Unknown package — error response

```json
// Request
POST /api/analyze
{ "package_name": "totally-fake-pkg-xyz-12345", "version": "1.0.0" }
```
```json
// Response (404)
{ "error": { "code": "package_not_found",
             "message": "Package 'totally-fake-pkg-xyz-12345' was not found on the npm registry" } }
```
Every error follows `{"error": {"code", "message"}}`; validation errors additionally carry `details`.

## Features

- **npm and PyPI** packages, each resolved against their own registry and matched to a GitHub source
  repository by `gitHead`/tag.
- **Deterministic risk engine** — the verdict (`VERIFIED` / `WARNING` / `HIGH_RISK`) is computed from
  file-hash comparison and static-pattern findings alone; never softened or overridden.
- **Optional AI explanations** (GPT-OSS-120B via Groq, or any OpenAI-compatible provider) that narrate the
  deterministic result in prose. Fully optional; the analysis is complete without it. Grounded: the model
  can only cite findings that exist, and its claimed severities are overwritten with the real ones.
- **Optional shared analysis cache (Supabase)** — a given package version is immutable once published, so
  one finished analysis can answer every later request for it instead of re-downloading and re-scanning.
  See [backend/README.md § Shared analysis cache](backend/README.md#shared-analysis-cache-supabase).
- **Hardened archive handling** — path-traversal, symlink, zip-bomb, oversized-file and special-file
  protections before any byte of an attacker-controlled package is written to disk.
- Persistent analysis history (SQLite), a searchable/filterable history page, and a terms-and-conditions
  page linked from the landing page's footer.

## Configuration

Both halves are configured entirely through environment variables, never hardcoded. Full reference:
[backend/.env.example](backend/.env.example) (backend) and [.env.example](.env.example) (frontend).

| Where | Key variables | Purpose |
|---|---|---|
| Frontend | `VITE_USE_MOCK`, `VITE_API_BASE_URL` | mock mode vs. a real backend, and where it lives |
| Backend | `GITHUB_TOKEN` | raises the GitHub API rate limit from 60/hr to 5000/hr |
| Backend | `DATABASE_PATH` | SQLite analysis history (default `backend/data/trustpack.db`) |
| Backend | `AI_ENABLED`, `AI_PROVIDER`, `AI_MODEL`, `AI_API_KEY` | optional AI explanations — off by default |
| Backend | `SUPABASE_URL`, `SUPABASE_SERVICE_KEY` | optional shared analysis cache — off by default |
| Backend | `CORS_ORIGINS` | browser origins allowed to call the API (must list the deployed frontend's exact URL once public) |
| Backend | `RATE_LIMIT_PER_MINUTE` | per-IP throttle on starting an analysis (default 20/min); matters once the API is public |

Secrets (`GITHUB_TOKEN`, `AI_API_KEY`, `SUPABASE_SERVICE_KEY`) are server-side only, read from
`backend/.env` (gitignored), and never sent to the frontend.

## Routes (frontend)

| Path | Page |
|---|---|
| `/` | Landing / about (footer has the Terms and conditions link) |
| `/dashboard` | Overview and recent analyses |
| `/new` | Start an analysis (npm or PyPI) |
| `/analysis/:id` | Analysis result |
| `/history` | Search and filter past analyses |
| `/settings` | Theme and app info |
| `/terms` | Terms and conditions |

## Project layout

```text
src/                  React frontend
  components/         analysis/, about/, common/, dashboard/, layout/
  pages/               route pages (Dashboard, NewAnalysis, AnalysisResults, History, Settings, TermsPage, About)
  services/           mock/HTTP service boundary (src/services/analysisService.ts)
  types/               request/response types (src/types/analysis.ts)

backend/              FastAPI backend
  app/
    api/               routes.py (canonical + frontend-contract endpoints), frontend_adapter.py
    models/            request/response Pydantic models
    registries/        npm / PyPI registry clients
    services/          orchestrator, risk engine, comparator, archive extraction, report store,
                        analysis_cache (Supabase), ai_explainer, source_resolver, ...
    utils/             hardened archive extraction, SSRF-safe HTTP, logging
  tests/               pytest suite (respx-mocked HTTP, no real network calls)
  supabase/schema.sql  shared-cache table definition
```

## Testing and CI

```bash
cd backend && python -m pytest        # backend: no network access required, everything is mocked
npm run build                         # frontend: tsc --noEmit, then the production build
```

[.github/workflows/ci.yml](.github/workflows/ci.yml) runs both on every push and pull request against
`main`: the backend suite on Python 3.9 and 3.12, and the frontend type-check + build on Node 20.

## Contributing

Pull requests use [.github/PULL_REQUEST_TEMPLATE.md](.github/PULL_REQUEST_TEMPLATE.md) — it asks what
changed, how it was tested, and whether docs/tests were updated. CI must pass (see above) before merging.
Never commit secrets: `.env` files are gitignored; double-check `git status` before pushing if you've been
editing them.

## Stack

**Frontend:** React 18, TypeScript, Vite 5, React Router 6, Tailwind CSS 3, lucide-react.
**Backend:** FastAPI, Pydantic v2, httpx, SQLite (stdlib `sqlite3`), pytest + respx for testing.

## License

Apache License 2.0 — see [LICENSE](LICENSE). Built for Hacktoberfest 2026 Hack Day Sonipat by team *The
Debugger* (see [HACKATHON.md](HACKATHON.md)).
