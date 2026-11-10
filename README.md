# TrustPack

TrustPack checks whether a package published to a supported package registry actually matches the source
repository it claims to come from. Supported ecosystems include npm, PyPI, Maven Central, NuGet, crates.io,
Go modules, RubyGems, Packagist, pub.dev, Hex, CocoaPods, SwiftPM GitHub releases, Conda-forge, selected
Linux distributions, and public Docker Hub images. Paste a GitHub repository or directory URL to detect
package manifests and autofill package candidates. TrustPack downloads the published artifact and matching source revision,
compares every file by SHA-256, checks registry integrity/provenance, and returns an evidence-based
verdict (`VERIFIED` / `WARNING` / `HIGH_RISK`) — never a bare "safe" or "unsafe". An optional AI step can
explain that verdict in plain language, but it never computes or changes it.

The project has two halves in this repo:

- **`src/`** — the React + TypeScript frontend (forms, risk summary, file-diff viewer, history).
- **`backend/`** — the FastAPI backend that does the actual download/compare/score work.

## Installation

Requires **Node.js 18+** and **Python 3.9+**.

```bash
git clone <this repo's URL>
cd TrustPack

# Frontend dependencies
npm install

# Backend dependencies
cd backend
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
cd ..
```

## Running the backend server

```bash
cd backend
source .venv/bin/activate          # if not already active
python -m uvicorn app.main:app --reload --port 8000
```

- Health check: `curl localhost:8000/health` → `{"status":"ok"}`
- Swagger UI: http://127.0.0.1:8000/docs
- Analysis history is stored in `backend/data/trustpack.db` (SQLite, created automatically).
- **Add your GitHub personal access token to `backend/.env`:**
  ```env
  GITHUB_TOKEN=<your GitHub PAT>
  ```
  Without it, GitHub allows only 60 API calls/hour; with a token, 5000/hour. Create one at
  [github.com/settings/tokens](https://github.com/settings/tokens) — a classic token with no scopes
  selected (public read access) is enough. Never commit this file; `backend/.env` is gitignored.

## Running the frontend

In a second terminal, from the repo root:

```bash
npm run dev
```

By default it talks to the backend at `http://localhost:8000` (`.env.local` already sets
`VITE_API_BASE_URL`). Open the URL it prints, go to **New Analysis**, select an ecosystem, or paste a
GitHub repository/directory URL to scan package manifests and autofill a detected package.

## Enabling the AI agent

The deterministic analysis above is complete and correct without this — AI only adds a plain-language
explanation of a result that's already been computed. It's off by default.

1. Get an API key from your AI provider. This project is already wired up for **OpenAI**
   (`AI_PROVIDER=openai`); Groq, OpenRouter, Together, Fireworks, or any OpenAI-compatible server also
   work by changing `AI_PROVIDER`/`AI_MODEL`/`AI_BASE_URL`.
2. In `backend/.env`, set:
   ```env
   AI_ENABLED=true
   AI_PROVIDER=openai
   AI_MODEL=gpt-4o-mini
   AI_API_KEY=<your OpenAI key>
   ```
3. Restart the backend server (`--reload` watches `.py` files, not `.env` — you need a real restart, not
   just a save). Every analysis response now includes a populated `ai_explanation` field.

If `AI_API_KEY` is wrong or the provider rejects it, the analysis still completes — `ai_explanation` just
reports `"status": "unavailable"` with the reason, instead of failing the whole request.
