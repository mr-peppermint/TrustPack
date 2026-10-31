# TrustPack Backend (PS04 — Published Package vs Source Code Integrity Analyzer)

FastAPI backend that analyzes whether a published npm package corresponds to its
claimed source repository, and surfaces evidence-based, explainable findings —
without ever claiming a package is malicious on the basis of a difference alone.

## What it actually does

1. Fetches exact-version metadata from the npm registry (never substitutes a
   different version).
2. Downloads the published tarball and verifies it against the registry's
   published integrity digest (SHA-512 SRI, falling back to legacy SHA-1 `shasum`).
3. Resolves the source repository (GitHub only, for the MVP) using strict
   priority: exact `gitHead` commit → matching version tag → unresolved
   (reported as `INCONCLUSIVE`, never guessed).
4. Safely extracts both archives into sandboxed temp directories (path
   traversal / symlink / size / count protections — see "Security model" below).
5. Builds SHA-256 file manifests for both sides and classifies every file as
   `IDENTICAL`, `MODIFIED`, `ADDED`, `REMOVED`, `EXPECTED_GENERATED`, or
   `UNEXPLAINED`.
6. Statically scans package scripts, dependencies, and published JS for
   known-suspicious patterns (lifecycle scripts, `eval`, `child_process`,
   base64 blobs, etc.) — framed explicitly as pattern matches, not proof.
7. Reports available provenance (npm sigstore attestations) separately from
   the baseline registry signature and from tarball integrity.
8. Computes an explainable risk level (`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`/`INCONCLUSIVE`)
   with a rationale, and returns everything as one structured JSON report.

## Project structure

```
backend/
  app/
    main.py                  FastAPI app, CORS, exception handlers
    config.py                All configuration (env-driven)
    api/routes.py             /health, /analyze, /report/{id}
    services/
      npm_registry.py         npm registry metadata fetch
      package_downloader.py   tarball download + integrity verification
      source_resolver.py      GitHub repo/commit/tag resolution
      archive_extractor.py    safe tar.gz extraction (wraps utils/security.py)
      manifest_generator.py   SHA-256 file manifests
      normalizer.py           expected-build-artifact heuristics
      comparator.py           file-level diff classification
      metadata_analyzer.py    scripts/dependency/pattern static analysis
      provenance_checker.py   provenance vs. registry-signature distinction
      risk_engine.py           explainable risk scoring
      report_generator.py     report assembly + bounded in-memory store
      orchestrator.py         ties the whole pipeline together
    models/
      request.py   Pydantic request schema + validation
      response.py  Pydantic response schema
    utils/
      security.py   URL allow-listing + safe tar extraction (mandatory controls)
      hashing.py    SHA-256/SHA-512 + npm integrity-field verification
      errors.py     domain exceptions -> HTTP status mapping
      logging.py    structured JSON logging
  tests/           pytest suite (all HTTP mocked with respx; no live network needed)
  requirements.txt
  .env.example
```

## Setup

Requires Python 3.9+ (tested on 3.9.6; no 3.10+ syntax is used).

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # optional: set GITHUB_TOKEN to raise GitHub's 60/hr unauth rate limit
```

## Running

```bash
uvicorn app.main:app --reload --port 8000
```

- Swagger UI: http://127.0.0.1:8000/docs
- Health check: `GET http://127.0.0.1:8000/health`

## Running tests

```bash
python -m pytest -v
```

All 47 tests pass. Every test mocks npm-registry/GitHub HTTP calls with
`respx`/local tar fixtures — the suite never depends on live network access
(one `respx`-mocked end-to-end test exercises the full pipeline).

## API

### `GET /health`
Returns `{"status": "ok"}`.

### `POST /analyze`
Request:
```json
{ "package_name": "left-pad", "version": "1.3.0" }
```
Also accepts scoped packages: `{"package_name": "@babel/core", "version": "7.22.0"}`.

Response: see `app/models/response.py` for the full schema. Top-level shape:
```json
{
  "report_id": "uuid",
  "package": {"name": "...", "version": "..."},
  "source": {"repository": "...", "commit": "...", "resolution_method": "gitHead|tag|null", "correspondence": "EXACT|INFERRED|NONE", "directory": null},
  "integrity": {"tarball_verified": true, "verification_algorithm": "sha512", "provenance_status": "AVAILABLE|NOT_AVAILABLE", "registry_signature_present": true},
  "summary": {"identical": 0, "modified": 0, "added": 0, "removed": 0, "expected_generated": 0, "unexplained": 0},
  "risk": {"level": "LOW|MEDIUM|HIGH|CRITICAL|INCONCLUSIVE", "score": 0, "rationale": ["..."]},
  "findings": [{"file": "...", "category": "...", "severity": "...", "confidence": "...", "evidence": "...", "explanation": "...", "recommendation": "..."}],
  "comparison": [{"path": "...", "status": "...", "source_sha256": "...", "published_sha256": "..."}],
  "limitations": ["..."],
  "analysis_complete": true
}
```

Errors are always `{"error": {"code": "...", "message": "..."}}` with an
appropriate HTTP status (422 invalid input, 404 package/version/report not
found, 429 upstream rate limited, 502 upstream/archive failure, 504 timeout).
No stack traces or internal paths are ever returned to the client.

### `GET /report/{report_id}`
Re-fetches a previously generated report (in-memory store, retained up to
`REPORT_RETENTION_LIMIT`, oldest evicted first — no database).

## Security model (mandatory controls — see `app/utils/security.py`, `app/utils/http_client.py`)

- All outbound URLs are allow-listed by host (`registry.npmjs.org`,
  `github.com`, `codeload.github.com`, `api.github.com`) and must be `https`.
- **SSRF protection**: every hostname is resolved and every resolved IP is
  checked against private/loopback/link-local/multicast/reserved ranges
  before connecting — including on every redirect hop. Redirects are never
  auto-followed by the HTTP client; each `Location` is independently
  re-validated (host allow-list + safe IP) before being requested, which
  defends against DNS-rebinding attacks even on an allow-listed hostname.
- Archive extraction validates each tar member immediately after reading its
  header — before asking the stream to skip past its body — so a single
  maliciously-oversized entry is rejected without ever having to decompress
  its declared body (the actual decompression-bomb defense; just checking
  size *after* a bulk `getmembers()` call would already have decompressed it).
- Archives are **never** executed. No `npm install`, no lifecycle scripts, no
  package/repo code is ever run. `shell=False`/no subprocess calls are used
  at all for extraction — pure Python `tarfile` with manual member validation.
- Tar extraction rejects: absolute paths, `..` traversal, symlinks/hardlinks,
  device/fifo files, oversized single files, oversized total extracted size,
  and excessive file counts — checked member-by-member *before* any bytes
  are written to disk.
- All temp directories are created per-request and `shutil.rmtree`'d in a
  `finally` block, even on failure.
- Tarball downloads are size-capped while streaming (abort mid-download if
  the registry-declared size is exceeded, rather than buffering unbounded).

## Provenance verification — scope

`app/services/provenance_checker.py` fetches and parses real npm provenance
attestations (SLSA v1 / in-toto statements) and cross-checks their claims
(subject tarball digest, build repository, build commit) against facts this
analysis independently established. It deliberately does **not** perform
Fulcio certificate-chain or Rekor transparency-log verification — that
requires trusting Sigstore's TUF root and validating a full cert chain,
which is out of scope for this MVP. Because of that, a structurally-consistent
attestation is reported as `NOT_VERIFIED`, never `VERIFIED` (which this
implementation never emits) — per the rule that verification must never be
inferred from metadata presence alone. An attestation whose claims actively
contradict independently-observed facts (wrong digest/repo/commit) is
reported as `INVALID`, which needs no cryptography, just comparison.

## Known limitations (documented, not hidden)

- **GitHub only.** GitLab/Bitbucket/self-hosted repos are explicitly rejected
  rather than guessed at; those packages return `correspondence: NONE`.
- **Unauthenticated GitHub API rate limit is 60 requests/hour.** Set
  `GITHUB_TOKEN` in `.env` for 5000/hour. When rate-limited mid-resolution,
  the report says so explicitly rather than reporting "no match found."
- **The `UNEXPLAINED` vs `MODIFIED` vs `EXPECTED_GENERATED` classification is
  heuristic** (based on `dist/`-style path prefixes, `.min.js`/`.map`
  suffixes, and package.json's declared `main`/`module`/`types`/`exports`).
  It will occasionally misclassify an unusual-but-legitimate build layout —
  this is flagged in `limitations`, not silently assumed correct.
- **Static pattern scanning (`eval`, `child_process`, base64 blobs, etc.) is
  a substring/regex match**, not AST analysis or sandboxed execution. It
  cannot detect obfuscated or multi-stage payloads, and every such finding
  explicitly states it is not proof of malicious intent.
- **No reproducible build step.** This tool compares as-published bytes to
  as-resolved source bytes; it does not attempt to actually run the
  package's build and diff the result, so it cannot claim a build was
  "reproduced."
- **Monorepo `repository.directory`** is honored when present (compares
  against that subdirectory of the resolved repo) but is not exhaustively
  tested against every real-world monorepo layout.
- **In-memory report store** — reports are lost on restart; this is an
  intentional hackathon-scope tradeoff (no database), bounded by
  `REPORT_RETENTION_LIMIT`.

## Example

```bash
curl -s -X POST http://127.0.0.1:8000/analyze \
  -H 'Content-Type: application/json' \
  -d '{"package_name": "is-odd", "version": "3.0.1"}' | python3 -m json.tool
```

See `sample_report.json` in this directory for a full example response,
captured by running the real pipeline end-to-end (`app/services/orchestrator.py`)
against a synthetic package/repo pair with HTTP mocked via `respx` — every
field is a genuinely computed value, not hand-written. It illustrates a
`HIGH`-risk case with a mix of `IDENTICAL`, `ADDED`, `REMOVED`,
`EXPECTED_GENERATED`, and `UNEXPLAINED` files, a lifecycle-script finding,
and a dependency discrepancy.

Note: live GitHub API calls are rate-limited to 60/hour without a
`GITHUB_TOKEN`. During development this was hit repeatedly, and the backend's
own response makes that transparent rather than reporting it as "no matching
tag found" — try a live call yourself:
```bash
curl -s -X POST http://127.0.0.1:8000/analyze -H 'Content-Type: application/json' \
  -d '{"package_name": "is-odd", "version": "3.0.1"}' | python3 -m json.tool
```
