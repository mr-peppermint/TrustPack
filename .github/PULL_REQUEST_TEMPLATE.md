<!-- Thanks for contributing to TrustPack! Fill in what's relevant and delete the rest. -->

## Summary

<!-- What does this change, and why? Link an issue if there is one. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change (changes an existing API response shape, env var, or CLI behavior)
- [ ] Documentation only
- [ ] Chore / refactor / CI

## Area

- [ ] Backend (`backend/app/...`)
- [ ] Frontend (`src/...`)
- [ ] Both / infra (CI, docs, Supabase schema, ...)

## How was this tested?

<!-- e.g. "ran the backend test suite", "hit POST /api/analyze with left-pad@1.3.0 and checked the
     response", "ran npm run build and clicked through the new page". Be specific — "it works" isn't
     enough for a reviewer to trust. -->

## Checklist

- [ ] `cd backend && python -m pytest` passes
- [ ] `npm run build` passes (runs `tsc --noEmit` then the production build)
- [ ] New/changed behavior has test coverage (backend: `backend/tests/`; frontend: described above if no
      test runner covers it)
- [ ] Docs updated if this changes setup, configuration, or the API/response shape
      (`README.md`, `backend/README.md`, `.env.example` / `backend/.env.example`)
- [ ] No secrets (API keys, tokens, `.env` contents) committed or pasted into this PR

## Screenshots (frontend changes)

<!-- Delete if not applicable. -->
