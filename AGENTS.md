# Agent rules

These rules apply to every change in this repository.

## Branching and pull requests

- **Never make changes on `main`.** Do not commit or push to `main`.
- Always create a **new branch** from the latest `main`, do the work there, and open a **pull request** into `main`.
- **Never force-push** to any branch (`git push --force`, `git push --force-with-lease`, or rewriting published history).

## Development practice

- **Always follow test-driven development (TDD):** add or update a failing test that expresses the desired behavior, implement until the test passes, then refactor while keeping tests green.
- **Always run formatting and linting** (`ruff format`, `ruff check`) **before committing**, and fix every issue they report.

## Secrets and tenants

- **Never commit credentials, raw tokens, or unmasked claims.** Tenant settings live in a local `.env` (git-ignored). Captured fixtures go through `idpkit capture`, which masks identifiers.
- **CI never talks to a real identity provider.** Unit tests use the in-process mock issuer only.
- Provider facts in `src/idpkit/profiles/*.toml` cite their sources and say whether a real token confirmed them (`verified`, `verified_on`). Do not mark a profile verified without a captured fixture.
