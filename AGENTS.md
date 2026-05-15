# Repository Guidelines

## Project Structure & Module Organization

Canopy is a Go module at `github.com/ssnxd/canopy`. The root package contains the public auth API, HTTP handler, service logic, models, store interface, and tests. Subpackages are organized by concern:

- `oauth/`: shared OAuth provider interfaces and profile types.
- `providers/google/`, `providers/apple/`: first-party OAuth providers.
- `password/`: password hashing interfaces and Argon2id implementation.
- `sessions/`: session cookie configuration and helpers.
- `ratelimit/`: built-in in-memory rate limiter.
- `store/postgres/`: Postgres adapter and migrations.

Tests live next to the code as `*_test.go`. There are no frontend assets in this repository.

## Build, Test, and Development Commands

Use a workspace-local Go cache in sandboxed environments:

```sh
GOCACHE="$PWD/.gocache" go test ./...
GOCACHE="$PWD/.gocache" go vet ./...
gofmt -w .
```

`go test ./...` runs all unit tests. `go vet ./...` checks common Go issues. `gofmt` is required before committing Go changes.

## Coding Style & Naming Conventions

Follow standard Go style: tabs for indentation, exported identifiers documented when they are part of public API, and package comments in `doc.go` for public packages. Prefer small interfaces and explicit typed errors. Keep secrets out of JSON responses, logs, URLs, and test output.

Provider IDs should be stable lowercase strings, for example `google`, `apple`, or `github`. Test helpers may remain unexported.

## Testing Guidelines

Use Go’s standard `testing` package. Name tests as `TestFeatureBehavior`, for example `TestOAuthFlowCreatesSessionAndRejectsReplay`. Security-sensitive changes need negative tests for expiry, replay, revocation, invalid tokens, account-linking rejection, and rate limiting where relevant.

Run both tests and vet before submitting changes.

## Commit & Pull Request Guidelines

This repository has no established commit history yet. Use concise imperative commit messages, such as `Add password reset flow` or `Document OAuth provider guide`.

Pull requests should include a summary, test results, public API changes, and README/CHANGELOG updates when behavior changes. Link related issues when available.

## Security & Configuration Tips

Do not weaken auth defaults without documenting the tradeoff. Keep provider token refresh separate from session lookup. Do not silently link users by email across providers. For multi-instance deployments, prefer a shared `RateLimiter` implementation over the in-memory limiter.

