# Contributing to Canopy

Thanks for helping improve Canopy. This project is a Go authentication library inspired by Better Auth, with a Go-native API surface and `net/http` as the integration point.

The long-term goal is to support the broad Better Auth feature set in Go while keeping security-sensitive behavior explicit and testable.

## Development Setup

Run the full local check before opening a PR:

```sh
GOCACHE="$PWD/.gocache" go test ./...
GOCACHE="$PWD/.gocache" go vet ./...
```

Postgres-backed e2e tests are opt-in because they require a live database:

```sh
CANOPY_E2E_DATABASE_URL="postgres://user:pass@localhost:5432/canopy_test?sslmode=disable" \
  GOCACHE="$PWD/.gocache" go test -tags=e2e ./...
```

Each e2e test creates and drops its own Postgres schema.

Use `gofmt` on all Go changes:

```sh
gofmt -w .
```

Do not commit `.gocache/`.

## Contribution Guidelines

- Keep public APIs small and explicit.
- Prefer `net/http` compatibility over framework-specific dependencies.
- Add typed sentinel errors for new user-visible failure modes.
- Avoid leaking secrets in JSON responses, logs, errors, or URLs.
- Do not silently link accounts by email.
- Keep provider token refresh separate from session lookup.
- Add tests for security-sensitive behavior.
- Update `README.md` and `CHANGELOG.md` for public API changes.
- Add package comments for new packages.

## Adding an OAuth Provider

OAuth providers live under `providers/<name>`.

Each provider should implement:

```go
type Provider interface {
	ID() string
	Config(ctx context.Context) (*oauth2.Config, error)
	AuthCodeOptions(oauth.StartOptions) []oauth2.AuthCodeOption
	Exchange(ctx context.Context, code string, verifier string) (*oauth2.Token, error)
	Refresh(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	Profile(ctx context.Context, token *oauth2.Token, nonce string) (*oauth.Profile, error)
}
```

Provider requirements:

- Use stable provider IDs, such as `google`, `apple`, or `github`.
- Use `golang.org/x/oauth2` for authorization code exchange.
- Use PKCE when the provider supports it.
- Verify OIDC ID tokens when the provider supports OIDC.
- Validate issuer, audience, expiry, and nonce for OIDC providers.
- Normalize profile data into `oauth.Profile`.
- Return a stable provider account ID from the provider, not an email address.
- Preserve refresh tokens when the provider rotates them.
- Add unit tests with mocked token/profile behavior.
- Document provider scopes, callback URLs, and provider-specific caveats.

Do not implement “same email means same user” linking. If a provider returns an email that already belongs to another account, Canopy should return `ErrAccountLinking` until an explicit linking flow is implemented.

## Adding a Store

Stores must satisfy `canopy.Store`.

Requirements:

- Return `canopy.ErrNotFound` when records do not exist.
- Return `canopy.ErrConflict` where practical for unique constraint violations.
- Enforce unique normalized user email.
- Enforce unique session tokens.
- Enforce unique `(provider_id, account_id)`.
- Enforce unique `(user_id, provider_id)`.
- Delete sessions when users are deleted if the database supports cascading constraints.
- Support one-time verification consumption atomically.
- Add migration files or documented setup steps.
- Add store tests when the backing system can run in CI.

Future store work should prioritize transactional APIs for user/account/session creation.

## Adding Planned Features

Planned features should follow these rules:

- Start with the data model and threat model.
- Add service methods before HTTP routes.
- Keep HTTP responses stable and generic for sensitive flows.
- Avoid account enumeration.
- Add audit events for security-relevant actions.
- Add hooks only for app-level behavior, not security logging.
- Add tests for replay, expiry, revocation, and invalid-token behavior.
- Document the caveats in `README.md`.

Good first feature areas:

- Account linking confirmation flow.
- Session listing and device management.
- Email provider examples.
- MySQL store.
- SQLite store.

Larger feature areas:

- Magic link.
- Passkeys/WebAuthn.
- Two-factor authentication.
- Organization/team support.
- Admin APIs.
- Plugin system.

## Security Contributions

For security-sensitive changes, include tests for failure modes, not just happy paths. Examples:

- Expired tokens are rejected.
- Replayed tokens are rejected.
- Revoked sessions are rejected.
- OAuth state cookie mismatches are rejected.
- Password reset revokes old sessions.
- Provider account conflicts do not silently link users.

If you believe you found a vulnerability, do not open a public issue with exploit details. Contact the maintainers privately first.

## Release Checklist

Before tagging a release:

- `go test ./...` passes.
- `go vet ./...` passes.
- `README.md` reflects the current API.
- `CHANGELOG.md` has an entry for the release.
- Public packages have package comments.
- New public APIs have tests.
- Known caveats are documented.
