# Changelog

All notable changes to Canopy will be documented in this file.

Canopy follows semantic versioning from v1.0.0. Releases after v1.0.0 do not
make breaking changes to the public API without a major version increase.

## [Unreleased]

### Planned

- Live Google and Apple OAuth integration tests.
- Magic links and passkeys.
- Additional OAuth providers.
- Email provider examples.
- MySQL and SQLite stores.
- Cleanup for expired organization invitations.
- An actor field on administrator audit events.

## [1.0.1] - 2026-08-03

A post-release audit of v1.0.0 covered the complete v1.0.0 surface, including
the teams feature, the `accountlink` module, and the router adapters. This
release fixes every defect that the audit confirmed as release-blocking. See
report 2 in `SECURITY_AUDIT.md`. No public API is removed or changed.

### Security

- Reject a relative callback URL that a browser can fold into another origin.
  `resolveCallbackURL` accepted values such as `/\host` and paths that hold a
  control character. A browser folds a backslash into a slash and strips
  control characters, so those values resolved to a foreign host. A relative
  callback URL must now start with exactly one slash and must contain no
  backslash, no percent-encoded backslash, and no control character.
- Remove a member only when the member does not hold the protected role at
  commit time. The role-update path already held this guard; the removal path
  did not. A concurrent promotion could leave an organization without an
  owner, which no route can undo.
- Revoke the presented token on sign-out. The handler derived the token from a
  successful session lookup, so it reported success without revoking whenever
  the session could not be resolved, for example an account that awaits email
  verification.

### Fixed

- Account linking now completes with the built-in Google and Apple providers.
  The authorization request carried the provider's configured redirect URL,
  which addresses the core OAuth callback route, so the provider returned the
  user to the wrong route and the link failed with an invalid-state error.

### Added

- `oauth.StartOptions.RedirectURL` replaces the configured redirect URL for
  one authorization request and its matching token exchange.
- `oauth.RedirectExchanger`, an optional provider capability that exchanges a
  code with that same redirect URL. Both built-in providers implement it.
- `canopy.ProtectedMemberRemovalStore`, an optional store capability that
  re-reads the member role inside its own transaction before removal. Both
  built-in stores implement it. A store without it keeps the earlier
  behavior, which holds the race.

### Changed

- Pull requests now build, vet, and scan the three router adapter modules.
  The release workflow now runs the Postgres end-to-end suite before it
  publishes. Neither check would have caught the account-linking defect.
- `SECURITY_AUDIT.md` now holds two dated reports. The 2026-07-24 review is a
  frozen record with a scope limitation. Two of its remediation claims are
  marked partially remediated, with pointers to the findings that complete
  them.

## [1.0.0] - 2026-08-03

This is the first stable release. It contains the full remediation of the
2026-07-24 security audit. See `SECURITY_AUDIT.md`.

### Security

- Pin the patched `go1.26.5` toolchain in `go.mod` so this project's own
  builds, tests, releases, and vulnerability scans use a standard library with
  all current security fixes. Applications compile Canopy with their own
  toolchain and must keep it patched.
- Update `github.com/coreos/go-oidc/v3` to v3.20.0, `golang.org/x/crypto` to
  v0.54.0, and the indirect dependencies to their current versions.
- Store session tokens as SHA-256 digests and OAuth provider credentials as
  AES-256-GCM ciphertext.
- Require parent-session proof before restoring an administrator after
  impersonation.
- Require verified OAuth email claims for email-based identity decisions and
  preserve existing verified-email state.
- Prevent TOTP replay, atomically consume backup codes, and require recent
  authentication for sensitive two-factor changes.
- Atomically replace and consume password reset tokens, update credentials,
  revoke sessions, and invalidate sibling tokens in the built-in stores.
- Bound Argon2id verification parameters and validate Apple P-256 client-secret
  signing keys and lifetimes.
- Revalidate active organization membership and prevent concurrent changes
  from removing or demoting the last owner.
- Trust forwarded client IP headers only from configured proxy IPs or CIDRs.
- Add strict, bounded request parsing, defensive browser response headers, and
  safe callback URL construction.
- Add staged key rotation with `Config.PreviousSecrets`.
- Restrict modules to non-secret runtime configuration and purpose-separated
  keys.

### Added

- The `accountlink` module: an explicit account-linking confirmation flow
  with `POST /link-social` and a provider callback route. Linking requires a
  recent authentication, a non-impersonated session, and a verified provider
  email that equals the session user's email. The signed link state is
  single-use and browser-bound. The optional `AccountLinkStore` capability
  consumes the state and creates the account atomically; no schema migration
  is needed. This closes the security audit's residual-risk item on account
  linking. New typed error `ErrAccountLinkMismatch`.
- Teams within organizations: `Team` and `TeamMember` entities, seven
  `/organization/*-team*` endpoints, five `team:*` permissions, an optional
  invitation `TeamID` that creates the team membership on acceptance, and
  Postgres migration 4. Removing an organization member also removes the
  member's team memberships in the same operation. Team membership carries no
  role; the organization role stays authoritative.
- First-party router adapter modules `adapters/chi`, `adapters/echo`, and
  `adapters/gin`. Each provides `Mount`, `RequireSession`, and
  `OptionalSession`; the Echo and Gin adapters also provide `Session`. The
  adapters are separate Go modules, so the core module stays free of
  framework dependencies. They receive their own version tags after the core
  `v1.0.0` tag.
- `Auth.OptionalSession` and `Auth.RequireSession`, with matching service
  methods.
- `ValidationError` and field-level HTTP error details.
- `Config.ProviderTokenCodec`, `HookErrorHandler`, `TrustedProxies`,
  `PreviousSecrets`, and `Modules`.
- `SessionValidator`, `RuntimeConfig`, and `ModuleKeyring` module APIs.
- Atomic organization and two-factor store operations.
- Versioned Postgres migrations, `postgres.Migrations`, and the
  `canopy_schema_migration` history table.
- `Service.CleanupExpired` and store methods for expired session and
  verification cleanup.
- Build-tagged Postgres end-to-end tests and CI checks for formatting, race
  detection, vet, vulnerabilities, and release configuration.
- Security policy, production deployment checklist, and security/DX audit
  report.

### Changed

- The module now requires Go 1.25.12 or later, which includes the
  standard-library security fixes enforced by `govulncheck`. The project itself
  builds and releases with the pinned `go1.26.5` toolchain.
- The zero-value environment now defaults to `Production`; local development
  must select `canopy.Development` explicitly.
- `BasePath` now controls request routing and default cookie scope. Mount the
  handler at that path without `http.StripPrefix`.
- `Middleware` is deprecated because it has optional-session semantics.
- `Store` now requires expired-session cleanup, verification replacement, and
  identifier cleanup methods.
- `OrganizationStore` and `TwoFactorStore` now require atomic security
  operations. Organization roles are validated against built-in or configured
  assignable roles.
- `Core.Config` returns `RuntimeConfig`; modules use `ModuleKeys`,
  `HashPassword`, and `ClientIP` instead of root secrets or concrete config.
- OAuth providers may implement `oauth.Validator`; built-in providers validate
  configuration during `canopy.New` and cache successful OIDC discovery.
- After-hooks run after committed state and report failures through
  `HookErrorHandler` instead of returning a false operation failure.
- Postgres migrations are ordered and tracked instead of exposed as one
  unversioned SQL constant.

### Fixed

- Preserve refresh and identity tokens when an OAuth provider omits a
  replacement on a later login.
- Normalize Postgres not-found, unique-conflict, and storage failures to Canopy
  typed errors and stable HTTP statuses.
- Avoid stale active organization state after membership removal.
- Return stable field validation details instead of requiring error-string
  parsing.

### Upgrade notes

- Run all Postgres migrations before serving the new build. Migration 3 revokes
  legacy plaintext sessions and clears legacy plaintext provider credentials;
  affected users must sign in or authorize again. Migration 4 adds the team
  tables and converts the organization-member unique index to a named
  constraint.
- Generate a production secret of at least 32 random bytes. If rotating an
  existing secret, retain the old value in `PreviousSecrets` until signed
  tokens expire and persistent ciphertext has been rewrapped.
- Update custom stores for the expanded `Store`, `OrganizationStore`, and
  `TwoFactorStore` contracts. Security-sensitive methods documented as atomic
  must use a transaction or equivalent compare-and-write primitive.
- Replace `http.StripPrefix` mounting with `Config.BasePath`, and replace
  ambiguous `Middleware` use with `OptionalSession` or `RequireSession`.
- Update modules for `RuntimeConfig`, purpose-separated keys, password hashing,
  and trusted client IP access. The removed `AccountLinkingPolicy` and
  `sessions.Codec` APIs had no effective behavior.

## [0.1.0] - 2026-05-15

### Added

- Root `canopy` package with `New`, `Auth`, `Service`, `Handler`, and
  `Middleware`.
- Email/password sign-up and sign-in.
- Argon2id password hashing through the `password.Hasher` interface.
- Email verification and password reset flows.
- Server-side opaque sessions, cookies, lookup, refresh-age extension,
  sign-out, and user-wide revocation.
- Google and Apple OAuth providers with OIDC verification, PKCE, nonce, signed
  state, cookie binding, replay prevention, and provider token refresh.
- Audit logging, hooks, Postgres storage, migrations, and package
  documentation.

### Known limitations

- Live provider tests are not included.
- Email delivery is callback-based through `EmailSender`.
- Account linking is rejected without a first-party confirmation flow.
