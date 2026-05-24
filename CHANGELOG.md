# Changelog

All notable changes to Canopy will be documented in this file.

Canopy follows semantic versioning after the first stable release. Until v1.0.0, public APIs may change when needed to improve the v1 design.

## [Unreleased]

### Added

- Build-tagged Postgres e2e tests for email/password and OAuth HTTP flows.

### Fixed

- Postgres-backed user/account provisioning now runs in one transaction when Canopy creates a new account.

### Planned

- Transactional store APIs for atomic user/account/session creation.
- Live Google and Apple OAuth integration tests.
- Account linking confirmation flow.
- Additional OAuth providers.
- Email provider examples.
- MySQL and SQLite stores.

## [0.1.0] - 2026-05-15

### Added

- Root `canopy` package with `New`, `Auth`, `Service`, `Handler`, and `Middleware`.
- Email/password sign-up and sign-in.
- Argon2id password hashing through the `password.Hasher` interface.
- Email verification tokens and routes.
- Password reset tokens and routes.
- Server-side opaque sessions.
- Session cookie helpers.
- Session lookup, refresh-age extension, sign-out, and user-wide revocation.
- Google OAuth provider.
- Apple OAuth provider.
- Apple ES256 client-secret JWT helper.
- OAuth state signing, state cookie binding, PKCE, nonce validation, and replay prevention.
- Provider access-token refresh API.
- Audit logging interface.
- App hooks for user creation, sign-in, sign-out, OAuth, email verification, and password reset.
- Postgres store and migrations.
- Detailed README and package documentation.

### Known Limitations

- User/account/session creation is not yet transactional.
- OAuth tests use fake providers; live provider tests are still planned.
- Email delivery is callback-based through `EmailSender`; no first-party email provider package is included yet.
- Account linking is safely rejected but the confirmation UX/API is not implemented yet.
