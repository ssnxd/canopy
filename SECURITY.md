# Security Policy

## Supported versions

Security fixes are applied to the latest v1.x release. Older releases do not
receive fixes. Upgrade to the newest release before reporting an issue that
may already be fixed.

| Version | Supported |
| --- | --- |
| Latest v1.x release | Yes |
| Older v1.x releases | No |
| v0.x | No |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting flow from the repository's
Security tab. Include the affected revision, configuration, reproduction
steps, impact, and any proposed mitigation.

Do not publish exploitable details in a public issue. If private vulnerability
reporting is unavailable, open a public issue containing no sensitive details
and ask the maintainers for a private contact channel.

## Deployment checklist

- Generate `Config.Secret` from at least 32 cryptographically random bytes and
  keep it out of source control, logs, URLs, and error responses.
- Leave `Environment` unset for the production-safe default. Set
  `canopy.Development` only in an explicitly local environment.
- Terminate TLS before browser traffic reaches Canopy. Keep `Secure`,
  `HttpOnly`, and an appropriate `SameSite` mode on authentication cookies.
- Configure every browser origin in `TrustedOrigins` and do not disable origin
  checking in production.
- Configure `TrustedProxies` only with reverse proxy addresses or networks you
  operate. Canopy ignores forwarded client IP headers from all other peers.
- Apply shared rate limits to sign-in, sign-up, password reset, email
  verification, OAuth start/callback, two-factor challenge, and admin routes.
  Consider both client IP and normalized account identifier.
- Configure a real `EmailSender` before enabling required email verification.
  Avoid logging email verification, reset, OAuth, session, impersonation, or
  backup-code secrets.
- Run Postgres migrations before serving traffic. Migration 3 intentionally
  revokes legacy plaintext sessions and clears legacy plaintext provider
  credentials.
- Schedule `auth.API().CleanupExpired` to remove expired sessions and
  verifications.
- Send `AuditLogger` events and `HookErrorHandler` failures to monitored,
  access-controlled telemetry. Do not add bearer credentials to those events.
- Treat modules as trusted server code. Modules cannot read Canopy's root
  configuration secrets, but they receive the configured `Store` and may
  access sensitive application data through it.
- Encrypt database backups and restrict database and telemetry access. OAuth
  tokens and TOTP secrets are encrypted by default, but user and operational
  metadata remain sensitive.
- Use the built-in Postgres or memory store atomic operations as the reference
  semantics for a custom store. Security-sensitive compare-and-write methods
  must be implemented transactionally.

## Key rotation

Put the new key in `Secret` and the former key in `PreviousSecrets`. New
signatures and ciphertext use the new key while reads accept both.

Do not remove a previous key until:

1. Every one-time token signed with it has expired.
2. Every persisted provider credential and two-factor secret encrypted with it
   has been re-encrypted or retired.

For independent rotation schedules or managed keys, configure a custom
`ProviderTokenCodec` and two-factor `Codec` backed by a KMS or HSM.

## Security boundaries

Canopy authenticates application users; it does not replace TLS, rate limiting,
authorization policy, secure email delivery, secret management, database
access control, or dependency and host patching. Provider token refresh is
deliberately separate from application session validation.
