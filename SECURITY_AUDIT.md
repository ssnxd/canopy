# Canopy Security and Developer-Experience Audit

This file holds two reports. The first report is the pre-release review of
2026-07-24. The second report is the post-release audit of 2026-08-03. Read
both. The first report is a frozen record. Later sections correct it where
the code proved a claim incomplete.

---

# Report 1 — Pre-release review

Date: 2026-07-24

Scope: the root authentication package, HTTP surface, session handling, OAuth
providers, password hashing, two-factor, organization and admin modules,
Postgres and memory stores, migrations, tests, documentation, and release
automation.

This was a source review and local test-driven hardening pass. It was not a
black-box penetration test, a cryptographic certification, or a live Google or
Apple integration test.

Scope limitation: this report predates v1.0.0. It does not cover the teams
feature, the `accountlink` module, or the three router adapter modules. Report
2 covers those. Two remediation claims in the table below are incomplete. Each
one carries a correction note.

## Executive summary

The review found unsafe credential-at-rest handling, an impersonation
restoration weakness, incomplete identity-verification semantics, replay and
transaction gaps, permissive production defaults, and several integration
traps in the public API and documentation. All identified findings were
addressed in one focused commit per issue.

The resulting design fails closed by default, protects stored bearer material,
adds atomic state transitions to the built-in stores, normalizes public errors,
and makes session middleware and path mounting explicit. The remaining risks
are operational or deliberately out of scope: applications must supply rate
limiting, TLS, email delivery, secret management, and application authorization;
account linking still requires an application-owned confirmation flow. The
`accountlink` module later replaced that requirement. Report 2 records its
state.

## Findings and remediation

| ID | Severity | Finding | Resolution | Commit |
| --- | --- | --- | --- | --- |
| AUTH-01 | High | An impersonated session could restore an administrator identity without proving possession of the original session. | Added a separate parent-session proof cookie and bound restoration to it. | `b9c1361` |
| DATA-01 | Critical | Session and OAuth bearer credentials were stored in plaintext. | Session lookups now use SHA-256 digests; provider credentials use authenticated encryption. The migration revokes unconvertible legacy credentials. | `6be6737` |
| OAUTH-01 | High | Provider email claims could influence identity decisions without consistently preserving or requiring verification. | Preserved verified-email state and rejected unverified provider email claims for email-based decisions. | `4ee65ff` |
| ORG-01 | High | A session's active organization could outlive the user's membership. | Added session-time membership revalidation and cleared stale active organization state. | `76c0d3d` |
| CFG-01 | High | Zero-value configuration selected development behavior and allowed several unsafe production combinations. | Defaulted to production and validated secrets, lifetimes, origins, cookies, email delivery, and provider configuration. | `3c8d27b` |
| MFA-01 | High | TOTP codes could be replayed and sensitive two-factor changes lacked recent-authentication checks. | Added atomic TOTP counter consumption, one-time backup-code semantics, and recent-authentication requirements. | `2e7c60d` |
| RESET-01 | High | Password reset consumption, password update, session revocation, and token invalidation were not one atomic recovery operation. | Added latest-token replacement and atomic reset operations to built-in stores. | `a2a7641` |
| HASH-01 | High | Attacker-controlled Argon2 hash parameters could trigger excessive resource use during verification. | Enforced conservative upper and lower bounds before allocating or hashing. | `df423ef` |
| APPLE-01 | Medium | Apple client-secret signing accepted incompatible keys and unsafe token lifetimes. | Required P-256 signing material and bounded the generated JWT lifetime. | `a18bc55` |
| OAUTH-02 | Medium | A subsequent OAuth login could erase a previously stored refresh token when the provider omitted it. | Preserved existing credentials unless replacements were supplied and propagated update failures. | `f6a5476` |
| HTTP-01 | Medium | Browser responses and request decoding lacked consistent defensive controls. | Added no-store and security headers, strict and bounded JSON/form parsing, and safe callback URL token construction. | `dac44a2` |
| ERR-01 | Medium | Storage failures and unique conflicts could leak inconsistent HTTP behavior. | Normalized store errors and mapped internal failures to stable public 500 responses. | `d7ceb51` |
| KEY-01 | Medium | Rotating the root secret immediately invalidated outstanding data and tokens. | Added staged `PreviousSecrets` verification and decryption across core and built-in modules. | `65888f3` |
| TX-01 | High | Multi-record organization and two-factor state transitions could partially commit; after-hooks could report a committed operation as failed. | Added atomic built-in store operations and out-of-band after-hook error reporting. | `20258f3` |
| MOD-01 | Medium | Modules received the complete root configuration, including secrets unrelated to their purpose. | Replaced it with non-secret runtime configuration and purpose-separated module keys. | `250f6e6` |
| NET-01 | Medium | Forwarded client IP headers were trusted without proving that the immediate peer was an authorized proxy. | Added exact-IP/CIDR trusted proxy configuration and peer validation. | `252a599` |
| ORG-02 | High | Concurrent role or member changes could leave an organization without an owner; arbitrary invitation roles were accepted. | **Partially remediated.** Added transactional last-owner protection to the role-update path and explicit assignable-role validation. The member-removal path kept an unprotected delete. See ORG-03 in report 2. | `94a3136` |
| DX-01 | Medium | `BasePath` did not consistently control routes and cookies, encouraging error-prone `StripPrefix` setups. | Made the handler base-path aware and scoped default cookies to it. | `70fa08c` |
| DX-02 | Medium | `Middleware` silently allowed anonymous requests, which was easy to mistake for authentication enforcement. | Added explicit `OptionalSession` and `RequireSession`; retained a deprecated compatibility alias. | `9d07895` |
| DX-03 | Low | Invalid input exposed only a broad error, forcing clients to parse strings or duplicate validation. | Added typed field validation and stable HTTP field details. | `c775c3b` |
| OAUTH-03 | Medium | Invalid provider settings could fail only during a user flow and OIDC discovery was repeated. | Added provider validation during construction and concurrency-safe successful discovery caching. | `7e00452` |
| DB-01 | High | Schema changes were unversioned, cleanup was not operationalized, and legacy bearer data had no safe upgrade path. | **Partially remediated.** Added ordered migrations, advisory locking, external-runner metadata, credential cleanup, and an expiry cleanup API. `CleanupExpired` covers sessions and verifications only. Expired invitations are never removed. See DB-02 in report 2. | `e6a33e6` |
| SUPPLY-01 | Medium | CI did not exercise race, vulnerability, formatting, and Postgres paths consistently; actions were not immutable. | Added hardened checks, pinned actions by full commit SHA, and pinned release tooling. | `03aa7e3` |

## Developer-experience assessment

The public API is now clearer at the three highest-risk integration points:

- `BasePath` owns route and cookie scoping, so applications mount the handler
  without manipulating request paths.
- Authentication intent is visible at the call site through
  `OptionalSession` or `RequireSession`.
- Invalid fields and storage failures are typed and stable enough for clients,
  logs, retry policy, and tests without string matching.

Configuration validation occurs during `canopy.New`, including OAuth provider
validation and module capability checks. Modules receive a smaller facade, and
the store documentation identifies atomic requirements. The README now shows a
production-oriented server with timeouts and explains migration side effects,
trusted proxy behavior, key rotation, hook timing, and cleanup.

Adopters who upgrade from 0.x must account for breaking changes to `Store`, module `Core`,
organization and two-factor store capabilities, migration APIs, the default
environment, base-path mounting, and removed dead APIs. See `CHANGELOG.md`.

## Verification

The hardening commits were exercised with:

```sh
GOCACHE="$PWD/.gocache" go test ./...
GOCACHE="$PWD/.gocache" go vet ./...
```

CI additionally runs formatting checks, the race detector, `govulncheck`, and
build-tagged Postgres end-to-end tests. OAuth unit tests use deterministic fake
providers; live provider interoperability remains a release-validation task.

## Residual risk

This section is superseded. Report 2 holds the current residual-risk list.

---

# Report 2 — Post-release audit

Date: 2026-08-03

Scope: the complete v1.0.0 surface. This includes everything in report 1, and
also the teams feature, the `accountlink` module, the `adapters/chi`,
`adapters/echo`, and `adapters/gin` modules, and the release pipeline.

Method: seven independent source reviews ran in parallel. Each review covered
one angle: cryptography and keys; session lifecycle; OAuth and account
linking; authorization and multi-tenancy; the HTTP surface; the data layer;
and supply chain, operations, and documentation. A separate reviewer then
tried to refute every finding. That step rejected 13 of 49 findings. The
maintainer reproduced each release-blocking finding directly against the code
before it entered this table.

This was again a source review. It was not a penetration test. It was not a
live Google or Apple integration test.

## Executive summary

No finding exceeded medium severity. No finding lets an attacker cross an
authentication boundary. No finding grants a privilege that the actor did not
already hold. The core cryptography, the storage layer, and the origin checks
held up under review.

The audit found one attacker-reachable open redirect. It found that the
account-linking feature cannot complete with either built-in provider. It
found that the member-removal path never received the last-owner protection
that report 1 claimed. It found that sign-out could report success without
revoking a session. Canopy v1.0.1 fixes all four.

The audit also showed why the defects survived release. The account-linking
tests used a fake provider that accepts any redirect URL. A real provider
accepts one. The tests therefore proved a flow that no deployment can run.

## Findings and remediation

| ID | Severity | Finding | Resolution | Commit |
| --- | --- | --- | --- | --- |
| REDIR-01 | Medium | `resolveCallbackURL` rejected protocol-relative and foreign absolute URLs, but accepted any value that parsed as a relative reference. A browser folds a backslash into a slash and strips control characters, so `/\host` resolved to a foreign host. | A relative callback URL must now start with exactly one slash. It must contain no backslash, no percent-encoded backslash, and no control character. | `a51acfa` |
| LINK-01 | Medium | The `accountlink` module could not complete with the built-in providers. The authorization request carried the provider's configured redirect URL, which addresses the core callback route. The provider returned the user to the wrong route and the link failed. | Added a redirect override to the authorization request and the matching token exchange. The test provider now enforces one redirect URL, as a real provider does. | `d7c9697` |
| ORG-03 | Medium | Member removal held no transactional last-owner guard. The handler read the role, then deleted without a lock or a role predicate. A concurrent promotion could leave an organization with no owner, and no route can restore one. | Added an optional store capability that re-reads the role under the organization row lock and refuses to remove a protected role. | `310b7c1` |
| SESS-02 | Low | Sign-out derived the token from a successful session lookup. When the session could not be resolved, the handler cleared the cookie, reported success, and left the session row usable. | Sign-out now revokes the presented token. | `cf463c5` |
| SUPPLY-02 | Low | Pull requests did not build the adapter modules. Tag pushes did not run the Postgres end-to-end suite. Neither defect above could be caught by the pipeline. | The Verify job now covers the adapter modules. The release job now runs the end-to-end suite before publication. | `6007ab0` |
| DB-02 | Low | `CleanupExpired` never removes expired invitations. Invitation rows hold invitee email addresses and grow without limit. | Open. Planned for the next minor release. | — |

## Accepted risk

The audit produced further findings that the maintainer accepts for now. Each
one is real in the code. None is reachable in a default or documented
configuration. The full list, with the rationale for each item, is tracked
outside this file. The most notable items are:

- Role grants are not bounded by the actor's own role. Default configurations
  are safe, because Canopy's admin model is flat. An application that defines
  a role above `admin` must supply its own check.
- The memory store and the Postgres store differ in several edge cases. The
  memory store is for tests and local development only. A test can therefore
  pass a flow that Postgres rejects.
- Admin audit events do not record the acting user. An impersonated
  administrator can act without a separate record.
- Impersonation sessions use the standard session lifetime. A short dedicated
  lifetime would reduce the exposure.

## Residual risk and recommended follow-up

1. Add deployment-specific distributed rate limiting and abuse detection.
2. Run live Google and Apple authorization tests before a production release.
   The LINK-01 defect proves that fake providers hide integration errors.
3. Prefer the built-in stores until a custom store has concurrency and
   rollback tests for every method documented as atomic.
4. Narrow the module `Core.Providers` facade so a module can build an
   authorization URL without reading OAuth client secrets. Modules are trusted
   compile-time code, so this is a hardening item, not a vulnerability.
5. Bound the actor's assignable roles, and record the acting user on every
   administrator audit event.
6. Commission an independent penetration test before you treat a stable
   release as a high-assurance authentication boundary.
