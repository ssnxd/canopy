# Canopy

Canopy is a Go authentication library for API servers. It provides email/password auth, Google and Apple OAuth sign-in, database-backed opaque sessions, audit hooks, and a Postgres storage adapter.

Canopy is inspired by [Better Auth](https://better-auth.com/): the core entity names, route names, and product direction intentionally follow the same mental model. Canopy is not a Better Auth port and it is not a hosted service. It is a Go-native library built around `net/http`, explicit interfaces, typed errors, and server-side session storage.

The long-term goal is to support the full Better Auth feature surface in Go over time, while keeping the v1 API small, explicit, and production-oriented.

Project docs:

- [Security policy and deployment checklist](SECURITY.md)
- [Security and developer-experience audit](SECURITY_AUDIT.md)
- [Changelog](CHANGELOG.md)
- [Contributing](CONTRIBUTING.md)
- [License](LICENSE)

## Status

Implemented today:

- Email/password sign-up and sign-in.
- Email verification.
- Password reset.
- Google OAuth sign-in.
- Apple OAuth sign-in.
- OIDC ID token verification for Google and Apple.
- PKCE, nonce validation, signed OAuth state, state cookie binding, and replay prevention.
- Server-side opaque sessions.
- Session cookies and session middleware.
- Sign-out and session revocation.
- Provider access-token refresh API.
- Two-factor authentication (TOTP) with backup codes.
- Organizations, members, roles, teams, and invitations.
- Admin APIs: list and create users, set roles, ban and unban, list and revoke sessions, and impersonation.
- Module system for optional features and plugins.
- Audit logging interface.
- Postgres store and in-memory store.
- Typed public errors for common auth failures.
- First-party router adapters for chi, Echo, and Gin.
- Explicit account-linking confirmation flow through the accountlink module.

Not implemented yet:

- Magic link and passkeys. These stay out of scope for v1.
- Built-in rate limiting. Applications should apply rate limiting in HTTP middleware, gateways, or other client-owned request controls.
- Automatic provider token refresh during session lookup. This is intentionally separate.

## Install

Canopy requires Go 1.25.12 or later.

```sh
go get github.com/ssnxd/canopy
go get github.com/ssnxd/canopy/store/postgres
go get github.com/ssnxd/canopy/providers/google
go get github.com/ssnxd/canopy/providers/apple
go get github.com/lib/pq
```

## Quick Start

```go
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/providers/google"
	"github.com/ssnxd/canopy/store/postgres"
	_ "github.com/lib/pq"
)

func main() {
	db, err := sql.Open("postgres", os.Getenv("DATABASE_URL"))
	if err != nil {
		log.Fatal(err)
	}

	store := postgres.New(db)
	if err := store.Migrate(context.Background()); err != nil {
		log.Fatal(err)
	}

	auth, err := canopy.New(canopy.Config{
		Store:       store,
		Secret:      os.Getenv("CANOPY_SECRET"),
		Environment: canopy.Production,
		BasePath:    "/auth",
		TrustedOrigins: []string{
			"https://app.example.com",
		},
		Providers: []oauth.Provider{
			google.Provider{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "https://api.example.com/auth/callback/google",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", auth.Handler())
	mux.Handle("/api/me", auth.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, _ := canopy.SessionFromContext(r.Context())
		_ = json.NewEncoder(w).Encode(session.User)
	})))

	server := &http.Server{
		Addr:              ":8080",
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Fatal(server.ListenAndServe())
}
```

`database/sql` drivers are registered by side-effect imports in the application binary. If you use `sql.Open("postgres", ...)`, import `github.com/lib/pq` as shown above. If you prefer pgx, import `github.com/jackc/pgx/v5/stdlib` and open the database with `sql.Open("pgx", ...)`.

## Router Adapters

Canopy serves plain `net/http`, so most routers mount the handler directly. First-party adapters remove the mounting and middleware boilerplate for chi, Echo, and Gin. Each adapter is a separate Go module, so the core module stays free of framework dependencies.

```sh
go get github.com/ssnxd/canopy/adapters/chi
go get github.com/ssnxd/canopy/adapters/echo
go get github.com/ssnxd/canopy/adapters/gin
```

The adapter modules receive their own version tags after the core `v1.0.0` tag. Use the tagged adapter releases; development snapshots pin the core module with a local replace directive.

Each adapter has the same three-part surface:

- `Mount(router, auth)` registers the Canopy handler at `Config.BasePath`. Do not use `http.StripPrefix`.
- `RequireSession(auth)` returns framework middleware that adds session data to the request context or ends the request with a 401 JSON error.
- `OptionalSession(auth)` returns framework middleware that adds session data when a valid session is present and continues anonymously otherwise.

The Gin and Echo adapters also provide `Session(c)`, which reads the session from the framework context. With chi, read the session with `canopy.SessionFromContext(r.Context())`.

```go
import canopygin "github.com/ssnxd/canopy/adapters/gin"

router := gin.New()
canopygin.Mount(router, auth)

protected := router.Group("/", canopygin.RequireSession(auth))
protected.GET("/me", func(c *gin.Context) {
	data, ok := canopygin.Session(c)
	if !ok {
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	c.JSON(http.StatusOK, data.User)
})
```

## Database

The Postgres schema follows Better Auth-compatible core entities:

- `user`
- `session`
- `account`
- `verification`

Run the migration:

```go
store := postgres.New(db)
err := store.Migrate(ctx)
```

`Migrate` serializes migration runs with a Postgres advisory lock and records
applied versions in `canopy_schema_migration`. Deployments with an external
migration runner can read the same ordered migrations with
`postgres.Migrations()`.

Migration 3 protects credentials at rest. It revokes legacy plaintext session
tokens and clears legacy plaintext OAuth credentials because they cannot be
safely converted without exposing the bearer values. Plan for users to sign in
or re-authorize again when upgrading an existing database.

Important constraints and indexes:

- Unique normalized user email: `lower(email)`.
- Unique session token.
- Unique OAuth account pair: `(provider_id, account_id)`.
- Unique user-provider pair: `(user_id, provider_id)`.
- Foreign keys from `session.user_id` and `account.user_id` to `user.id`.
- Expiry indexes for session and verification cleanup.

Schedule expired-record cleanup:

```go
err := auth.API().CleanupExpired(ctx, time.Now())
```

## Configuration

```go
type Config struct {
	Store           canopy.Store
	Secret          string
	PreviousSecrets []string
	Environment     canopy.Environment
	BasePath        string

	DisableSignup            bool
	RequireEmailVerification bool
	PasswordMinLength        int
	PasswordMaxLength        int
	PasswordHasher           password.Hasher
	ProviderTokenCodec       canopy.ProviderTokenCodec

	AuditLogger      canopy.AuditLogger
	HookErrorHandler canopy.HookErrorHandler
	EmailSender      canopy.EmailSender

	TrustedOrigins     []string
	TrustedProxies     []string
	DisableOriginCheck bool

	Providers            []oauth.Provider
	OAuthStateTTL        time.Duration
	OAuthStateCookieName string
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration

	Modules []canopy.Module

	Session sessions.Config
	Hooks   canopy.Hooks
}
```

Defaults:

- Environment: `production`. Set `canopy.Development` explicitly for local development.
- Base path: `/`.
- Password length: 8 to 128 bytes.
- Password hashing: Argon2id.
- Session expiry: 7 days.
- Session refresh/update age: 1 day.
- Session absolute lifetime: 30 days.
- Session cookie: `canopy.session_token`.
- OAuth state TTL: 10 minutes.
- Email verification TTL: 24 hours.
- Password reset TTL: 1 hour.
- Account linking policy: reject implicit linking.

Production requirements:

- `Secret` and every `PreviousSecrets` entry must be at least 32 bytes in production and must be unique.
- Cookies are `Secure` in production.
- `RequireEmailVerification` requires a non-default `EmailSender`.
- Set `TrustedOrigins` for browser-facing deployments. Keep origin checking enabled.
- Only list reverse proxies you operate in `TrustedProxies`; forwarded client IP headers from other peers are ignored.
- Apply rate limiting before Canopy handlers in browser-facing deployments.

`PreviousSecrets` supports staged rotation for signed tokens and encrypted
provider or two-factor data. New data uses `Secret`; reads also try previous
keys. Keep old keys until their signed tokens expire and persisted encrypted
data has been rewrapped. For independent key management, provide
`ProviderTokenCodec` and the two-factor module's `Codec`.

## HTTP API

Mount the handler:

```go
auth, err := canopy.New(canopy.Config{
	Store:    store,
	Secret:   os.Getenv("CANOPY_SECRET"),
	BasePath: "/auth",
})
mux.Handle("/auth/", auth.Handler())
```

`BasePath` controls routing and cookie scope. Do not also strip the prefix. The
examples below assume the handler uses `BasePath: "/auth"`.

### `POST /auth/sign-up/email`

Creates a user with an email/password account and starts a Canopy session.

Request:

```json
{
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "password": "correct-password",
  "image": "https://example.com/avatar.png",
  "rememberMe": true
}
```

Response:

```json
{
  "user": {
    "id": "usr_...",
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "emailVerified": false,
    "image": "https://example.com/avatar.png",
    "createdAt": "...",
    "updatedAt": "..."
  },
  "session": {
    "id": "ses_...",
    "userId": "usr_...",
    "expiresAt": "...",
    "createdAt": "...",
    "updatedAt": "..."
  }
}
```

Also sets the `canopy.session_token` cookie.

Sign-up creates the user with `emailVerified=false`; password possession is not
proof that the email address is controlled by the user. When
`RequireEmailVerification` is enabled, Canopy creates a one-time verification
token, calls `EmailSender.SendEmailVerification`, and returns
`UNVERIFIED_EMAIL` from email/password sign-in until verification succeeds.

Sign-up still sets a session cookie, but the session is inactive until the user verifies the email. `GetSession` and the middleware return unauthorized for an unverified user. The same session becomes active after verification, so the user does not sign in again.

### `POST /auth/send-verification-email`

Creates a fresh one-time email verification token and sends it through `EmailSender`.

Request:

```json
{
  "email": "ada@example.com",
  "callbackURL": "https://app.example.com/verify-email"
}
```

Response:

```json
{ "success": true }
```

This endpoint returns success even when the email does not exist. That avoids account enumeration.

### `POST /auth/verify-email`

Consumes a one-time email verification token and marks the user as verified.

Request:

```json
{
  "token": "..."
}
```

Response:

```json
{
  "id": "usr_...",
  "name": "Ada Lovelace",
  "email": "ada@example.com",
  "emailVerified": true,
  "createdAt": "...",
  "updatedAt": "..."
}
```

### `GET /auth/verify-email?token=...`

Same behavior as `POST /auth/verify-email`. This route is convenient for email links.

### `POST /auth/request-password-reset`

Creates a one-time password reset token and sends it through `EmailSender`.

Request:

```json
{
  "email": "ada@example.com",
  "callbackURL": "https://app.example.com/reset-password"
}
```

Response:

```json
{ "success": true }
```

This endpoint returns success even when the email does not exist or the account has no password credential. That avoids account enumeration.

### `POST /auth/reset-password`

Consumes a one-time password reset token, updates the email/password account hash, and revokes all existing sessions for that user.

Request:

```json
{
  "token": "...",
  "newPassword": "new-correct-password"
}
```

Response:

```json
{ "success": true }
```

### `POST /auth/sign-in/email`

Verifies an email/password account and starts a new Canopy session.

Request:

```json
{
  "email": "ada@example.com",
  "password": "correct-password",
  "rememberMe": true
}
```

Every successful sign-in creates a fresh session token. Canopy does not reuse any previous unauthenticated or authenticated session token.

### `POST /auth/sign-in/social`

Starts a Google or Apple OAuth flow.

Request:

```json
{
  "provider": "google",
  "callbackURL": "https://app.example.com/dashboard",
  "rememberMe": true
}
```

Response:

```json
{
  "url": "https://accounts.google.com/o/oauth2/v2/auth?..."
}
```

The response also sets an HttpOnly OAuth state binding cookie. Redirect the user to `url`.

### `GET /auth/callback/{provider}`

Completes OAuth after the provider redirects back to Canopy.

Example:

```text
GET /auth/callback/google?code=...&state=...
```

Canopy verifies:

- Signed state.
- State binding cookie.
- Server-side one-time state record.
- PKCE verifier.
- OIDC ID token issuer, audience, expiry, and nonce.
- Provider account identity.

On success, Canopy creates or updates the provider account, creates a Canopy session, sets the session cookie, and redirects to `callbackURL` when one was supplied.

### `POST /auth/callback/{provider}`

Same behavior as `GET /auth/callback/{provider}`. This is useful for clients or intermediaries that prefer form POST callbacks.

### `GET /auth/get-session`

Reads the current Canopy session from the session cookie or `Authorization: Bearer <token>`.

Response when authenticated:

```json
{
  "user": { "...": "..." },
  "session": { "...": "..." }
}
```

Response when unauthenticated:

```json
null
```

`GET /get-session` is the normal cookie-backed session lookup.

### `POST /auth/get-session`

Same behavior as `GET /auth/get-session`. This exists for clients and infrastructure that avoid credentialed GET requests. It does not refresh provider access tokens.

### `POST /auth/sign-out`

Revokes the current session and clears the session cookie.

Canopy reads the session token from the cookie or `Authorization: Bearer <token>`.

Response:

```json
{ "success": true }
```

### `POST /auth/refresh-provider-token`

Refreshes a Google or Apple provider access token for the currently authenticated Canopy user.

Request:

```json
{
  "providerId": "google"
}
```

Response:

```json
{
  "accountId": "google-subject",
  "providerId": "google",
  "accessToken": "...",
  "accessTokenExpiresAt": "...",
  "scope": "openid email profile"
}
```

This endpoint is intentionally separate from `get-session`. A Canopy session answers, “is this user authenticated with my app?” Provider token refresh answers, “can my app still call Google or Apple APIs for this user?” Those are different lifecycles with different failure modes.

## Go Service API

The handler is optional. You can use Canopy as a pure service library.

### Constructor

```go
auth, err := canopy.New(canopy.Config{...})
```

### Accessors

```go
api := auth.API()
handler := auth.Handler()
optionalSession := auth.OptionalSession(next)
requiredSession := auth.RequireSession(next)
```

`OptionalSession` always calls the next handler and adds a session to the
context only when one is valid. `RequireSession` returns Canopy's stable 401
JSON response without calling the next handler when authentication fails.
`Middleware` remains as a deprecated alias for `OptionalSession`.

### Email/password

```go
data, token, err := auth.API().SignUpEmail(ctx, canopy.SignUpEmailInput{
	Name:     "Ada Lovelace",
	Email:    "ada@example.com",
	Password: "correct-password",
	Image:    "https://example.com/avatar.png",
})
```

```go
result, err := auth.API().SignInEmail(ctx, canopy.SignInEmailInput{
	Email:    "ada@example.com",
	Password: "correct-password",
})
// result.Session and result.Token hold the new session on success.
// result.Challenge is set when a second factor is required.
if result.TwoFactorRequired() {
	// Prompt for the second factor with result.Challenge.
}
```

### Email Verification

```go
err := auth.API().SendEmailVerification(ctx, canopy.SendEmailVerificationInput{
	Email:       "ada@example.com",
	CallbackURL: "https://app.example.com/verify-email",
})
```

```go
user, err := auth.API().VerifyEmail(ctx, canopy.VerifyEmailInput{
	Token: tokenFromEmail,
})
```

### Password Reset

```go
err := auth.API().RequestPasswordReset(ctx, canopy.RequestPasswordResetInput{
	Email:       "ada@example.com",
	CallbackURL: "https://app.example.com/reset-password",
})
```

```go
err := auth.API().ResetPassword(ctx, canopy.ResetPasswordInput{
	Token:       tokenFromEmail,
	NewPassword: "new-correct-password",
})
```

### OAuth

```go
start, stateCookieValue, err := auth.API().SignInSocial(ctx, canopy.SignInSocialInput{
	Provider:    "google",
	CallbackURL: "https://app.example.com/dashboard",
})
```

`start.URL` is the provider authorization URL. `stateCookieValue` is the value that must be placed in the OAuth state binding cookie when using the service API directly.

```go
out, err := auth.API().OAuthCallback(ctx, canopy.OAuthCallbackInput{
	Provider:     "google",
	Code:         code,
	State:        state,
	StateBinding: stateCookieValue,
	IPAddress:    ip,
	UserAgent:    userAgent,
})
// out.Result holds the sign-in result (session or challenge).
// out.CallbackURL and out.RememberMe drive the browser redirect and cookie.
```

### Sessions

```go
data, err := auth.API().GetSession(ctx, token)
```

```go
err := auth.API().SignOut(ctx, token)
```

```go
err := auth.API().RevokeUserSessions(ctx, userID)
```

```go
data, ok := canopy.SessionFromContext(r.Context())
```

### Provider Token Refresh

```go
token, err := auth.API().RefreshProviderToken(ctx, canopy.RefreshProviderTokenInput{
	UserID:     userID,
	ProviderID: "google",
})
```

`ErrNoRefreshToken` means the user must re-authorize the provider before Canopy can refresh access.

## Google OAuth

```go
import (
	"github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/providers/google"
)

auth, err := canopy.New(canopy.Config{
	Store:  store,
	Secret: os.Getenv("CANOPY_SECRET"),
	Providers: []oauth.Provider{
		google.Provider{
			ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
			ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
			RedirectURL:  "https://api.example.com/auth/callback/google",
		},
	},
})
```

Default scopes:

```text
openid email profile
```

Google sometimes does not return a refresh token on later authorizations if the user already granted access. If refresh is required, your app may need to force a re-consent flow.

## Apple OAuth

Apple requires an ES256-signed client-secret JWT. Canopy supports either a custom `ClientSecretSource` or the built-in JWT helper.

```go
secretSource, err := apple.NewJWTClientSecretSource(
	os.Getenv("APPLE_TEAM_ID"),
	os.Getenv("APPLE_CLIENT_ID"),
	os.Getenv("APPLE_KEY_ID"),
	[]byte(os.Getenv("APPLE_PRIVATE_KEY_PEM")),
)
if err != nil {
	return err
}

auth, err := canopy.New(canopy.Config{
	Store:  store,
	Secret: os.Getenv("CANOPY_SECRET"),
	Providers: []oauth.Provider{
		apple.Provider{
			ClientID:     os.Getenv("APPLE_CLIENT_ID"),
			RedirectURL:  "https://api.example.com/auth/callback/apple",
			SecretSource: secretSource,
		},
	},
})
```

Default scopes:

```text
openid email name
```

Apple caveats:

- Apple may only provide name on the first authorization.
- Apple may not provide a refresh token in some flows.
- Canopy verifies Apple ID tokens through OIDC and handles string or boolean `email_verified` claims.

## Two-Factor Authentication

Add the two-factor module for TOTP with backup codes.

```go
import "github.com/ssnxd/canopy/twofactor"

auth, err := canopy.New(canopy.Config{
	Store:   store,
	Secret:  os.Getenv("CANOPY_SECRET"),
	Modules: []canopy.Module{
		twofactor.New(twofactor.Options{Issuer: "Example"}),
	},
})
```

The store must implement `canopy.TwoFactorStore`. The Postgres store and the in-memory store implement it.

Endpoints (mounted under the auth handler):

- `POST /two-factor/enable` — start enrollment. Returns the TOTP secret and an `otpauth://` URI. Requires a session.
- `POST /two-factor/verify` — confirm enrollment with a code. Returns one-time backup codes. Requires a session.
- `POST /two-factor/disable` — turn off two-factor. Requires a session and a valid code.
- `POST /two-factor/challenge` — complete sign-in with a TOTP code.
- `POST /two-factor/backup` — complete sign-in with a backup code.

When a user enables two-factor, sign-in returns a challenge instead of a session:

```json
{ "twoFactorRequired": true, "token": "...", "methods": ["totp", "backup_code"] }
```

Send the challenge token and a code to `/two-factor/challenge` to receive the session. Canopy stores the TOTP secret encrypted. The default codec derives an AES-256-GCM key from `Secret`. Set `Options.Codec` to use a KMS or an HSM instead.

## Organizations

Add the organization module for organizations, members, roles, and invitations.

```go
import "github.com/ssnxd/canopy/organization"

auth, err := canopy.New(canopy.Config{
	Store:   store,
	Secret:  os.Getenv("CANOPY_SECRET"),
	Modules: []canopy.Module{
		organization.New(organization.Options{}),
	},
})
```

The store must implement `canopy.OrganizationStore`. The Postgres store and the in-memory store implement it.

Endpoints (mounted under the auth handler, all require a session):

- `POST /organization/create` — create an organization. The creator becomes the owner.
- `GET /organization/list` — list the organizations of the current user.
- `POST /organization/set-active` — set the active organization on the session.
- `POST /organization/invite` — invite an email address with a role. Returns the invitation.
- `POST /organization/accept-invitation` — accept an invitation. The session email must match the invited email.
- `GET /organization/members?organizationId=...` — list members.
- `POST /organization/update-member-role` — change a member role.
- `POST /organization/remove-member` — remove a member.

Roles are `owner`, `admin`, and `member`. The default `Authorizer` maps roles to
permissions. Set `Options.Authorizer` for custom access control and
`Options.AssignableRoles` to add application-defined roles. Canopy rejects
unknown roles, verifies the accepting user's email, and atomically prevents
demoting or removing the last owner.

An invitation returns a token, which is its id. Your application delivers the invitation link to the invitee. The invitee accepts it while signed in with the invited email address. Read the active organization from `SessionData.Session.ActiveOrganizationID`.

### Teams

Teams group organization members for scoped access. A team belongs to exactly one organization. A team member must already be a member of the organization. Team membership carries no role; the organization role stays authoritative for permissions.

Endpoints (mounted under the auth handler, all require a session):

- `POST /organization/create-team` — create a team. Body: `organizationId`, `name`.
- `GET /organization/list-teams?organizationId=...` — list the teams of an organization.
- `POST /organization/update-team` — rename a team. Body: `organizationId`, `teamId`, `name`.
- `POST /organization/delete-team` — delete a team and its memberships. Body: `organizationId`, `teamId`.
- `POST /organization/add-team-member` — add an organization member to a team. Body: `organizationId`, `teamId`, `userId`.
- `POST /organization/remove-team-member` — remove a team member. Body: `organizationId`, `teamId`, `userId`.
- `GET /organization/list-team-members?organizationId=...&teamId=...` — list team members.

The `owner` and `admin` roles hold the `team:create`, `team:update`, `team:delete`, `team:view`, and `team:member:manage` permissions. The `member` role holds `team:view`.

An invitation accepts an optional `teamId`. When set, acceptance creates the organization membership and the team membership in one atomic operation. When a team is deleted, its pending invitations lose the team assignment and stay acceptable as plain organization invitations. When an organization membership is removed, the database removes the member's team memberships in the same operation. Run migration 4 before you use teams.

## Account Linking

Add the accountlink module for an explicit account-linking confirmation flow. Canopy never links accounts implicitly; without this module, a provider identity that matches an existing account is rejected.

```go
import "github.com/ssnxd/canopy/accountlink"

auth, err := canopy.New(canopy.Config{
	Store:     store,
	Secret:    os.Getenv("CANOPY_SECRET"),
	Providers: providers,
	Modules: []canopy.Module{
		accountlink.New(accountlink.Options{}),
	},
})
```

Endpoints (mounted under the auth handler, both require a session):

- `POST /link-social` — start a link. Body: `provider`, optional `callbackURL`. Returns the provider authorization URL.
- `GET|POST /link-social/callback/{provider}` — complete the link. Returns `{"success": true, "providerId": ..., "accountId": ...}` or redirects to the callback URL.

The flow fails closed:

- The session must be recent. The default `RecentAuthMaxAge` is 10 minutes; after that, the user must sign in again before linking.
- An impersonated session cannot link accounts.
- The provider email must be verified and must equal the session user's email.
- The link state is signed, single-use, bound to the browser with an HttpOnly cookie, and expires after `LinkStateTTL` (default 10 minutes).
- A provider account that belongs to another user returns a conflict.
- A start request for a provider that the user already linked returns a conflict.

The store consumes the link state and creates the provider account in one atomic operation. No schema migration is needed; the flow reuses the verification and account tables.

## Admin

Add the admin module for administrator operations.

```go
import "github.com/ssnxd/canopy/admin"

auth, err := canopy.New(canopy.Config{
	Store:   store,
	Secret:  os.Getenv("CANOPY_SECRET"),
	Modules: []canopy.Module{
		admin.New(admin.Options{AdminRoles: []string{"admin"}}),
	},
})
```

The store must implement `canopy.AdminStore`. The Postgres store and the in-memory store implement it.

An `AdminAuthorizer` decides who is an admin. The default treats a user with the role `admin` as an administrator. Set a role with the admin API or with your own provisioning. Set `Options.Authorizer` for custom rules.

Endpoints (mounted under the auth handler, all require an admin session unless noted):

- `GET /admin/users?q=&limit=&offset=` — list users with a search and paging.
- `POST /admin/create-user` — create a user with an email/password account.
- `POST /admin/set-role` — set a user role.
- `POST /admin/ban-user` — ban a user, with an optional reason and `expiresInSeconds`.
- `POST /admin/unban-user` — remove a ban.
- `GET /admin/user-sessions?userId=...` — list a user's sessions.
- `POST /admin/revoke-user-sessions` — revoke all of a user's sessions.
- `POST /admin/impersonate` — start a session as another user.
- `POST /admin/stop-impersonating` — end impersonation and restore the admin. Requires an impersonation session, not an admin session.

A ban takes effect at once. The module revokes the banned user's sessions, and the core rejects a banned user in `GetSession` and at sign-in. Impersonation records the admin on the session as `ImpersonatedBy`.

## Rate Limiting

Canopy does not include built-in rate limiting. Apply rate limits in your application before requests reach Canopy's HTTP handler or service calls. This keeps brute-force protection close to your deployment topology, whether that is a reverse proxy, API gateway, shared Redis-backed middleware, or framework-specific middleware.

```go
func rateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !allowRequest(r) {
			http.Error(w, "too many requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

mux := http.NewServeMux()
mux.Handle("/auth/", rateLimit(auth.Handler()))
```

For email/password sign-in, limit by IP address and normalized email where practical. In multi-instance deployments, use shared state at the gateway or middleware layer so attempts are counted consistently across instances.

## Email Delivery

Canopy generates email verification and password reset tokens, stores their hashes in `verification`, and calls `EmailSender`. Your application owns the actual email delivery provider and templates.

```go
type EmailSender interface {
	SendEmailVerification(ctx context.Context, message canopy.EmailVerificationMessage) error
	SendPasswordReset(ctx context.Context, message canopy.PasswordResetMessage) error
}
```

Each message includes:

- `User`
- `Email`
- `Token`
- `URL`
- `CallbackURL`
- `ExpiresAt`

`URL` is built by parsing `CallbackURL`, adding the URL-escaped token query
parameter, and preserving existing query parameters and fragments. If you
prefer to build links yourself, use `Token` directly.

Canopy validates `CallbackURL` before it builds the link. Canopy keeps a relative path or a URL on a trusted origin. Canopy drops any other URL and leaves `URL` and `CallbackURL` empty. `Token` stays available in that case. Add your web origin to `TrustedOrigins` to use absolute callback URLs. This prevents an attacker from delivering a one-time token to a host that they control.

```go
type Mailer struct{}

func (Mailer) SendEmailVerification(ctx context.Context, msg canopy.EmailVerificationMessage) error {
	return sendEmail(msg.Email, "Verify your email", msg.URL)
}

func (Mailer) SendPasswordReset(ctx context.Context, msg canopy.PasswordResetMessage) error {
	return sendEmail(msg.Email, "Reset your password", msg.URL)
}
```

## Audit Logging

```go
type AuditLogger interface {
	LogAuthEvent(ctx context.Context, event canopy.AuditEvent)
}
```

Canopy emits events for:

- Email sign-in success.
- Email sign-in failure.
- Email verification requested.
- Email verification success or failure.
- Password reset requested.
- Password reset success or failure.
- OAuth callback success.
- OAuth callback failure.
- Provider token refresh success.
- Provider token refresh failure.
- Session revocation.

Use this to send security events to structured logs, metrics, or a SIEM.

## Hooks

```go
type Hooks struct {
	BeforeUserCreate func(user *canopy.User) error
	AfterUserCreate  func(user canopy.User) error
	AfterSignIn      func(data canopy.SessionData) error
	AfterSignOut     func(session *canopy.Session) error
	AfterOAuth       func(data canopy.SessionData) error
	AfterEmailVerified func(user canopy.User) error
	AfterPasswordReset func(user canopy.User) error
}
```

Hooks are app-level callbacks. Audit logging is separate and should be used for security telemetry.

`BeforeUserCreate` runs before persistence and can reject the operation. Every
`After...` hook runs after the relevant state is committed. An after-hook error
does not turn a successful write into a false failure; Canopy sends it to
`Config.HookErrorHandler`. Configure that handler to report hook failures to
your logs or error monitor.

## Modules

A module is an optional feature that plugs into the handler and the service. The built-in features use this seam. A third-party plugin uses the same seam. Add a module through `Config.Modules`.

```go
type Module interface {
	ID() string
	Init(core canopy.Core) error
}
```

A module can also implement optional capabilities:

- `RouteModule` mounts HTTP routes under the handler.
- `SignInInterceptor` pauses session creation after primary authentication. The two-factor module uses this to require a second step.
- `SessionValidator` revalidates module-owned session state. The organization module uses this to reject stale active memberships.

`Core` is the narrow facade that a module depends on. It exposes the store,
non-secret `RuntimeConfig`, purpose-separated `ModuleKeys`, password hashing,
trusted client IP resolution, session operations, and audit logging. Root
configuration secrets and provider configuration are not exposed. Modules are
still trusted code because `Store` can contain sensitive application data.

The built-in two-factor, organization, and admin features are available today.
Each fails fast in `Init` when the configured store lacks its required
capability.

## Store Interface

Applications can implement custom storage by satisfying `canopy.Store`.

```go
type Store interface {
	FindUserByID(ctx context.Context, id string) (*canopy.User, error)
	FindUserByEmail(ctx context.Context, email string) (*canopy.User, error)
	CreateUser(ctx context.Context, user *canopy.User) error
	UpdateUser(ctx context.Context, user *canopy.User) error

	FindAccount(ctx context.Context, providerID, accountID string) (*canopy.Account, error)
	FindAccountByUserProvider(ctx context.Context, userID, providerID string) (*canopy.Account, error)
	CreateAccount(ctx context.Context, account *canopy.Account) error
	UpdateAccount(ctx context.Context, account *canopy.Account) error

	CreateSession(ctx context.Context, session *canopy.Session) error
	FindSessionByToken(ctx context.Context, token string) (*canopy.SessionData, error)
	UpdateSession(ctx context.Context, session *canopy.Session) error
	DeleteSessionByToken(ctx context.Context, token string) error
	DeleteUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context, now time.Time) error

	CreateVerification(ctx context.Context, verification *canopy.Verification) error
	ReplaceVerification(ctx context.Context, verification *canopy.Verification) error
	ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*canopy.Verification, error)
	DeleteVerificationsByIdentifier(ctx context.Context, identifier string) error
	DeleteExpiredVerifications(ctx context.Context, now time.Time) error
}
```

Custom stores should return Canopy typed errors, especially `ErrNotFound`,
`ErrConflict`, and `ErrStorageFailure`. The built-in modules require additional
interfaces such as `canopy.TwoFactorStore`, `canopy.OrganizationStore`, and
`canopy.AdminStore`. Methods documented as atomic must perform their complete
compare-and-write operation in one transaction.

The Postgres store and the in-memory store (`store/memory`) implement the core
store and the built-in capabilities. They also provide atomic user/account
creation and password reset operations discovered by Canopy. Custom stores
should provide methods with the same signatures as `CreateUserAccount` and
`ApplyPasswordReset`:

```go
CreateUserAccount(ctx context.Context, user *canopy.User, account *canopy.Account) error
ApplyPasswordReset(ctx context.Context, identifier, value string, now time.Time, account *canopy.Account) error
```

Otherwise Canopy uses the portable multi-call fallback.
Use `store/memory` for tests and local development. It is not durable.

## Data Model

### User

```go
type User struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         string
	Role          string
	Banned        bool
	BanReason     string
	BanExpiresAt  *time.Time
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
```

`Role`, `Banned`, `BanReason`, and `BanExpiresAt` support the admin module. A banned user is not authenticated. A ban with an expiry in the past is not active.

### Session

```go
type Session struct {
	ID                   string
	UserID               string
	Token                string
	ExpiresAt            time.Time
	IPAddress            string
	UserAgent            string
	ActiveOrganizationID string
	ImpersonatedBy       string
	CreatedAt            time.Time
	UpdatedAt            time.Time
}
```

`Token` is intentionally omitted from JSON responses. `ActiveOrganizationID` holds the active organization for the session. `ImpersonatedBy` records the admin user during impersonation.

### Account

```go
type Account struct {
	ID                    string
	UserID                string
	AccountID             string
	ProviderID            string
	AccessToken           string
	RefreshToken          string
	AccessTokenExpiresAt  *time.Time
	RefreshTokenExpiresAt *time.Time
	Scope                 string
	IDToken               string
	Password              string
	CreatedAt             time.Time
	UpdatedAt             time.Time
}
```

Email/password credentials are stored as an account with provider ID `email-password`.

### Verification

```go
type Verification struct {
	ID         string
	Identifier string
	Value      string
	ExpiresAt  time.Time
	CreatedAt  time.Time
	UpdatedAt  time.Time
}
```

OAuth state replay prevention, email verification, and password reset use the verification store in v1. Stored values are hashes of one-time signed tokens.

## Public Errors

Canopy exposes typed sentinel errors:

- `ErrInvalidCredentials`
- `ErrSignupDisabled`
- `ErrUnverifiedEmail`
- `ErrInvalidState`
- `ErrInvalidToken`
- `ErrExpiredToken`
- `ErrProviderFailure`
- `ErrStorageFailure`
- `ErrAccountLinking`
- `ErrAccountLinkMismatch`
- `ErrNoRefreshToken`
- `ErrProviderTokenRefreshFailed`
- `ErrProviderAccountNotFound`
- `ErrNotFound`
- `ErrConflict`
- `ErrInvalidInput`
- `ErrUnauthorized`
- `ErrForbidden`
- `ErrUserBanned`
- `ErrInvalidTwoFactorCode`
- `ErrRecentAuthentication`
- `ErrOrganizationNotFound`
- `ErrTeamNotFound`
- `ErrNotOrganizationMember`
- `ErrInvitationInvalid`
- `ErrLastOrganizationOwner`

Use `errors.Is(err, canopy.ErrInvalidCredentials)` rather than comparing error strings.
Invalid input may also be a `*canopy.ValidationError`; its `Fields` map is
returned by the HTTP API as stable field-level details.

## Security Defaults

- Argon2id password hashing.
- Bounded Argon2id parameters when verifying stored hashes.
- Opaque random session tokens generated with `crypto/rand`.
- SHA-256 session-token digests at rest.
- AES-256-GCM encryption of OAuth provider credentials at rest by default.
- Server-side session storage.
- Fresh session token after every successful authentication.
- Absolute and sliding session lifetimes.
- HttpOnly session cookies.
- SameSite=Lax by default.
- Cross-origin request checks use the Origin header and Sec-Fetch metadata.
- Secure cookies in production.
- Production-safe environment defaults and secret/configuration validation.
- Forwarded client IPs accepted only from configured trusted proxies.
- Conservative email normalization.
- OAuth PKCE.
- OAuth nonce validation.
- OAuth provider configuration validation and cached OIDC discovery.
- Verified provider email claims required before email-based account decisions.
- Signed state.
- State cookie binding.
- Server-side state replay prevention.
- Signed one-time email verification tokens.
- Signed one-time password reset tokens.
- Latest-token-only password reset with atomic consumption and session revocation in built-in stores.
- TOTP replay prevention, one-time backup codes, and recent-authentication requirements for two-factor changes.
- Parent-session proof for ending admin impersonation.
- Last-owner protection and active-membership revalidation for organizations.
- Callback and OAuth redirect URLs are limited to trusted origins.
- Strict, size-bounded request parsing and defensive browser response headers.
- Typed errors mapped to stable JSON codes.
- Staged key rotation through `PreviousSecrets`.

## Important Caveats

Account linking:

Canopy does not silently link accounts by email. If a user signs up with email/password and later signs in with Google using the same email, Canopy returns `ErrAccountLinking`. This avoids the common security footgun of treating “same email” as proof of same identity across providers. Add the accountlink module for the explicit confirmation flow.

Custom stores:

Canopy can only provide the same atomicity as the configured store. The
Postgres and memory adapters implement atomic account provisioning, password
reset, two-factor enrollment and consumption, organization creation,
invitation acceptance, role protection, and member removal. Custom stores must
honor the atomic method contracts and should implement the optional atomic
user/account and password-reset capabilities described above.

Rate limiting:

Canopy does not enforce request limits internally. Add rate limiting in middleware, a gateway, or another application-owned layer before auth requests reach Canopy.

Provider token refresh:

`GET /get-session` never refreshes Google or Apple access tokens. Use `RefreshProviderToken` when your application is about to call provider APIs and needs a fresh access token.

Apple profile data:

Apple may only provide some user fields once. Store what you need on first sign-in.

Email delivery:

Canopy calls `EmailSender`, but it does not send SMTP or provider email itself. Applications must connect this to their email provider.

Key rotation:

Removing a previous key too early invalidates outstanding signed links and can
make provider or two-factor ciphertext unreadable. Keep it configured until
the token lifetime has elapsed and persistent ciphertext has been re-encrypted,
or use application-owned codecs backed by a KMS.

## Roadmap

The intent is to grow Canopy toward Better Auth feature parity while keeping Go-native APIs:

- Magic link.
- Passkeys/WebAuthn.
- More OAuth providers.
- MySQL and SQLite stores.
- Device/session management.
- Optional stateless or cookie-cache session strategies.

## Design Principles

- Library first, not hosted service.
- `net/http` first, no framework lock-in.
- Opaque database-backed sessions by default.
- Provider tokens are separate from Canopy sessions.
- Explicit security failures over silent magic.
- Typed errors over string matching.
- Narrow interfaces for custom storage and enterprise integration.
