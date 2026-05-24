# Canopy

Canopy is a Go authentication library for API servers. It provides email/password auth, Google and Apple OAuth sign-in, database-backed opaque sessions, rate-limiting hooks, audit hooks, and a Postgres storage adapter.

Canopy is inspired by [Better Auth](https://better-auth.com/): the core entity names, route names, and product direction intentionally follow the same mental model. Canopy is not a Better Auth port and it is not a hosted service. It is a Go-native library built around `net/http`, explicit interfaces, typed errors, and server-side session storage.

The long-term goal is to support the full Better Auth feature surface in Go over time, while keeping the v1 API small, explicit, and production-oriented.

Project docs:

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
- Built-in in-memory rate limiter.
- Audit logging interface.
- Postgres store and schema migration.
- Typed public errors for common auth failures.

Not implemented yet:

- Magic link, passkeys, two-factor auth, organization/team features, admin APIs, and plugins.
- First-party adapters for Gin, Echo, Chi, Gorilla, etc. `net/http` works with most routers directly.
- Distributed rate limiting. The built-in limiter is process-local.
- Automatic provider token refresh during session lookup. This is intentionally separate.
- Explicit account-linking confirmation flow. v1 rejects unsafe implicit linking.

## Install

```sh
go get github.com/ssnxd/canopy
go get github.com/ssnxd/canopy/store/postgres
go get github.com/ssnxd/canopy/providers/google
go get github.com/ssnxd/canopy/providers/apple
go get github.com/ssnxd/canopy/ratelimit
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

	"github.com/ssnxd/canopy"
	"github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/providers/google"
	"github.com/ssnxd/canopy/ratelimit"
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
		TrustedOrigins: []string{
			"https://app.example.com",
		},
		RateLimiter: ratelimit.New(ratelimit.Config{}),
		Providers: []oauth.Provider{
			google.Provider{
				ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
				ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
				RedirectURL:  "https://api.example.com/callback/google",
			},
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
	mux.Handle("/api/me", auth.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := canopy.SessionFromContext(r.Context())
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = json.NewEncoder(w).Encode(session.User)
	})))

	log.Fatal(http.ListenAndServe(":8080", mux))
}
```

`database/sql` drivers are registered by side-effect imports in the application binary. If you use `sql.Open("postgres", ...)`, import `github.com/lib/pq` as shown above. If you prefer pgx, import `github.com/jackc/pgx/v5/stdlib` and open the database with `sql.Open("pgx", ...)`.

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

Important constraints and indexes:

- Unique normalized user email: `lower(email)`.
- Unique session token.
- Unique OAuth account pair: `(provider_id, account_id)`.
- Unique user-provider pair: `(user_id, provider_id)`.
- Foreign keys from `session.user_id` and `account.user_id` to `user.id`.
- Expiry indexes for session and verification cleanup.

## Configuration

```go
type Config struct {
	Store       canopy.Store
	Secret      string
	Environment canopy.Environment
	BasePath    string

	DisableSignup            bool
	RequireEmailVerification bool
	PasswordMinLength        int
	PasswordMaxLength        int
	PasswordHasher           password.Hasher

	RateLimiter          canopy.RateLimiter
	AuditLogger          canopy.AuditLogger
	EmailSender          canopy.EmailSender
	AccountLinkingPolicy canopy.AccountLinkingPolicy

	TrustedOrigins     []string
	DisableOriginCheck bool

	Providers            []oauth.Provider
	OAuthStateTTL        time.Duration
	OAuthStateCookieName string
	EmailVerificationTTL time.Duration
	PasswordResetTTL     time.Duration

	Session sessions.Config
	Hooks   canopy.Hooks
}
```

Defaults:

- Environment: `development`.
- Password length: 8 to 128 characters.
- Password hashing: Argon2id.
- Session expiry: 7 days.
- Session refresh/update age: 1 day.
- Session cookie: `canopy.session_token`.
- OAuth state TTL: 10 minutes.
- Email verification TTL: 24 hours.
- Password reset TTL: 1 hour.
- Account linking policy: reject implicit linking.

Production requirements:

- `Secret` must be at least 32 bytes in production.
- Cookies are `Secure` in production.
- Set `TrustedOrigins` for browser-facing deployments.
- Use a shared rate limiter in multi-instance deployments if brute-force protection must be global.

## HTTP API

Mount the handler:

```go
mux.Handle("/auth/", http.StripPrefix("/auth", auth.Handler()))
```

The examples below assume the handler is mounted at `/auth`.

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
    "emailVerified": true,
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

When `RequireEmailVerification` is enabled, sign-up creates the user with `emailVerified=false`, creates a one-time verification token, and calls `EmailSender.SendEmailVerification`. Email/password sign-in returns `UNVERIFIED_EMAIL` until the token is verified.

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
middleware := auth.Middleware(next)
```

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
data, token, err := auth.API().SignInEmail(ctx, canopy.SignInEmailInput{
	Email:    "ada@example.com",
	Password: "correct-password",
})
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
data, sessionToken, callbackURL, rememberMe, err := auth.API().OAuthCallback(ctx, canopy.OAuthCallbackInput{
	Provider:     "google",
	Code:         code,
	State:        state,
	StateBinding: stateCookieValue,
	IPAddress:    ip,
	UserAgent:    userAgent,
})
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

## Rate Limiting

Canopy calls `RateLimiter.Allow` before email/password sign-in and `RateLimiter.Report` after success or failure.

```go
type RateLimiter interface {
	Allow(ctx context.Context, request canopy.RateLimitRequest) error
	Report(ctx context.Context, request canopy.RateLimitRequest, success bool)
}
```

Use the built-in limiter:

```go
limiter := ratelimit.New(ratelimit.Config{
	FailureLimit:  5,
	FailureWindow: 15 * time.Minute,
})

auth, err := canopy.New(canopy.Config{
	Store:       store,
	Secret:      os.Getenv("CANOPY_SECRET"),
	RateLimiter: limiter,
})
```

Inspect attempts:

```go
snapshot := limiter.Snapshot(canopy.RateLimitRequest{
	Email:     "ada@example.com",
	IPAddress: "203.0.113.10",
})
```

The built-in limiter is in-memory. For horizontally scaled production systems, implement `RateLimiter` with Redis, your gateway, or another shared system.

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

`URL` is built by appending `?token=...` or `&token=...` to `CallbackURL`. If you prefer to build links yourself, use `Token` directly.

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
- Rate-limited sign-in attempts.
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

	CreateVerification(ctx context.Context, verification *canopy.Verification) error
	ConsumeVerification(ctx context.Context, identifier, value string, now time.Time) (*canopy.Verification, error)
	DeleteExpiredVerifications(ctx context.Context, now time.Time) error
}
```

Custom stores should return Canopy typed errors where possible, especially `ErrNotFound` and `ErrConflict`.

## Data Model

### User

```go
type User struct {
	ID            string
	Name          string
	Email         string
	EmailVerified bool
	Image         string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}
```

### Session

```go
type Session struct {
	ID        string
	UserID    string
	Token     string
	ExpiresAt time.Time
	IPAddress string
	UserAgent string
	CreatedAt time.Time
	UpdatedAt time.Time
}
```

`Token` is intentionally omitted from JSON responses.

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
- `ErrRateLimited`
- `ErrAccountLinking`
- `ErrNoRefreshToken`
- `ErrProviderTokenRefreshFailed`
- `ErrProviderAccountNotFound`
- `ErrNotFound`
- `ErrConflict`
- `ErrInvalidInput`
- `ErrUnauthorized`

Use `errors.Is(err, canopy.ErrInvalidCredentials)` rather than comparing error strings.

## Security Defaults

- Argon2id password hashing.
- Opaque random session tokens generated with `crypto/rand`.
- Server-side session storage.
- Fresh session token after every successful authentication.
- HttpOnly session cookies.
- SameSite=Lax by default.
- Secure cookies in production.
- Production secret length validation.
- Conservative email normalization.
- OAuth PKCE.
- OAuth nonce validation.
- Signed state.
- State cookie binding.
- Server-side state replay prevention.
- Signed one-time email verification tokens.
- Signed one-time password reset tokens.
- Password reset revokes existing sessions.
- Typed errors mapped to stable JSON codes.

## Important Caveats

Account linking:

Canopy does not silently link accounts by email. If a user signs up with email/password and later signs in with Google using the same email, Canopy returns `ErrAccountLinking`. This avoids the common security footgun of treating “same email” as proof of same identity across providers. Build an explicit confirmation flow for linking.

Transactions:

The current `Store` interface performs user, account, and session writes as separate calls. The Postgres adapter relies on constraints, but a future hardening pass should add store-level transactional creation APIs so user/account/session creation is atomic.

Rate limiting:

The built-in limiter is process-local. It is useful for one-instance deployments and tests. Use a shared implementation for multi-instance production.

Provider token refresh:

`GET /get-session` never refreshes Google or Apple access tokens. Use `RefreshProviderToken` when your application is about to call provider APIs and needs a fresh access token.

Apple profile data:

Apple may only provide some user fields once. Store what you need on first sign-in.

Email delivery:

Canopy calls `EmailSender`, but it does not send SMTP or provider email itself. Applications must connect this to their email provider.

## Roadmap

The intent is to grow Canopy toward Better Auth feature parity while keeping Go-native APIs:

- Magic link.
- Passkeys/WebAuthn.
- Two-factor authentication.
- Organization/team support.
- Admin user management APIs.
- Account linking confirmation flows.
- More OAuth providers.
- Redis-backed rate limiter.
- MySQL and SQLite stores.
- Transactional store APIs.
- Session listing APIs.
- Device/session management.
- Hooks and plugin system.
- First-party router adapters where `net/http` is not ergonomic enough.
- Optional stateless or cookie-cache session strategies.

## Design Principles

- Library first, not hosted service.
- `net/http` first, no framework lock-in.
- Opaque database-backed sessions by default.
- Provider tokens are separate from Canopy sessions.
- Explicit security failures over silent magic.
- Typed errors over string matching.
- Narrow interfaces for custom storage and enterprise integration.
