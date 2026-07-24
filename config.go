package canopy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/ssnxd/canopy/oauth"
	"github.com/ssnxd/canopy/password"
	"github.com/ssnxd/canopy/sessions"
)

type Environment string

const (
	Development Environment = "development"
	Production  Environment = "production"
)

type Hooks struct {
	BeforeUserCreate   func(user *User) error
	AfterUserCreate    func(user User) error
	AfterSignIn        func(data SessionData) error
	AfterSignOut       func(session *Session) error
	AfterOAuth         func(data SessionData) error
	AfterEmailVerified func(user User) error
	AfterPasswordReset func(user User) error
}

type AuditEvent struct {
	Type       string
	UserID     string
	Email      string
	ProviderID string
	IPAddress  string
	UserAgent  string
	Success    bool
	Error      string
	At         time.Time
}

type AuditLogger interface {
	LogAuthEvent(ctx context.Context, event AuditEvent)
}

type noopAuditLogger struct{}

func (noopAuditLogger) LogAuthEvent(ctx context.Context, event AuditEvent) {}

type EmailVerificationMessage struct {
	User        User
	Email       string
	Token       string
	URL         string
	CallbackURL string
	ExpiresAt   time.Time
}

type PasswordResetMessage struct {
	User        User
	Email       string
	Token       string
	URL         string
	CallbackURL string
	ExpiresAt   time.Time
}

type EmailSender interface {
	SendEmailVerification(ctx context.Context, message EmailVerificationMessage) error
	SendPasswordReset(ctx context.Context, message PasswordResetMessage) error
}

type noopEmailSender struct{}

func (noopEmailSender) SendEmailVerification(ctx context.Context, message EmailVerificationMessage) error {
	return nil
}

func (noopEmailSender) SendPasswordReset(ctx context.Context, message PasswordResetMessage) error {
	return nil
}

type AccountLinkingPolicy string

const (
	AccountLinkingRejectExplicit AccountLinkingPolicy = "reject-explicit"
)

type Config struct {
	Store       Store
	Secret      string
	Environment Environment
	BasePath    string

	DisableSignup            bool
	RequireEmailVerification bool
	PasswordMinLength        int
	PasswordMaxLength        int
	PasswordHasher           password.Hasher
	ProviderTokenCodec       ProviderTokenCodec
	AuditLogger              AuditLogger
	EmailSender              EmailSender
	AccountLinkingPolicy     AccountLinkingPolicy
	TrustedOrigins           []string
	DisableOriginCheck       bool
	Providers                []oauth.Provider
	OAuthStateTTL            time.Duration
	OAuthStateCookieName     string
	EmailVerificationTTL     time.Duration
	PasswordResetTTL         time.Duration

	Modules []Module

	Session sessions.Config
	Hooks   Hooks
}

func (c *Config) setDefaults() {
	if c.Environment == "" {
		c.Environment = Development
	}
	if c.BasePath == "" {
		c.BasePath = "/"
	}
	if c.PasswordMinLength == 0 {
		c.PasswordMinLength = 8
	}
	if c.PasswordMaxLength == 0 {
		c.PasswordMaxLength = 128
	}
	if c.PasswordHasher == nil {
		c.PasswordHasher = password.DefaultHasher()
	}
	if c.ProviderTokenCodec == nil {
		c.ProviderTokenCodec = newProviderTokenCodec(c.Secret)
	}
	if c.AuditLogger == nil {
		c.AuditLogger = noopAuditLogger{}
	}
	if c.EmailSender == nil {
		c.EmailSender = noopEmailSender{}
	}
	if c.AccountLinkingPolicy == "" {
		c.AccountLinkingPolicy = AccountLinkingRejectExplicit
	}
	if c.OAuthStateTTL == 0 {
		c.OAuthStateTTL = 10 * time.Minute
	}
	if c.OAuthStateCookieName == "" {
		c.OAuthStateCookieName = "canopy.oauth_state"
	}
	if c.EmailVerificationTTL == 0 {
		c.EmailVerificationTTL = 24 * time.Hour
	}
	if c.PasswordResetTTL == 0 {
		c.PasswordResetTTL = time.Hour
	}
	c.Session.SetDefaults(c.Environment == Production)
	if c.Session.Expiry == 0 {
		c.Session.Expiry = 7 * 24 * time.Hour
	}
	if c.Session.UpdateAge == 0 {
		c.Session.UpdateAge = 24 * time.Hour
	}
}

func (c Config) validate() error {
	if c.Store == nil {
		return errors.New("canopy: store is required")
	}
	if c.Environment == Production && len(c.Secret) < 32 {
		return fmt.Errorf("canopy: production secret must be at least 32 bytes")
	}
	if c.Secret == "" {
		return fmt.Errorf("canopy: secret is required")
	}
	if c.PasswordMinLength < 1 || c.PasswordMaxLength < c.PasswordMinLength {
		return fmt.Errorf("canopy: invalid password length bounds")
	}
	seen := map[string]bool{}
	for _, provider := range c.Providers {
		if provider == nil || provider.ID() == "" {
			return fmt.Errorf("canopy: oauth provider id is required")
		}
		if seen[provider.ID()] {
			return fmt.Errorf("canopy: duplicate oauth provider %q", provider.ID())
		}
		seen[provider.ID()] = true
	}
	moduleSeen := map[string]bool{}
	for _, module := range c.Modules {
		if module == nil || module.ID() == "" {
			return fmt.Errorf("canopy: module id is required")
		}
		if moduleSeen[module.ID()] {
			return fmt.Errorf("canopy: duplicate module %q", module.ID())
		}
		moduleSeen[module.ID()] = true
	}
	return nil
}

func (c Config) CheckOrigin(r *http.Request) bool {
	if c.DisableOriginCheck || r.Method == http.MethodGet || r.Method == http.MethodHead || r.Method == http.MethodOptions {
		return true
	}
	origin := r.Header.Get("Origin")
	// Sec-Fetch-Site is set by the browser and script cannot change it.
	// Use it first, because it is the most reliable signal.
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin", "none":
		return true
	case "cross-site", "same-site":
		return origin != "" && c.isTrustedOrigin(origin)
	}
	// No Sec-Fetch metadata. Fall back to the Origin header.
	// A missing Origin is a non-browser client, so allow it.
	if origin == "" {
		return true
	}
	return c.isTrustedOrigin(origin)
}

// isTrustedOrigin reports if origin is in the trusted origin list.
func (c Config) isTrustedOrigin(origin string) bool {
	return slices.Contains(c.TrustedOrigins, origin)
}

// resolveCallbackURL returns callbackURL only when it is safe to use.
// It permits a relative path or a URL on a trusted origin.
// It returns an empty string for an untrusted or invalid URL.
// This prevents callback URLs from leaking one-time tokens to
// attacker-controlled hosts and prevents open-redirect abuse.
func (c Config) resolveCallbackURL(callbackURL string) string {
	callbackURL = strings.TrimSpace(callbackURL)
	if callbackURL == "" {
		return ""
	}
	u, err := url.Parse(callbackURL)
	if err != nil {
		return ""
	}
	if u.Scheme == "" && u.Host == "" {
		return callbackURL
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return ""
	}
	if c.isTrustedOrigin(u.Scheme + "://" + u.Host) {
		return callbackURL
	}
	return ""
}
