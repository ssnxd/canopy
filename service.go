package canopy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/ssnxd/canopy/oauth"
	xoauth2 "golang.org/x/oauth2"
)

type contextKey string

const sessionContextKey contextKey = "canopy.session"

type SignUpEmailInput struct {
	Name        string
	Email       string
	Password    string
	Image       string
	CallbackURL string
	RememberMe  *bool
	IPAddress   string
	UserAgent   string
}

type SignInEmailInput struct {
	Email      string
	Password   string
	RememberMe *bool
	IPAddress  string
	UserAgent  string
}

type SignInSocialInput struct {
	Provider    string
	CallbackURL string
	RememberMe  *bool
}

type SignInSocialOutput struct {
	URL string `json:"url"`
}

type OAuthCallbackInput struct {
	Provider     string
	Code         string
	State        string
	StateBinding string
	IPAddress    string
	UserAgent    string
}

type RefreshProviderTokenInput struct {
	UserID     string
	ProviderID string
}

type RefreshProviderTokenOutput struct {
	AccountID             string     `json:"accountId"`
	ProviderID            string     `json:"providerId"`
	AccessToken           string     `json:"accessToken"`
	RefreshToken          string     `json:"-"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt,omitempty"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt,omitempty"`
	Scope                 string     `json:"scope,omitempty"`
}

type SendEmailVerificationInput struct {
	Email       string
	CallbackURL string
}

type VerifyEmailInput struct {
	Token string
}

type RequestPasswordResetInput struct {
	Email       string
	CallbackURL string
}

type ResetPasswordInput struct {
	Token       string
	NewPassword string
}

type Service struct {
	cfg       Config
	providers map[string]oauth.Provider
	dummyOnce sync.Once
	dummyHash string
}

type userAccountStore interface {
	CreateUserAccount(ctx context.Context, user *User, account *Account) error
}

type oauthCallbackResult struct {
	Data        *SessionData
	Token       string
	CallbackURL string
	RememberMe  *bool
}

type actionTokenKind struct {
	purpose   string
	ttl       time.Duration
	auditBase string
}

func newService(cfg Config) *Service {
	providers := make(map[string]oauth.Provider, len(cfg.Providers))
	for _, provider := range cfg.Providers {
		providers[provider.ID()] = provider
	}
	return &Service{cfg: cfg, providers: providers}
}

func (s *Service) SignUpEmail(ctx context.Context, in SignUpEmailInput) (*SessionData, string, error) {
	if s.cfg.DisableSignup {
		return nil, "", ErrSignupDisabled
	}
	email := normalizeEmail(in.Email)
	if err := validateEmailPassword(email, in.Password, s.cfg.PasswordMinLength, s.cfg.PasswordMaxLength); err != nil {
		return nil, "", err
	}
	if strings.TrimSpace(in.Name) == "" {
		return nil, "", ErrInvalidInput
	}
	if existing, err := s.cfg.Store.FindUserByEmail(ctx, email); err == nil && existing != nil {
		return nil, "", ErrConflict
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	now := time.Now().UTC()
	userID, err := newID("usr")
	if err != nil {
		return nil, "", err
	}
	user := &User{
		ID:        userID,
		Name:      strings.TrimSpace(in.Name),
		Email:     email,
		Image:     strings.TrimSpace(in.Image),
		CreatedAt: now,
		UpdatedAt: now,
	}
	if !s.cfg.RequireEmailVerification {
		user.EmailVerified = true
	}
	if s.cfg.Hooks.BeforeUserCreate != nil {
		if err := s.cfg.Hooks.BeforeUserCreate(user); err != nil {
			return nil, "", err
		}
	}
	hash, err := s.cfg.PasswordHasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, "", err
	}
	accountID, err := newID("acc")
	if err != nil {
		return nil, "", err
	}
	account := &Account{
		ID:         accountID,
		UserID:     user.ID,
		AccountID:  email,
		ProviderID: ProviderEmailPassword,
		Password:   hash,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.createUserAccount(ctx, user, account); err != nil {
		return nil, "", err
	}
	if s.cfg.Hooks.AfterUserCreate != nil {
		if err := s.cfg.Hooks.AfterUserCreate(*user); err != nil {
			return nil, "", err
		}
	}
	if s.cfg.RequireEmailVerification {
		if err := s.sendEmailVerification(ctx, *user, in.CallbackURL); err != nil {
			return nil, "", err
		}
	}
	return s.createSession(ctx, *user, in.RememberMe, in.IPAddress, in.UserAgent)
}

func (s *Service) SendEmailVerification(ctx context.Context, in SendEmailVerificationInput) error {
	email := normalizeEmail(in.Email)
	user, err := s.cfg.Store.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.audit(ctx, AuditEvent{Type: "email_verification.requested", Email: email, Success: true})
			return nil
		}
		return err
	}
	if user.EmailVerified {
		s.audit(ctx, AuditEvent{Type: "email_verification.requested_already_verified", UserID: user.ID, Email: user.Email, Success: true})
		return nil
	}
	return s.sendEmailVerification(ctx, *user, in.CallbackURL)
}

func (s *Service) VerifyEmail(ctx context.Context, in VerifyEmailInput) (*User, error) {
	kind := s.emailVerificationTokenKind()
	payload, err := s.consumeActionToken(ctx, kind, in.Token)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "email_verification.failed", Success: false, Error: err.Error()})
		return nil, err
	}
	user, err := s.cfg.Store.FindUserByEmail(ctx, payload.Email)
	if err != nil {
		return nil, err
	}
	if !user.EmailVerified {
		user.EmailVerified = true
		user.UpdatedAt = time.Now().UTC()
		if err := s.cfg.Store.UpdateUser(ctx, user); err != nil {
			return nil, err
		}
	}
	if s.cfg.Hooks.AfterEmailVerified != nil {
		if err := s.cfg.Hooks.AfterEmailVerified(*user); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, AuditEvent{Type: "email_verification.succeeded", UserID: user.ID, Email: user.Email, Success: true})
	return user, nil
}

func (s *Service) RequestPasswordReset(ctx context.Context, in RequestPasswordResetInput) error {
	email := normalizeEmail(in.Email)
	user, err := s.cfg.Store.FindUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			s.audit(ctx, AuditEvent{Type: "password_reset.requested", Email: email, Success: true})
			return nil
		}
		return err
	}
	account, err := s.cfg.Store.FindAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
	if err != nil || account.Password == "" {
		s.audit(ctx, AuditEvent{Type: "password_reset.requested_no_password_account", UserID: user.ID, Email: user.Email, Success: true})
		return nil
	}
	kind := s.passwordResetTokenKind()
	token, expiresAt, err := s.issueActionToken(ctx, kind, user.Email)
	if err != nil {
		return err
	}
	callbackURL := s.cfg.resolveCallbackURL(in.CallbackURL)
	message := PasswordResetMessage{
		User:        *user,
		Email:       user.Email,
		Token:       token,
		URL:         appendToken(callbackURL, token),
		CallbackURL: callbackURL,
		ExpiresAt:   expiresAt,
	}
	if err := s.cfg.EmailSender.SendPasswordReset(ctx, message); err != nil {
		return err
	}
	s.audit(ctx, AuditEvent{Type: "password_reset.requested", UserID: user.ID, Email: user.Email, Success: true})
	return nil
}

func (s *Service) ResetPassword(ctx context.Context, in ResetPasswordInput) error {
	if len(in.NewPassword) < s.cfg.PasswordMinLength || len(in.NewPassword) > s.cfg.PasswordMaxLength {
		return ErrInvalidInput
	}
	kind := s.passwordResetTokenKind()
	payload, err := s.consumeActionToken(ctx, kind, in.Token)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "password_reset.failed", Success: false, Error: err.Error()})
		return err
	}
	user, err := s.cfg.Store.FindUserByEmail(ctx, payload.Email)
	if err != nil {
		return err
	}
	account, err := s.cfg.Store.FindAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
	if err != nil || account.Password == "" {
		return ErrInvalidToken
	}
	hash, err := s.cfg.PasswordHasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	account.Password = hash
	account.UpdatedAt = time.Now().UTC()
	if err := s.cfg.Store.UpdateAccount(ctx, account); err != nil {
		return err
	}
	if err := s.cfg.Store.DeleteUserSessions(ctx, user.ID); err != nil {
		return err
	}
	if s.cfg.Hooks.AfterPasswordReset != nil {
		if err := s.cfg.Hooks.AfterPasswordReset(*user); err != nil {
			return err
		}
	}
	s.audit(ctx, AuditEvent{Type: "password_reset.succeeded", UserID: user.ID, Email: user.Email, Success: true})
	return nil
}

func (s *Service) SignInSocial(ctx context.Context, in SignInSocialInput) (*SignInSocialOutput, string, error) {
	provider, ok := s.providers[in.Provider]
	if !ok {
		return nil, "", ErrProviderFailure
	}
	cfg, err := provider.Config(ctx)
	if err != nil {
		return nil, "", err
	}
	stateID, err := randomToken(18)
	if err != nil {
		return nil, "", err
	}
	nonce, err := randomToken(18)
	if err != nil {
		return nil, "", err
	}
	pkce, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	binding, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	payload := oauthStatePayload{
		ID:           stateID,
		Provider:     provider.ID(),
		Nonce:        nonce,
		PKCEVerifier: pkce,
		CallbackURL:  s.cfg.resolveCallbackURL(in.CallbackURL),
		BindingHash:  hashString(binding),
		RememberMe:   in.RememberMe,
		IssuedAt:     time.Now().UTC(),
	}
	state, err := s.signOAuthState(payload)
	if err != nil {
		return nil, "", err
	}
	now := time.Now().UTC()
	verificationID, err := newID("ver")
	if err != nil {
		return nil, "", err
	}
	if err := s.cfg.Store.CreateVerification(ctx, &Verification{
		ID:         verificationID,
		Identifier: oauthStateIdentifier,
		Value:      hashString(state),
		ExpiresAt:  now.Add(s.cfg.OAuthStateTTL),
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return nil, "", err
	}
	start := oauth.StartOptions{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: pkce,
		CallbackURL:  payload.CallbackURL,
	}
	authOpts := append(provider.AuthCodeOptions(start), xoauth2.SetAuthURLParam("nonce", nonce))
	url := cfg.AuthCodeURL(state, authOpts...)
	return &SignInSocialOutput{URL: url}, binding, nil
}

func (s *Service) OAuthCallback(ctx context.Context, in OAuthCallbackInput) (*SessionData, string, string, *bool, error) {
	out, err := s.oauthCallback(ctx, in)
	if err != nil {
		return nil, "", "", nil, err
	}
	return out.Data, out.Token, out.CallbackURL, out.RememberMe, nil
}

func (s *Service) oauthCallback(ctx context.Context, in OAuthCallbackInput) (*oauthCallbackResult, error) {
	provider, ok := s.providers[in.Provider]
	if !ok {
		return nil, ErrProviderFailure
	}
	payload, err := s.verifyOAuthState(in.State)
	if err != nil || payload.Provider != provider.ID() || !hmac.Equal([]byte(payload.BindingHash), []byte(hashString(in.StateBinding))) {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: ErrInvalidState.Error()})
		return nil, ErrInvalidState
	}
	if _, err := s.cfg.Store.ConsumeVerification(ctx, oauthStateIdentifier, hashString(in.State), time.Now().UTC()); err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: ErrInvalidState.Error()})
		return nil, ErrInvalidState
	}
	tok, err := provider.Exchange(ctx, in.Code, payload.PKCEVerifier)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: err.Error()})
		return nil, ErrProviderFailure
	}
	profile, err := provider.Profile(ctx, tok, payload.Nonce)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: err.Error()})
		return nil, ErrProviderFailure
	}
	data, sessionToken, err := s.signInOAuthProfile(ctx, provider.ID(), profile, payload.RememberMe, in.IPAddress, in.UserAgent)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, Email: normalizeEmail(profile.Email), IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: err.Error()})
		return nil, err
	}
	if s.cfg.Hooks.AfterOAuth != nil {
		if err := s.cfg.Hooks.AfterOAuth(*data); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, AuditEvent{Type: "oauth.callback.succeeded", UserID: data.User.ID, Email: data.User.Email, ProviderID: provider.ID(), IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	return &oauthCallbackResult{
		Data:        data,
		Token:       sessionToken,
		CallbackURL: payload.CallbackURL,
		RememberMe:  payload.RememberMe,
	}, nil
}

func (s *Service) RefreshProviderToken(ctx context.Context, in RefreshProviderTokenInput) (*RefreshProviderTokenOutput, error) {
	if in.UserID == "" || in.ProviderID == "" {
		return nil, ErrInvalidInput
	}
	provider, ok := s.providers[in.ProviderID]
	if !ok {
		return nil, ErrProviderFailure
	}
	account, err := s.cfg.Store.FindAccountByUserProvider(ctx, in.UserID, in.ProviderID)
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, ErrProviderAccountNotFound
		}
		return nil, err
	}
	if account.RefreshToken == "" {
		s.audit(ctx, AuditEvent{Type: "oauth.token_refresh.failed", UserID: in.UserID, ProviderID: in.ProviderID, Success: false, Error: ErrNoRefreshToken.Error()})
		return nil, ErrNoRefreshToken
	}
	token, err := provider.Refresh(ctx, account.RefreshToken)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.token_refresh.failed", UserID: in.UserID, ProviderID: in.ProviderID, Success: false, Error: err.Error()})
		return nil, ErrProviderTokenRefreshFailed
	}
	if token.AccessToken == "" {
		s.audit(ctx, AuditEvent{Type: "oauth.token_refresh.failed", UserID: in.UserID, ProviderID: in.ProviderID, Success: false, Error: "empty access token"})
		return nil, ErrProviderTokenRefreshFailed
	}
	account.AccessToken = token.AccessToken
	if token.RefreshToken != "" {
		account.RefreshToken = token.RefreshToken
	}
	if !token.Expiry.IsZero() {
		exp := token.Expiry
		account.AccessTokenExpiresAt = &exp
	}
	if scope, ok := token.Extra("scope").(string); ok && scope != "" {
		account.Scope = scope
	}
	account.UpdatedAt = time.Now().UTC()
	if err := s.cfg.Store.UpdateAccount(ctx, account); err != nil {
		return nil, err
	}
	s.audit(ctx, AuditEvent{Type: "oauth.token_refresh.succeeded", UserID: in.UserID, ProviderID: in.ProviderID, Success: true})
	return &RefreshProviderTokenOutput{
		AccountID:             account.AccountID,
		ProviderID:            account.ProviderID,
		AccessToken:           account.AccessToken,
		RefreshToken:          account.RefreshToken,
		AccessTokenExpiresAt:  account.AccessTokenExpiresAt,
		RefreshTokenExpiresAt: account.RefreshTokenExpiresAt,
		Scope:                 account.Scope,
	}, nil
}

func (s *Service) signInOAuthProfile(ctx context.Context, providerID string, profile *oauth.Profile, rememberMe *bool, ip, ua string) (*SessionData, string, error) {
	if profile == nil || profile.AccountID == "" {
		return nil, "", ErrProviderFailure
	}
	if profile.ProviderID != "" && profile.ProviderID != providerID {
		return nil, "", ErrProviderFailure
	}
	account, err := s.cfg.Store.FindAccount(ctx, providerID, profile.AccountID)
	if err == nil {
		user, err := s.cfg.Store.FindUserByID(ctx, account.UserID)
		if err != nil {
			return nil, "", err
		}
		updateAccountFromProfile(account, profile)
		account.UpdatedAt = time.Now().UTC()
		_ = s.cfg.Store.UpdateAccount(ctx, account)
		return s.createSession(ctx, *user, rememberMe, ip, ua)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	email := normalizeEmail(profile.Email)
	if email == "" {
		return nil, "", ErrProviderFailure
	}
	if existing, err := s.cfg.Store.FindUserByEmail(ctx, email); err == nil && existing != nil {
		return nil, "", ErrAccountLinking
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, "", err
	}
	now := time.Now().UTC()
	userID, err := newID("usr")
	if err != nil {
		return nil, "", err
	}
	user := &User{
		ID:            userID,
		Name:          strings.TrimSpace(profile.Name),
		Email:         email,
		EmailVerified: profile.EmailVerified,
		Image:         strings.TrimSpace(profile.Image),
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if user.Name == "" {
		user.Name = email
	}
	if s.cfg.Hooks.BeforeUserCreate != nil {
		if err := s.cfg.Hooks.BeforeUserCreate(user); err != nil {
			return nil, "", err
		}
	}
	accountID, err := newID("acc")
	if err != nil {
		return nil, "", err
	}
	account = &Account{
		ID:         accountID,
		UserID:     user.ID,
		AccountID:  profile.AccountID,
		ProviderID: providerID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	updateAccountFromProfile(account, profile)
	if err := s.createUserAccount(ctx, user, account); err != nil {
		return nil, "", err
	}
	if s.cfg.Hooks.AfterUserCreate != nil {
		if err := s.cfg.Hooks.AfterUserCreate(*user); err != nil {
			return nil, "", err
		}
	}
	return s.createSession(ctx, *user, rememberMe, ip, ua)
}

func (s *Service) SignInEmail(ctx context.Context, in SignInEmailInput) (*SessionData, string, error) {
	email := normalizeEmail(in.Email)
	user, userErr := s.cfg.Store.FindUserByEmail(ctx, email)
	var account *Account
	if userErr == nil {
		account, _ = s.cfg.Store.FindAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
	}
	// Always run a password verify, even when the account is missing.
	// This keeps the response time constant. It stops an attacker from
	// learning if an account exists through a timing side channel.
	encodedHash := s.passwordEqualizerHash()
	if account != nil && account.Password != "" {
		encodedHash = account.Password
	}
	ok, needsRehash, verifyErr := s.cfg.PasswordHasher.Verify(ctx, in.Password, encodedHash)
	if userErr != nil || account == nil || account.Password == "" || verifyErr != nil || !ok {
		auditUserID := ""
		if userErr == nil {
			auditUserID = user.ID
		}
		s.audit(ctx, AuditEvent{Type: "sign_in.email.failed", UserID: auditUserID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: ErrInvalidCredentials.Error()})
		return nil, "", ErrInvalidCredentials
	}
	if s.cfg.RequireEmailVerification && !user.EmailVerified {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.failed", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: ErrUnverifiedEmail.Error()})
		return nil, "", ErrUnverifiedEmail
	}
	if needsRehash {
		if hash, hashErr := s.cfg.PasswordHasher.Hash(ctx, in.Password); hashErr == nil {
			account.Password = hash
			account.UpdatedAt = time.Now().UTC()
			_ = s.cfg.Store.UpdateAccount(ctx, account)
		}
	}
	data, token, err := s.createSession(ctx, *user, in.RememberMe, in.IPAddress, in.UserAgent)
	if err == nil {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.succeeded", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	}
	return data, token, err
}

func (s *Service) GetSession(ctx context.Context, token string) (*SessionData, error) {
	if token == "" {
		return nil, ErrUnauthorized
	}
	data, err := s.cfg.Store.FindSessionByToken(ctx, token)
	if err != nil {
		return nil, ErrUnauthorized
	}
	now := time.Now().UTC()
	if !data.Session.ExpiresAt.After(now) {
		_ = s.cfg.Store.DeleteSessionByToken(ctx, token)
		return nil, ErrUnauthorized
	}
	// Do not treat an unverified user as authenticated when the
	// application requires email verification. The same session works
	// after the user verifies the email.
	if s.cfg.RequireEmailVerification && !data.User.EmailVerified {
		return nil, ErrUnauthorized
	}
	if s.cfg.Session.UpdateAge > 0 && now.Sub(data.Session.UpdatedAt) >= s.cfg.Session.UpdateAge {
		data.Session.ExpiresAt = now.Add(s.cfg.Session.Expiry)
		data.Session.UpdatedAt = now
		_ = s.cfg.Store.UpdateSession(ctx, &data.Session)
	}
	return data, nil
}

func (s *Service) SignOut(ctx context.Context, token string) error {
	if token == "" {
		return nil
	}
	data, _ := s.cfg.Store.FindSessionByToken(ctx, token)
	if err := s.cfg.Store.DeleteSessionByToken(ctx, token); err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if data != nil {
		s.audit(ctx, AuditEvent{Type: "session.revoked", UserID: data.User.ID, Email: data.User.Email, Success: true})
	}
	if s.cfg.Hooks.AfterSignOut != nil && data != nil {
		return s.cfg.Hooks.AfterSignOut(&data.Session)
	}
	return nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidInput
	}
	return s.cfg.Store.DeleteUserSessions(ctx, userID)
}

func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := requestToken(r, s.cfg.Session.CookieName)
		if data, sessionErr := s.GetSession(r.Context(), token); sessionErr == nil {
			r = r.WithContext(ContextWithSession(r.Context(), data))
		}
		next.ServeHTTP(w, r)
	})
}

func ContextWithSession(ctx context.Context, data *SessionData) context.Context {
	return context.WithValue(ctx, sessionContextKey, data)
}

func SessionFromContext(ctx context.Context) (*SessionData, bool) {
	data, ok := ctx.Value(sessionContextKey).(*SessionData)
	return data, ok && data != nil
}

func (s *Service) createSession(ctx context.Context, user User, rememberMe *bool, ip, ua string) (*SessionData, string, error) {
	now := time.Now().UTC()
	token, err := randomToken(32)
	if err != nil {
		return nil, "", err
	}
	id, err := newID("ses")
	if err != nil {
		return nil, "", err
	}
	session := &Session{
		ID:        id,
		UserID:    user.ID,
		Token:     token,
		ExpiresAt: now.Add(s.cfg.Session.Expiry),
		IPAddress: ip,
		UserAgent: ua,
		CreatedAt: now,
		UpdatedAt: now,
	}
	if rememberMe != nil && !*rememberMe {
		session.ExpiresAt = now.Add(s.cfg.Session.BrowserSessionMaxAge)
	}
	if err := s.cfg.Store.CreateSession(ctx, session); err != nil {
		return nil, "", err
	}
	data := &SessionData{User: user, Session: *session}
	if s.cfg.Hooks.AfterSignIn != nil {
		if err := s.cfg.Hooks.AfterSignIn(*data); err != nil {
			return nil, "", err
		}
	}
	return data, token, nil
}

// passwordEqualizerHash returns a stable decoy hash. A sign-in for a
// missing account verifies the supplied password against this hash.
// The decoy uses the configured hasher, so the work matches a real
// verify. This removes the timing signal that reveals account existence.
func (s *Service) passwordEqualizerHash() string {
	s.dummyOnce.Do(func() {
		if hash, err := s.cfg.PasswordHasher.Hash(context.Background(), "canopy-timing-equalizer"); err == nil {
			s.dummyHash = hash
		}
	})
	return s.dummyHash
}

func (s *Service) createUserAccount(ctx context.Context, user *User, account *Account) error {
	if store, ok := s.cfg.Store.(userAccountStore); ok {
		return store.CreateUserAccount(ctx, user, account)
	}
	if err := s.cfg.Store.CreateUser(ctx, user); err != nil {
		return err
	}
	return s.cfg.Store.CreateAccount(ctx, account)
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

const oauthStateIdentifier = "oauth_state"

const (
	verificationPurposeEmail         = "email_verification"
	verificationPurposePasswordReset = "password_reset"
)

type oauthStatePayload struct {
	ID           string    `json:"id"`
	Provider     string    `json:"provider"`
	Nonce        string    `json:"nonce"`
	PKCEVerifier string    `json:"pkceVerifier"`
	CallbackURL  string    `json:"callbackURL,omitempty"`
	BindingHash  string    `json:"bindingHash"`
	RememberMe   *bool     `json:"rememberMe,omitempty"`
	IssuedAt     time.Time `json:"issuedAt"`
}

func (s *Service) signOAuthState(payload oauthStatePayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	_, _ = mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig, nil
}

func (s *Service) verifyOAuthState(state string) (oauthStatePayload, error) {
	var payload oauthStatePayload
	parts := strings.Split(state, ".")
	if len(parts) != 2 {
		return payload, ErrInvalidState
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	_, _ = mac.Write([]byte(parts[0]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(got, want) {
		return payload, ErrInvalidState
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, ErrInvalidState
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return payload, ErrInvalidState
	}
	if payload.ID == "" || payload.Provider == "" || payload.Nonce == "" || payload.PKCEVerifier == "" || payload.BindingHash == "" {
		return payload, ErrInvalidState
	}
	return payload, nil
}

func hashString(value string) string {
	sum := sha256.Sum256([]byte(value))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type actionTokenPayload struct {
	ID        string    `json:"id"`
	Purpose   string    `json:"purpose"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expiresAt"`
	IssuedAt  time.Time `json:"issuedAt"`
}

func (s *Service) sendEmailVerification(ctx context.Context, user User, callbackURL string) error {
	kind := s.emailVerificationTokenKind()
	token, expiresAt, err := s.issueActionToken(ctx, kind, user.Email)
	if err != nil {
		return err
	}
	callbackURL = s.cfg.resolveCallbackURL(callbackURL)
	message := EmailVerificationMessage{
		User:        user,
		Email:       user.Email,
		Token:       token,
		URL:         appendToken(callbackURL, token),
		CallbackURL: callbackURL,
		ExpiresAt:   expiresAt,
	}
	if err := s.cfg.EmailSender.SendEmailVerification(ctx, message); err != nil {
		return err
	}
	s.audit(ctx, AuditEvent{Type: "email_verification.requested", UserID: user.ID, Email: user.Email, Success: true})
	return nil
}

func (s *Service) emailVerificationTokenKind() actionTokenKind {
	return actionTokenKind{
		purpose:   verificationPurposeEmail,
		ttl:       s.cfg.EmailVerificationTTL,
		auditBase: "email_verification",
	}
}

func (s *Service) passwordResetTokenKind() actionTokenKind {
	return actionTokenKind{
		purpose:   verificationPurposePasswordReset,
		ttl:       s.cfg.PasswordResetTTL,
		auditBase: "password_reset",
	}
}

func (s *Service) issueActionToken(ctx context.Context, kind actionTokenKind, email string) (string, time.Time, error) {
	now := time.Now().UTC()
	id, err := randomToken(18)
	if err != nil {
		return "", time.Time{}, err
	}
	payload := actionTokenPayload{
		ID:        id,
		Purpose:   kind.purpose,
		Email:     normalizeEmail(email),
		ExpiresAt: now.Add(kind.ttl),
		IssuedAt:  now,
	}
	token, err := s.signActionToken(payload)
	if err != nil {
		return "", time.Time{}, err
	}
	verificationID, err := newID("ver")
	if err != nil {
		return "", time.Time{}, err
	}
	if err := s.cfg.Store.CreateVerification(ctx, &Verification{
		ID:         verificationID,
		Identifier: verificationIdentifier(kind.purpose, payload.Email),
		Value:      hashString(token),
		ExpiresAt:  payload.ExpiresAt,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		return "", time.Time{}, err
	}
	return token, payload.ExpiresAt, nil
}

func (s *Service) consumeActionToken(ctx context.Context, kind actionTokenKind, token string) (actionTokenPayload, error) {
	payload, err := s.verifyActionToken(token, kind.purpose)
	if err != nil {
		return payload, err
	}
	if _, err := s.cfg.Store.ConsumeVerification(ctx, verificationIdentifier(kind.purpose, payload.Email), hashString(token), time.Now().UTC()); err != nil {
		s.audit(ctx, AuditEvent{Type: kind.auditBase + ".failed", Email: payload.Email, Success: false, Error: ErrInvalidToken.Error()})
		return payload, ErrInvalidToken
	}
	return payload, nil
}

func (s *Service) signActionToken(payload actionTokenPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	_, _ = mac.Write([]byte(encoded))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return encoded + "." + sig, nil
}

func (s *Service) verifyActionToken(token, purpose string) (actionTokenPayload, error) {
	var payload actionTokenPayload
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return payload, ErrInvalidToken
	}
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	_, _ = mac.Write([]byte(parts[0]))
	want := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(got, want) {
		return payload, ErrInvalidToken
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return payload, ErrInvalidToken
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return payload, ErrInvalidToken
	}
	if payload.ID == "" || payload.Purpose != purpose || payload.Email == "" {
		return payload, ErrInvalidToken
	}
	if !payload.ExpiresAt.After(time.Now().UTC()) {
		return payload, ErrExpiredToken
	}
	return payload, nil
}

func verificationIdentifier(purpose, email string) string {
	return purpose + ":" + normalizeEmail(email)
}

func appendToken(callbackURL, token string) string {
	callbackURL = strings.TrimSpace(callbackURL)
	if callbackURL == "" {
		return ""
	}
	sep := "?"
	if strings.Contains(callbackURL, "?") {
		sep = "&"
	}
	return callbackURL + sep + "token=" + token
}

func updateAccountFromProfile(account *Account, profile *oauth.Profile) {
	account.AccessToken = profile.AccessToken
	account.RefreshToken = profile.RefreshToken
	account.AccessTokenExpiresAt = profile.AccessTokenExpiresAt
	account.RefreshTokenExpiresAt = profile.RefreshTokenExpiresAt
	account.Scope = profile.Scope
	account.IDToken = profile.IDToken
}

func (s *Service) audit(ctx context.Context, event AuditEvent) {
	event.At = time.Now().UTC()
	s.cfg.AuditLogger.LogAuthEvent(ctx, event)
}

func validateEmailPassword(email, pass string, min, max int) error {
	if !strings.Contains(email, "@") || strings.ContainsAny(email, " \t\r\n") {
		return ErrInvalidInput
	}
	if len(pass) < min || len(pass) > max {
		return ErrInvalidInput
	}
	return nil
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}
