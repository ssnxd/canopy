package canopy

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/ssnxd/canopy/oauth"
	"golang.org/x/crypto/hkdf"
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

// SignInResult is the outcome of a sign-in attempt. Exactly one of
// Session or Challenge is set. Session is set on a full sign-in.
// Challenge is set when a second authentication step is required.
type SignInResult struct {
	Session   *SessionData
	Token     string
	Challenge *StepUpChallenge
}

// TwoFactorRequired reports if the sign-in needs a second step.
func (r SignInResult) TwoFactorRequired() bool { return r.Challenge != nil }

// OAuthCallbackResult is the outcome of an OAuth callback. It carries the
// sign-in result and the redirect data for the browser flow.
type OAuthCallbackResult struct {
	Result      *SignInResult
	CallbackURL string
	RememberMe  *bool
}

type Service struct {
	cfg          Config
	providers    map[string]oauth.Provider
	interceptors []SignInInterceptor
	validators   []SessionValidator
	dummyOnce    sync.Once
	dummyHash    string
}

type userAccountStore interface {
	CreateUserAccount(ctx context.Context, user *User, account *Account) error
}

type passwordResetStore interface {
	ApplyPasswordReset(
		ctx context.Context,
		identifier string,
		value string,
		now time.Time,
		account *Account,
	) error
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
	s := &Service{cfg: cfg, providers: providers}
	for _, module := range cfg.Modules {
		if interceptor, ok := module.(SignInInterceptor); ok {
			s.interceptors = append(s.interceptors, interceptor)
		}
		if validator, ok := module.(SessionValidator); ok {
			s.validators = append(s.validators, validator)
		}
	}
	return s
}

// Store returns the configured store. It satisfies the Core interface.
func (s *Service) Store() Store { return s.cfg.Store }

// Config returns the non-secret runtime configuration exposed to modules.
func (s *Service) Config() RuntimeConfig {
	return RuntimeConfig{
		Environment:       s.cfg.Environment,
		BasePath:          s.cfg.BasePath,
		PasswordMinLength: s.cfg.PasswordMinLength,
		PasswordMaxLength: s.cfg.PasswordMaxLength,
		Session:           s.cfg.Session,
	}
}

// HashPassword hashes a password with the configured hasher.
func (s *Service) HashPassword(ctx context.Context, value string) (string, error) {
	return s.cfg.PasswordHasher.Hash(ctx, value)
}

type moduleCore struct {
	*Service
	moduleID string
}

func (c moduleCore) ModuleKeys(purpose string) (ModuleKeyring, error) {
	if purpose == "" || strings.ContainsAny(purpose, "\x00\r\n") {
		return ModuleKeyring{}, fmt.Errorf("canopy: module key purpose is required")
	}
	derive := func(secret string) ([]byte, error) {
		key := make([]byte, 32)
		label := "canopy/" + c.moduleID + "/" + purpose
		if _, err := io.ReadFull(hkdf.New(sha256.New, []byte(secret), nil, []byte(label)), key); err != nil {
			return nil, err
		}
		return key, nil
	}
	current, err := derive(c.cfg.Secret)
	if err != nil {
		return ModuleKeyring{}, err
	}
	keys := ModuleKeyring{Current: current}
	for _, secret := range c.cfg.PreviousSecrets {
		key, err := derive(secret)
		if err != nil {
			return ModuleKeyring{}, err
		}
		keys.Previous = append(keys.Previous, key)
	}
	return keys, nil
}

// Authenticate resolves the session for a request. It reads the bearer
// token or the session cookie. It satisfies the Core interface.
func (s *Service) Authenticate(r *http.Request) (*SessionData, error) {
	return s.GetSession(r.Context(), requestToken(r, s.cfg.Session.CookieName))
}

// ClientIP returns the direct peer unless it is a configured trusted proxy.
// For trusted proxies it walks X-Forwarded-For from right to left.
func (s *Service) ClientIP(r *http.Request) string {
	peer := remoteIP(r.RemoteAddr)
	if peer == nil || !s.cfg.isTrustedProxy(peer) {
		return ipString(peer, r.RemoteAddr)
	}
	forwarded := strings.Split(r.Header.Get("X-Forwarded-For"), ",")
	for i := len(forwarded) - 1; i >= 0; i-- {
		value := strings.TrimSpace(forwarded[i])
		if value == "" {
			continue
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return peer.String()
		}
		if !s.cfg.isTrustedProxy(ip) {
			return ip.String()
		}
	}
	return peer.String()
}

// Audit emits an audit event. It satisfies the Core interface.
func (s *Service) Audit(ctx context.Context, event AuditEvent) {
	s.audit(ctx, event)
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
			s.reportHookError(ctx, "after_user_create", err)
		}
	}
	if s.cfg.RequireEmailVerification {
		if err := s.sendEmailVerification(ctx, *user, in.CallbackURL); err != nil {
			return nil, "", err
		}
	}
	return s.IssueSession(ctx, *user, SessionOptions{RememberMe: in.RememberMe, IPAddress: in.IPAddress, UserAgent: in.UserAgent})
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
			s.reportHookError(ctx, "after_email_verified", err)
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
	account, err := s.findAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
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
	payload, err := s.verifyActionToken(in.Token, kind.purpose)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "password_reset.failed", Success: false, Error: err.Error()})
		return err
	}
	user, err := s.cfg.Store.FindUserByEmail(ctx, payload.Email)
	if err != nil {
		return err
	}
	account, err := s.findAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
	if err != nil || account.Password == "" {
		return ErrInvalidToken
	}
	hash, err := s.cfg.PasswordHasher.Hash(ctx, in.NewPassword)
	if err != nil {
		return err
	}
	account.Password = hash
	account.UpdatedAt = time.Now().UTC()
	identifier := verificationIdentifier(kind.purpose, payload.Email)
	value := hashString(in.Token)
	now := time.Now().UTC()
	if store, ok := s.cfg.Store.(passwordResetStore); ok {
		storedAccount, err := encryptAccountTokens(s.cfg.ProviderTokenCodec, account)
		if err != nil {
			return err
		}
		if err := store.ApplyPasswordReset(ctx, identifier, value, now, storedAccount); err != nil {
			if errors.Is(err, ErrNotFound) {
				return ErrInvalidToken
			}
			return err
		}
	} else {
		if _, err := s.cfg.Store.ConsumeVerification(ctx, identifier, value, now); err != nil {
			return ErrInvalidToken
		}
		if err := s.updateAccount(ctx, account); err != nil {
			return err
		}
		if err := s.cfg.Store.DeleteUserSessions(ctx, user.ID); err != nil {
			return err
		}
		if err := s.cfg.Store.DeleteVerificationsByIdentifier(ctx, identifier); err != nil {
			return err
		}
	}
	if s.cfg.Hooks.AfterPasswordReset != nil {
		if err := s.cfg.Hooks.AfterPasswordReset(*user); err != nil {
			s.reportHookError(ctx, "after_password_reset", err)
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

func (s *Service) OAuthCallback(ctx context.Context, in OAuthCallbackInput) (*OAuthCallbackResult, error) {
	return s.oauthCallback(ctx, in)
}

func (s *Service) oauthCallback(ctx context.Context, in OAuthCallbackInput) (*OAuthCallbackResult, error) {
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
	result, err := s.signInOAuthProfile(ctx, provider.ID(), profile, payload.RememberMe, in.IPAddress, in.UserAgent)
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.failed", ProviderID: in.Provider, Email: normalizeEmail(profile.Email), IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: err.Error()})
		return nil, err
	}
	if result.Session != nil {
		if s.cfg.Hooks.AfterOAuth != nil {
			if err := s.cfg.Hooks.AfterOAuth(*result.Session); err != nil {
				s.reportHookError(ctx, "after_oauth", err)
			}
		}
		s.audit(ctx, AuditEvent{Type: "oauth.callback.succeeded", UserID: result.Session.User.ID, Email: result.Session.User.Email, ProviderID: provider.ID(), IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	} else {
		s.audit(ctx, AuditEvent{Type: "oauth.callback.two_factor_required", ProviderID: provider.ID(), IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	}
	return &OAuthCallbackResult{
		Result:      result,
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
	account, err := s.findAccountByUserProvider(ctx, in.UserID, in.ProviderID)
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
	if err := s.updateAccount(ctx, account); err != nil {
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

func (s *Service) signInOAuthProfile(ctx context.Context, providerID string, profile *oauth.Profile, rememberMe *bool, ip, ua string) (*SignInResult, error) {
	opt := SessionOptions{RememberMe: rememberMe, IPAddress: ip, UserAgent: ua}
	if profile == nil || profile.AccountID == "" {
		return nil, ErrProviderFailure
	}
	if profile.ProviderID != "" && profile.ProviderID != providerID {
		return nil, ErrProviderFailure
	}
	account, err := s.findAccount(ctx, providerID, profile.AccountID)
	if err == nil {
		user, err := s.cfg.Store.FindUserByID(ctx, account.UserID)
		if err != nil {
			return nil, err
		}
		updateAccountFromProfile(account, profile)
		account.UpdatedAt = time.Now().UTC()
		if err := s.updateAccount(ctx, account); err != nil {
			return nil, err
		}
		return s.finishSignIn(ctx, *user, opt)
	}
	if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	email := normalizeEmail(profile.Email)
	if email == "" || !profile.EmailVerified {
		return nil, ErrProviderFailure
	}
	if existing, err := s.cfg.Store.FindUserByEmail(ctx, email); err == nil && existing != nil {
		return nil, ErrAccountLinking
	} else if err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	now := time.Now().UTC()
	userID, err := newID("usr")
	if err != nil {
		return nil, err
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
			return nil, err
		}
	}
	accountID, err := newID("acc")
	if err != nil {
		return nil, err
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
		return nil, err
	}
	if s.cfg.Hooks.AfterUserCreate != nil {
		if err := s.cfg.Hooks.AfterUserCreate(*user); err != nil {
			s.reportHookError(ctx, "after_user_create", err)
		}
	}
	return s.finishSignIn(ctx, *user, opt)
}

func (s *Service) SignInEmail(ctx context.Context, in SignInEmailInput) (*SignInResult, error) {
	email := normalizeEmail(in.Email)
	user, userErr := s.cfg.Store.FindUserByEmail(ctx, email)
	var account *Account
	if userErr == nil {
		account, _ = s.findAccountByUserProvider(ctx, user.ID, ProviderEmailPassword)
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
		return nil, ErrInvalidCredentials
	}
	if s.cfg.RequireEmailVerification && !user.EmailVerified {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.failed", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: ErrUnverifiedEmail.Error()})
		return nil, ErrUnverifiedEmail
	}
	if needsRehash {
		if hash, hashErr := s.cfg.PasswordHasher.Hash(ctx, in.Password); hashErr == nil {
			account.Password = hash
			account.UpdatedAt = time.Now().UTC()
			_ = s.updateAccount(ctx, account)
		}
	}
	result, err := s.finishSignIn(ctx, *user, SessionOptions{RememberMe: in.RememberMe, IPAddress: in.IPAddress, UserAgent: in.UserAgent})
	if err != nil {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.failed", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: false, Error: err.Error()})
		return nil, err
	}
	if result.Session != nil {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.succeeded", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	} else {
		s.audit(ctx, AuditEvent{Type: "sign_in.email.two_factor_required", UserID: user.ID, Email: email, IPAddress: in.IPAddress, UserAgent: in.UserAgent, Success: true})
	}
	return result, nil
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
	// Enforce an absolute lifetime. A session cannot live past this cap
	// even with regular use. This limits how long a stolen token stays
	// valid.
	absoluteEnabled := !s.cfg.Session.DisableAbsoluteExpiry && s.cfg.Session.AbsoluteMaxAge > 0
	var deadline time.Time
	if absoluteEnabled {
		deadline = data.Session.CreatedAt.Add(s.cfg.Session.AbsoluteMaxAge)
		if !now.Before(deadline) {
			_ = s.cfg.Store.DeleteSessionByToken(ctx, token)
			return nil, ErrUnauthorized
		}
	}
	// A banned user is not authenticated. Keep the session, because the
	// ban may expire.
	if isBanned(data.User, now) {
		return nil, ErrUserBanned
	}
	// Do not treat an unverified user as authenticated when the
	// application requires email verification. The same session works
	// after the user verifies the email.
	if s.cfg.RequireEmailVerification && !data.User.EmailVerified {
		return nil, ErrUnauthorized
	}
	for _, validator := range s.validators {
		if err := validator.ValidateSession(ctx, data); err != nil {
			return nil, ErrUnauthorized
		}
	}
	if s.cfg.Session.UpdateAge > 0 && now.Sub(data.Session.UpdatedAt) >= s.cfg.Session.UpdateAge {
		data.Session.ExpiresAt = now.Add(s.cfg.Session.Expiry)
		if absoluteEnabled && data.Session.ExpiresAt.After(deadline) {
			data.Session.ExpiresAt = deadline
		}
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
		if err := s.cfg.Hooks.AfterSignOut(&data.Session); err != nil {
			s.reportHookError(ctx, "after_sign_out", err)
		}
	}
	return nil
}

func (s *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	if userID == "" {
		return ErrInvalidInput
	}
	return s.cfg.Store.DeleteUserSessions(ctx, userID)
}

// Middleware is a deprecated alias for OptionalSession.
// Deprecated: use OptionalSession or RequireSession to make intent explicit.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return s.OptionalSession(next)
}

// OptionalSession resolves a session when present and always calls next.
func (s *Service) OptionalSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := requestToken(r, s.cfg.Session.CookieName)
		if data, sessionErr := s.GetSession(r.Context(), token); sessionErr == nil {
			r = r.WithContext(ContextWithSession(r.Context(), data))
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession resolves a session and returns unauthorized without calling
// next when credentials are missing or invalid.
func (s *Service) RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := requestToken(r, s.cfg.Session.CookieName)
		data, err := s.GetSession(r.Context(), token)
		if err != nil {
			writeError(w, ErrUnauthorized)
			return
		}
		next.ServeHTTP(w, r.WithContext(ContextWithSession(r.Context(), data)))
	})
}

func ContextWithSession(ctx context.Context, data *SessionData) context.Context {
	return context.WithValue(ctx, sessionContextKey, data)
}

func SessionFromContext(ctx context.Context) (*SessionData, bool) {
	data, ok := ctx.Value(sessionContextKey).(*SessionData)
	return data, ok && data != nil
}

// finishSignIn runs the sign-in interceptors and then issues a session.
// It rejects a banned user. It returns a challenge when a module requires
// a second authentication step.
func (s *Service) finishSignIn(ctx context.Context, user User, opt SessionOptions) (*SignInResult, error) {
	if isBanned(user, time.Now().UTC()) {
		return nil, ErrUserBanned
	}
	for _, interceptor := range s.interceptors {
		challenge, err := interceptor.AfterPrimaryAuth(ctx, user)
		if err != nil {
			return nil, err
		}
		if challenge != nil {
			return &SignInResult{Challenge: challenge}, nil
		}
	}
	data, token, err := s.IssueSession(ctx, user, opt)
	if err != nil {
		return nil, err
	}
	return &SignInResult{Session: data, Token: token}, nil
}

// IssueSession creates a session for the user and returns the token.
// It satisfies the Core interface, so a module can complete a sign-in.
func (s *Service) IssueSession(ctx context.Context, user User, opt SessionOptions) (*SessionData, string, error) {
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
		ID:                   id,
		UserID:               user.ID,
		Token:                token,
		ExpiresAt:            now.Add(s.cfg.Session.Expiry),
		IPAddress:            opt.IPAddress,
		UserAgent:            opt.UserAgent,
		ActiveOrganizationID: opt.ActiveOrganizationID,
		ImpersonatedBy:       opt.ImpersonatedBy,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if opt.RememberMe != nil && !*opt.RememberMe {
		session.ExpiresAt = now.Add(s.cfg.Session.BrowserSessionMaxAge)
	}
	if err := s.cfg.Store.CreateSession(ctx, session); err != nil {
		return nil, "", err
	}
	data := &SessionData{User: user, Session: *session}
	if s.cfg.Hooks.AfterSignIn != nil {
		if err := s.cfg.Hooks.AfterSignIn(*data); err != nil {
			s.reportHookError(ctx, "after_sign_in", err)
		}
	}
	return data, token, nil
}

// isBanned reports if the user is banned at time now. A ban with an
// expiry in the past is not active.
func isBanned(u User, now time.Time) bool {
	if !u.Banned {
		return false
	}
	if u.BanExpiresAt != nil && !u.BanExpiresAt.After(now) {
		return false
	}
	return true
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
	storedAccount, err := encryptAccountTokens(s.cfg.ProviderTokenCodec, account)
	if err != nil {
		return err
	}
	if store, ok := s.cfg.Store.(userAccountStore); ok {
		return store.CreateUserAccount(ctx, user, storedAccount)
	}
	if err := s.cfg.Store.CreateUser(ctx, user); err != nil {
		return err
	}
	return s.cfg.Store.CreateAccount(ctx, storedAccount)
}

func (s *Service) findAccount(ctx context.Context, providerID, accountID string) (*Account, error) {
	account, err := s.cfg.Store.FindAccount(ctx, providerID, accountID)
	if err != nil {
		return nil, err
	}
	return decryptAccountTokens(s.cfg.ProviderTokenCodec, account)
}

func (s *Service) findAccountByUserProvider(ctx context.Context, userID, providerID string) (*Account, error) {
	account, err := s.cfg.Store.FindAccountByUserProvider(ctx, userID, providerID)
	if err != nil {
		return nil, err
	}
	return decryptAccountTokens(s.cfg.ProviderTokenCodec, account)
}

func (s *Service) updateAccount(ctx context.Context, account *Account) error {
	storedAccount, err := encryptAccountTokens(s.cfg.ProviderTokenCodec, account)
	if err != nil {
		return err
	}
	return s.cfg.Store.UpdateAccount(ctx, storedAccount)
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
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !s.validSignature(parts[0], got) {
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
	if err := s.cfg.Store.ReplaceVerification(ctx, &Verification{
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
	got, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !s.validSignature(parts[0], got) {
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

func (s *Service) validSignature(value string, signature []byte) bool {
	valid := false
	for _, secret := range append([]string{s.cfg.Secret}, s.cfg.PreviousSecrets...) {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(value))
		if hmac.Equal(signature, mac.Sum(nil)) {
			valid = true
		}
	}
	return valid
}

func verificationIdentifier(purpose, email string) string {
	return purpose + ":" + normalizeEmail(email)
}

func appendToken(callbackURL, token string) string {
	callbackURL = strings.TrimSpace(callbackURL)
	if callbackURL == "" {
		return ""
	}
	parsed, err := url.Parse(callbackURL)
	if err != nil {
		return ""
	}
	query := parsed.Query()
	query.Set("token", token)
	parsed.RawQuery = query.Encode()
	return parsed.String()
}

func updateAccountFromProfile(account *Account, profile *oauth.Profile) {
	if profile.AccessToken != "" {
		account.AccessToken = profile.AccessToken
	}
	if profile.RefreshToken != "" {
		account.RefreshToken = profile.RefreshToken
	}
	if profile.AccessTokenExpiresAt != nil {
		account.AccessTokenExpiresAt = profile.AccessTokenExpiresAt
	}
	if profile.RefreshTokenExpiresAt != nil {
		account.RefreshTokenExpiresAt = profile.RefreshTokenExpiresAt
	}
	if profile.Scope != "" {
		account.Scope = profile.Scope
	}
	if profile.IDToken != "" {
		account.IDToken = profile.IDToken
	}
}

func (s *Service) audit(ctx context.Context, event AuditEvent) {
	event.At = time.Now().UTC()
	s.cfg.AuditLogger.LogAuthEvent(ctx, event)
}

func (s *Service) reportHookError(ctx context.Context, hook string, err error) {
	s.audit(ctx, AuditEvent{
		Type:    "hook." + hook + ".failed",
		Success: false,
		Error:   err.Error(),
	})
	if s.cfg.HookErrorHandler != nil {
		s.cfg.HookErrorHandler(ctx, hook, err)
	}
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

func remoteIP(remoteAddr string) net.IP {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		return net.ParseIP(host)
	}
	return net.ParseIP(remoteAddr)
}

func ipString(ip net.IP, fallback string) string {
	if ip == nil {
		return fallback
	}
	return ip.String()
}

func (c Config) isTrustedProxy(ip net.IP) bool {
	for _, value := range c.TrustedProxies {
		if trusted := net.ParseIP(value); trusted != nil {
			if trusted.Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(value)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}
